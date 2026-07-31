// SECURITY H-09 (CWE-89 SQL injection / OWASP A03:2021 Injection).
// Values throughout this data-access layer are ALREADY fully parameterised - see
// Database/DbRepository.cs:L517-L607, where every value is bound through
// command.CreateParameter() with an explicit NpgsqlDbType and referenced as @name. PostgreSQL
// cannot parameterise an IDENTIFIER, so the residual injection exposure is confined to the six
// sites that concatenate a table identifier into SQL. This helper closes that exposure with
// allow-list validation plus double-quoting, and FAILS HARD on rejection: a silent sanitise or
// pass-through would reintroduce the vulnerability while appearing to fix it.

using System.Text.RegularExpressions;

namespace WebVella.Erp.Database
{
	/// <summary>
	/// Validates, and where required quotes, the PostgreSQL identifiers that this layer has to
	/// concatenate into SQL text because PostgreSQL cannot bind an identifier as a parameter.
	/// </summary>
	/// <remarks>
	/// Two members are exposed because the call sites sit in two different SQL contexts, and
	/// using the wrong one is a silent defect rather than a compile error.
	/// <see cref="Quote(string)"/> is for an IDENTIFIER position - "FROM ident", "DROP TABLE
	/// ident" - and returns the identifier enclosed in double quotes.
	/// <see cref="Validate(string)"/> is for a single-quoted SQL STRING LITERAL position, such
	/// as the pg_tables probe "tablename = 'ident'", and returns the identifier bare: a
	/// double-quoted form would be compared as literal text including the quote characters and
	/// would silently match nothing, turning an existence check into a wrong answer.
	/// This type is deliberately public, unlike Utilities/PasswordUtil.cs whose members are all
	/// restricted to this assembly. Every PasswordUtil caller lives in this assembly, whereas
	/// three of this helper's call sites are in WebVella.Erp.Plugins.SDK, a separate assembly
	/// that project-references this one, so restricting this helper's visibility the same way
	/// would break that project's compilation. Both choices are correct for their callers.
	/// It is a stateless static utility by design - no interface, no dependency-injection
	/// registration, no instance state and no configuration surface.
	/// </remarks>
	public static partial class DbIdentifier
	{
		/// <summary>
		/// The allow-list an identifier must match in full. Replicated from the platform's own
		/// identifier grammar at Api/Models/ValidationUtility.cs:L9 so that this helper accepts
		/// exactly what the platform already accepts: it must begin with a lower-case letter,
		/// may contain only lower-case letters, digits and underscores, must not contain two
		/// consecutive underscores, and must not end with an underscore. The pattern is anchored
		/// at both ends - an unanchored match would admit "a; DROP TABLE x" on its prefix alone.
		/// It is replicated rather than reused because that constant is private, because
		/// ValidateName throws outright when asked for a maximum length above 63 and so cannot
		/// be called for a 67-character identifier at all, and because it reports soft ErrorModel
		/// results where this helper must fail hard.
		/// </summary>
		private const string IdentifierPattern = @"^[a-z](?!.*__)[a-z0-9_]*[a-z0-9]$";

		/// <summary>
		/// The maximum accepted length. This is 67 and NOT 63 deliberately. The platform caps an
		/// ENTITY name at 63 characters (Api/EntityManager.cs:L69-L70), but every call site
		/// passes the already-prefixed TABLE identifier - "rec_" or "rel_" followed by the entity
		/// or relation name - so a wholly legitimate identifier can be 67 characters long. A 63
		/// cap would throw for every existing entity whose name is 60 to 63 characters long and
		/// break record queries, entity deletion and SDK code generation: a self-inflicted outage
		/// caused by a security fix. Do not tighten this back to 63. The security property here is
		/// the character allow-list, which makes injection impossible by construction; this bound
		/// exists only to respect the PostgreSQL identifier length limit.
		/// </summary>
		private const int MaxIdentifierLength = 67;

		/// <summary>
		/// The allow-list matcher. Source-generated so the pattern is compiled at build time
		/// instead of being re-parsed on every call, because this helper sits on the record-query
		/// hot path in Database/DbRecordRepository.cs.
		/// </summary>
		[GeneratedRegex(IdentifierPattern)]
		private static partial Regex IdentifierRegex();

		/// <summary>
		/// Validates a single PostgreSQL identifier against the allow-list and returns it
		/// unchanged. Use this where the identifier is emitted into a single-quoted SQL string
		/// literal, such as the pg_tables existence probe in
		/// WebVella.Erp.Plugins.SDK/Services/CodeGenService.cs, where the value must stay bare.
		/// Use <see cref="Quote(string)"/> instead wherever the identifier occupies an identifier
		/// position in the statement.
		/// </summary>
		/// <param name="identifier">
		/// A single, unqualified identifier - never a schema-qualified path. Schema qualification
		/// remains the caller's responsibility, exactly as CodeGenService.cs keeps its "public."
		/// prefix outside the interpolation, so a dot is rejected: quoting "public.rel_x" would
		/// ask PostgreSQL for one table whose name literally contains a dot and would silently
		/// address the wrong table.
		/// </param>
		/// <returns>The identifier exactly as supplied, once it has been proven valid.</returns>
		/// <exception cref="DbException">
		/// Thrown when the identifier is null, empty, whitespace only, contains a double quote,
		/// fails the allow-list, or is longer than <see cref="MaxIdentifierLength"/> characters.
		/// A rejection is always an exception and never a sanitised, unchanged, null or empty
		/// value: a silent repair would reintroduce the injection exposure while making the
		/// finding read as closed.
		/// </exception>
		public static string Validate(string identifier)
		{
			if (string.IsNullOrWhiteSpace(identifier))
			{
				throw new DbException("Invalid SQL identifier: a null, empty or whitespace-only identifier cannot be used in SQL.");
			}

			// Rejected explicitly and by name as defence in depth, not as a duplicate of the
			// allow-list below. The double quote is the one character that could terminate the
			// quoting applied by Quote(string), so it stays rejected here on its own account even
			// if the grammar is ever loosened by a future edit.
			if (identifier.Contains('"'))
			{
				throw new DbException($"Invalid SQL identifier '{identifier}': a double quote character is not permitted.");
			}

			// The allow-list is the actual security control. Note that the input is never
			// trimmed, lower-cased or otherwise normalised into validity: an identifier that does
			// not already conform is rejected outright.
			if (!IdentifierRegex().IsMatch(identifier))
			{
				throw new DbException($"Invalid SQL identifier '{identifier}': only lower-case letters, digits and single underscores are permitted. It must begin with a lower-case letter, must not end with an underscore, must not contain two consecutive underscores, must not be schema-qualified with a dot, and must be at least 2 characters long.");
			}

			if (identifier.Length > MaxIdentifierLength)
			{
				throw new DbException($"Invalid SQL identifier '{identifier}': length {identifier.Length} exceeds the maximum of {MaxIdentifierLength} characters supported by PostgreSQL.");
			}

			return identifier;
		}

		/// <summary>
		/// Validates a single PostgreSQL identifier against the allow-list and returns it wrapped
		/// in double quotes, ready to be concatenated into an identifier position such as
		/// "FROM ident" or "DROP TABLE ident". The emitted shape is exactly the one this layer
		/// already writes by hand at Database/DbRepository.cs:L549, L583 and L601, so no existing
		/// query text changes. Quoting is behaviour-preserving because the allow-list rejects
		/// upper case, so every accepted identifier is already lower case and folds to itself:
		/// rec_user and "rec_user" name the same table. Use <see cref="Validate(string)"/> instead
		/// wherever the identifier is emitted into a single-quoted SQL string literal.
		/// </summary>
		/// <param name="identifier">
		/// A single, unqualified identifier - see <see cref="Validate(string)"/>.
		/// </param>
		/// <returns>The validated identifier enclosed in double quotes.</returns>
		/// <exception cref="DbException">
		/// Thrown on any rejection - see <see cref="Validate(string)"/>.
		/// </exception>
		public static string Quote(string identifier)
		{
			// No inner escaping is performed, and none is needed: Validate rejects the double
			// quote outright, so the quoted form cannot be broken out of.
			return "\"" + Validate(identifier) + "\"";
		}
	}
}
