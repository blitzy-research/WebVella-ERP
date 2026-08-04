// SECURITY H-09 (CWE-89 SQL injection / OWASP A03:2021 Injection).
// Values throughout this data-access layer are ALREADY fully parameterised - see
// Database/DbRepository.cs:L517-L607, where every value is bound through
// command.CreateParameter() with an explicit NpgsqlDbType and referenced as @name. PostgreSQL
// cannot parameterise an IDENTIFIER, so the residual injection exposure is confined to the sites
// that concatenate a table identifier into SQL text. The H-09 finding enumerates six such
// locators - Database/DbEntityRepository.cs:L275, Database/DbRecordRepository.cs:L664 and :L666,
// and WebVella.Erp.Plugins.SDK/Services/CodeGenService.cs:L1018, :L1291 and :L1305 - but those are
// the finding's evidence, not the full application surface: remediation swept the whole layer and
// routed every identifier concatenation through this helper, which is why it is now invoked from
// seven files rather than three. The per-site inventory is recorded in
// docs/security/remediation-log.md so this header does not have to be re-counted whenever a call
// site moves. This helper closes the exposure with allow-list validation plus double-quoting, and
// FAILS HARD on rejection: a silent sanitise or pass-through would reintroduce the vulnerability
// while appearing to fix it.

using System.Globalization;
using System.Text;
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
		/// ValidateName trims its input and reports soft ErrorModel results where this helper must
		/// neither normalise nor forgive, and because ValidateName validates a user-facing NAME
		/// whereas this helper validates the prefixed PHYSICAL identifier that reaches the server.
		/// </summary>
		private const string IdentifierPattern = @"^[a-z](?!.*__)[a-z0-9_]*[a-z0-9]$";

		/// <summary>
		/// The maximum accepted length of the PHYSICAL identifier, in BYTES: 67, being the 4-byte
		/// "rec_" or "rel_" prefix every caller applies plus the 63 characters the platform's own
		/// name validation admits for an entity or relation name.
		/// </summary>
		/// <remarks>
		/// SECURITY H-09 (CWE-89 SQL injection). The injection control in this helper is the
		/// allow-list at <see cref="IdentifierPattern"/> - lowercase ASCII letters, digits and
		/// single underscores only, so no quote, dot, whitespace, comment marker or statement
		/// separator can survive it. This length bound contributes NOTHING to that defence; it
		/// exists only so the helper refuses input so long that it could not have come from a
		/// validated platform name at all. Widening or narrowing it cannot make an injection
		/// reachable, which is why the bound is set where the platform's real names live rather
		/// than lower.
		///
		/// Why 67 and not 63, measured rather than assumed:
		/// <list type="bullet">
		/// <item><description>Api/EntityManager.cs:L69-L70 and Api/Models/ValidationUtility.cs:L12
		/// cap an entity or field NAME at 63 characters - that is the platform's contract with its
		/// users, and names of that length are already deployed.</description></item>
		/// <item><description>EVERY caller of this helper passes an already-PREFIXED physical name:
		/// Eql/EqlBuilder.Sql.cs:L48 and L53, Database/DbRecordRepository.cs:L1880 and L1981,
		/// Database/DbRelationRepository.cs:L80-L81 and L294, Database/DbEntityRepository.cs:L82
		/// and L321, Database/DbRepository.cs:L412 and L454, and the SDK plugin and code
		/// generator. The prefix is always 4 bytes.</description></item>
		/// </list>
		/// 63 characters of validated name plus a 4-byte prefix is 67 bytes, so 67 is the longest
		/// physical name the platform can legitimately construct. It must remain addressable.
		///
		/// Do NOT tighten this to 63: the allow-list already supplies all of the injection resistance,
		/// and a 63-byte cap would make every entity or relation whose name is 60 characters or longer
		/// wholly unaddressable - read, write, EQL, relation maintenance and deletion would all throw at
		/// the SQL boundary on an already-deployed installation. PostgreSQL truncation is deterministic,
		/// so an over-long name still resolves consistently; a collision needs two names agreeing on
		/// their first 63 bytes, which is a uniqueness question settled at CREATE time and invisible to a
		/// helper that only ever sees one name.
		///
		/// Both <see cref="Validate(string)"/> and <see cref="Quote(string)"/> apply this same
		/// bound to the same physical name, so the two contexts can never disagree about what is
		/// addressable.
		///
		/// RESIDUAL, owned elsewhere and recorded in docs/security/risk-register.md: the
		/// platform's name validation admits names that cannot survive prefixing UNIQUELY, so two
		/// entity names agreeing on their first 59 characters still collapse onto one physical
		/// table after truncation. That belongs to entity-creation uniqueness validation, where
		/// both names are in scope and a comparison is possible, not to this helper.
		///
		/// Byte length is measured, not character length, because the two differ for any non-ASCII
		/// input and the server's budget is denominated in bytes. For an identifier that PASSES
		/// the ASCII-only allow-list the two are necessarily equal; the distinction matters only
		/// while rejecting hostile input, which is precisely when it must be correct.
		/// </remarks>
		private const int MaxIdentifierLengthBytes = 67;

		/// <summary>
		/// The longest rejected value echoed back in an exception message. See
		/// <see cref="DescribeRejected(string)"/> for why the echo is bounded at all.
		/// </summary>
		private const int MaxEchoedValueLength = 64;

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
		/// Thrown when the identifier is null, empty, whitespace only, longer than
		/// <see cref="MaxIdentifierLengthBytes"/> bytes, contains a double quote, or fails the
		/// allow-list. A rejection is always an exception and never a sanitised, unchanged, null
		/// or empty value: a silent repair would reintroduce the injection exposure while making
		/// the finding read as closed.
		/// </exception>
		public static string Validate(string identifier)
		{
			if (string.IsNullOrWhiteSpace(identifier))
			{
				throw new DbException("Invalid SQL identifier: a null, empty or whitespace-only identifier cannot be used in SQL.");
			}

			// SECURITY H-09 hardening (CWE-400 uncontrolled resource consumption). The length bound is
			// evaluated FIRST - before the double-quote scan and before the allow-list match - because it
			// is the only check whose cost does not grow with the input: String.Length is a stored field,
			// so an oversized identifier is refused in constant time having read none of it. The
			// allow-list pattern is source-generated and its (?!.*__) lookahead runs once from a fixed
			// position, so the cost is linear rather than super-linear; but a linear scan over
			// attacker-influenced input of unbounded length is still needless work on the record-query hot
			// path, performed on a value already known to be invalid. Order, not a match timeout, is what
			// removes that exposure.
			//
			// Characters are tested before bytes purely as the cheaper gate: a UTF-8 encoding is
			// never shorter than its character count, so anything over the budget in characters is
			// necessarily over it in bytes and can be refused without encoding anything.
			if (identifier.Length > MaxIdentifierLengthBytes)
			{
				throw new DbException($"Invalid SQL identifier {DescribeRejected(identifier)}: length {identifier.Length} exceeds the maximum physical identifier length of {MaxIdentifierLengthBytes} bytes, being a 4-byte table prefix plus the 63 characters the platform admits in an entity or relation name. No validated platform name can produce a physical identifier this long.");
			}

			// Measured on the physical name because the server's budget is denominated in bytes.
			// Only reachable for input that is within budget by character count but not by byte
			// count, which means it contains non-ASCII characters and so cannot pass the
			// allow-list either; the bound is applied here regardless so that no oversized value
			// ever reaches the matcher.
			int byteLength = Encoding.UTF8.GetByteCount(identifier);
			if (byteLength > MaxIdentifierLengthBytes)
			{
				throw new DbException($"Invalid SQL identifier {DescribeRejected(identifier)}: encoded length {byteLength} bytes exceeds the maximum physical identifier length of {MaxIdentifierLengthBytes} bytes.");
			}

			// Rejected explicitly and by name as defence in depth, not as a duplicate of the
			// allow-list below. The double quote is the one character that could terminate the
			// quoting applied by Quote(string), so it stays rejected here on its own account even
			// if the grammar is ever loosened by a future edit.
			if (identifier.Contains('"'))
			{
				throw new DbException($"Invalid SQL identifier {DescribeRejected(identifier)}: a double quote character is not permitted.");
			}

			// The allow-list is the actual security control. Note that the input is never
			// trimmed, lower-cased or otherwise normalised into validity: an identifier that does
			// not already conform is rejected outright. By this point the candidate is known to be
			// at most MaxIdentifierLengthBytes long, so the match runs over a bounded input.
			if (!IdentifierRegex().IsMatch(identifier))
			{
				throw new DbException($"Invalid SQL identifier {DescribeRejected(identifier)}: only lower-case letters, digits and single underscores are permitted. It must begin with a lower-case letter, must not end with an underscore, must not contain two consecutive underscores, must not be schema-qualified with a dot, and must be at least 2 characters long.");
			}

			return identifier;
		}

		/// <summary>
		/// Renders a rejected identifier for inclusion in an exception message: truncated to
		/// <see cref="MaxEchoedValueLength"/> characters, with every character outside the
		/// printable ASCII range replaced by an escape, and wrapped in single quotes.
		/// </summary>
		/// <remarks>
		/// SECURITY H-09 hardening (CWE-117 improper output neutralisation for logs, CWE-400). The
		/// rejected value is attacker-influenced text on a path whose whole purpose is to reject
		/// attacker-influenced text, and these messages reach the platform log and diagnostics, so it
		/// must never be echoed raw. Unbounded, a megabyte-long candidate would turn a rejection into
		/// an amplification primitive; unescaped, newlines, carriage returns or terminal control
		/// sequences could forge additional log lines or manipulate a console reading them - and a
		/// rejected SQL identifier is exactly the kind of value that carries such characters
		/// deliberately.
		///
		/// Bounding and escaping keeps the message diagnostically useful - an operator can still
		/// see what was refused - while ensuring the untrusted fragment cannot restructure the
		/// record that contains it. Truncation is marked so a bounded value is never mistaken for
		/// the whole of what was submitted.
		/// </remarks>
		private static string DescribeRejected(string identifier)
		{
			if (identifier == null)
			{
				return "'(null)'";
			}

			bool truncated = identifier.Length > MaxEchoedValueLength;
			int length = truncated ? MaxEchoedValueLength : identifier.Length;

			StringBuilder builder = new StringBuilder(length + 16);
			builder.Append('\'');

			for (int i = 0; i < length; i++)
			{
				char candidate = identifier[i];

				// Printable ASCII is emitted as-is, apart from the single quote that delimits this
				// rendering, which is doubled so the boundary of the echoed value stays
				// unambiguous. Everything else - control characters, newlines and all non-ASCII -
				// becomes a \uXXXX escape so it cannot act on whatever consumes the message.
				if (candidate == '\'')
				{
					builder.Append("''");
				}
				else if (candidate >= ' ' && candidate <= '~')
				{
					builder.Append(candidate);
				}
				else
				{
					// Invariant culture: this escape is a wire format, so its digits must not
					// vary with the server's locale.
					builder.Append("\\u").Append(((int)candidate).ToString("x4", CultureInfo.InvariantCulture));
				}
			}

			builder.Append('\'');

			if (truncated)
			{
				builder.Append(" (truncated from ").Append(identifier.Length).Append(" characters)");
			}

			return builder.ToString();
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
