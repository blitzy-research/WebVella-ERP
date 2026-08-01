// SECURITY H-09 (CWE-89 SQL injection / OWASP A03:2021 Injection).
// Values throughout this data-access layer are ALREADY fully parameterised - see
// Database/DbRepository.cs:L517-L607, where every value is bound through
// command.CreateParameter() with an explicit NpgsqlDbType and referenced as @name. PostgreSQL
// cannot parameterise an IDENTIFIER, so the residual injection exposure is confined to the six
// sites that concatenate a table identifier into SQL. This helper closes that exposure with
// allow-list validation plus double-quoting, and FAILS HARD on rejection: a silent sanitise or
// pass-through would reintroduce the vulnerability while appearing to fix it.

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
		/// The maximum accepted length of the PHYSICAL identifier, in BYTES. PostgreSQL stores an
		/// identifier in a fixed NAMEDATALEN buffer and its usable width is NAMEDATALEN-1 = 63
		/// bytes; anything longer is not rejected by the server but SILENTLY TRUNCATED to 63
		/// bytes. The platform enforces the same 63 everywhere it validates a name itself -
		/// Api/EntityManager.cs:L69-L70 caps an entity name, and Api/Models/ValidationUtility.cs
		/// throws outright when asked for a maximum above 63.
		/// </summary>
		/// <remarks>
		/// SECURITY M-04 (CWE-20 improper input validation, CWE-400 resource exhaustion). An
		/// earlier revision of this file set this bound to 67 on the reasoning that callers pass
		/// the already-prefixed table identifier - "rec_" or "rel_" plus a name the platform
		/// allows to be 63 characters - so 67 characters was thought legitimate. That reasoning
		/// had the limit in the wrong place, and the consequence is a security defect rather than
		/// a cosmetic one.
		///
		/// The 63-byte budget applies to the FULL physical name that reaches the server, prefix
		/// included - not to the entity name the platform validated. So an entity name of 60 to 63
		/// characters yields a 64- to 67-byte physical name, PostgreSQL truncates it to 63 bytes,
		/// and two DISTINCT entity names that agree on their first 59 characters then collapse
		/// onto the SAME physical table. Reads and writes intended for one entity silently address
		/// another. Accepting 67 here made this helper endorse exactly that collision.
		///
		/// This bound is therefore measured against the identifier as supplied - the physical
		/// name - and truncation is refused rather than accepted, because an identifier the server
		/// will rewrite is one this layer cannot address unambiguously. Refusing it is loud and
		/// diagnosable; permitting it is silent cross-entity data corruption. Both
		/// <see cref="Validate(string)"/> and <see cref="Quote(string)"/> apply this same bound to
		/// the same physical name, so the two contexts can never disagree about what is
		/// addressable.
		///
		/// Operational consequence, stated rather than hidden: an existing entity or relation
		/// whose name is 60 characters or longer now fails hard at the SQL boundary instead of
		/// quietly sharing a truncated table. Such an entity was already in a collision-prone
		/// state before this change - the failure surfaces a latent defect, it does not create
		/// one. The residual gap is that the platform's own name validation still admits names
		/// that cannot survive prefixing; that belongs to entity creation, not to this helper, and
		/// is recorded in docs/security/risk-register.md.
		///
		/// Byte length is measured, not character length, because the two differ for any non-ASCII
		/// input and the server's budget is denominated in bytes. For an identifier that PASSES
		/// the ASCII-only allow-list the two are necessarily equal; the distinction matters only
		/// while rejecting hostile input, which is precisely when it must be correct.
		/// </remarks>
		private const int MaxIdentifierLengthBytes = 63;

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

			// SECURITY M-04 (CWE-400 uncontrolled resource consumption). The length bound is
			// evaluated FIRST, before the double-quote scan and before the allow-list match,
			// because it is the only check whose cost does not grow with the input. String.Length
			// is a stored field, so an oversized identifier - the one case where the regex would
			// be asked to do the most work - is refused in constant time having read none of it.
			// An earlier revision ran the regex first and reached this bound last, which meant a
			// megabyte-long candidate was pattern-matched in full before being rejected for its
			// length. The allow-list pattern contains a (?!.*__) lookahead, so scanning attacker
			// influenced input of unbounded length was a needless super-linear cost on the
			// record-query hot path. Ordering the bound first removes that exposure outright
			// rather than relying on a match timeout to contain it.
			//
			// Characters are tested before bytes purely as the cheaper gate: a UTF-8 encoding is
			// never shorter than its character count, so anything over the budget in characters is
			// necessarily over it in bytes and can be refused without encoding anything.
			if (identifier.Length > MaxIdentifierLengthBytes)
			{
				throw new DbException($"Invalid SQL identifier {DescribeRejected(identifier)}: length {identifier.Length} exceeds the PostgreSQL limit of {MaxIdentifierLengthBytes} bytes for the full physical name. PostgreSQL would truncate it, which can make two distinct names address the same table.");
			}

			// Measured on the physical name because the server's budget is denominated in bytes.
			// Only reachable for input that is within budget by character count but not by byte
			// count, which means it contains non-ASCII characters and so cannot pass the
			// allow-list either; the bound is applied here regardless so that no oversized value
			// ever reaches the matcher.
			int byteLength = Encoding.UTF8.GetByteCount(identifier);
			if (byteLength > MaxIdentifierLengthBytes)
			{
				throw new DbException($"Invalid SQL identifier {DescribeRejected(identifier)}: encoded length {byteLength} bytes exceeds the PostgreSQL limit of {MaxIdentifierLengthBytes} bytes for the full physical name.");
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
		/// SECURITY M-04 (CWE-117 improper output neutralisation for logs, CWE-400). An earlier
		/// revision interpolated the rejected value into the message verbatim and unbounded. That
		/// echo is attacker-influenced text on a path whose whole purpose is to reject attacker
		/// influenced text, and these messages are written to the platform log and surfaced in
		/// diagnostics, so echoing it raw had two consequences. A megabyte-long candidate produced
		/// a megabyte-long exception message and log record, turning a rejection into an
		/// amplification primitive. And a candidate containing newlines, carriage returns or
		/// terminal control sequences could forge additional log lines or manipulate a console
		/// reading them - a rejected SQL identifier is exactly the kind of value that carries such
		/// characters deliberately.
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
