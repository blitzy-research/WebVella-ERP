// SECURITY H-09 (CWE-89 SQL injection / OWASP A03:2021). Values throughout this data-access layer are
// already fully parameterised, but PostgreSQL cannot parameterise an IDENTIFIER, so the residual
// exposure is confined to the sites that concatenate a table identifier into SQL text. Every such site
// in the layer routes through this helper, which closes the exposure with allow-list validation plus
// double-quoting and FAILS HARD on rejection: a silent sanitise or pass-through would reintroduce the
// vulnerability while appearing to fix it. The per-site inventory lives in
// docs/security/remediation-log.md, so this header never has to be re-counted when a call site moves.

using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace WebVella.Erp.Database
{
	/// <summary>
	/// Validates, and where required quotes, the PostgreSQL identifiers this layer must concatenate into SQL
	/// text because PostgreSQL cannot bind an identifier as a parameter.
	/// </summary>
	/// <remarks>
	/// TWO MEMBERS, BECAUSE THE CALL SITES SIT IN TWO DIFFERENT SQL CONTEXTS, and using the wrong one is a
	/// silent defect rather than a compile error. <see cref="Quote(string)"/> is for an IDENTIFIER position
	/// and returns the identifier double-quoted; <see cref="Validate(string)"/> is for a single-quoted SQL
	/// STRING LITERAL position and returns it bare, because a double-quoted form would be compared as literal
	/// text including the quotes, silently matching nothing. Public, because some call sites are in a separate
	/// project; a stateless static utility by design.
	/// </remarks>
	public static partial class DbIdentifier
	{
		/// <summary>
		/// The allow-list an identifier must match in full: a leading lower-case letter, then only lower-case
		/// letters, digits and single underscores, and no trailing underscore. Anchored at both ends - an
		/// unanchored match would admit "a; DROP TABLE x" on its prefix alone. Replicated from the platform's own
		/// grammar rather than reused, because that constant is private and its validator trims input and reports
		/// soft results where this helper must neither normalise nor forgive.
		/// </summary>
		private const string IdentifierPattern = @"^[a-z](?!.*__)[a-z0-9_]*[a-z0-9]$";

		/// <summary>
		/// The maximum accepted length of the PHYSICAL identifier, in BYTES: 67, being the 4-byte "rec_" or
		/// "rel_" prefix every caller applies plus the 63 characters the platform's name validation admits.
		/// </summary>
		/// <remarks>
		/// SECURITY H-09 (CWE-89). The injection control here is the allow-list at
		/// <see cref="IdentifierPattern"/>, which admits no quote, dot, whitespace, comment marker or statement
		/// separator; this bound contributes NOTHING to that defence and exists only to refuse input too long to
		/// have come from a validated platform name.
		/// DO NOT TIGHTEN IT TO 63: a 63-byte cap would make every entity or relation whose name is 60 characters
		/// or longer wholly unaddressable on an already-deployed installation. Both members apply the same bound
		/// to the same physical name, so the two contexts cannot disagree about what is addressable. Bytes, not
		/// characters, because the server's budget is in bytes - for input that passes the ASCII-only allow-list
		/// the two are equal, and the distinction matters only while rejecting hostile input. RESIDUAL, owned by
		/// entity-creation uniqueness validation and recorded in docs/security/risk-register.md: two names
		/// agreeing on their first 59 characters still collapse onto one physical table after truncation.
		/// </remarks>
		private const int MaxIdentifierLengthBytes = 67;

		/// <summary>
		/// The longest rejected value echoed back in an exception message. See
		/// <see cref="DescribeRejected(string)"/> for why the echo is bounded at all.
		/// </summary>
		private const int MaxEchoedValueLength = 64;

		/// <summary>
		/// The allow-list matcher, source-generated so the pattern is compiled at build time rather than
		/// re-parsed on every call, because this helper sits on the record-query hot path.
		/// </summary>
		[GeneratedRegex(IdentifierPattern)]
		private static partial Regex IdentifierRegex();

		/// <summary>
		/// Validates a single PostgreSQL identifier against the allow-list and returns it UNCHANGED, for a
		/// single-quoted SQL string literal position where the value must stay bare; use
		/// <see cref="Quote(string)"/> wherever it occupies an identifier position.
		/// </summary>
		/// <param name="identifier">
		/// A single, unqualified identifier - never a schema-qualified path, which remains the caller's
		/// responsibility, so a dot is rejected: quoting "public.rel_x" would ask for one table whose name
		/// literally contains a dot and would silently address the wrong table.
		/// </param>
		/// <returns>The identifier exactly as supplied, once proven valid.</returns>
		/// <exception cref="DbException">
		/// Thrown when the identifier is null, empty, whitespace only, over-long, contains a double quote, or
		/// fails the allow-list. A rejection is ALWAYS an exception and never a sanitised or empty value: a
		/// silent repair would reintroduce the exposure while making the finding read as closed.
		/// </exception>
		public static string Validate(string identifier)
		{
			if (string.IsNullOrWhiteSpace(identifier))
			{
				throw new DbException("Invalid SQL identifier: a null, empty or whitespace-only identifier cannot be used in SQL.");
			}

			// SECURITY H-09 hardening (CWE-400 uncontrolled resource consumption). The length bound is evaluated
			// FIRST - before the double-quote scan and before the allow-list match - because it is the only check
			// whose cost does not grow with the input: String.Length is a stored field, so an oversized identifier
			// is refused in constant time having read none of it. Order, not a match timeout, is what removes that
			// exposure. Characters before bytes purely as the cheaper gate: a UTF-8 encoding is never shorter than
			// its character count.
			if (identifier.Length > MaxIdentifierLengthBytes)
			{
				throw new DbException($"Invalid SQL identifier {DescribeRejected(identifier)}: length {identifier.Length} exceeds the maximum physical identifier length of {MaxIdentifierLengthBytes} bytes, being a 4-byte table prefix plus the 63 characters the platform admits in an entity or relation name. No validated platform name can produce a physical identifier this long.");
			}

			// Measured on the physical name because the server's budget is in bytes. Only reachable for input
			// within budget by character count but not by byte count, which cannot pass the allow-list either; the
			// bound is applied regardless so no oversized value reaches the matcher.
			int byteLength = Encoding.UTF8.GetByteCount(identifier);
			if (byteLength > MaxIdentifierLengthBytes)
			{
				throw new DbException($"Invalid SQL identifier {DescribeRejected(identifier)}: encoded length {byteLength} bytes exceeds the maximum physical identifier length of {MaxIdentifierLengthBytes} bytes.");
			}

			// Rejected explicitly and by name as defence in depth, not as a duplicate of the allow-list below: the
			// double quote is the one character that could terminate the quoting Quote(string) applies, so it stays
			// rejected on its own account even if the grammar is ever loosened.
			if (identifier.Contains('"'))
			{
				throw new DbException($"Invalid SQL identifier {DescribeRejected(identifier)}: a double quote character is not permitted.");
			}

			// The allow-list is the actual security control. The input is never trimmed, lower-cased or otherwise
			// normalised into validity: a non-conforming identifier is rejected outright. By this point the
			// candidate is known to be within bounds, so the match runs over bounded input.
			if (!IdentifierRegex().IsMatch(identifier))
			{
				throw new DbException($"Invalid SQL identifier {DescribeRejected(identifier)}: only lower-case letters, digits and single underscores are permitted. It must begin with a lower-case letter, must not end with an underscore, must not contain two consecutive underscores, must not be schema-qualified with a dot, and must be at least 2 characters long.");
			}

			return identifier;
		}

		/// <summary>
		/// Renders a rejected identifier for an exception message: truncated, with every character outside
		/// printable ASCII escaped, and wrapped in single quotes.
		/// </summary>
		/// <remarks>
		/// SECURITY H-09 hardening (CWE-117 improper output neutralisation for logs, CWE-400). The rejected value
		/// is attacker-influenced text on a path whose purpose is to reject attacker-influenced text, and these
		/// messages reach the platform log: unbounded, a megabyte-long candidate turns a rejection into an
		/// amplification primitive, and unescaped, newlines or control sequences could forge log lines.
		/// Truncation is marked, so a bounded value is never mistaken for the whole submission.
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

				// Printable ASCII is emitted as-is, apart from the single quote delimiting this rendering, which is
				// doubled so the boundary stays unambiguous. Everything else - control characters, newlines and all
				// non-ASCII - becomes a \uXXXX escape so it cannot act on whatever consumes the message.
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
		/// Validates a single PostgreSQL identifier and returns it wrapped in double quotes, for an identifier
		/// position such as "FROM ident". The emitted shape is exactly the one this layer already wrote by hand,
		/// so no existing query text changes, and quoting is behaviour-preserving because the allow-list rejects
		/// upper case. Use <see cref="Validate(string)"/> for a single-quoted string literal position.
		/// </summary>
		/// <param name="identifier">A single, unqualified identifier - see <see cref="Validate(string)"/>.</param>
		/// <returns>The validated identifier enclosed in double quotes.</returns>
		/// <exception cref="DbException">Thrown on any rejection - see <see cref="Validate(string)"/>.</exception>
		public static string Quote(string identifier)
		{
			// No inner escaping is performed, and none is needed: Validate rejects the double
			// quote outright, so the quoted form cannot be broken out of.
			return "\"" + Validate(identifier) + "\"";
		}
	}
}
