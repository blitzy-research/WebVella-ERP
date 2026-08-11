// SECURITY F-03 (CWE-1333 inefficient regular expression complexity, CWE-400 uncontrolled resource
// consumption / OWASP A03:2021 Injection + A05:2021 Security Misconfiguration).
//
// A caller-supplied regular expression used to travel straight into a WHERE predicate that
// PostgreSQL evaluates ONCE PER ROW, under a ten-minute command timeout. The per-row
// multiplication is what makes this a denial of service rather than a slow query.
//
// The control below is calibrated against measurement rather than against the textbook threat
// model, because on this engine the two disagree. Measured against PostgreSQL 16 on this
// toolchain, over a 20,000-row probe table:
//
//   PATTERN                        PRODUCT OF BOUNDS      TIME
//   ^(a+)+$                                      1      16.8 ms
//   ^(a*)*$                                      1      15.2 ms
//   ^([ab]+)+$                                   1      50.9 ms
//   \d+(\.\d+)*                                  1      44.1 ms
//   ^(a{1,8}){1,8}$                             64      37.3 ms
//   ^(a{1,16}){1,16}$                          256     106.9 ms
//   ^(a{1,32}){1,32}$                         1024     372.3 ms
//   ^(a{1,64}){1,64}$                         4096   1,385.4 ms
//   ^(a{1,120}){1,120}$                      14400   3,944.9 ms
//   ^(a{1,200}){1,200}$                      40000   fails while COMPILING, attempting a
//                                                    1.6 GB allocation
//
// Two conclusions follow, and both shaped this control:
//
//   1. COST IS LINEAR IN THE PRODUCT OF THE EXPLICIT REPETITION BOUNDS. That product, not the
//      presence of nesting, is the hazard. At 3,944 ms per 20,000 rows a table of ordinary ERP
//      size runs for the whole ten-minute ceiling while holding a pooled connection and a CPU
//      core, and a handful of concurrent requests exhausts the pool.
//
//   2. THE TEXTBOOK CATASTROPHIC-BACKTRACKING PAYLOADS ARE NOT A THREAT HERE. PostgreSQL's regex
//      engine is a hybrid DFA/NFA, and for a boolean WHERE predicate it never needs the
//      backtracking path: '^(a+)+$' returned in 16.8 ms amplified over 20,000 rows, and in 0.5 ms
//      against a single adversarial 10,000-character subject. Refusing that shape would import a
//      threat model from PCRE-family engines and would cost real functionality - '\d+(\.\d+)*'
//      is the same shape - while closing nothing. It is therefore deliberately ADMITTED, and this
//      paragraph exists so that its admission reads as a measured decision rather than an
//      oversight.
//
// The bound is consequently placed on the PRODUCT of explicit bounds along any nesting path, set
// so that the worst admissible pattern costs about a tenth of a second per 20,000 rows. The
// compile-time allocation shape is closed by the same ceiling, and only a static bound can close
// it: it fails or succeeds in milliseconds and so is never reached by any execution timeout. A
// short command timeout in DbRecordRepository is the second, independent layer behind this one.
//
// The rule lives in this assembly, at the data layer, because there are two entry points and only
// one of them is an API action: WebVella.Erp.Web/Controllers/WebApiController.cs
// GetRecordsByFieldAndRegex, and the SDK administrative record filter at
// WebVella.Erp.Plugins.SDK/Pages/entity/data.cshtml.cs, which passes a submitted filter value
// directly to EntityQuery.QueryRegex. Enforcing at the point where the REGEX predicate is generated
// covers both, and covers any future caller, which a check bolted onto one controller would not.
// EntityQuery.QueryRegex itself is deliberately left alone: it is public API and making it throw
// would be the behavioural contract change the plan forbids.

using System;
using System.Collections.Generic;
using System.Globalization;

namespace WebVella.Erp.Database
{
	/// <summary>
	/// Bounds the complexity of a caller-supplied regular expression before it can reach a
	/// PostgreSQL WHERE predicate.
	/// </summary>
	/// <remarks>
	/// Finding F-03. Two members are exposed because the two callers need different failure
	/// behaviour, and conflating them would either lose the friendly response or lose the
	/// enforcement.
	/// <see cref="DescribeRejection(string)"/> reports a refusal without throwing, so an API action
	/// can answer with a specific, caller-safe 400 instead of a fault.
	/// <see cref="Validate(object)"/> FAILS HARD, and is invoked at the predicate-generation seam so
	/// that no caller can bypass the bound. A silent sanitise or a pass-through would reintroduce
	/// the weakness while appearing to fix it - the same reasoning Database/DbIdentifier.cs records
	/// for SQL identifiers.
	///
	/// This type is public because one of the two entry points lives in WebVella.Erp.Plugins.SDK, a
	/// separate assembly, exactly as DbIdentifier is public for the same reason.
	///
	/// No refusal message quotes the pattern. These messages are surfaced to a caller when
	/// ErpSettings.DevelopmentMode is set, so echoing attacker-supplied text back would make the
	/// refusal itself a reflection vector.
	///
	/// This validator is deliberately a single left-to-right character scan and uses NO regular
	/// expression of its own. A validator that judged an attacker-supplied pattern by matching it
	/// with System.Text.RegularExpressions.Regex would be precisely the weakness it exists to
	/// prevent, relocated from the database into the application process. The scan is O(n) over a
	/// length-capped input, so its own cost is bounded by construction.
	/// </remarks>
	public static class DbRegexPattern
	{
		/// <summary>
		/// Longest admissible pattern. Generous for a field filter and far below any length at which
		/// compilation becomes expensive.
		/// </summary>
		public const int MaxLength = 256;

		/// <summary>
		/// Largest admissible number of repetition operators. The bound exists for the
		/// 'a?a?a?...a?' family, where cost grows with the NUMBER of independent optional terms
		/// rather than with any single one of them.
		/// </summary>
		public const int MaxQuantifierCount = 20;

		/// <summary>
		/// Ceiling on the PRODUCT of the explicit repetition bounds that apply along any one nesting
		/// path.
		/// </summary>
		/// <remarks>
		/// Finding F-03. Set from the calibration table in this file's header, where cost is linear
		/// in this product: 256 admits a worst case of about 107 ms per 20,000 rows, while the next
		/// step up, 1024, costs 372 ms and the measured attack shapes cost seconds. The same ceiling
		/// also admits a single unnested bound of up to 255, which is PostgreSQL's own maximum, so no
		/// pattern the engine itself accepts as a simple bound is refused here.
		///
		/// An unbounded quantifier - '*', '+' or '?' - contributes a factor of one rather than being
		/// refused, because the header's measurements show unbounded repetition is not the hazard on
		/// this engine.
		/// </remarks>
		public const int MaxRepetitionProduct = 256;

		/// <summary>
		/// Returns null when the pattern is admissible, otherwise a fixed, caller-safe reason for
		/// refusing it.
		/// </summary>
		/// <remarks>
		/// Finding F-03. What is refused, and why each shape:
		/// <list type="bullet">
		/// <item>A PRODUCT of explicit repetition bounds above <see cref="MaxRepetitionProduct"/>
		/// along any nesting path. This is the measured hazard, and expressing the rule as a product
		/// rather than as a ban on nesting is what lets '\d+(\.\d+)*' and '^(a+)+$' through - both
		/// measured harmless - while still refusing '(a{1,120}){1,120}', '((a{1,30}){1,30}){1,30}'
		/// and the 40,000-product shape that fails while merely compiling.</item>
		/// <item>A quantifier stacked directly on another, as in 'a{1,10}+' or 'a++'. PostgreSQL
		/// rejects this itself with "quantifier operand invalid", so refusing it costs no working
		/// query and keeps the product accounting well defined.</item>
		/// <item>BACK-REFERENCES, which are the one construct that forces this engine off its
		/// non-backtracking path.</item>
		/// <item>More than <see cref="MaxQuantifierCount"/> quantifiers, or a pattern longer than
		/// <see cref="MaxLength"/>. These bound the 'a?a?a?...a?' family, where cost grows with the
		/// NUMBER of independent optional terms rather than with any single bound.</item>
		/// <item>Structurally malformed input - unbalanced parentheses, an unterminated bracket
		/// expression, a trailing incomplete escape - which PostgreSQL would reject anyway, refused
		/// here so it becomes a clean 400 rather than a database fault.</item>
		/// </list>
		/// Bracket expressions are tracked, because inside '[...]' the characters '*', '+', '?' and
		/// '{' are literal - treating them as quantifiers there would refuse an ordinary pattern such
		/// as '[0-9*+]' for no reason. A ']' appearing first inside a bracket expression is literal,
		/// as POSIX requires, so '[]*+{]' is admitted exactly as PostgreSQL admits it. Escapes are
		/// consumed as a unit for the same reason: '\{' is a literal brace, not the start of a bound.
		/// </remarks>
		public static string DescribeRejection(string pattern)
		{
			if (string.IsNullOrWhiteSpace(pattern))
				return "A regular expression pattern is required.";

			if (pattern.Length > MaxLength)
				return $"The regular expression pattern is too long. The maximum supported length is {MaxLength.ToString(CultureInfo.InvariantCulture)} characters.";

			// Per-level scan state. "Level" means one parenthesised group depth. For each level we
			// carry the LARGEST product of explicit bounds seen so far at that level: largest rather
			// than accumulated, because sequential quantifiers cost the sum of their parts whereas
			// nested ones cost the product, and only the product is the hazard.
			var enclosingLevelMaxProduct = new Stack<int>();
			int levelMaxProduct = 1;
			int quantifierCount = 0;
			bool insideBracketExpression = false;
			bool previousTokenWasQuantifier = false;

			for (int index = 0; index < pattern.Length; index++)
			{
				char current = pattern[index];

				// Consumed once per token: a quantifier is only "stacked" when it directly follows
				// another one, so the flag has to be cleared by any intervening token.
				bool priorTokenWasQuantifier = previousTokenWasQuantifier;
				previousTokenWasQuantifier = false;

				if (current == '\\')
				{
					// An escape consumes the following character whatever it is. A digit there is a
					// back-reference, the one construct that forces the backtracking engine.
					if (index + 1 >= pattern.Length)
						return "The regular expression pattern ends with an incomplete escape sequence.";

					char escaped = pattern[index + 1];
					if (!insideBracketExpression && escaped >= '1' && escaped <= '9')
						return "Back-references are not supported in regular expression filters.";

					index++;
					continue;
				}

				if (insideBracketExpression)
				{
					if (current == ']')
						insideBracketExpression = false;
					continue;
				}

				if (current == '[')
				{
					insideBracketExpression = true;

					// POSIX: a ']' immediately after '[', or after a leading '^', is a literal member
					// of the set rather than the terminator. Consuming it here is what lets '[]*+{]'
					// through, which PostgreSQL accepts and which would otherwise be misread as an
					// empty set followed by stacked quantifiers.
					int firstMember = index + 1;
					if (firstMember < pattern.Length && pattern[firstMember] == '^')
						firstMember++;
					if (firstMember < pattern.Length && pattern[firstMember] == ']')
						index = firstMember;

					continue;
				}

				if (current == '(')
				{
					enclosingLevelMaxProduct.Push(levelMaxProduct);
					levelMaxProduct = 1;
					continue;
				}

				if (current == ')')
				{
					if (enclosingLevelMaxProduct.Count == 0)
						return "The regular expression pattern has unbalanced parentheses.";

					int closedLevelMaxProduct = levelMaxProduct;
					levelMaxProduct = enclosingLevelMaxProduct.Pop();

					// A quantifier immediately after the closing parenthesis applies to the whole
					// group, so its bound MULTIPLIES whatever the group already contained. This is the
					// product the ceiling is calibrated against.
					// NOTE the absence of a stacked-quantifier check here. The closing parenthesis is
					// itself an intervening token, so a quantifier inside the group followed by one on
					// the group - '(a+)+' - is NESTING, priced by the product below, and not stacking.
					// Genuine stacking on a group, '(ab)++', is still caught: the group's own
					// quantifier sets the flag, and the second one is then seen at the ordinary site.
					int groupQuantifierLength = MeasureQuantifier(pattern, index + 1, out int groupBound);
					if (groupQuantifierLength > 0)
					{
						quantifierCount++;
						if (quantifierCount > MaxQuantifierCount)
							return TooManyQuantifiersRejection;

						int groupProduct = MultiplyBounds(closedLevelMaxProduct, groupBound);
						if (groupProduct > MaxRepetitionProduct)
							return RepetitionProductRejection;

						if (groupProduct > levelMaxProduct)
							levelMaxProduct = groupProduct;

						previousTokenWasQuantifier = true;
						index += groupQuantifierLength;
					}
					else if (closedLevelMaxProduct > levelMaxProduct)
					{
						// An unquantified group still contributes whatever it contains, so a bound
						// nested inside it is not forgotten when the group closes.
						levelMaxProduct = closedLevelMaxProduct;
					}

					continue;
				}

				int quantifierLength = MeasureQuantifier(pattern, index, out int repetitionBound);
				if (quantifierLength > 0)
				{
					// A quantifier stacked directly on another, as in 'a{1,10}+' or 'a++', is the same
					// product shape as group nesting written without the parentheses. PostgreSQL
					// rejects it itself with "quantifier operand invalid", so refusing it changes no
					// working query and keeps the product accounting unambiguous.
					if (priorTokenWasQuantifier)
						return StackedQuantifierRejection;

					quantifierCount++;
					if (quantifierCount > MaxQuantifierCount)
						return TooManyQuantifiersRejection;

					if (repetitionBound > MaxRepetitionProduct)
						return RepetitionProductRejection;

					if (repetitionBound > levelMaxProduct)
						levelMaxProduct = repetitionBound;

					previousTokenWasQuantifier = true;
					index += quantifierLength - 1;
				}
			}

			if (enclosingLevelMaxProduct.Count > 0)
				return "The regular expression pattern has unbalanced parentheses.";

			if (insideBracketExpression)
				return "The regular expression pattern has an unterminated bracket expression.";

			return null;
		}

		// Refusal reasons are compile-time constants shared by the two sites that can raise them, so
		// the text cannot drift between them. None of them quotes the pattern: these messages reach a
		// caller when ErpSettings.DevelopmentMode is set, so echoing attacker-supplied text back would
		// make the refusal itself a reflection vector.
		private const string StackedQuantifierRejection = "Stacked repetition is not supported in regular expression filters. Rewrite the pattern without applying one quantifier directly to another.";
		private const string TooManyQuantifiersRejection = "The regular expression pattern contains too many repetition operators.";
		private const string RepetitionProductRejection = "The repetition in the regular expression pattern is too large, because its cost grows as the product of the repetition bounds. Reduce the bounds, or remove a quantifier applied to a group that already contains one.";

		/// <summary>
		/// Multiplies two repetition bounds, saturating instead of overflowing.
		/// </summary>
		/// <remarks>
		/// Finding F-03. Both operands are already capped at three digits by
		/// <see cref="MeasureQuantifier"/>, so a signed overflow is not reachable today - but a
		/// saturating multiply means a deeply nested pattern cannot wrap around into a small product
		/// and slip past the ceiling if that cap ever changes. Failing safe here costs one comparison.
		/// </remarks>
		private static int MultiplyBounds(int left, int right)
		{
			long product = (long)Math.Max(left, 1) * Math.Max(right, 1);
			return product > int.MaxValue ? int.MaxValue : (int)product;
		}

		/// <summary>
		/// Throws when the supplied filter value is not an admissible regular expression pattern.
		/// </summary>
		/// <remarks>
		/// Finding F-03. Invoked where the REGEX predicate is generated, so the bound cannot be
		/// bypassed by any caller. Failing hard is deliberate and is safe for the response surface:
		/// RecordManager.Find and RecordManager.Count both wrap their execution in a catch that
		/// answers with the fixed message "The query is incorrect and cannot be executed" and gates
		/// the exception detail behind ErpSettings.DevelopmentMode, so a refusal reaches an API
		/// caller as a clean 400 rather than as a stack trace.
		///
		/// A non-string value is refused rather than coerced. PostgreSQL would coerce it to text and
		/// match against it, so silently accepting one would leave an unvalidated pattern shape
		/// reaching the engine by a side door.
		/// </remarks>
		public static void Validate(object value)
		{
			string pattern = value as string;
			if (pattern == null && value != null)
				throw new DbException("Invalid regular expression filter: the pattern must be supplied as text.");

			string rejection = DescribeRejection(pattern);
			if (rejection != null)
				throw new DbException("Invalid regular expression filter: " + rejection);
		}

		/// <summary>
		/// Measures the quantifier starting at <paramref name="index"/>, returning its length in
		/// characters, or 0 when there is no quantifier there.
		/// </summary>
		/// <remarks>
		/// Finding F-03. '*', '+' and '?' are one character and carry no explicit bound, reported as
		/// <paramref name="repetitionBound"/> zero, which the caller treats as a factor of one: the
		/// header's measurements show unbounded repetition is not the expensive shape on this engine,
		/// whereas a product of large EXPLICIT bounds is. A '{' not followed by a well-formed bound is
		/// treated as a literal brace, which is how PostgreSQL reads it too, so ordinary text is not
		/// refused. The larger of the two numbers in the bound is reported, since that is the
		/// multiplier.
		/// </remarks>
		private static int MeasureQuantifier(string pattern, int index, out int repetitionBound)
		{
			repetitionBound = 0;

			if (index < 0 || index >= pattern.Length)
				return 0;

			char current = pattern[index];
			if (current == '*' || current == '+' || current == '?')
			{
				// A trailing '?' makes the quantifier non-greedy rather than starting a new one, so
				// it is consumed here instead of being counted twice.
				if (index + 1 < pattern.Length && pattern[index + 1] == '?')
					return 2;

				return 1;
			}

			if (current != '{')
				return 0;

			int cursor = index + 1;
			int lowerBound = ReadBoundDigits(pattern, ref cursor, out int lowerDigitCount);
			if (lowerDigitCount == 0 || lowerDigitCount > 3)
				return 0;

			int upperBound = -1;
			if (cursor < pattern.Length && pattern[cursor] == ',')
			{
				cursor++;
				upperBound = ReadBoundDigits(pattern, ref cursor, out int upperDigitCount);
				if (upperDigitCount > 3)
					return 0;

				// '{n,}' is open-ended, so there is no explicit upper bound to compare and only the
				// lower one counts.
				if (upperDigitCount == 0)
					upperBound = -1;
			}

			if (cursor >= pattern.Length || pattern[cursor] != '}')
				return 0;

			repetitionBound = Math.Max(lowerBound, upperBound);

			int quantifierLength = cursor - index + 1;

			// A non-greedy bound, '{n,m}?', is one quantifier and not two.
			if (cursor + 1 < pattern.Length && pattern[cursor + 1] == '?')
				quantifierLength++;

			return quantifierLength;
		}

		/// <summary>
		/// Reads the run of ASCII digits at <paramref name="cursor"/>, advancing it past them.
		/// </summary>
		/// <remarks>
		/// Finding F-03. Digits are counted as well as accumulated so the caller can reject an
		/// over-long run instead of letting it overflow: PostgreSQL's own ceiling on a repetition
		/// bound is 255, so three digits spans the entire legal range and a longer run is malformed
		/// by definition.
		/// </remarks>
		private static int ReadBoundDigits(string pattern, ref int cursor, out int digitCount)
		{
			int value = 0;
			digitCount = 0;

			while (cursor < pattern.Length && char.IsAsciiDigit(pattern[cursor]))
			{
				digitCount++;
				if (digitCount > 3)
				{
					cursor++;
					continue;
				}

				value = (value * 10) + (pattern[cursor] - '0');
				cursor++;
			}

			return value;
		}
	}
}
