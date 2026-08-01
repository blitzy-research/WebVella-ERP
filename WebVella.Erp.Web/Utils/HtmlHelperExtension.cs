using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace WebVella.Erp.Web
{
	public static class WvTaghelperExtension
	{
		// Security fix M-18 (CWE-116, OWASP A03): the previous implementation replaced the single exact
		// literal "</script>", and string.Replace being ordinal and case-sensitive let "</Script>",
		// "</script >" and similar variants through to terminate the enclosing script block. Escaping
		// '<' closes every variant at once; the escape comes from the framework JavaScript encoder and
		// resolves to \u003C, which is valid both in a JSON string value and in a JavaScript string
		// literal, so callers keep parsing identically. Only '<' is escaped - a lone '>' opens nothing.
		private static readonly string ScriptBreakoutEscape = JavaScriptEncoder.Default.Encode("<");

		/// <summary>
		/// Emits an already-serialized JSON document inside a &lt;script&gt; block.
		/// </summary>
		/// <remarks>
		/// CONTRACT: <paramref name="input"/> must be a COMPLETE serialized JSON document that is written
		/// into script content on its own - for example <c>var x = @Html.WvJsonRaw(Model.Json);</c>. It must
		/// NOT be used for a value placed inside a quoted JavaScript string; use
		/// <see cref="WvJsScriptString"/> for that.
		///
		/// Finding M-5 (CWE-116 improper encoding, CWE-79), OWASP A03. Escaping '&lt;' is sufficient and
		/// correct for THIS context and no more: '&lt;' is the only character that can begin the
		/// "&lt;/script&gt;" sequence which would terminate the enclosing block, and '&lt;' is never legal
		/// in a JSON structural position, so a well-formed document still parses identically. What escaping
		/// '&lt;' does NOT do is make a value safe inside a quoted string - a '"' or a backslash there
		/// escapes the quoting entirely - which is why that case now has its own method rather than
		/// borrowing this one.
		/// </remarks>
		public static IHtmlContent WvJsonRaw(this IHtmlHelper helper, string input)
		{
			if (string.IsNullOrEmpty(input))
				return HtmlString.Empty;

			return new HtmlString(input.Replace("<", ScriptBreakoutEscape));
		}

		/// <summary>
		/// Emits a value that sits INSIDE a quoted JavaScript string literal, fully encoded for that context.
		/// </summary>
		/// <remarks>
		/// CONTRACT: the caller supplies the surrounding quotes; this method returns only the string
		/// CONTENTS - for example <c>var t = "@Html.WvJsScriptString(Model.Type)";</c>.
		///
		/// Finding M-5 (CWE-116, CWE-79), OWASP A03. THREAT: a value interpolated into a quoted JavaScript
		/// string was previously passed through the JSON-document helper, which escapes only '&lt;'. That
		/// left the two characters that actually matter in a string context untouched: a '"' closes the
		/// literal and everything after it becomes executable script, and a trailing backslash escapes the
		/// closing quote so the following code is swallowed into the string. The value at the one such call
		/// site is a constant today, so this is not presently exploitable - it is closed now because the
		/// distinction is invisible at the call site, and the next value assigned there will not come with a
		/// warning that it must be constant.
		///
		/// JavaScriptEncoder.Default encodes the complete string-context threat set - quote, apostrophe,
		/// backslash, '&lt;', '&gt;', '&amp;', control characters, line and paragraph separators, and all
		/// non-ASCII - into \uXXXX escapes that are valid inside both a JavaScript string literal and a JSON
		/// string value. Using the framework encoder rather than a hand-written replacement list is
		/// deliberate: an allow-list encoder cannot be defeated by a character its author failed to think of.
		/// </remarks>
		public static IHtmlContent WvJsScriptString(this IHtmlHelper helper, string input)
		{
			if (string.IsNullOrEmpty(input))
				return HtmlString.Empty;

			return new HtmlString(JavaScriptEncoder.Default.Encode(input));
		}
	}
}
