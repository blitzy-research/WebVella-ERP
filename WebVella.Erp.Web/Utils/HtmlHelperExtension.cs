using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace WebVella.Erp.Web
{
	public static class WvTaghelperExtension
	{
		// SECURITY M-18 (CWE-116, OWASP A03). Escaping '<' closes every spelling of a "</script>" breakout at once,
		// which an ordinal case-sensitive replacement of that one literal cannot. The framework JavaScript encoder
		// yields \u003C, valid in both a JSON string value and a JavaScript string literal; a lone '>' opens nothing.
		private static readonly string ScriptBreakoutEscape = JavaScriptEncoder.Default.Encode("<");

		/// <summary>
		/// Emits an already-serialized JSON document inside a &lt;script&gt; block.
		/// </summary>
		/// <remarks>
		/// SECURITY M-18 (CWE-116 improper encoding, CWE-79), OWASP A03. Escaping '&lt;' is sufficient and correct for
		/// THIS context and no more - it is the only character that can begin the "&lt;/script&gt;" sequence that would
		/// terminate the enclosing block, and it is never legal in a JSON structural position, so a well-formed
		/// document still parses identically.
		/// <para>
		/// CONTRACT: <paramref name="input"/> must be a COMPLETE serialized JSON document written into script content
		/// on its own. It must NOT be used for a value inside a quoted JavaScript string, where a '"' or a backslash
		/// escapes the quoting entirely; encode such a value on the page model with <c>JavaScriptEncoder</c> and expose
		/// it as an already-encoded property, as the <c>ReturnUrlEncoded</c> properties elsewhere in this repository do.
		/// </para>
		/// </remarks>
		public static IHtmlContent WvJsonRaw(this IHtmlHelper helper, string input)
		{
			if (string.IsNullOrEmpty(input))
				return HtmlString.Empty;

			return new HtmlString(input.Replace("<", ScriptBreakoutEscape));
		}
	}
}
