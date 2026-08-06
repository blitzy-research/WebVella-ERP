using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace WebVella.Erp.Web
{
	public static class WvTaghelperExtension
	{
		// Security M-18 (CWE-116, OWASP A03). Escaping '<' closes every spelling of a "</script>" breakout
		// at once, which an ordinal case-sensitive replacement of that one literal cannot do. The escape
		// comes from the framework JavaScript encoder and resolves to \u003C, valid both in a JSON string
		// value and in a JavaScript string literal. Only '<' is escaped - a lone '>' opens nothing.
		private static readonly string ScriptBreakoutEscape = JavaScriptEncoder.Default.Encode("<");

		/// <summary>
		/// Emits an already-serialized JSON document inside a &lt;script&gt; block.
		/// </summary>
		/// <remarks>
		/// CONTRACT: <paramref name="input"/> must be a COMPLETE serialized JSON document that is written
		/// into script content on its own - for example <c>var x = @Html.WvJsonRaw(Model.Json);</c>. It must
		/// NOT be used for a value placed inside a quoted JavaScript string. That context needs the full
		/// string-context threat set encoded, which this method does not do; encode such a value on the page
		/// model with <c>JavaScriptEncoder</c> instead, exposing it as an already-encoded property in the
		/// manner of the <c>ReturnUrlEncoded</c> properties used elsewhere in this repository. No helper is
		/// published for it - review finding API-01 - because a single sink does not justify widening this
		/// assembly's public API surface for every consumer. (The example previously cited here,
		/// <c>Pages/ckeditor/ImageFinder.cshtml.cs</c>, was retired with the orphaned CKEditor 4 shell under
		/// review finding C-04, so the guidance is stated directly rather than by reference.)
		///
		/// Finding M-18 (CWE-116 improper encoding, CWE-79), OWASP A03. Escaping '&lt;' is sufficient and
		/// correct for THIS context and no more: '&lt;' is the only character that can begin the
		/// "&lt;/script&gt;" sequence which would terminate the enclosing block, and '&lt;' is never legal
		/// in a JSON structural position, so a well-formed document still parses identically. What escaping
		/// '&lt;' does NOT do is make a value safe inside a quoted string - a '"' or a backslash there
		/// escapes the quoting entirely - which is why that case must be encoded on the page model as
		/// described above rather than by borrowing this method.
		/// </remarks>
		public static IHtmlContent WvJsonRaw(this IHtmlHelper helper, string input)
		{
			if (string.IsNullOrEmpty(input))
				return HtmlString.Empty;

			return new HtmlString(input.Replace("<", ScriptBreakoutEscape));
		}
	}
}
