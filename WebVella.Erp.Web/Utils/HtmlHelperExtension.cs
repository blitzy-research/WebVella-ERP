using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace WebVella.Erp.Web
{
	public static class WvTaghelperExtension
	{
		// Security fix M-18 (CWE-116 improper encoding or escaping of output, OWASP A03
		// injection). The previous implementation substituted one exact nine-character literal,
		// the lower-case closing script tag. string.Replace is ordinal and case-sensitive, and
		// HTML tolerates whitespace or trailing junk inside a closing tag, so "</Script>",
		// "</SCRIPT>", "</script >", a tab or newline before the ">" and "</script/foo>" all
		// passed through untouched, terminated the enclosing script block and let stored or
		// reflected content execute as script on this application's own origin.
		// Escaping the single character '<' closes every one of those variants at once, because
		// '<' is non-alphabetic (so it has no casing variants) and one character long (so it has
		// no internal-whitespace variants); it also neutralises "<script", "<!--" and "<![CDATA[".
		// The escape text is derived from the framework JavaScript encoder rather than hard-coded
		// and resolves to \u003C, which is a valid escape both inside a JSON string value and
		// inside a JavaScript string literal, while '<' is never legal in a JSON structural
		// position - so the callers that emit a bare JSON document keep parsing identically.
		// Only '<' is escaped: a lone '>' cannot open a tag, so escaping it would close nothing.
		private static readonly string ScriptBreakoutEscape = JavaScriptEncoder.Default.Encode("<");

		public static IHtmlContent WvJsonRaw(this IHtmlHelper helper, string input)
		{
			return new HtmlString(helper.Raw(input).ToString().Replace("<", ScriptBreakoutEscape));
		}
	}
}
