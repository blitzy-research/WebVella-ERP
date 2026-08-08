using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Text.Encodings.Web;
using HtmlAgilityPack;

namespace WebVella.Erp.Web.Utils
{
	/// <summary>
	/// Allow-list sanitizer for rich text that is rendered as MARKUP by a client component.
	/// </summary>
	/// <remarks>
	/// <para>
	/// THREAT ADDRESSED - stored cross-site scripting, CWE-79, OWASP A03:2021. Review finding M-01. The
	/// project activity surfaces do not render their text through Razor, so Razor's automatic encoding never
	/// applies to them: the page components serialize whole records into a JSON attribute and the client
	/// bundles assign the record's <c>body</c> and <c>subject</c> straight to <c>innerHTML</c>. Anything an
	/// author stored is therefore parsed as markup in every later reader's session, under the application's
	/// own origin and with that reader's session cookie. The Content-Security-Policy this platform emits is
	/// report-only, so it records such an injection and does not stop it.
	/// </para>
	/// <para>
	/// WHY AN ALLOW-LIST AND NOT ENCODING. These two fields are legitimately rich text - authors write them
	/// in a WYSIWYG editor and the stored value is real markup - so encoding them wholesale would render the
	/// tags as visible characters and destroy the feature. Encoding is correct only for the values that are
	/// TEXT by contract, which is what <see cref="EncodeText"/> is for. Everything here is therefore decided
	/// by enumerating what is PERMITTED rather than what is forbidden: an element, an attribute or a URL
	/// scheme that is not named below is removed, so a vector nobody thought of fails closed instead of
	/// passing through. That is the ordering the platform's own remediation standard requires.
	/// </para>
	/// <para>
	/// SCOPE OF THE GUARANTEE. This makes a value safe to place in an HTML ELEMENT context. It does not make
	/// it safe inside a quoted JavaScript string, a URL, a CSS block or an unquoted attribute, none of which
	/// occur on the paths this serves. No new package is introduced: HtmlAgilityPack is already a direct
	/// dependency of this assembly and already parses HTML in <c>RenderService</c> and <c>DataUtils</c>, and
	/// the encoder is the framework's own - the same one Razor uses.
	/// </para>
	/// </remarks>
	public static class HtmlSanitizer
	{
		/// <summary>
		/// Elements an author may keep. Confined to text structure, emphasis, lists, tables, links and
		/// images - the vocabulary the editor actually produces. Absent by intent: every element that can
		/// execute, load or submit.
		/// </summary>
		private static readonly HashSet<string> ALLOWED_TAGS = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
		{
			"p", "br", "hr", "div", "span", "blockquote", "pre", "code",
			"strong", "b", "em", "i", "u", "s", "strike", "del", "ins", "mark", "small", "sub", "sup",
			"h1", "h2", "h3", "h4", "h5", "h6",
			"ul", "ol", "li", "dl", "dt", "dd",
			"a", "img", "figure", "figcaption",
			"table", "thead", "tbody", "tfoot", "tr", "td", "th", "caption", "colgroup", "col"
		};

		/// <summary>
		/// Elements removed WITH their content rather than unwrapped. Keeping the text of a
		/// <c>&lt;script&gt;</c> would paste its body into the document as visible source, and keeping the
		/// text of a <c>&lt;style&gt;</c> would do the same for a rule set, so for these the content is as
		/// unwanted as the element. <c>svg</c> and <c>math</c> are here because both open foreign-content
		/// parsing, where markup this list does not model can execute.
		/// </summary>
		private static readonly HashSet<string> DROPPED_WITH_CONTENT = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
		{
			"script", "style", "iframe", "frame", "frameset", "object", "embed", "applet",
			"form", "input", "button", "select", "option", "optgroup", "textarea", "label", "fieldset",
			"link", "meta", "base", "title", "head", "noscript", "template", "svg", "math", "portal"
		};

		/// <summary>
		/// Attributes permitted on any allowed element. <c>style</c> is deliberately absent - it is an
		/// injection surface of its own and no stored value needs it - and so is every <c>on*</c> handler,
		/// which this list excludes by construction rather than by pattern matching.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding N23. <c>class</c> was permitted here and is now removed, on exactly the
		/// reasoning that already excluded <c>style</c> and that <c>BaseErpPageModel.EncodeMenuIconClass</c> gives
		/// for allow-listing icon classes: the platform ships its own stylesheets, so a stored value that can name
		/// arbitrary classes can position, size, hide or overlay elements - a user-interface redressing primitive
		/// (CWE-1021) that no amount of element and scheme filtering touches. A token allow-list was considered and
		/// rejected as unverifiable: any list admitting the typography utilities also has to be proved not to admit
		/// a positioning one, for every future stylesheet. Removal is provable. The blast radius is bounded and was
		/// measured: administrator-authored literal markup in the HTML-block component never reaches this
		/// sanitizer (<c>PcHtmlBlock.ResolveHtmlForRawSink</c> returns it unsanitized), so what loses class
		/// attributes is user-authored comment, timelog and feed content, whose <c>style</c> attributes this
		/// sanitizer already dropped. Recorded as a residual in docs/security/risk-register.md.
		/// </remarks>
		private static readonly HashSet<string> ALLOWED_ATTRIBUTES_GLOBAL = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
		{
			"title", "dir", "lang"
		};

		/// <summary>
		/// Additional attributes permitted only on the element that needs them.
		/// </summary>
		private static readonly Dictionary<string, HashSet<string>> ALLOWED_ATTRIBUTES_BY_TAG = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase)
		{
			{ "a", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "href", "target", "rel", "name" } },
			{ "img", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "src", "alt", "width", "height" } },
			{ "td", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "colspan", "rowspan" } },
			{ "th", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "colspan", "rowspan", "scope" } },
			{ "ol", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "start", "type" } },
			{ "col", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "span" } },
			{ "colgroup", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "span" } }
		};

		/// <summary>
		/// Attributes carrying a URL, which need their scheme checked and not merely their name allowed.
		/// </summary>
		private static readonly HashSet<string> URL_ATTRIBUTES = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
		{
			"href", "src"
		};

		/// <summary>
		/// Schemes an absolute URL may use. <c>javascript</c> executes, and <c>data</c> can carry a whole
		/// document with script in it, so neither appears; nor does anything else, because this is an
		/// allow-list.
		/// </summary>
		private static readonly HashSet<string> ALLOWED_URL_SCHEMES = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
		{
			"http", "https", "mailto", "tel"
		};

		/// <summary>
		/// The characters that end a URL's opaque head. Hoisted into a cached instance because
		/// <see cref="IsUrlAllowed"/> runs once per URL attribute of every sanitized value.
		/// </summary>
		private static readonly SearchValues<char> URL_PATH_DELIMITERS = SearchValues.Create("/?#");

		/// <summary>
		/// Returns <paramref name="html"/> reduced to the allow-listed vocabulary, safe to render as markup.
		/// </summary>
		/// <remarks>
		/// Null and whitespace pass through unchanged so a caller cannot turn an absent value into an empty
		/// one, and a value this method cannot parse is ENCODED rather than returned: failing to a visible,
		/// inert rendering is the only failure that is still safe at an <c>innerHTML</c> sink.
		/// </remarks>
		public static string Sanitize(string html)
		{
			if (string.IsNullOrWhiteSpace(html))
			{
				return html;
			}

			try
			{
				var document = new HtmlDocument();
				document.LoadHtml(html);

				//A comment is not rendered, but it can hide a conditional-comment payload and it can end
				//early and resume parsing as markup, so comments are removed outright rather than kept.
				RemoveComments(document.DocumentNode);
				SanitizeNode(document.DocumentNode);

				return document.DocumentNode.InnerHtml;
			}
			catch (Exception)
			{
				//An unparseable value must not be handed to the sink as-is. Encoding it keeps the text
				//visible to the reader while guaranteeing the browser treats it as characters.
				return EncodeText(html);
			}
		}

		/// <summary>
		/// Encodes a value that is TEXT by contract but is rendered into a markup context.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - CWE-79, and specifically the RE-ACTIVATION of an already-neutralised payload.
		/// The activity-feed body is a plain-text extract taken from a record's markup, and the extraction
		/// reads element inner text - so a payload the author had stored in ENCODED form is returned by that
		/// extraction as live markup, and the feed then assigns it to <c>innerHTML</c>. Encoding at the point
		/// the text is stored is what stops a value that was inert in its original field from becoming
		/// executable in its summary. <see cref="HtmlEncoder.Default"/> is the encoder Razor itself uses, so
		/// an encoded value renders as exactly the characters the author typed.
		/// </remarks>
		public static string EncodeText(string text)
		{
			if (string.IsNullOrEmpty(text))
			{
				return text;
			}

			return HtmlEncoder.Default.Encode(text);
		}

		/// <summary>
		/// Removes every comment node beneath <paramref name="node"/>.
		/// </summary>
		private static void RemoveComments(HtmlNode node)
		{
			var comments = new List<HtmlNode>();
			foreach (var descendant in node.DescendantsAndSelf())
			{
				if (descendant.NodeType == HtmlNodeType.Comment)
				{
					comments.Add(descendant);
				}
			}

			foreach (var comment in comments)
			{
				comment.Remove();
			}
		}

		/// <summary>
		/// Applies the allow-list to <paramref name="node"/> and everything beneath it.
		/// </summary>
		/// <remarks>
		/// Children are copied before iterating and walked in reverse, because the loop both removes and
		/// replaces nodes and mutating a live child collection during a forward walk silently skips
		/// siblings - which on this path would mean skipping an element that was about to be sanitized.
		/// </remarks>
		private static void SanitizeNode(HtmlNode node)
		{
			var children = new List<HtmlNode>(node.ChildNodes);
			for (var index = children.Count - 1; index >= 0; index--)
			{
				var child = children[index];

				if (child.NodeType == HtmlNodeType.Text)
				{
					//Text is already inert in an element context and is left exactly as stored, so
					//legitimate content survives byte for byte.
					continue;
				}

				if (child.NodeType != HtmlNodeType.Element)
				{
					child.Remove();
					continue;
				}

				if (DROPPED_WITH_CONTENT.Contains(child.Name))
				{
					child.Remove();
					continue;
				}

				//Descend BEFORE deciding this element's own fate, so that an unwrapped element's children
				//have already been sanitized by the time they are promoted into its place.
				SanitizeNode(child);

				if (!ALLOWED_TAGS.Contains(child.Name))
				{
					//Unwrap rather than delete: an element that merely is not modelled here - a custom tag,
					//or one this vocabulary does not include - carries author text that must survive. Its
					//children are already sanitized, and the element itself, with all of its attributes,
					//disappears.
					UnwrapNode(child);
					continue;
				}

				SanitizeAttributes(child);
			}
		}

		/// <summary>
		/// Replaces <paramref name="node"/> with its children, discarding the element and its attributes.
		/// </summary>
		private static void UnwrapNode(HtmlNode node)
		{
			var parent = node.ParentNode;
			if (parent == null)
			{
				return;
			}

			var children = new List<HtmlNode>(node.ChildNodes);
			for (var index = children.Count - 1; index >= 0; index--)
			{
				parent.InsertAfter(children[index], node);
			}

			parent.RemoveChild(node);
		}

		/// <summary>
		/// Strips every attribute of <paramref name="element"/> that the allow-list does not permit, and
		/// every URL attribute whose scheme is not permitted.
		/// </summary>
		private static void SanitizeAttributes(HtmlNode element)
		{
			if (!element.HasAttributes)
			{
				return;
			}

			ALLOWED_ATTRIBUTES_BY_TAG.TryGetValue(element.Name, out var tagAttributes);

			var attributes = new List<HtmlAttribute>(element.Attributes);
			foreach (var attribute in attributes)
			{
				var permitted = ALLOWED_ATTRIBUTES_GLOBAL.Contains(attribute.Name)
					|| (tagAttributes != null && tagAttributes.Contains(attribute.Name));

				if (!permitted)
				{
					//This is where every "on*" handler goes, along with "style", "srcset", "formaction",
					//"srcdoc" and anything else not named above. None is enumerated as a threat; each is
					//simply not permitted.
					attribute.Remove();
					continue;
				}

				if (URL_ATTRIBUTES.Contains(attribute.Name) && !IsUrlAllowed(attribute.Value))
				{
					attribute.Remove();
				}
			}

			ForceSafeLinkRelationship(element);
		}

		/// <summary>
		/// Guarantees that an anchor which kept a <c>target</c> also carries <c>rel="noopener noreferrer"</c>.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding N22, CWE-1022 (use of a web link to an untrusted target with a window-opener
		/// reference), OWASP A03:2021. <c>target</c> is allow-listed on <c>&lt;a&gt;</c> because a stored value
		/// legitimately opens a reference in a new tab. Without <c>rel</c>, the opened document receives a live
		/// <c>window.opener</c> handle to this application's window and can navigate it - reverse tabnabbing, which
		/// needs no script in the sanitized value at all, so no element or scheme filtering reaches it. The value is
		/// SET rather than merely defaulted, because an author-supplied <c>rel</c> was itself allow-listed and could
		/// have named something weaker; <c>noreferrer</c> is included with <c>noopener</c> so the destination is not
		/// told which record the reader was on. Applied only when <c>target</c> survived attribute filtering, so an
		/// ordinary same-tab link is untouched and its rendered markup is unchanged.
		/// </remarks>
		private static void ForceSafeLinkRelationship(HtmlNode element)
		{
			if (!string.Equals(element.Name, "a", StringComparison.OrdinalIgnoreCase))
			{
				return;
			}

			if (element.Attributes["target"] == null)
			{
				return;
			}

			element.SetAttributeValue("rel", "noopener noreferrer");
		}

		/// <summary>
		/// Decides whether a URL attribute value may be kept.
		/// </summary>
		/// <remarks>
		/// The value is de-entitized and then stripped of ALL whitespace and control characters before the
		/// scheme is read. Both steps are load-bearing: a browser resolves
		/// <c>&amp;#106;avascript:</c> and <c>java&lt;TAB&gt;script:</c> to the same live scheme that a naive
		/// <c>StartsWith("javascript:")</c> test would not recognise. A value with no scheme - relative,
		/// root-relative, query-only or fragment-only - is allowed, which is what keeps the platform's own
		/// internally generated links working.
		/// <para>
		/// SECURITY - review finding N24, CWE-183 (permissive list of allowed inputs). A SCHEME-RELATIVE value is
		/// refused before the scheme test is reached. <c>//host/path</c> carries no scheme text at all, so it left
		/// through the no-colon branch, and <c>//host:8080/path</c> left through the path-colon branch - yet a
		/// browser resolves both against the PAGE's scheme and fetches an entirely different origin, which is
		/// exactly what the <c>{http, https, mailto, tel}</c> allow-list exists to decide. The backslash form
		/// <c>/\host</c> is refused with it, because browsers normalise a backslash in the authority position to a
		/// forward slash. A single leading slash - the platform's own root-relative links - is unaffected.
		/// </para>
		/// </remarks>
		private static bool IsUrlAllowed(string value)
		{
			if (string.IsNullOrWhiteSpace(value))
			{
				return false;
			}

			var candidate = HtmlEntity.DeEntitize(value) ?? value;

			var builder = new StringBuilder(candidate.Length);
			foreach (var character in candidate)
			{
				if (!char.IsWhiteSpace(character) && !char.IsControl(character))
				{
					builder.Append(character);
				}
			}

			var normalized = builder.ToString();
			if (normalized.Length == 0)
			{
				return false;
			}

			//Review finding N24 - scheme-relative, tested BEFORE the scheme is read because such a value has no
			//scheme text to test. Both delimiters are checked in both positions: a browser treats "\" in the
			//authority position as "/", so //h, /\h, \\h and \/h all resolve to a foreign origin.
			if (normalized.Length >= 2
				&& (normalized[0] == '/' || normalized[0] == '\\')
				&& (normalized[1] == '/' || normalized[1] == '\\'))
			{
				return false;
			}

			var colonIndex = normalized.IndexOf(':');
			if (colonIndex < 0)
			{
				return true;
			}

			//A '/', '?' or '#' before the first ':' means the colon belongs to a path, query or fragment
			//rather than to a scheme - "/a:b" is a relative path, not a "/a" scheme.
			var pathIndex = normalized.AsSpan().IndexOfAny(URL_PATH_DELIMITERS);
			if (pathIndex >= 0 && pathIndex < colonIndex)
			{
				return true;
			}

			return ALLOWED_URL_SCHEMES.Contains(normalized.Substring(0, colonIndex));
		}
	}
}
