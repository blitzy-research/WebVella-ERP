using System;
//SECURITY - review finding F-01: supplies StringBuilder for the display-text guard below.
using System.Text;

namespace WebVella.Erp.Web.Utils
{
	/// <summary>
	/// Allow-list guards for the database-sourced presentation metadata the platform renders into HTML: a
	/// CSS class list, a CSS colour, and display text handed to a component that writes it unencoded.
	/// </summary>
	/// <remarks>
	/// SECURITY - H-06 (CWE-79, OWASP A03:2021 - stored cross-site scripting).
	/// <para>
	/// The two original guards - <see cref="IconClass"/> and <see cref="CssColor"/> - exist for values
	/// that originate in the <c>options</c> of a select or multi-select field, so they are database
	/// configuration rather than compile-time constants: whoever can edit that field chooses what every
	/// screen rendering it emits. Several independent render paths consume the same two values, which is
	/// why these checks live here as one shared, reviewable implementation instead of as private members
	/// of a single component. The alternative - repeating the same two checks at each site - is what
	/// allowed path after path to be missed. Two further guards were added later for review findings and
	/// are described at the end of these remarks.
	/// </para>
	/// <para>
	/// SECOND CORRECTION OF RECORD, and the reason <see cref="DisplayText(string)"/> exists. The remarks
	/// below, and the ones that used to sit on <see cref="ModelExtensions.ToWvSelectOption"/>, asserted
	/// that the option LABEL needed no guard because "the same component already encodes it in edit
	/// mode". That claim was tested against the decompiled component rather than accepted, and it is
	/// false in two ways: four of the package's renderings pass the label to <c>AppendHtml</c> with
	/// nothing encoding it, and the select2 dropdown re-parses the DECODED option text as HTML
	/// client-side on every path, icon or no icon. The label was therefore a live stored
	/// cross-site-scripting channel product-wide, not an accepted residual. The full evidence is
	/// recorded on <see cref="DisplayText(string)"/>.
	/// </para>
	/// <para>
	/// WHY THE LABEL GUARD REMOVES RATHER THAN ESCAPES. Escaping the two markup delimiters - writing
	/// <c>&amp;lt;</c> and <c>&amp;gt;</c> into the option text - was considered for this finding and
	/// rejected, because the evidence in the paragraph above is precisely what defeats it. The select2
	/// templates return <c>record.text</c>, which is the option's text AFTER the browser has decoded it,
	/// and they insert that through <c>innerHTML</c> with <c>escapeMarkup: markup =&gt; markup</c>. A
	/// label escaped to <c>&amp;lt;img&amp;gt;</c> is therefore decoded back to <c>&lt;img&gt;</c> and
	/// re-parsed as an element, so escaping closes the server-rendered sinks while leaving the widest
	/// client-side one open. Escaping also leaves <c>"</c> intact, which one inline-edit script
	/// concatenates into <c>title="..."</c>. Removing the characters survives the decode - what is not
	/// in the text cannot come back out of it - and needs no double-encoding on the paths that already
	/// encode. <see cref="DisplayText"/> therefore removes, and states its one residual openly.
	/// </para>
	/// <para>
	/// CORRECTION OF RECORD. The earlier remarks on this class asserted that "four independent render
	/// paths consume the same two values". That count was short by one, and the missing path is by far
	/// the widest: <see cref="ModelExtensions.ToWvSelectOption"/> is the single conversion boundary
	/// through which every select and multi-select field in the product hands its stored options to the
	/// third-party WebVella.TagHelpers display component, and that component concatenates both values
	/// straight into a <c>class</c> attribute and a <c>style</c> attribute with no encoding. It is
	/// reachable on every host that renders any select field, not only on the hosts carrying the
	/// Project plugin. That is also why this class lives in WebVella.Erp.Web rather than in a plugin:
	/// the framework cannot call into a plugin that references the framework, so a guard owned by a
	/// plugin could never have reached the widest sink of the five.
	/// </para>
	/// <para>
	/// Guarding at that boundary additionally closes a sink that correct server-side encoding cannot
	/// reach. The framework does encode the inline-edit <c>&lt;option data-icon data-color&gt;</c>
	/// attributes, but the select2 script reads the DECODED attribute value back out of the DOM and
	/// re-inserts it as markup, reproducing the identical attribute break-out client-side. Because the
	/// value is allow-listed before it is ever written into those attributes, what the script reads
	/// back is already safe.
	/// </para>
	/// <para>
	/// Encoding alone is not sufficient for either value, which is the reason an allow-list exists at
	/// all. A class attribute that is HTML-encoded still accepts extra class names, letting stored
	/// configuration restyle or reposition an element. A style attribute is worse: the value never has
	/// to escape the attribute to do harm, because a semicolon simply starts another declaration and a
	/// <c>url(...)</c> function reaches back out to the network. Constraining what the value may
	/// contain is the control; encoding is the layer underneath it.
	/// </para>
	/// <para>
	/// A rejected value degrades to an empty string in both cases. That is deliberate and is not an
	/// invented fallback: it is exactly what the platform already yields for an option with no icon or
	/// no colour configured, so the rejected rendering is an existing state of the product.
	/// </para>
	/// <para>
	/// TWO GUARDS WERE ADDED LATER, both for review findings, and both belong here for the same reason the
	/// first two do - they are consumed by more than one render path and must have one reviewable
	/// implementation. <see cref="DisplayText"/> (finding F-01) covers the option LABEL at the same vendor
	/// boundary the class-and-colour guards already cover, and it restricts rather than encodes because
	/// that boundary feeds an encoding sink and a raw sink simultaneously. <see cref="ApprovedIconClass"/>
	/// (finding F-06) is a stricter, TOKEN-level form of <see cref="IconClass"/> for the page header, where
	/// a character-level rule still allowed stored metadata to contribute arbitrary class names to a
	/// component that renders on nearly every screen. Each member documents its own reasoning at its own
	/// declaration.
	/// </para>
	/// </remarks>
	public static class SafeStyleValue
	{
		/// <summary>
		/// Returns database-sourced display text that is safe to render even where the consuming component
		/// writes it into markup without encoding it.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding F-01, H-06 / P-23 (CWE-79, OWASP A03:2021 - stored cross-site
		/// scripting). This is the guard for a <see cref="WebVella.TagHelpers.Models.WvSelectOption"/>
		/// label, applied at <see cref="ModelExtensions.ToWvSelectOption"/> - the single conversion boundary
		/// through which every select and multi-select field in the product hands its stored options to the
		/// third-party WebVella.TagHelpers components.
		/// <para>
		/// WHY THE VALUE IS RESTRICTED RATHER THAN ENCODED. Encoding cannot close this sink, and that is a
		/// measured property of the consuming component rather than a preference. The same label instance
		/// reaches an ENCODING sink and a RAW sink in one render:
		/// <list type="bullet">
		/// <item>raw - <c>WvFieldSelect</c> and <c>WvFieldMultiSelect</c> concatenate the label into
		/// <c>&lt;i class=".."&gt;&lt;/i&gt; {Label}</c> and write it with <c>AppendHtml</c> in Display,
		/// Simple and InlineEdit modes, and <c>WvFieldCheckboxList</c> and <c>WvFieldRadioList</c> write it
		/// with <c>AppendHtml</c> unconditionally;</item>
		/// <item>encoded - the same components write the same label into <c>&lt;option&gt;</c> text, and
		/// into the Display and Simple spans when no icon is configured, with <c>Append</c>.</item>
		/// </list>
		/// Pre-encoding therefore double-encodes wherever the encoded path is taken, which is exactly the
		/// user-visible regression this fix must avoid. Worse, pre-encoding does not even close the raw
		/// half: those components initialise select2 with <c>escapeMarkup: markup =&gt; markup</c> and their
		/// templates return <c>record.text</c>, the DECODED text of the option element, which select2 then
		/// inserts through <c>innerHTML</c> - so a label stored as <c>&amp;lt;img&amp;gt;</c> is decoded back
		/// to <c>&lt;img&gt;</c> before it is re-inserted as markup. The inline-edit scripts do the same
		/// through <c>.html(optionLabel)</c> and through an <c>&lt;li title="..."&gt;</c> string they build
		/// by concatenation.
		/// </para>
		/// <para>
		/// WHAT IS REMOVED, AND WHY ONLY THAT. Exactly two characters can create markup at those sinks and
		/// both are dropped:
		/// <list type="bullet">
		/// <item><c>&lt;</c> is the only character that can begin a tag, a comment or a processing
		/// instruction. Without it a label cannot become an element, so it cannot carry an attribute and
		/// cannot carry an event handler.</item>
		/// <item><c>"</c> is dropped because one client-side sink builds <c>title="' + optionLabel + '"</c>
		/// by string concatenation, where a quote closes the attribute and lets a new one - including a
		/// handler - be added. Server-side attribute writes go through <c>TagBuilder</c> and are already
		/// encoded; this covers the one that does not.</item>
		/// </list>
		/// <c>&amp;</c>, <c>'</c> and <c>&gt;</c> are deliberately LEFT INTACT, so a legitimate label such
		/// as <c>R&amp;D</c> or <c>Client's copy</c> is returned byte-for-byte unchanged and renders
		/// identically to how it renders today. None of the three is dangerous here: a character reference
		/// never produces markup - <c>&amp;lt;script&amp;gt;</c> renders as the literal text
		/// <c>&lt;script&gt;</c> - <c>&gt;</c> is inert outside a tag, and <c>'</c> cannot terminate a
		/// double-quoted attribute.
		/// </para>
		/// <para>
		/// A census of all 150 <c>SelectOption</c> construction sites in this repository found no label that
		/// contains markup, and none that contains either removed character, so no shipped screen changes.
		/// Dropping the character rather than rejecting the whole value keeps a pathological label readable
		/// instead of blanking a field's option text, which would be the larger user-visible regression.
		/// </para>
		/// </remarks>
		/// <param name="value">The label recorded against the option.</param>
		/// <returns>
		/// The original value when it contains neither removed character - the overwhelmingly common case,
		/// returned as the same instance - and otherwise the value with those characters removed.
		/// </returns>
		public static string DisplayText(string value)
		{
			if (String.IsNullOrEmpty(value))
				return value;

			//the common path allocates nothing: a label that needs no change is returned as it arrived
			if (value.IndexOf('<') < 0 && value.IndexOf('"') < 0)
				return value;

			var builder = new StringBuilder(value.Length);
			foreach (var character in value)
			{
				if (character != '<' && character != '"')
					builder.Append(character);
			}

			return builder.ToString();
		}

		/// <summary>
		/// Returns the supplied Font Awesome icon class when it is safe to render into a class
		/// attribute, and an empty string when it is not.
		/// </summary>
		/// <remarks>
		/// SECURITY - H-06 (CWE-79): only what a CSS class list can legitimately contain is accepted -
		/// letters, digits, spaces, hyphens and underscores. Anything else rejects the whole value
		/// rather than escaping part of it, because a partially escaped class list is still a class
		/// list the attacker influenced.
		/// </remarks>
		/// <param name="value">The icon class recorded against the option.</param>
		/// <returns>The original value, or an empty string when it contains anything unexpected.</returns>
		public static string IconClass(string value)
		{
			if (String.IsNullOrEmpty(value))
				return "";

			foreach (var character in value)
			{
				if (!Char.IsLetterOrDigit(character) && character != ' ' && character != '-' && character != '_')
					return "";
			}

			return value;
		}

		/// <summary>
		/// Returns the supplied icon class when every one of its tokens is a class this product is known to
		/// author, and an empty string when any token is not.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding F-06 (CWE-20, CWE-79, OWASP A03:2021). This is the stricter sibling of
		/// <see cref="IconClass"/> and exists because a CHARACTER allow-list is not sufficient at the page
		/// header. <see cref="IconClass"/> accepts anything spelled with letters, digits, spaces, hyphens
		/// and underscores, which stops attribute break-out but still lets stored metadata contribute
		/// ARBITRARY class names to the element - <c>d-none</c> hides it, <c>position-fixed</c> lifts it out
		/// of the layout, a utility width class resizes it. On <c>WvPageHeader</c> the value arrives from
		/// entity, application and page metadata resolved through a data source, so whoever can edit that
		/// metadata chooses those classes on a component that renders at the top of essentially every
		/// screen. The control therefore has to be a TOKEN allow-list.
		/// <para>
		/// The accepted shapes are the ones the product actually authors, measured across every
		/// <c>icon-class</c>, <c>icon_name</c> and <c>IconClass</c> value in the repository:
		/// <list type="bullet">
		/// <item>a Font Awesome family token - <c>fa</c>, <c>fas</c>, <c>far</c>, <c>fab</c>, <c>fal</c>,
		/// <c>fad</c> and their siblings, matched as <c>fa</c> followed by at most three letters;</item>
		/// <item>a Font Awesome glyph or utility token - <c>fa-</c> followed by letters, digits and internal
		/// hyphens, which covers every glyph name and <c>fa-fw</c>;</item>
		/// <item>the platform's own <c>icon</c> layout token, which three shipped page headers use
		/// (<c>fa fa-cog icon</c>, <c>far fa-calendar-alt icon</c>, <c>far fa-sticky-note icon</c>);</item>
		/// <item>the platform's <c>go-</c> colour utility tokens, spelled with letters only.</item>
		/// </list>
		/// Anything else rejects the WHOLE value rather than dropping the offending token, because a
		/// partially accepted class list is still a class list the author influenced.
		/// </para>
		/// <para>
		/// A rejected value degrades to an empty string, and the caller then renders exactly what it
		/// renders for metadata with no icon configured - an existing state of the product, not an invented
		/// fallback. Comparisons are ordinal and case-sensitive: every class this product authors is lower
		/// case, and a culture-sensitive or case-insensitive test would be a security decision that varies
		/// with the server's locale.
		/// </para>
		/// </remarks>
		/// <param name="value">The icon class recorded against the entity, application or page.</param>
		/// <returns>The original value, or an empty string when any token is not an approved one.</returns>
		public static string ApprovedIconClass(string value)
		{
			if (String.IsNullOrWhiteSpace(value))
				return "";

			foreach (var token in value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
			{
				if (!IsApprovedIconToken(token))
					return "";
			}

			return value;
		}

		/// <summary>
		/// True when a single whitespace-separated class token is one this product is known to author.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding F-06. Kept separate from <see cref="ApprovedIconClass"/> so the
		/// per-token rule is stated once and can be read on its own.
		/// </remarks>
		private static bool IsApprovedIconToken(string token)
		{
			//the platform's own layout token, carried by three shipped page headers
			if (token == "icon")
				return true;

			//the base Font Awesome family token on its own - by far the most common token in this product,
			//and the one an "at least one letter after the prefix" rule would wrongly refuse
			if (token == "fa")
				return true;

			//a Font Awesome glyph or utility token: "fa-" then letters, digits and internal hyphens
			if (token.StartsWith("fa-", StringComparison.Ordinal))
				return IsLowerCaseIdentifierWithHyphens(token, 3);

			//a Font Awesome family token: "fa" then at most three letters - fas, far, fab, fal, fad
			if (token.StartsWith("fa", StringComparison.Ordinal) && token.Length <= 5)
				return IsLowerCaseLetters(token, 2);

			//the platform's colour utility tokens: "go-" then letters only
			if (token.StartsWith("go-", StringComparison.Ordinal))
				return IsLowerCaseLetters(token, 3);

			return false;
		}

		/// <summary>
		/// True when every character of <paramref name="token"/> from <paramref name="startIndex"/> onwards
		/// is a lower-case ASCII letter, and at least one character follows the prefix.
		/// </summary>
		private static bool IsLowerCaseLetters(string token, int startIndex)
		{
			if (token.Length <= startIndex)
				return false;

			for (var index = startIndex; index < token.Length; index++)
			{
				if (token[index] < 'a' || token[index] > 'z')
					return false;
			}

			return true;
		}

		/// <summary>
		/// True when <paramref name="token"/> from <paramref name="startIndex"/> onwards is spelled with
		/// lower-case ASCII letters, digits and internal single hyphens, and neither begins nor ends with a
		/// hyphen.
		/// </summary>
		private static bool IsLowerCaseIdentifierWithHyphens(string token, int startIndex)
		{
			if (token.Length <= startIndex)
				return false;

			if (token[startIndex] == '-' || token[token.Length - 1] == '-')
				return false;

			for (var index = startIndex; index < token.Length; index++)
			{
				var character = token[index];
				var isLowerCaseLetter = character >= 'a' && character <= 'z';
				var isDigit = character >= '0' && character <= '9';

				if (!isLowerCaseLetter && !isDigit && character != '-')
					return false;
			}

			return true;
		}

		/// <summary>
		/// Returns the supplied colour when it is safe to render inside a style declaration, and an
		/// empty string when it is not.
		/// </summary>
		/// <remarks>
		/// SECURITY - H-06 (CWE-79): two shapes are accepted, which together cover every colour this
		/// product actually stores - a hexadecimal literal of 3, 4, 6 or 8 digits, and a bare CSS
		/// colour keyword of letters only. Letters alone cannot open a new declaration, close the
		/// attribute, or form a function call such as <c>url(...)</c> or <c>expression(...)</c>.
		/// A rejected value makes the caller emit "color:", a declaration the browser discards, leaving
		/// the element with its inherited colour.
		/// </remarks>
		/// <param name="value">The colour recorded against the option.</param>
		/// <returns>The original value, or an empty string when it is not a recognised colour shape.</returns>
		public static string CssColor(string value)
		{
			if (String.IsNullOrEmpty(value))
				return "";

			if (value[0] == '#')
			{
				//A leading hash must be followed by exactly 3, 4, 6 or 8 hexadecimal digits.
				if (value.Length != 4 && value.Length != 5 && value.Length != 7 && value.Length != 9)
					return "";

				for (var index = 1; index < value.Length; index++)
				{
					if (!Uri.IsHexDigit(value[index]))
						return "";
				}

				return value;
			}

			//Otherwise only a bare colour keyword is accepted.
			foreach (var character in value)
			{
				if (!Char.IsLetter(character))
					return "";
			}

			return value;
		}
	}
}
