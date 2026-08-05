using System;

namespace WebVella.Erp.Plugins.Project.Services
{
	/// <summary>
	/// Allow-list guards for the two pieces of database-sourced presentation metadata this plugin
	/// renders into HTML attributes: a CSS class list and a CSS colour.
	/// </summary>
	/// <remarks>
	/// SECURITY - H-06 (CWE-79, OWASP A03:2021 - stored cross-site scripting).
	/// <para>
	/// Both values originate in the <c>options</c> of the task entity's "priority" select field, so
	/// they are database configuration rather than compile-time constants: whoever can edit that field
	/// chooses what every dashboard in the product renders. Four independent render paths consume the
	/// same two values, and the audit found only one of them guarded, which is why these checks live
	/// here as one shared, reviewable implementation instead of as private members of a single
	/// component. The alternative - repeating the same two checks at each site - is what allowed three
	/// of the four paths to be missed in the first place.
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
	/// invented fallback: it is exactly what the platform already yields for a priority option with no
	/// icon or no colour configured, so the rejected rendering is an existing state of the product.
	/// </para>
	/// </remarks>
	public static class SafeStyleValue
	{
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
