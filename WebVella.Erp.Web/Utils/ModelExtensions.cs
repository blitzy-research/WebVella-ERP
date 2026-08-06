using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Exceptions;
using WebVella.Erp.Web.Models;
using WebVella.TagHelpers.Models;

namespace WebVella.Erp.Web.Utils
{
	public static class ModelExtensions
	{
		public static string GetLabel<T>(this T e) where T : IConvertible
		{
			string label = "";

			if (e is Enum)
			{
				Type type = e.GetType();
				Array values = Enum.GetValues(type);

				foreach (int val in values)
				{
					if (val == e.ToInt32(CultureInfo.InvariantCulture))
					{
						var memInfo = type.GetMember(type.GetEnumName(val));
						var soAttributes = memInfo[0].GetCustomAttributes(typeof(Api.Models.SelectOptionAttribute), false);
						if (soAttributes.Length > 0)
						{
							// we're only getting the first description we find
							// others will be ignored
							label = ((Api.Models.SelectOptionAttribute)soAttributes[0]).Label;
						}

						break;
					}
				}
			}

			return label;
		}

		public static List<SelectOption> GetEnumAsSelectOptions<T>()
		{
			var selectOptions = new List<SelectOption>();
			var values = Enum.GetValues(typeof(T));
			var type = typeof(T);
			foreach (var val in values)
			{
				var memInfo = type.GetMember(type.GetEnumName(val));
				var enumAuxAttributes = memInfo[0].GetCustomAttributes(typeof(SelectOptionAttribute), false);
				var label = "";
				var iconClass = "";
				var color = "";
				if (enumAuxAttributes.Length > 0)
				{
					// we're only getting the first description we find
					// others will be ignored
					var enumAux = (SelectOptionAttribute)enumAuxAttributes[0];
					label = enumAux.Label;
					iconClass = enumAux.IconClass;
					color = enumAux.Color;
				}

				selectOptions.Add(new SelectOption() { Value = ((int)val).ToString(), Label = label, Color = color, IconClass = iconClass });
			}
			return selectOptions;
		}

		public static List<KeyValuePair<string, string>> ToErrorList(this ValidationException validation, List<string> includeFields = null, List<string> excludeFields = null)
		{
			if(validation == null)
				return null;

			var result = new List<KeyValuePair<string, string>>();
			if(includeFields == null)
				includeFields = new List<string>();

			if(excludeFields == null)
				excludeFields = new List<string>();

			foreach (var valError in validation.Errors)
			{
				var isIncluded = false;

				if(includeFields.Count == 0)
					isIncluded = true;
				else if(includeFields.Contains(valError.PropertyName))
					isIncluded = true;
				if (excludeFields.Contains(valError.PropertyName))
					isIncluded = false;

				if (isIncluded)
					result.Add(new KeyValuePair<string, string>(valError.PropertyName, valError.Message));
			}

			return result;
		}

		public static List<KeyValuePair<string, string>> ToKeyValuePair(this List<ValidationError> errors)
		{
			if(errors == null)
				return null;

			return errors.Select(x=> new KeyValuePair<string, string>(x.PropertyName,x.Message)).ToList();
		}

		public static List<WvSelectOption> ToWvSelectOption(this List<SelectOption> originOptions)
		{
			if(originOptions == null)
				return null;

			//THREAT ADDRESSED - CWE-79 (stored cross-site scripting), OWASP A03:2021, finding H-06.
			//Color and IconClass are database configuration read from a select field's stored options,
			//and this method is the ONLY place in the repository that constructs a WvSelectOption - so
			//it is the single boundary at which those two values leave the platform and enter the
			//third-party WebVella.TagHelpers select component. That component's display path
			//concatenates them straight into a class attribute and a style attribute with no encoding,
			//which let a stored value close the attribute and add a new one of its own, including an
			//event handler. Its inline-edit path writes the same two values into data-icon/data-color,
			//and the select2 script then reads the DECODED attribute back out of the DOM and re-inserts
			//it as markup - so correct server-side attribute encoding does not close that half.
			//Allow-listing here closes both, product-wide, for every wv-field-select and
			//wv-field-multiselect, and it has to sit on this side of the boundary because the component
			//ships inside a NuGet package this work may only version-update.
			//
			//THREAT ADDRESSED - review finding F-01, the SAME weakness in the third member of this type.
			//Label is now guarded too, and the earlier note here - that it was "deliberately NOT
			//altered" because the component encodes it in edit mode - was wrong on the facts and is
			//retracted. The component encodes the label ONLY where it writes it with Append: into
			//<option> text, and into the Display and Simple spans when no icon is configured. Wherever
			//an icon IS configured it writes "<i class=..></i> {Label}" with AppendHtml, and
			//WvFieldCheckboxList and WvFieldRadioList write the label with AppendHtml unconditionally.
			//A stored label therefore executed, which QA reproduced live with an <img onerror> payload.
			//Encoding at this boundary is the wrong control twice over: it would double-encode wherever
			//the Append path is taken - the regression the earlier note correctly feared - and it would
			//not even close the raw path, because those components initialise select2 with
			//escapeMarkup: markup => markup and their templates re-insert record.text, the DECODED text
			//of the option element, through innerHTML. SafeStyleValue.DisplayText therefore RESTRICTS
			//the value instead, removing only the two characters that can create markup at those sinks,
			//so every legitimate label - including one containing an ampersand or an apostrophe - is
			//returned byte-for-byte unchanged and renders exactly as it does today.
			return originOptions.Select(x=> new WvSelectOption{Color = SafeStyleValue.CssColor(x.Color),IconClass = SafeStyleValue.IconClass(x.IconClass),Label = SafeStyleValue.DisplayText(x.Label), Value = x.Value}).ToList();
		}	

		public static WvSelectOptionsAjaxDatasource ToWvSelectOptionsAjaxDatasource(this SelectOptionsAjaxDatasource origin){
			if(origin == null)
				return null;

			var result = new WvSelectOptionsAjaxDatasource{
				DatasourceName = origin.DatasourceName,
				InitOptions = origin.InitOptions.ToWvSelectOption(),
				UseSelectApi = origin.UseSelectApi,
				Label = origin.Label,
				PageSize = origin.PageSize,
				Value = origin.Value
			};
			return result;
		}
	}
}
