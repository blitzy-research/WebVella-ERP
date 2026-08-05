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
			//Label is deliberately NOT altered here: the same component already encodes it in edit
			//mode, so encoding it at this boundary would double-encode every legitimate label
			//containing an ampersand, an apostrophe or an angle bracket. That residual is recorded in
			//docs/security/risk-register.md rather than closed with a user-visible regression.
			return originOptions.Select(x=> new WvSelectOption{Color = SafeStyleValue.CssColor(x.Color),IconClass = SafeStyleValue.IconClass(x.IconClass),Label = x.Label, Value = x.Value}).ToList();
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
