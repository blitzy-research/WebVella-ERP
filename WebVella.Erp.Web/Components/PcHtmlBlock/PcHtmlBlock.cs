using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using WebVella.Erp.Exceptions;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Services;
using WebVella.Erp.Web.Utils;

namespace WebVella.Erp.Web.Components
{
	[PageComponent(Label = "Html Block", Library = "WebVella", Description = "Example block with background color", Version = "0.0.1", IconClass = "fas fa-align-left")]
	public class PcHtmlBlock : PageComponent
	{
		protected ErpRequestContext ErpRequestContext { get; set; }

		public PcHtmlBlock([FromServices]ErpRequestContext coreReqCtx)
		{
			ErpRequestContext = coreReqCtx;
		}

		public class PcHtmlBlockOptions
		{
			[JsonProperty(PropertyName = "is_visible")]
			public string IsVisible { get; set; } = "";

			[JsonProperty(PropertyName = "html")]
			public string Html { get; set; } = "html";
		}

		public async Task<IViewComponentResult> InvokeAsync(PageComponentContext context)
		{
			ErpPage currentPage = null;
			try
			{
				#region << Init >>
				if (context.Node == null)
				{
					return await Task.FromResult<IViewComponentResult>(Content("Error: The node Id is required to be set as query parameter 'nid', when requesting this component"));
				}

				var pageFromModel = context.DataModel.GetProperty("Page");
				if (pageFromModel == null)
				{
					return await Task.FromResult<IViewComponentResult>(Content("Error: PageModel cannot be null"));
				}
				else if (pageFromModel is ErpPage)
				{
					currentPage = (ErpPage)pageFromModel;
				}
				else
				{
					return await Task.FromResult<IViewComponentResult>(Content("Error: PageModel does not have Page property or it is not from ErpPage Type"));
				}

				var instanceOptions = new PcHtmlBlockOptions();
				if (context.Options != null)
				{
					instanceOptions = JsonConvert.DeserializeObject<PcHtmlBlockOptions>(context.Options.ToString());
				}

				var componentMeta = new PageComponentLibraryService().GetComponentMeta(context.Node.ComponentName);
				#endregion

				ViewBag.Options = instanceOptions;
				ViewBag.Node = context.Node;
				ViewBag.ComponentMeta = componentMeta;
				ViewBag.RequestContext = ErpRequestContext;
				ViewBag.AppContext = ErpAppContext.Current;
				ViewBag.ComponentContext = context;

                if (context.Mode != ComponentMode.Options && context.Mode != ComponentMode.Help)
                {
                    var isVisible = true;
                    var isVisibleDS = context.DataModel.GetPropertyValueByDataSource(instanceOptions.IsVisible);
                    if (isVisibleDS is string && !String.IsNullOrWhiteSpace(isVisibleDS.ToString()))
                    {
                        if (Boolean.TryParse(isVisibleDS.ToString(), out bool outBool))
                        {
                            isVisible = outBool;
                        }
                    }
                    else if (isVisibleDS is Boolean)
                    {
                        isVisible = (bool)isVisibleDS;
                    }
                    if (!isVisible && context.Mode == ComponentMode.Display)
                        return await Task.FromResult<IViewComponentResult>(Content(""));

                    ViewBag.ProccessedHtml = ResolveHtmlForRawSink(instanceOptions.Html, context.DataModel);
                }



				switch (context.Mode)
				{
					case ComponentMode.Display:
						return await Task.FromResult<IViewComponentResult>(View("Display"));
					case ComponentMode.Design:
						return await Task.FromResult<IViewComponentResult>(View("Design"));
					case ComponentMode.Options:
						return await Task.FromResult<IViewComponentResult>(View("Options"));
					case ComponentMode.Help:
						return await Task.FromResult<IViewComponentResult>(View("Help"));
					default:
						ViewBag.Error = new ValidationException()
						{
							Message = "Unknown component mode"
						};
						return await Task.FromResult<IViewComponentResult>(View("Error"));
				}

			}
			catch (ValidationException ex)
			{
				ViewBag.Error = ex;
				return await Task.FromResult<IViewComponentResult>(View("Error"));
			}
			catch (Exception ex)
			{
				ViewBag.Error = new ValidationException()
				{
					Message = ex.Message
				};
				return await Task.FromResult<IViewComponentResult>(View("Error"));
			}
		}

		/// <summary>
		/// Resolves this component's <c>html</c> option for the raw sink in its Display and Design views,
		/// sanitizing every value whose bytes are not administrator-authored literal markup.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - review finding HIGH-01, stored cross-site scripting; CWE-79 improper
		/// neutralization of input during web page generation, OWASP A03:2021 Injection. Also CWE-668
		/// exposure of a resource to the wrong sphere, which is the precise shape of the defect.
		/// <para>
		/// THE DEFECT, AND WHY IT WAS MISSED. This component is a DELIBERATE raw-markup channel: its whole
		/// purpose is to let an author place markup on a page, so the Agent Action Plan lists its two views
		/// as by-design raw channels that must not be encoded, and the compensating control recorded for
		/// them was "only an administrator can place such a channel on a page or set its option". That
		/// premise held for the CHANNEL and not for the BYTES. The option is not a literal: it is passed to
		/// <c>PageDataModel.GetPropertyValueByDataSource</c>, which - when the stored option is a
		/// <c>DataSourceVariable</c> of type <c>DATASOURCE</c> - RESOLVES IT AGAINST THE PAGE DATA MODEL and
		/// returns a record field's value. So an administrator only had to point the block at a field; from
		/// that moment anybody able to WRITE that field decided what was emitted unencoded, on the
		/// application's own origin, in every later reader's authenticated session. The
		/// Content-Security-Policy this platform emits ships report-only by mandate, so it records such an
		/// injection and does not stop it - which is exactly why this cannot be left to the policy.
		/// </para>
		/// <para>
		/// THE FIX SEPARATES PROVENANCE FROM DELIVERY, which is what makes it possible to close the hole
		/// WITHOUT breaking the feature and WITHOUT touching either view:
		/// <list type="bullet">
		/// <item><description>
		/// A plain literal option - anything that is not a <c>DataSourceVariable</c> document - is markup an
		/// administrator typed into the page designer. It is TRUSTED and returned unchanged, so the
		/// markup-block feature behaves exactly as before.
		/// </description></item>
		/// <item><description>
		/// A <c>DataSourceVariable</c> of type <c>HTML</c> is the designer's own literal-markup variable: its
		/// <c>String</c> is authored in the page definition, not read from data. Also TRUSTED, unchanged.
		/// </description></item>
		/// <item><description>
		/// Every other variable type - <c>DATASOURCE</c>, <c>CODE</c> and <c>SNIPPET</c> - produces bytes at
		/// REQUEST time from the data model, a compiled expression or a stored snippet. Those bytes are
		/// sanitized through <see cref="HtmlSanitizer.Sanitize(string)"/>, the allow-list sanitizer this
		/// repository already uses for rich text that reaches an <c>innerHTML</c>-equivalent sink.
		/// <c>CODE</c> and <c>SNIPPET</c> are included deliberately even though the expression itself is
		/// author-supplied: what they RETURN routinely interpolates record values, so trusting the author of
		/// the expression is not the same as trusting the output of it. Deny-by-default at the uncertain
		/// edge.
		/// </description></item>
		/// </list>
		/// </para>
		/// <para>
		/// WHY SANITIZE RATHER THAN ENCODE. Encoding would render an author's legitimate stored markup as
		/// visible tag text and destroy the feature for every existing page - the preservation requirement
		/// this engagement is bound by. The sanitizer keeps the vocabulary an author actually uses
		/// (paragraphs, emphasis, lists, tables, links, images) and removes what can execute, load or
		/// submit, so a legitimate value renders identically and only a payload changes.
		/// </para>
		/// <para>
		/// WHY THE VIEWS ARE NOT TOUCHED. <c>Display.cshtml</c> and <c>Design.cshtml</c> keep
		/// <c>Html.Raw</c>. Removing it would encode the trusted literal case as well, which is the outcome
		/// the plan's must-not-encode exclusion exists to prevent. The provenance decision belongs where
		/// provenance is known - here - not at the sink, and putting it here means the Design surface an
		/// administrator previews and the Display surface a reader sees are fed by ONE resolution path and
		/// cannot disagree about what is safe.
		/// </para>
		/// <para>
		/// The value is resolved ONCE and re-inspected rather than resolved twice: calling the data model a
		/// second time could return a different value - a code variable is re-evaluated on each call - and a
		/// check performed on a value other than the one emitted would be a time-of-check to time-of-use gap
		/// (CWE-367) in a security control.
		/// </para>
		/// </remarks>
		/// <param name="htmlOption">The stored <c>html</c> option, as authored in the page definition.</param>
		/// <param name="dataModel">The page data model the option is resolved against.</param>
		/// <returns>Markup safe to place in the raw sink, or null when the option resolves to nothing.</returns>
		private static object ResolveHtmlForRawSink(string htmlOption, PageDataModel dataModel)
		{
			object resolved = dataModel.GetPropertyValueByDataSource(htmlOption);

			if (IsAdministratorAuthoredLiteralMarkup(htmlOption))
				return resolved;

			//Not a string means no markup can be produced from it by the raw sink - Html.Raw would emit
			//ToString(), which for the platform's own model types is a type name and not author content - so
			//it is returned as-is rather than forced through a string sanitizer that would only stringify it.
			if (!(resolved is string resolvedMarkup))
				return resolved;

			return HtmlSanitizer.Sanitize(resolvedMarkup);
		}

		/// <summary>
		/// True when the stored option is markup an administrator authored in the page definition, rather
		/// than a reference the data model resolves at request time.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding HIGH-01. This mirrors the discrimination
		/// <c>PageDataModel.GetPropertyValueByDataSource(string)</c> performs, deliberately and by the same
		/// test, so the two cannot disagree about what a stored option IS: a value whose trimmed text does
		/// not begin with <c>{</c> is never parsed as a variable there, and a document that fails to
		/// deserialize into a <see cref="DataSourceVariable"/> is returned verbatim there. Both of those are
		/// literal markup and are treated as such here. Only a document that genuinely deserializes AND
		/// declares type <c>HTML</c> is a designer literal; every other declared type reaches data.
		/// <para>
		/// <c>MissingMemberHandling.Error</c> matches that method exactly. Without it a JSON document with
		/// no <c>type</c> member would deserialize with <c>type</c> defaulting to <c>DATASOURCE</c> here
		/// while being rejected there and returned as literal text - the two paths would disagree, and the
		/// disagreement would be in the direction of sanitizing text the sink treats as literal.
		/// </para>
		/// </remarks>
		private static bool IsAdministratorAuthoredLiteralMarkup(string htmlOption)
		{
			if (string.IsNullOrWhiteSpace(htmlOption))
				return true;

			//The char overload, not the string one: it is ordinal by construction, so the test cannot be
			//made culture-sensitive by a later edit, and it keeps this file free of new analyzer diagnostics.
			if (!htmlOption.Trim().StartsWith('{'))
				return true;

			DataSourceVariable variable;
			try
			{
				variable = JsonConvert.DeserializeObject<DataSourceVariable>(htmlOption,
					new JsonSerializerSettings() { MissingMemberHandling = MissingMemberHandling.Error });
			}
			catch
			{
				//Not a variable document, so the data model returns the option VERBATIM as literal markup.
				//The catch is deliberately as broad as the bare catch in the method this mirrors: any
				//narrower filter would let an exception the data model swallows escape from a security
				//check and turn an author's literal option into an error view, and returning trusted here
				//is exactly right because the bytes that reach the sink in this case ARE the author's own
				//literal option rather than anything resolved from data.
				return true;
			}

			return variable != null && variable.Type == DataSourceVariableType.HTML;
		}
	}
}
