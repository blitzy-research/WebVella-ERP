using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Services;
using WebVella.Erp.Web.Utils;
using WebVella.Erp.Api.Models;
using System.Linq;
using System.Globalization;
using HtmlAgilityPack;
using WebVella.TagHelpers.Models;

namespace WebVella.Erp.Web.TagHelpers
{
	[HtmlTargetElement("wv-page-header")]
	[RestrictChildren("wv-page-header-actions", "wv-page-header-toolbar", "wv-page-header-actions-aux")]
	public class WvPageHeader : TagHelper
	{

		[HtmlAttributeNotBound]
		[ViewContext]
		public ViewContext ViewContext { get; set; }

		[HtmlAttributeName("is-visible")]
		public bool isVisible { get; set; } = true;

		[HtmlAttributeName("color")]
		public string Color { get; set; } = "";

		[HtmlAttributeName("icon-color")]
		public string IconColor { get; set; } = "";

		[HtmlAttributeName("area-label")]
		public string AreaLabel { get; set; } = "";

		[HtmlAttributeName("area-sublabel")]
		public string AreaSubLabel { get; set; } = "";

		[HtmlAttributeName("title")]
		public string Title { get; set; } = "";

		[HtmlAttributeName("subtitle")]
		public string SubTitle { get; set; } = "";

		/// <summary>
		/// Ordinary description text. HTML-ENCODED when rendered.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding F-02 (CWE-79, OWASP A03:2021 - stored cross-site scripting). This
		/// attribute used to be a raw markup channel, on the strength of a comment claiming its only
		/// non-literal supplier was <c>PageUtils.GenerateListPageDescription</c>. That claim was false:
		/// <c>PcPageHeader</c> resolves the value through
		/// <c>context.DataModel.GetPropertyValueByDataSource(instanceOptions.Description)</c> and both of
		/// its component views bind it here, so arbitrary page and record data reached a raw sink on a
		/// component that renders at the top of essentially every screen.
		/// <para>
		/// The two channels are now separate types of thing rather than one attribute with two meanings.
		/// This one is text and is encoded, which is the safe DEFAULT that any present or future caller
		/// gets without having to know anything. Trusted markup has to be opted into explicitly through
		/// <see cref="DescriptionHtml"/>, which is what makes the five list pages that genuinely compose
		/// markup keep working while the data-bound path stops being a sink.
		/// </para>
		/// </remarks>
		[HtmlAttributeName("description")]
		public string Description { get; set; } = "";

		/// <summary>
		/// Description markup composed by the application itself. Rendered RAW, and must therefore never
		/// carry a value that originates in the database, in a request, or in any other untrusted source.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding F-02 (CWE-79, OWASP A03:2021). This is the explicit trusted-markup
		/// counterpart to <see cref="Description"/>, added rather than keeping the single attribute raw so
		/// that the dangerous behaviour is opt-in and visible in the view that opts into it.
		/// <para>
		/// It has exactly one legitimate supplier: <c>PageUtils.GenerateListPageDescription</c>, which
		/// composes an inline <c>ul</c>/<c>li</c> list wrapping a bold <c>sorted by</c> and
		/// <c>filtered by</c>. Encoding that would show those tags to the user as literal text on every
		/// list screen in the product, which is why a trusted channel exists at all. The
		/// attacker-influenceable fragments that builder interpolates - the <c>sortBy</c> query value and
		/// each filter name - are encoded AT THE BUILDER, where the value and the markup around it are
		/// still distinguishable.
		/// </para>
		/// <para>
		/// Five views bind this attribute, all of them SDK list pages passing that builder's output:
		/// <c>application/list</c>, <c>data_source/list</c>, <c>entity/list</c>, <c>entity/pages</c> and
		/// <c>page/list</c>. A new caller must not be added without the same guarantee. When both
		/// attributes are supplied this one wins, and the encoded text is ignored rather than concatenated,
		/// so a caller can never accidentally produce a half-raw, half-encoded fragment.
		/// </para>
		/// </remarks>
		[HtmlAttributeName("description-html")]
		public string DescriptionHtml { get; set; } = "";

		[HtmlAttributeName("icon-class")]
		public string IconClass { get; set; } = "";

		[HtmlAttributeName("return-url")]
		public string ReturnUrl { get; set; } = "";

		[HtmlAttributeName("fix-on-scroll")]
		public bool FixOnScroll { get; set; } = false;

		[HtmlAttributeName("page-switch-items")]
		public List<PageSwitchItem> PageSwitchItems { get; set; } = new List<PageSwitchItem>();

		public override async Task ProcessAsync(TagHelperContext context, TagHelperOutput output)
		{
			if (!isVisible)
			{
				output.SuppressOutput();
			}
			else
			{
				var elementId = Guid.NewGuid();
				var content = await output.GetChildContentAsync();
				var htmlDoc = new HtmlDocument();
				htmlDoc.LoadHtml(content.GetContent());

				var actionsContentHtml = "";
				var actionsAuxContentHtml = "";
				var toolbarContentHtml = "";
				var actionTagHelperList = htmlDoc.DocumentNode.Descendants("wv-page-header-actions");
				var actionAuxTagHelperList = htmlDoc.DocumentNode.Descendants("wv-page-header-actions-aux");
				var toolbarTagHelperList = htmlDoc.DocumentNode.Descendants("wv-page-header-toolbar");

				foreach (var node in actionTagHelperList)
				{
					actionsContentHtml += node.InnerHtml.ToString();
				}

				foreach (var node in actionAuxTagHelperList)
				{
					actionsAuxContentHtml += node.InnerHtml.ToString();
				}

				foreach (var node in toolbarTagHelperList)
				{
					toolbarContentHtml += node.InnerHtml.ToString();
				}


				// THREAT ADDRESSED - review finding F-06 (CWE-20, CWE-79, OWASP A03:2021). Color, IconColor
				// and IconClass are the three presentation values on this tag helper that are NOT text
				// channels: they are written into a style attribute and into a class attribute. All three
				// are database metadata - PcPageHeader resolves each of them through
				// context.DataModel.GetPropertyValueByDataSource, and the SDK views bind them from
				// ErpEntity.Color, ErpEntity.IconName and App.IconClass - so whoever can edit entity,
				// application or page metadata chooses what this component, which renders at the top of
				// essentially every screen, puts in those attributes.
				// TagBuilder encodes an attribute VALUE, which is what stops break-out into a new attribute
				// or a new handler, and that half was already sound. What encoding cannot constrain is what
				// the value MEANS inside the attribute it legitimately occupies: a semicolon simply starts
				// another CSS declaration, a url(...) function reaches back out to the network, and a class
				// attribute accepts any further class name - d-none to hide the element, a position or width
				// utility to move or resize it. The guards below are therefore allow-lists, applied once
				// here so that every sink in this method reads the same already-checked value and a future
				// sink cannot reintroduce the defect by reading the raw property.
				// A rejected value becomes an empty string, at which point the code below renders exactly
				// what it renders for metadata that configures no colour and no icon - an existing state of
				// the product rather than an invented fallback. The icon guard is the TOKEN-level
				// ApprovedIconClass rather than the character-level SafeStyleValue.IconClass precisely
				// because arbitrary class TOKENS, not stray punctuation, are the exposure here.
				var safeColor = SafeStyleValue.CssColor(Color);
				var safeIconColor = SafeStyleValue.CssColor(IconColor);
				var safeIconClass = SafeStyleValue.ApprovedIconClass(IconClass);

				output.TagName = "div";
				// has-icon/no-icon must agree with whether an icon element is actually emitted below, so it
				// reads the guarded value: a rejected icon class emits no icon, and the layout class has to
				// say so or the header reserves space for a glyph that is not there.
				output.AddCssClass($"pc-page-header {(!String.IsNullOrWhiteSpace(toolbarContentHtml) ? "has-toolbar" : "")} {(!String.IsNullOrWhiteSpace(safeIconClass) ? "has-icon" : "")} {(!String.IsNullOrWhiteSpace(ReturnUrl) ? "has-btn-back" : "")} {(String.IsNullOrWhiteSpace(safeIconClass) ? "no-icon" : "")}");
				output.Attributes.Add("id", $"wv-{elementId}");

				#region << Upper >>
				//Wrapper should be rendered
					var upperWrapperEl = new TagBuilder("div");
					upperWrapperEl.AddCssClass("upper");

					#region << Upper > Left Actions >>
					if (!String.IsNullOrWhiteSpace(ReturnUrl))
					{
						var leftActionWrapperEl = new TagBuilder("div");
						leftActionWrapperEl.AddCssClass("actions left");

						var backBtnEl = new TagBuilder("a");
						backBtnEl.AddCssClass("btn btn-sm btn-outline-secondary btn-back");
						// SECURITY (CWE-79 / CWE-601): this attribute is the single href sink for every return
						// URL rendered by the platform's page header - 44 views bind return-url to it, and the
						// PcPageHeader component feeds it from both the inbound query string and a configured
						// data source. TagBuilder HTML-encodes the value, which closes attribute breakout, but
						// encoding does not constrain the URI scheme: an unvalidated "javascript:alert(1)"
						// stays executable on click, and "//attacker.example" stays a phishing redirect.
						// Validating here rather than at each feeder keeps one authority over the sink, so a
						// future caller cannot introduce the same defect by supplying its own value.
						backBtnEl.Attributes.Add("href", BaseErpPageModel.SanitizeReturnUrl(ReturnUrl));
						var backBtnIconEl = new TagBuilder("span");
						backBtnIconEl.AddCssClass("fa fa-arrow-left");
						backBtnEl.InnerHtml.AppendHtml(backBtnIconEl);
						leftActionWrapperEl.InnerHtml.AppendHtml(backBtnEl);
						upperWrapperEl.InnerHtml.AppendHtml(leftActionWrapperEl);
					}
					#endregion

					#region << Upper > Meta >>
						//Wrapper should be rendered
						var metaWrapperEl = new TagBuilder("div");
						metaWrapperEl.AddCssClass("meta");

						#region << Meta > Icon >>
						//SECURITY - finding F-06: the guarded values from the top of this method, never the
						//raw properties. See the note there.
						if (!String.IsNullOrWhiteSpace(safeIconClass))
						{
							var metaLabelIconWrapperEl = new TagBuilder("div");
							metaLabelIconWrapperEl.AddCssClass("meta-icon");
							if (!String.IsNullOrWhiteSpace(safeColor))
							{
								metaLabelIconWrapperEl.Attributes.Add("style", $"background-color:{safeColor};");
							}
							var metaLabelIconEl = new TagBuilder("span");
							metaLabelIconEl.AddCssClass(safeIconClass);
							if (!String.IsNullOrWhiteSpace(safeIconColor))
							{
								metaLabelIconEl.Attributes.Add("style", $"color:{safeIconColor};");
							}
							metaLabelIconWrapperEl.InnerHtml.AppendHtml(metaLabelIconEl);
							metaWrapperEl.InnerHtml.AppendHtml(metaLabelIconWrapperEl);
						}
						#endregion

						#region << Meta > Meta-title >>
						if (!String.IsNullOrWhiteSpace(AreaLabel) ||
							PageSwitchItems.Count > 1 || !String.IsNullOrWhiteSpace(Title) || !String.IsNullOrWhiteSpace(SubTitle))
						{
							var metaTitleEl = new TagBuilder("div");
							metaTitleEl.AddCssClass("meta-title");

							#region << Meta > Meta-title > Label AUX >>
							if (!String.IsNullOrWhiteSpace(AreaLabel))
							{
								var metaLabelAuxEl = new TagBuilder("div");
								metaLabelAuxEl.AddCssClass("meta-area");
								//SECURITY - finding F-06: the guarded colour, not the raw property.
								if (!String.IsNullOrWhiteSpace(safeColor))
								{
									metaLabelAuxEl.Attributes.Add("style", $"color:{safeColor};");
								}
								var metaLabelAuxTextEl = new TagBuilder("span");
								metaLabelAuxTextEl.AddCssClass("text");
								// SECURITY (CWE-79, OWASP A03:2021 - stored cross-site scripting): every one of the
								// value-bearing sinks in this tag helper is a TEXT channel, and AppendHtml writes its
								// argument to the response without encoding it. The values arrive from the database -
								// an entity name, a page label, an application label, a data-source name, a field
								// label - so a stored "<script>" reached the browser intact and executed in the
								// authenticated origin of whoever opened the record. Append is the encoding
								// counterpart of AppendHtml, so switching to it is both the minimal fix and the
								// complete one: no helper is added and no caller changes.
								// A census of all 50 views that bind this tag helper confirms not one of them passes
								// markup into area-label, area-sublabel, title or subtitle, so encoding them cannot
								// change what a legitimate value renders as. The one genuine markup channel is
								// Description - see the comment at its sink further down.
								metaLabelAuxTextEl.InnerHtml.Append(AreaLabel);
								metaLabelAuxEl.InnerHtml.AppendHtml(metaLabelAuxTextEl);
								if (!String.IsNullOrWhiteSpace(AreaSubLabel))
								{
									var metaSubLabelDividerAuxTextEl = new TagBuilder("span");
									metaSubLabelDividerAuxTextEl.AddCssClass("divider");
									metaSubLabelDividerAuxTextEl.InnerHtml.AppendHtml("/");
									metaLabelAuxEl.InnerHtml.AppendHtml(metaSubLabelDividerAuxTextEl);

									var metaSubLabelAuxTextEl = new TagBuilder("span");
									metaSubLabelAuxTextEl.AddCssClass("text");
									//SECURITY - CWE-79: text channel, encoded. See the AreaLabel sink above.
									metaSubLabelAuxTextEl.InnerHtml.Append(AreaSubLabel);
									metaLabelAuxEl.InnerHtml.AppendHtml(metaSubLabelAuxTextEl);
								}
								metaTitleEl.InnerHtml.AppendHtml(metaLabelAuxEl);
							}
							#endregion

							#region << Meta > Meta title > Label >>
							if (PageSwitchItems.Count > 1 || !String.IsNullOrWhiteSpace(Title) || !String.IsNullOrWhiteSpace(SubTitle))
							{
								var metaLabelEl = new TagBuilder("div");
								metaLabelEl.AddCssClass("meta-label");


								var metaLabelTextEl = new TagBuilder("span");
								metaLabelTextEl.AddCssClass("text");

								if (PageSwitchItems.Count > 1)
								{
									//If only the current page there is no switch needed
									var switchDropdownEl = new TagBuilder("div");
									switchDropdownEl.AddCssClass("dropdown");
									switchDropdownEl.AddCssClass("d-inline-block");

									//link
									var metaSubLabelTextEl = new TagBuilder("a");
									metaSubLabelTextEl.AddCssClass("page-switch");
									//metaSubLabelTextEl.AddCssClass("dropdown-toggle");
									metaSubLabelTextEl.Attributes.Add("data-toggle", "dropdown");
									metaSubLabelTextEl.Attributes.Add("href", "#");
									//metaSubLabelTextEl.InnerHtml.AppendHtml("switch");
									//SECURITY - CWE-79: the icon is a compile-time literal and stays raw, but Title is
									//database text and is appended separately so that it is encoded. Concatenating the
									//two before the call is what previously forced the whole string through the raw
									//path; splitting the call is the smallest change that keeps the icon and encodes
									//the value.
									metaSubLabelTextEl.InnerHtml.AppendHtml("<i class='icon fas fa-ellipsis-v'></i>");
									metaSubLabelTextEl.InnerHtml.Append(Title);
									switchDropdownEl.InnerHtml.AppendHtml(metaSubLabelTextEl);

									//Dropdown
									var switchDDMenuEl = new TagBuilder("div");
									switchDDMenuEl.AddCssClass("dropdown-menu");
									foreach (var pageSwitchItem in PageSwitchItems)
									{
										var switchItemEl = new TagBuilder("a");
										switchItemEl.AddCssClass("dropdown-item pl-2 pr-2");
										if (pageSwitchItem.IsSelected)
											switchItemEl.InnerHtml.AppendHtml("<i class=\"fas fa-fw fa-angle-right\"></i>");
										else
											switchItemEl.InnerHtml.AppendHtml("<i class=\"fa fa-fw\"></i>");

										switchItemEl.Attributes.Add("href", pageSwitchItem.Url);
										//SECURITY - CWE-79: text channel, encoded. PcPageHeader fills this from
										//ErpPage.Label, so it is database text exactly like Title and SubTitle.
										switchItemEl.InnerHtml.Append(pageSwitchItem.Label);
										switchDDMenuEl.InnerHtml.AppendHtml(switchItemEl);
									}
									switchDropdownEl.InnerHtml.AppendHtml(switchDDMenuEl);
									metaLabelTextEl.InnerHtml.AppendHtml(switchDropdownEl);

									if (!String.IsNullOrWhiteSpace(SubTitle))
									{
										var divider = new TagBuilder("span");
										divider.AddCssClass("fa fa-angle-right divider");
										metaLabelTextEl.InnerHtml.AppendHtml(divider);

										var metaSubLabelTextEl2 = new TagBuilder("span");
										metaSubLabelTextEl2.AddCssClass("subtext");
										//SECURITY - CWE-79: text channel, encoded. See the AreaLabel sink above.
										metaSubLabelTextEl2.InnerHtml.Append(SubTitle);
										metaLabelTextEl.InnerHtml.AppendHtml(metaSubLabelTextEl2);
									}
								}
								else
								{
									//SECURITY - CWE-79: text channel, encoded. This is the sink the audit reproduced -
									//a data-source name reached it through data_source/details.cshtml and executed.
									metaLabelTextEl.InnerHtml.Append(Title);

									if (!String.IsNullOrWhiteSpace(SubTitle))
									{
										var divider = new TagBuilder("span");
										divider.AddCssClass("fa fa-angle-right divider");
										metaLabelTextEl.InnerHtml.AppendHtml(divider);

										var metaSubLabelTextEl = new TagBuilder("span");
										metaSubLabelTextEl.AddCssClass("subtext");
										//SECURITY - CWE-79: text channel, encoded. See the AreaLabel sink above.
										metaSubLabelTextEl.InnerHtml.Append(SubTitle);
										metaLabelTextEl.InnerHtml.AppendHtml(metaSubLabelTextEl);
									}
								}

								metaLabelEl.InnerHtml.AppendHtml(metaLabelTextEl);
								metaTitleEl.InnerHtml.AppendHtml(metaLabelEl);
							}
							#endregion

							metaWrapperEl.InnerHtml.AppendHtml(metaTitleEl);
						}
						#endregion

						upperWrapperEl.InnerHtml.AppendHtml(metaWrapperEl);
					#endregion

					#region << Upper >> Right Actions >>
					if (!String.IsNullOrWhiteSpace(actionsContentHtml))
					{
						var actionColEl = new TagBuilder("div");
						actionColEl.AddCssClass("actions right");
						actionColEl.InnerHtml.AppendHtml(actionsContentHtml);

						upperWrapperEl.InnerHtml.AppendHtml(actionColEl);
					}
					#endregion

					//<<< Upper
					output.Content.AppendHtml(upperWrapperEl);
				#endregion

				//Description
				/////////////////////////////////////
				//SECURITY - finding F-02: the description block is rendered when EITHER channel carries a
				//value. The trusted markup channel takes precedence, and the two are never concatenated -
				//see the sink below.
				if (!String.IsNullOrWhiteSpace(DescriptionHtml) || !String.IsNullOrWhiteSpace(Description) || !String.IsNullOrWhiteSpace(actionsAuxContentHtml))
				{
					var metaDescriptionWrapperEl = new TagBuilder("div");
					metaDescriptionWrapperEl.AddCssClass("description-wrapper");
					var metaDescriptionRowEl = new TagBuilder("div");
					metaDescriptionRowEl.AddCssClass("row m-0 no-gutters");

					var metaDescriptionLeftColumn = new TagBuilder("div");
					metaDescriptionLeftColumn.AddCssClass("col-md align-self-center");

					var metaDescriptionRightColumn = new TagBuilder("div");
					metaDescriptionRightColumn.AddCssClass("col-md-auto align-self-center");


					if (!String.IsNullOrWhiteSpace(DescriptionHtml) || !String.IsNullOrWhiteSpace(Description))
					{
						var metaDescriptionEl = new TagBuilder("div");
						metaDescriptionEl.AddCssClass("description");
						// THREAT ADDRESSED - review finding F-02 (CWE-79, OWASP A03:2021 - stored cross-site
						// scripting). There used to be ONE attribute here and it was rendered raw, justified by a
						// comment asserting that PageUtils.GenerateListPageDescription was its only non-literal
						// supplier. That assertion was wrong and is retracted: PcPageHeader resolves the value
						// through context.DataModel.GetPropertyValueByDataSource(instanceOptions.Description) and
						// both of its component views bind it, so arbitrary page and record data reached this raw
						// sink on a component that renders at the top of essentially every screen.
						// The fix separates the two things the one attribute was being asked to be. Ordinary text
						// arrives on "description" and is ENCODED, which is now the default any caller gets
						// without having to know anything - so the data-bound path is closed at the sink rather
						// than at each of its feeders. Application-composed markup arrives on
						// "description-html" and stays RAW, which is what keeps the five SDK list pages rendering
						// their inline sorted-by/filtered-by list instead of showing its tags as literal text.
						// The trusted channel WINS when both are supplied and the encoded text is then ignored
						// rather than appended, so no caller can produce a half-raw, half-encoded fragment; and
						// because the choice is made by which attribute the view binds, a future caller cannot
						// reach the raw path by accident.
						if (!String.IsNullOrWhiteSpace(DescriptionHtml))
						{
							metaDescriptionEl.InnerHtml.AppendHtml(DescriptionHtml);
						}
						else
						{
							metaDescriptionEl.InnerHtml.Append(Description);
						}
						metaDescriptionLeftColumn.InnerHtml.AppendHtml(metaDescriptionEl);
					}

					metaDescriptionRowEl.InnerHtml.AppendHtml(metaDescriptionLeftColumn);

					// Aux actions
					if (!String.IsNullOrWhiteSpace(actionsAuxContentHtml))
					{
						metaDescriptionRightColumn.InnerHtml.AppendHtml(actionsAuxContentHtml);
						metaDescriptionRowEl.InnerHtml.AppendHtml(metaDescriptionRightColumn);
					}

					metaDescriptionWrapperEl.InnerHtml.AppendHtml(metaDescriptionRowEl);
					output.Content.AppendHtml(metaDescriptionWrapperEl);
				}

				//Toolbar
				/////////////////////////////////////
				if (!String.IsNullOrWhiteSpace(toolbarContentHtml))
				{
					var wrapEl = new TagBuilder("div");
					wrapEl.AddCssClass("page-header-toolbar");
					wrapEl.InnerHtml.AppendHtml(toolbarContentHtml);
					output.Content.AppendHtml(wrapEl);
				}


				if (FixOnScroll)
				{

					#region << Init Scripts >>
					var tagHelperInitialized = false;
					var scriptFileName = "script.js";
					if (ViewContext.HttpContext.Items.ContainsKey(typeof(WvPageHeader) + scriptFileName))
					{
						var tagHelperContext = (WvTagHelperContext)ViewContext.HttpContext.Items[typeof(WvPageHeader) + scriptFileName];
						tagHelperInitialized = tagHelperContext.Initialized;
					}

					if (!tagHelperInitialized)
					{
						var scriptContent = FileService.GetEmbeddedTextResource("script.js", "WebVella.Erp.Web.TagHelpers.WvPageHeader");
						var scriptEl = new TagBuilder("script");
						scriptEl.Attributes.Add("type", "text/javascript");
						scriptEl.InnerHtml.AppendHtml(scriptContent);
						//scriptEl.InnerHtml.AppendHtml(scriptContent);
						output.PostContent.AppendHtml(scriptEl);

						ViewContext.HttpContext.Items[typeof(WvPageHeader) + scriptFileName] = new WvTagHelperContext()
						{
							Initialized = true
						};

					}

					#endregion

					#region << Add Inline Init Script for this instance >>
					var initScript = new TagBuilder("script");
					initScript.Attributes.Add("type", "text/javascript");
					var scriptTemplate = @"
						$(function(){
							WebVellaErpWebComponentsPcPageHeader_Init(""{{ElementId}}"");
						});";
					scriptTemplate = scriptTemplate.Replace("{{ElementId}}", elementId.ToString());
					initScript.InnerHtml.AppendHtml(scriptTemplate);

					output.PostContent.AppendHtml(initScript);
					#endregion
				}
			}
			//return Task.CompletedTask;
		}


	}
}
