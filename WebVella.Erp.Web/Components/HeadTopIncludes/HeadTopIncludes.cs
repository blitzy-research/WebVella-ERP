using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using WebVella.Erp.Web.Hooks;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Services;

namespace WebVella.Erp.Web.Components
{

	[RenderHookAttachment("head-top", 10)]
	public class HeadTopIncludes : ViewComponent
	{
		public async Task<IViewComponentResult> InvokeAsync(BaseErpPageModel pageModel)
		{
			ViewBag.MetaTags = new List<MetaTagInclude>();
			ViewBag.LinkTags = new List<LinkTagInclude>();
			ViewBag.ScriptTags = new List<ScriptTagInclude>();

			var cacheKey = new RenderService().GetCacheKey();

			#region == <title> ==
			var includedTitle = pageModel.HttpContext.Items.ContainsKey("<title>") ? (string)pageModel.HttpContext.Items["<title>"] : "";
			ViewBag.Title = "";
			if (string.IsNullOrWhiteSpace(includedTitle))
			{
				//THREAT ADDRESSED - finding H-06 (CWE-79 improper neutralization of input during web page generation,
				//OWASP A03:2021), raised against the delivered tree as F-129 / Q2. This line composed the <title> element
				//by string concatenation and Default.cshtml emits the finished string through Html.Raw, so whatever
				//ViewData["Title"] held reached the browser as MARKUP. The value carries ErpRequestContext.Page.Label -
				//stored, administrator-editable database text - on every page view in this folder, and Site.cshtml does so
				//for the public /s/{name} route, which made it a stored cross-site-scripting sink reachable by the
				//LOWEST-privileged authenticated role.
				//WHY <title> IS NOT SELF-PROTECTING, which is what let this survive the original census: the element is
				//RCDATA, so a bare <script> inside it really is inert - but a literal "</title>" TERMINATES the element and
				//returns the tokenizer to the normal markup state, after which the rest of the stored value is parsed as
				//ordinary HTML. A label of "</title><script>alert(1)</script>" therefore built a real <script> as a SIBLING
				//inside <head> and executed it DURING PARSE, on the application's own authenticated origin. Runtime-verified;
				//the report-only Content-Security-Policy observed that violation without blocking it. The identical stored
				//value was already inert at the remediated SiteMenu sink in the SAME response, which is what identified this
				//as a scope gap in H-06 rather than a new defect.
				//The census that classified the 128 raw-output sites read .cshtml files for Html.Raw arguments; it could not
				//see that THIS argument is assembled here, in C#, from a database value, so the sink was recorded as
				//server-generated markup. RISK-170 carries the correction.
				//The fix is the smallest one that closes it (Minimal Change guideline 7): encode the value, not the tag, at
				//the single point of composition - one writer here and one reader in Default.cshtml, so no other emission
				//path needs touching, and the value cached in HttpContext.Items is safe for every later reader. The Html.Raw
				//in Default.cshtml is deliberately left alone because that same call also emits the <meta>, <link> and
				//<script> tags PageUtils builds - encoding there would break page head rendering outright.
				//WHY THIS ENCODER: HtmlEncoder.Default is the encoder Razor's own automatic encoding uses and the one
				//BaseErpPageModel.EncodeMenuText already applies to the menu half of this same value, so the fix matches an
				//in-repository precedent. Because RCDATA decodes character references the browser renders the identical
				//characters - a legitimate title, Unicode and apostrophes included, is unchanged on screen and in
				//document.title - which is what preserves user-facing behaviour, while "</title>" can no longer exit the
				//element.
				//The null coalesce reproduces the previous behaviour exactly - string concatenation rendered a null value as
				//empty, so a route that sets no title still emits <title></title> - and it is also required, because
				//ViewData["Title"] is an object and Encode throws on a null argument.
				var titleText = pageModel.PageContext.ViewData["Title"]?.ToString() ?? "";
				var titleTag = "<title>" + HtmlEncoder.Default.Encode(titleText) + "</title>";
				ViewBag.Title = titleTag;
				pageModel.HttpContext.Items["<title>"] = titleTag;
			}
			#endregion

			#region === <meta> ===
			{
				var includedMetaTags = pageModel.HttpContext.Items.ContainsKey(typeof(List<MetaTagInclude>)) ? (List<MetaTagInclude>)pageModel.HttpContext.Items[typeof(List<MetaTagInclude>)] : new List<MetaTagInclude>();
				var metaTagsToInclude = new List<MetaTagInclude>();
				//Your includes below >>>>

				#region << viewport >>
				{
					var tagName = "viewport";
					if (!includedMetaTags.Any(x => x.Name == tagName))
					{
						metaTagsToInclude.Add(new MetaTagInclude()
						{
							Name = tagName,
							Content = "width=device-width, initial-scale=1, shrink-to-fit=no"
						});
					}
				}
				#endregion

				#region << charset >>
				{
					var tagName = "charset";
					if (!includedMetaTags.Any(x => x.Name == tagName))
					{
						metaTagsToInclude.Add(new MetaTagInclude()
						{
							Charset = "utf-8"
						});
					}
				}
				#endregion

				//<<<< Your includes up
				includedMetaTags.AddRange(metaTagsToInclude);
				pageModel.HttpContext.Items[typeof(List<MetaTagInclude>)] = includedMetaTags;
				ViewBag.MetaTags = metaTagsToInclude;
			}
			#endregion


			#region === <link> ===
			{
				var includedLinkTags = pageModel.HttpContext.Items.ContainsKey(typeof(List<LinkTagInclude>)) ? (List<LinkTagInclude>)pageModel.HttpContext.Items[typeof(List<LinkTagInclude>)] : new List<LinkTagInclude>();
				var linkTagsToInclude = new List<LinkTagInclude>();
				
				//Your includes below >>>>

				#region << favicon >>
				{
					if (!includedLinkTags.Any(x => x.Href.Contains("favicon")))
					{
						linkTagsToInclude.Add(new LinkTagInclude()
						{
							Href = $"/_content/WebVella.Erp.Web/assets/favicon.png",
							Rel = RelType.Icon,
							Type = "image/png"
						});
					}
				}
				#endregion

				//#region << framework >>
				//{
				//	//Always include
				//	linkTagsToInclude.Add(new LinkTagInclude()
				//	{
				//		Href = "/api/v3.0/p/core/framework.css",
				//		CacheBreaker = pageModel.ErpAppContext.StyleFrameworkHash,
				//		CrossOrigin = CrossOriginType.Anonymous,
				//		Integrity = $"sha256-{pageModel.ErpAppContext.StyleFrameworkHash}"
				//	});
				//}
				//#endregion

				//#region << bootstrap.css >>
				//{
				//	if (!includedLinkTags.Any(x => x.Href.Contains("/bootstrap.css")))
				//	{
				//		linkTagsToInclude.Add(new LinkTagInclude()
				//		{
				//			Href = "/_content/WebVella.Erp.Web/lib/twitter-bootstrap/css/bootstrap.css?cb=" + cacheKey
				//		});
				//	}
				//}
				//#endregion

				//#region << flatpickr >>
				//{
				//	if (!includedLinkTags.Any(x => x.Href.Contains("/flatpickr")))
				//	{
				//		linkTagsToInclude.Add(new LinkTagInclude()
				//		{
				//			Href = "/_content/WebVella.Erp.Web/lib/flatpickr/flatpickr.min.css?cb=" + cacheKey
				//		});
				//	}
				//}
				//#endregion

				//#region << select2 >>
				//{
				//	if (!includedLinkTags.Any(x => x.Href.Contains("/select2")))
				//	{
				//		linkTagsToInclude.Add(new LinkTagInclude()
				//		{
				//			Href = "/_content/WebVella.Erp.Web/lib/select2/css/select2.min.css?cb=" + cacheKey
				//		});
				//	}
				//}
				//#endregion

				//#region << font-awesome >>
				//{
				//	if (!includedLinkTags.Any(x => x.Href.Contains("/font-awesome")))
				//	{
				//		linkTagsToInclude.Add(new LinkTagInclude()
				//		{
				//			Href = "/_content/WebVella.Erp.Web/css/font-awesome-5.10.2/css/all.min.css?cb=" + cacheKey
				//		});
				//	}
				//}
				//#endregion

				//#region << toastr >>
				//{
				//	if (!includedLinkTags.Any(x => x.Href.Contains("/toastr")))
				//	{
				//		linkTagsToInclude.Add(new LinkTagInclude()
				//		{
				//			Href = "/_content/WebVella.Erp.Web/lib/toastr.js/toastr.min.css?cb=" + cacheKey
				//		});
				//	}
				//}
				//#endregion

				//#region << colorpicker >>
				//{
				//	if (!includedLinkTags.Any(x => x.Href.Contains("/colorpicker")))
				//	{
				//		linkTagsToInclude.Add(new LinkTagInclude()
				//		{
				//			Href = "/_content/WebVella.Erp.Web/lib/spectrum/spectrum.min.css?cb=" + cacheKey
				//		});
				//	}
				//}
				//#endregion

				//<<<< Your includes up

				includedLinkTags.AddRange(linkTagsToInclude);
				pageModel.HttpContext.Items[typeof(List<LinkTagInclude>)] = includedLinkTags;
				ViewBag.LinkTags = linkTagsToInclude;
			}
			#endregion

			#region === <script> ===
			{
				var includedScriptTags = pageModel.HttpContext.Items.ContainsKey(typeof(List<ScriptTagInclude>)) ? (List<ScriptTagInclude>)pageModel.HttpContext.Items[typeof(List<ScriptTagInclude>)] : new List<ScriptTagInclude>();
				var scriptTagsToInclude = new List<ScriptTagInclude>();

				//Your includes below >>>>


				//<<<< Your includes up
				includedScriptTags.AddRange(scriptTagsToInclude);
				pageModel.HttpContext.Items[typeof(List<ScriptTagInclude>)] = includedScriptTags;
				ViewBag.ScriptTags = scriptTagsToInclude;
			}
			#endregion

			return await Task.FromResult<IViewComponentResult>(View("Default"));
		}
	}
}
