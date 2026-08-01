using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Collections.Generic;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Exceptions;
using WebVella.Erp.Plugins.SDK.Utils;
using WebVella.Erp.Web;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Services;

namespace WebVella.Erp.Plugins.SDK.Pages.Page
{
	public class ManageModel : BaseErpPageModel
	{
		public ManageModel([FromServices]ErpRequestContext reqCtx) { ErpRequestContext = reqCtx; }

		public ErpPage ErpPage { get; set; }

		[BindProperty]
		public int Weight { get; set; } = 10;

		[BindProperty]
		public string Label { get; set; } = "";

		//[BindProperty]
		public List<TranslationResource> LabelTranslations { get; set; } = new List<TranslationResource>();

		[BindProperty]
		public string Name { get; set; } = "";

		[BindProperty]
		public string IconClass { get; set; } = "";

		[BindProperty]
		public string Description { get; set; } = "";

		[BindProperty]
		public string Color { get; set; } = "";

		[BindProperty]
		public Guid? EntityId { get; set; } = null;

		[BindProperty]
		public Guid? AppId { get; set; } = null;

		[BindProperty]
		public Guid? AreaId { get; set; } = null;

		[BindProperty]
		public Guid? NodeId { get; set; } = null;

		[BindProperty]
		public PageType Type { get; set; } = PageType.Application;

		public List<PageBodyNode> Body { get; set; } = null;

		[BindProperty]
		public string Layout { get; set; } = "";

		public List<string> HeaderToolbar { get; private set; } = new List<string>();

		private void InitPage()
		{
			#region << Init Page >>
			var pageServ = new PageService();
			ErpPage = pageServ.GetPage(RecordId ?? Guid.Empty);
			if (ErpPage != null && PageContext.HttpContext.Request.Method == "GET")
			{
				Weight = ErpPage.Weight;
				Label = ErpPage.Label;
				LabelTranslations = ErpPage.LabelTranslations;
				Name = ErpPage.Name;
				IconClass = ErpPage.IconClass;
				Body = ErpPage.Body;
				EntityId = ErpPage.EntityId;
				AppId = ErpPage.AppId;
				AreaId = ErpPage.AreaId;
				NodeId = ErpPage.NodeId;
				Type = ErpPage.Type;
				Layout = ErpPage.Layout;
			}
			// SECURITY (CWE-601 unvalidated redirect / CWE-79 cross-site scripting, OWASP
			// A01:2021 and A03:2021) - ReturnUrl is URL-decoded query-string input, and this page
			// consumes it twice: the view renders it as the Cancel link target and as the page
			// header's back-link, and OnPost passes it straight to Redirect() after a successful
			// save. Neither sink is protected by HTML encoding, because a browser decodes HTML
			// entities before it parses a URL scheme and Redirect() never encodes at all - so an
			// absolute or "javascript:" value would either execute on click or bounce an
			// authenticated operator to an attacker-controlled origin. Accept the value only when
			// it is a same-site relative URL. A rejected value is treated exactly as an absent
			// one, which is the behaviour this branch already implemented, so no legitimate
			// navigation changes: every returnUrl the platform generates comes from
			// PageUtils.GetCurrentUrl, which returns a path and query only and is therefore
			// always local. The null check on ErpPage is required because InitPage runs before
			// the caller's NotFound() guard; without it a rejected value on a non-existent record
			// would raise a null reference instead of the 404 the caller already returns.
			if (String.IsNullOrWhiteSpace(ReturnUrl) || !Url.IsLocalUrl(ReturnUrl))
			{
				ReturnUrl = ErpPage != null ? $"/sdk/objects/page/r/{ErpPage.Id}/" : String.Empty;
			}

			#endregion

			HeaderToolbar.AddRange(AdminPageUtils.GetPageAdminSubNav(ErpPage, "manage"));
		}

		public IActionResult OnGet()
		{
			var initResult = Init();
			if (initResult != null)
				return initResult;

			InitPage();

			if (ErpPage == null)
			{
				return NotFound();
			}

			ErpRequestContext.PageContext = PageContext;
			BeforeRender();
			return Page();
		}

		public IActionResult OnPost()
		{
			if (!ModelState.IsValid) throw new Exception("Antiforgery check failed.");

			var initResult = Init();
			if (initResult != null)
				return initResult;

			InitPage();

			if (ErpPage == null)
			{
				return NotFound();
			}

			var pageServ = new PageService();
			try
			{
				pageServ.UpdatePage(ErpPage.Id, Name, Label, LabelTranslations, IconClass, ErpPage.System, Weight, Type,
					AppId, EntityId, NodeId, AreaId, ErpPage.IsRazorBody, ErpPage.RazorBody, Layout);

				if (!String.IsNullOrWhiteSpace(ReturnUrl))
				{
					// SECURITY - finding H-1, CWE-601 open redirect, OWASP A01.
					// THREAT: Redirect() honours any absolute or protocol-relative URL, so a crafted
					// returnUrl carried the user to an attacker's site immediately after a successful save
					// - a convincing phishing hand-off, because the journey began on this application.
					// LocalRedirect refuses a non-local URL outright. BaseErpPageModel.ReturnUrl already
					// guarantees locality at the point of assignment, so this is the second, independent
					// layer: were that guarantee ever weakened, this call fails closed instead of
					// redirecting off-site.
					return LocalRedirect(ReturnUrl);
				}
				else
				{
					return Redirect($"/sdk/objects/page/r/{ErpPage.Id}/");
				}
			}
			catch (ValidationException ex)
			{
				Validation.Message = ex.Message;
				Validation.Errors = ex.Errors;
			}

			ErpRequestContext.PageContext = PageContext;

			BeforeRender();
			return Page();
		}
	}
}