using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Collections.Generic;
using WebVella.Erp.Exceptions;
using WebVella.Erp.Plugins.SDK.Utils;
using WebVella.Erp.Web;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Services;

namespace WebVella.Erp.Plugins.SDK.Pages.Page
{
	public class ManageCustomModel : BaseErpPageModel
	{
		public ManageCustomModel([FromServices]ErpRequestContext reqCtx) { ErpRequestContext = reqCtx; }

		public ErpPage ErpPage { get; set; }

		[BindProperty]
		public bool IsRazorBody { get; set; } = false;

		[BindProperty]
		public string RazorBody { get; set; } = "";

		public List<string> HeaderToolbar { get; private set; } = new List<string>();

		private void InitPage()
		{
			#region << Init Page >>
			var pageServ = new PageService();
			ErpPage = pageServ.GetPage(RecordId ?? Guid.Empty);
			if (ErpPage != null && PageContext.HttpContext.Request.Method == "GET")
			{
				IsRazorBody = ErpPage.IsRazorBody;
				RazorBody = ErpPage.RazorBody;
			}

			// SECURITY (CWE-601 unvalidated redirect / CWE-79 cross-site scripting, OWASP
			// A01:2021 and A03:2021) - ReturnUrl is URL-decoded query-string input, and this page
			// consumes it twice: the view renders it as the Cancel link target and as the page
			// header's back-link, and OnPost passes it straight to Redirect() after a successful
			// save. Neither sink is protected by HTML encoding, because a browser decodes HTML
			// entities before it parses a URL scheme and Redirect() never encodes at all - so an
			// absolute or "javascript:" value would either execute on click or bounce an
			// authenticated operator to an attacker-controlled origin. Accept the value only when
			// it is a same-site relative URL. Clearing a rejected value makes it behave exactly
			// like an absent one, so OnPost falls through to the fixed record redirect it already
			// used in that case and the view renders the same empty target - no legitimate
			// navigation changes, because every returnUrl the platform generates comes from
			// PageUtils.GetCurrentUrl, which returns a path and query only and is always local.
			if (!String.IsNullOrWhiteSpace(ReturnUrl) && !Url.IsLocalUrl(ReturnUrl))
			{
				ReturnUrl = String.Empty;
			}

			#endregion

			HeaderToolbar.AddRange(AdminPageUtils.GetPageAdminSubNav(ErpPage, "manage-custom"));
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
				pageServ.UpdatePage(ErpPage.Id, ErpPage.Name, ErpPage.Label, ErpPage.LabelTranslations, ErpPage.IconClass, ErpPage.System, ErpPage.Weight, ErpPage.Type, ErpPage.AppId, ErpPage.EntityId, ErpPage.NodeId, ErpPage.AreaId, IsRazorBody, RazorBody, ErpPage.Layout);
				if (!String.IsNullOrWhiteSpace(ReturnUrl))
				{
					// SECURITY - finding H-1, CWE-601 open redirect, OWASP A01. Redirect() would honour an
					// absolute or protocol-relative returnUrl and hand the user to an attacker's site right
					// after a successful save. LocalRedirect refuses a non-local URL. Locality is already
					// guaranteed by BaseErpPageModel.ReturnUrl; this is the independent second layer.
					return LocalRedirect(ReturnUrl);
				}
				else
				{
					// Review finding M-03. This handler saves a PAGE, and ErpPage.Id is a page identifier -
					// but the route it redirected to, "/sdk/objects/application/r/{RecordId}", is served by
					// Pages/application/details.cshtml, which resolves its RecordId as an APPLICATION. A page
					// identifier can never name an application, so a successful save always landed the user
					// on a record that does not exist: the save worked and the interface reported failure.
					// The correct target is the page details route below, which is exactly what the sibling
					// handler for the non-custom page body already returns - see manage.cshtml.cs. Only the
					// no-returnUrl branch is affected; the LocalRedirect branch above is unchanged.
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