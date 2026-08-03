using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using WebVella.Erp.Hooks;
using WebVella.Erp.Web.Hooks;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Services;

namespace WebVella.Erp.Web.Pages
{
	public class LogoutModel : BaseErpPageModel
	{
		public LogoutModel([FromServices]ErpRequestContext reqCtx) { ErpRequestContext = reqCtx; }

		// THREAT ADDRESSED - finding F8 (session hijacking), CWE-613 (insufficient session expiration),
		// OWASP A07: this handler called a void AuthService.Logout(), which started SignOutAsync and
		// never awaited it. Two consequences, and both are security ones rather than style ones. The
		// redirect could be written and the request completed while the sign-out was still in flight, so
		// whether the cookie was actually cleared depended on a race; and any failure inside it was lost
		// on an unobserved task, so a sign-out could fail completely and silently while the user was
		// shown the logged-out page. The handler is therefore asynchronous and the sign-out is awaited,
		// which also makes the server-side session revocation inside LogoutAsync ordered before the
		// response - the revocation is the part that stops a COPIED ticket, so it must have happened
		// before this request ends.
		//
		// The Async name suffix is the Razor Pages handler convention, and both spellings are discovered
		// for the same GET/POST, so the route and the form action are unchanged.
		public async Task<IActionResult> OnGetAsync([FromServices]AuthService authService)
        {
			var initResult = Init();
			if (initResult != null) return initResult;
			await authService.LogoutAsync();

			var globalHookInstances = HookManager.GetHookedInstances<IPageHook>(HookKey);
			foreach (IPageHook inst in globalHookInstances)
			{
				var result = inst.OnGet(this);
				if (result != null) return result;
			}

			var hookInstances = HookManager.GetHookedInstances<ILogoutPageHook>(HookKey);
			foreach (ILogoutPageHook inst in hookInstances)
			{
				var result = inst.OnGet(this);
				if (result != null) return result;
			}

			return new LocalRedirectResult("/");
		}

		// THREAT ADDRESSED - finding F8 (session hijacking), CWE-613 (insufficient session expiration),
		// OWASP A07: this handler called a void AuthService.Logout(), which started SignOutAsync and
		// never awaited it. Two consequences, and both are security ones rather than style ones. The
		// redirect could be written and the request completed while the sign-out was still in flight, so
		// whether the cookie was actually cleared depended on a race; and any failure inside it was lost
		// on an unobserved task, so a sign-out could fail completely and silently while the user was
		// shown the logged-out page. The handler is therefore asynchronous and the sign-out is awaited,
		// which also makes the server-side session revocation inside LogoutAsync ordered before the
		// response - the revocation is the part that stops a COPIED ticket, so it must have happened
		// before this request ends.
		//
		// The Async name suffix is the Razor Pages handler convention, and both spellings are discovered
		// for the same GET/POST, so the route and the form action are unchanged.
		public async Task<IActionResult> OnPostAsync([FromServices]AuthService authService)
		{
			var initResult = Init();
			if (initResult != null) return initResult;
			await authService.LogoutAsync();

			var globalHookInstances = HookManager.GetHookedInstances<IPageHook>(HookKey);
			foreach (IPageHook inst in globalHookInstances)
			{
				var result = inst.OnPost(this);
				if (result != null) return result;
			}

			var hookInstances = HookManager.GetHookedInstances<ILogoutPageHook>(HookKey);
			foreach (ILogoutPageHook inst in hookInstances)
			{
				var result = inst.OnPost(this);
				if (result != null) return result;
			}

			return new LocalRedirectResult("/");
		}
	}
}