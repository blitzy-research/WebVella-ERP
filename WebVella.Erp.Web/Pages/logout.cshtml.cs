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
		//
		// THREAT ADDRESSED - review finding OBS-06, CWE-778 (insufficient logging), OWASP A09:2021, and the
		// user-specified Authentication Hardening standard's "proper logout with session invalidation" clause.
		// This handler recorded no audit event for the sign-out it performs, so nothing in the trail
		// distinguished "the user ended their session" from "the user stopped making requests" - and a later
		// replay of a credential copied before the sign-out therefore had no event to be correlated against.
		// The record is written inside AuthService.LogoutAsync rather than here, DELIBERATELY: that method is
		// the single implementation of "end this session" and is shared by this handler, OnPostAsync below and
		// the bearer revocation route, so one edit gives all three the identical event and the three cannot
		// drift apart. It carries the acting principal, never the ticket or the session identifier, and it is
		// written only on the live-to-revoked transition so a repeated logout cannot grow the log (CWE-779).
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
		//
		// THREAT ADDRESSED - review finding OBS-06, CWE-778, OWASP A09:2021. Identical to OnGetAsync above and
		// audited by the same single implementation inside AuthService.LogoutAsync, which is why neither handler
		// writes a record of its own: two call-site writes for one event is how the two sign-out paths would
		// come to report it differently.
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