using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using WebVella.Erp.Hooks;
using WebVella.Erp.Web.Hooks;
using WebVella.Erp.Web.Models;
//SECURITY - review finding M-OPEN-02. Supplies the request-initiator judgement shared with the API surface.
using WebVella.Erp.Web.Security;
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
		//
		// THREAT ADDRESSED - review finding M-OPEN-02, CWE-352 cross-site request forgery, OWASP A01:2021.
		// This handler CHANGES STATE ON A GET - it ends the session - so any page anywhere could end a signed-in
		// user's session simply by referencing this address, as an image, a background fetch, or a link the user
		// was persuaded to follow. The authentication cookie's SameSite=Lax value does not prevent it: Lax is
		// specified to accompany top-level GET navigations, which is exactly the shape a forced sign-out takes.
		// A forced sign-out is a nuisance on its own; chained with a sign-in the attacker controls it becomes
		// the first half of a session-fixation sequence.
		// THE HANDLER IS NOT REMOVED AND THE ROUTE DOES NOT CHANGE, which the review's suggested "POST-only"
		// remedy would have required: the platform renders Logout as two ordinary links in
		// Components/UserNav/UserNav.Default.cshtml, so a POST-only sign-out would break the visible interface
		// and the preservation requirement forbids that. Instead the GET only MUTATES when the browser itself
		// reports the request as this origin's own top-level navigation - which is precisely what clicking
		// either link is. A cross-site or same-site-sibling initiator, and any non-navigational subresource
		// load, is answered with the same redirect and no state change at all, so an attacking page cannot
		// tell that anything was declined and gains nothing to probe.
		// The two signals are read through the one implementation the API surface uses, so the two cannot come
		// to disagree about who initiated a request. Nothing is audited on the declined path, deliberately: no
		// state changed, and writing a record for an unauthenticated caller's redirect would hand that caller
		// an unbounded log-growth primitive (CWE-779), which this codebase already refuses elsewhere.
		// The POST handler below keeps its antiforgery protection and is unchanged - it is the mechanism a
		// client that wants a guaranteed sign-out should use.
		public async Task<IActionResult> OnGetAsync([FromServices]AuthService authService)
        {
			var initResult = Init();
			if (initResult != null) return initResult;

			//M-OPEN-02: mutate only for this origin's own navigation. Ordered before the sign-out and before
			//the hooks, so a declined request performs none of them.
			if (RequireSameOriginRequestAttribute.IsBrowserReportedCrossSite(Request)
				|| !RequireSameOriginRequestAttribute.IsNavigation(Request))
			{
				return new LocalRedirectResult("/");
			}

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