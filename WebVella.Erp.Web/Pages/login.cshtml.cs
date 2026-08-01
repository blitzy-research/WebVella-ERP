using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Hooks;
using WebVella.Erp.Web.Hooks;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Services;

namespace WebVella.Erp.Web.Pages
{
	[AllowAnonymous]
	public class LoginModel : BaseErpPageModel
	{
		[BindProperty]
		public string Username { get; set; }

		[BindProperty]
		public string Password { get; set; }

		// SECURITY (CWE-601 open redirect / CWE-79 javascript: URI): this page previously declared its own
		// shadowing "public new string ReturnUrl { get; set; }" carrying [BindProperty(Name = "returnUrl")].
		// Because model binding targets the most-derived declaration, the raw query value was bound into that
		// shadowing property and the validating setter on BaseErpPageModel.ReturnUrl was never executed. Both
		// LocalRedirectResult sinks below then received an unvalidated value, which made a crafted returnUrl
		// (for example "//attacker.example/path") turn a *successful* sign-in into an unhandled
		// InvalidOperationException - a 500 carrying a stack trace to an entirely anonymous caller.
		// The declaration is removed rather than re-annotated so that exactly one validating definition of
		// this property exists in the type hierarchy. The inherited base declaration is a strict superset of
		// what was here: it binds the same "returnUrl" name and additionally sets SupportsGet, so OnGet now
		// receives the value it was always written to expect.

		[BindProperty]
		public string Error { get; set; }

		public string BrandLogo { get; set; }

		public LoginModel([FromServices] ErpRequestContext reqCtx) { ErpRequestContext = reqCtx; }

		public IActionResult OnGet([FromServices] AuthService authService)
		{
			var initResult = Init();
			if (initResult != null) return initResult;
			var globalHookInstances = HookManager.GetHookedInstances<IPageHook>(HookKey);
			foreach (IPageHook inst in globalHookInstances)
			{
				var result = inst.OnGet(this);
				if (result != null) return result;
			}

			if (CurrentUser != null)
			{
				if (!string.IsNullOrWhiteSpace(ReturnUrl))
					return new LocalRedirectResult(ReturnUrl);
				else
					return new LocalRedirectResult("/");
			}

			var appContext = ErpAppContext.Current;
			var currentApp = ErpRequestContext.App;
			var theme = appContext.Theme;
			BrandLogo = theme.BrandLogo;
			if (!String.IsNullOrWhiteSpace(ErpSettings.NavLogoUrl))
			{
				BrandLogo = ErpSettings.NavLogoUrl;
			}
			BeforeRender();
			return Page();
		}

		// M-03 (OWASP A07): AuthService.Authenticate now awaits SignInAsync instead of discarding its Task - a discarded
		// sign-in raced the response, so the authentication cookie could be missing from it and any sign-in exception went
		// unobserved. Awaiting propagates here, to the platform's only login entry point; the handler name is unchanged, so
		// Razor Pages still binds this method to POST and the request/response contract is untouched.
		public async Task<IActionResult> OnPost([FromServices] AuthService authService, [FromServices] LoginThrottleService loginThrottle)
		{
			if (!ModelState.IsValid) throw new Exception("Antiforgery check failed.");

			var initResult = Init();
			if (initResult != null) return initResult;

			var globalHookInstances = HookManager.GetHookedInstances<IPageHook>(HookKey);
			foreach (IPageHook inst in globalHookInstances)
			{
				var result = inst.OnPost(this);
				if (result != null) return result;
			}

			var hookInstances = HookManager.GetHookedInstances<ILoginPageHook>(HookKey);
			try
			{
				foreach (ILoginPageHook inst in hookInstances)
				{
					var result = inst.OnPostPreLogin(this);
					if (result != null) return result;
				}
			}
			catch (Exception ex)
			{
				Error = ex.Message;
				BeforeRender();
				return Page();
			}

			// THREAT ADDRESSED - finding H-16, CWE-307 (Improper Restriction of Excessive Authentication
			// Attempts), OWASP A07: this line was reachable an unlimited number of times, so the login form
			// was an open credential-stuffing and brute-force oracle. The throttle is consulted here rather
			// than earlier so that the pre-login hooks above, which may short-circuit the request entirely,
			// cannot consume an account's attempt budget.
			//
			// The refusal message is byte-identical to the invalid-credential message below, deliberately.
			// Announcing "account locked" would turn this fix into a username-enumeration oracle - an
			// attacker could distinguish real accounts from fabricated ones by which of them can be locked -
			// and would also confirm to an attacker that their spraying is being counted.
			var remoteAddress = HttpContext?.Connection?.RemoteIpAddress?.ToString();
			if (!loginThrottle.TryBeginAttempt(Username, remoteAddress))
			{
				Error = "Invalid username or password";
				BeforeRender();
				return Page();
			}

			// The reserved attempt MUST be finalised on every path out of the credential check, or the
			// reservation counts against the principal until the window expires. try/catch/finally is
			// therefore not optional here: an exception from the datastore has to release the reservation
			// without recording a failure, so that an outage cannot lock out the entire user base.
			ErpUser user;
			try
			{
				user = await authService.Authenticate(Username, Password);
			}
			catch
			{
				loginThrottle.AbandonAttempt(Username, remoteAddress);
				throw;
			}

			// The outcome is judged from the credential check alone, before the post-login hooks below run,
			// so that a hook returning a short-circuit result can neither swallow a failed attempt nor
			// fabricate a successful one.
			if (user == null)
				loginThrottle.RegisterFailedAttempt(Username, remoteAddress);
			else
				loginThrottle.RegisterSuccess(Username, remoteAddress);

			foreach (ILoginPageHook inst in hookInstances)
			{
				var result = inst.OnPostAfterLogin(user, this);
				if (result != null) return result;
			}

			if (user == null)
			{
				Error = "Invalid username or password";
				BeforeRender();
				return Page();
			}

			if (!string.IsNullOrWhiteSpace(ReturnUrl))
				return new LocalRedirectResult(ReturnUrl);
			else
				return new LocalRedirectResult("/");

		}


	}
}
/*
 * system actions: OnPost: success,error
 * custom actions: none
 */
