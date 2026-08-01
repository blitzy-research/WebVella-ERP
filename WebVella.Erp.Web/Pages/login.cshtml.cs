using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Threading.Tasks;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Diagnostics;
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
				// Audited even though no credential was checked: a refusal is the signal that a lockout
				// threshold has actually been reached, which is the strongest brute-force indicator this
				// endpoint can emit. Recording it server-side leaks nothing to the caller - see the
				// deliberately generic response below.
				WriteAuthenticationAuditRecord(LogType.Error, "Authentication refused - account temporarily locked", remoteAddress);

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
			// The audit record is written from this same block, and for the same reason: it is the only
			// point on the request path that has seen the true outcome of the credential check and that
			// no hook can bypass. Exactly one record is written per evaluated attempt.
			if (user == null)
			{
				loginThrottle.RegisterFailedAttempt(Username, remoteAddress);
				WriteAuthenticationAuditRecord(LogType.Error, "Authentication failed", remoteAddress);
			}
			else
			{
				loginThrottle.RegisterSuccess(Username, remoteAddress);
				WriteAuthenticationAuditRecord(LogType.Info, "Authentication succeeded", remoteAddress);
			}

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

		// THREAT ADDRESSED - finding M-12, CWE-778 (Insufficient Logging), and the Authorization
		// Enforcement standard's "log authorization failures" clause: the platform recorded nothing
		// whatsoever about authentication outcomes. The only code that ever did is commented out at
		// Security/WebSecurityUtil.cs lines 40-85 and therefore unreachable (finding L-01, left in
		// place deliberately), so a credential-stuffing run against this form left no trace at all -
		// an operator could not distinguish an attack from ordinary traffic, and a later forensic
		// reader could not establish which account had been compromised or from where.
		//
		// THE SINK CHOICE IS LOAD-BEARING. This writes through the core WebVella.Erp.Diagnostics.Log
		// writer, which performs a parameterized INSERT into system_log and does nothing else. It must
		// NOT use WebVella.Erp.Web.Services.LogService: that wrapper calls MailService.SendLogMessage
		// BEFORE persisting whenever the notification status is NotNotified, so routing a per-attempt
		// audit record through it would turn this anonymous endpoint into an attacker-triggered mail
		// bomb and amplify finding M-17. LogNotificationStatus.DoNotNotify is consequently passed
		// EXPLICITLY rather than left to the parameter default of NotNotified, which would leave every
		// row eligible for that same notification path.
		private void WriteAuthenticationAuditRecord(LogType type, string message, string remoteAddress)
		{
			// An audit write must never be able to fail a login. This runs on the authentication happy
			// path, so without the guard a transient datastore fault during the INSERT would surface as
			// a total authentication outage - a functional regression introduced BY the remediation,
			// which the preservation requirements forbid.
			try
			{
				// The username is unvalidated input on an anonymous endpoint, so it is bounded here to
				// stop the audit trail itself becoming a storage-amplification vector. Only the
				// submitted identity and its source address are recorded: never the password, the
				// request body, headers, cookies or the antiforgery token. That keeps the trail useful
				// for attributing an attack without creating a fresh disclosure of its own.
				var auditedUsername = Username ?? string.Empty;
				if (auditedUsername.Length > 100)
				{
					auditedUsername = auditedUsername.Substring(0, 100);
				}

				// The source is a fixed literal, not a derived string, because Log.GetLogs filters on
				// source with ILIKE - a stable value is what makes this audit trail queryable in the
				// log viewer that already ships with the platform.
				new Log().Create(type, "LoginModel.OnPost", message,
					$"username: {auditedUsername}; ip: {remoteAddress ?? string.Empty}",
					LogNotificationStatus.DoNotNotify);
			}
			catch (Exception)
			{
				// Swallowed deliberately, following the exception handling already present in this file.
				// Rethrowing would hand an attacker a way to deny authentication to every user by
				// provoking the audit write rather than by attacking the credential check itself.
			}
		}


	}
}
/*
 * system actions: OnPost: success,error
 * custom actions: none
 */
