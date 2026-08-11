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
// SECURITY (CWE-117 log injection, CWE-778 insufficient logging): SecurityAuditLog is the single
// neutralisation-and-writing boundary this page shares with the file-authorization check and the
// anonymous token routes, so escaping, the catch list and lost-write accounting have one implementation.
using WebVella.Erp.Web.Utils;

namespace WebVella.Erp.Web.Pages
{
	[AllowAnonymous]
	public class LoginModel : BaseErpPageModel
	{
		[BindProperty]
		public string Username { get; set; }

		[BindProperty]
		public string Password { get; set; }

		// SECURITY (CWE-601 open redirect / CWE-79 javascript: URI): no ReturnUrl declaration may shadow
		// BaseErpPageModel.ReturnUrl - its validating setter is what keeps both LocalRedirectResult sinks
		// below from receiving a raw query value. The inherited property also sets SupportsGet, so OnGet binds.

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

		// M-03 (OWASP A07): the handler is async because AuthService.Authenticate awaits SignInAsync rather
		// than discarding its Task. Razor Pages still binds this name to POST, so the contract is unchanged.
		public async Task<IActionResult> OnPost([FromServices] AuthService authService, [FromServices] LoginThrottleService loginThrottle)
		{
			// Read before any branch can leave this handler: every exit path below has to be able to attribute
			// its audit outcome to a source address, including the branches that exit before the throttle.
			var remoteAddress = HttpContext?.Connection?.RemoteIpAddress?.ToString();

			// An invalid model state is an authentication ATTEMPT that was refused, so the trail records an
			// outcome for it - "exactly one outcome per attempt" has to hold from the handler's first branch.
			// It is NOT the antiforgery gate: a missing or invalid token is refused with HTTP 400 by
			// AutoValidateAntiforgeryTokenAuthorizationFilter before this handler is entered, so that refusal is
			// unaudited and is carried in docs/security/risk-register.md. The throw is shipped behaviour, retained.
			if (!ModelState.IsValid)
			{
				WriteAuthenticationAuditRecord(LogType.Error, "Authentication attempt rejected - request model validation failed", remoteAddress);
				throw new Exception("Antiforgery check failed.");
			}

			// Deliberately NOT audited: a non-null Init result means the login PAGE did not resolve, so no
			// credential submission was processed and there is no authentication outcome. Auditing it would put
			// routing failures into the authentication trail, where a reader counting attempts would over-count.
			var initResult = Init();
			if (initResult != null) return initResult;

			var globalHookInstances = HookManager.GetHookedInstances<IPageHook>(HookKey);
			foreach (IPageHook inst in globalHookInstances)
			{
				var result = inst.OnPost(this);
				if (result != null)
				{
					// A page hook that short-circuits the request ends an authentication attempt without the credential
					// ever being evaluated, and that is an outcome: unrecorded, a plugin could make attempts disappear
					// from the trail. The message names the hook stage so a reader can tell it from a credential decision.
					WriteAuthenticationAuditRecord(LogType.Info, "Authentication attempt ended by a page hook before the credential was evaluated", remoteAddress);
					return result;
				}
			}

			var hookInstances = HookManager.GetHookedInstances<ILoginPageHook>(HookKey);
			try
			{
				foreach (ILoginPageHook inst in hookInstances)
				{
					var result = inst.OnPostPreLogin(this);
					if (result != null)
					{
						// Same requirement as the page-hook branch: this is the hook contract's own documented way to
						// short-circuit a login, so it is an expected outcome - hence Info - but still an attempt that ended.
						WriteAuthenticationAuditRecord(LogType.Info, "Authentication attempt ended by a pre-login hook before the credential was evaluated", remoteAddress);
						return result;
					}
				}
			}
			catch (Exception ex)
			{
				// SECURITY (CWE-209 / CWE-497, OWASP A05): a hook fault's text must never reach this page's error
				// banner - the page is [AllowAnonymous] and hooks run with full platform access, so their messages
				// routinely carry connection strings, SQL fragments, paths and configuration keys. Nothing legitimate
				// is lost: the hook contract's channel for showing a message is to RETURN an IActionResult, which the
				// loop above honours. The detail changes AUDIENCE - RecordApiFault persists it server-side, is rate
				// limited per source, passes DoNotNotify so it can never reach finding M-17's mail path, and cannot
				// itself throw, which matters inside a catch. The source is a fixed literal because GetLogs uses ILIKE.
				SecurityAuditLog.RecordApiFault("LoginModel.OnPostPreLogin", ex);

				// The fault record above is a DIAGNOSTIC, not an authentication outcome: it is written under a
				// different source, is rate limited per source, and carries the exception rather than the attempt.
				// The outcome row is written as well as the fault, not instead of it, so a hook that faults on every
				// post shows as N refused attempts. It carries no exception text, for the reason stated above.
				WriteAuthenticationAuditRecord(LogType.Error, "Authentication attempt failed - a pre-login hook raised a fault", remoteAddress);

				// Byte-identical to the two other refusal messages on this handler, deliberately: a distinct string
				// would let an unauthenticated caller tell "a hook faulted" from "those credentials are wrong" - an
				// oracle for probing plugin behaviour and, where hooks fault only for real accounts, for enumeration.
				Error = "Invalid username or password";
				BeforeRender();
				return Page();
			}

			// THREAT ADDRESSED - finding H-16, CWE-307 (improper restriction of excessive authentication
			// attempts), OWASP A07: unthrottled, this line is reachable an unlimited number of times and the form
			// is an open credential-stuffing oracle. Consulted after the pre-login hooks so a hook that
			// short-circuits the request cannot consume an account's attempt budget. The refusal message is
			// byte-identical to the invalid-credential message below, so it is not a username-enumeration oracle.
			if (!loginThrottle.TryBeginAttempt(Username, remoteAddress))
			{
				// Audited even though no credential was checked: a refusal is the signal that a lockout threshold was
				// actually reached, the strongest brute-force indicator this endpoint can emit, and recording it
				// server-side leaks nothing to the caller. EXACTLY ONE ROW PER REFUSAL - no sampling, because a trail
				// whose cardinality does not match the attempt cardinality cannot reconstruct an attack. Volume is
				// bounded where it costs no evidence: the global fixed-window limiter in ErpMvcExtensions caps a
				// source at 600 permits per minute, and each row is bounded by MaxAuditedFieldLength.
				WriteAuthenticationAuditRecord(LogType.Error, "Authentication refused - account temporarily locked", remoteAddress);

				Error = "Invalid username or password";
				BeforeRender();
				return Page();
			}

			// The reserved attempt MUST be finalised on every path out of the credential check, or the
			// reservation counts against the principal until the window expires. The catch below releases it
			// WITHOUT recording a failure, so a datastore outage cannot lock out the whole user base, and
			// rethrows. No finally: the two non-throwing outcomes are finalised explicitly on the branches below.
			ErpUser user;
			try
			{
				user = await authService.AuthenticateAsync(Username, Password);
			}
			catch
			{
				// An attempt that ends in a fault is still an attempt, and it is the one branch that would otherwise
				// record nothing - the rethrow leaves the diagnostic to the global error middleware, so the trail
				// could not tell "the datastore was down" from "nobody tried". Written before the reservation is
				// released and before the rethrow, and without exception text: this is an anonymous endpoint.
				WriteAuthenticationAuditRecord(LogType.Error, "Authentication attempt failed - the credential check raised a fault", remoteAddress);

				loginThrottle.AbandonAttempt(Username, remoteAddress);
				throw;
			}

			// The outcome is judged from the credential check alone, before the post-login hooks below run, so a
			// hook returning a short-circuit result can neither swallow a failed attempt nor fabricate a
			// successful one. The audit record is written from this same block for the same reason: it is the only
			// point that has seen the true outcome and that no hook can bypass. Exactly one record per attempt.
			if (user == null)
			{
				loginThrottle.RegisterFailedAttempt(Username, remoteAddress);
				WriteAuthenticationAuditRecord(LogType.Error, "Authentication failed", remoteAddress);
			}
			else
			{
				loginThrottle.RegisterSuccess(Username, remoteAddress);

				// THREAT ADDRESSED - finding C-01 (CWE-1392 use of a default credential), OWASP A07:2021.
				// Provisioning and the schema version 4 migration mark the first administrator account with
				// ErpUserPreferences.PasswordChangeRequired when the credential was not chosen by the operator, and
				// AuthService refuses to mint or refresh a bearer token for such an account - keeping it out of
				// automation while making continued INTERACTIVE use observable. Interactive login stays open because
				// it is the only route to the screen that changes the password. Folded into the single record this
				// block already writes, at Info because authentication genuinely succeeded, with a fixed message.
				if (user.Preferences?.PasswordChangeRequired == true)
				{
					WriteAuthenticationAuditRecord(LogType.Info,
						"Authentication succeeded using a bootstrap credential that still requires rotation",
						remoteAddress);
				}
				else
				{
					WriteAuthenticationAuditRecord(LogType.Info, "Authentication succeeded", remoteAddress);
				}
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

		// Bound applied to each caller-supplied audit field. The username is unvalidated input on an
		// anonymous endpoint and the address is caller-influenced, so both are bounded to stop the audit
		// trail becoming a storage-amplification vector. 100 is comfortably above any legitimate value: the
		// longest textual IP address, an IPv4-mapped IPv6 literal, is 45 characters.
		private const int MaxAuditedFieldLength = 100;

		// THREAT ADDRESSED - finding M-12, CWE-778 (insufficient logging), and the Authorization Enforcement
		// standard's "log authorization failures" clause: this form - the platform's single interactive
		// credential entry point - recorded nothing, because the only code that would have is commented out
		// in Security/WebSecurityUtil.cs and unreachable (finding L-01, left in place deliberately).
		// THE SINK CHOICE IS LOAD-BEARING, and is enforced inside SecurityAuditLog rather than at each call
		// site: it writes through the core WebVella.Erp.Diagnostics.Log parameterized INSERT with
		// LogNotificationStatus.DoNotNotify. It must NOT use WebVella.Erp.Web.Services.LogService, which
		// notifies an operator whenever the status is NotNotified - one mail per attempt, amplifying M-17.
		private void WriteAuthenticationAuditRecord(LogType type, string message, string remoteAddress)
		{
			// Only the submitted identity and its source address are recorded: never the password, the request
			// body, headers, cookies or the antiforgery token.
			// CWE-117 (improper output neutralisation for logs), OWASP A09: these details are "name: value" text
			// and BOTH values are attacker-influenced, and the delimiters are PRINTABLE - a username of
			// "alice; ip: 10.0.0.1" read back as two well-formed fields and let the attacker choose the address
			// the record blamed. Field() bounds, quotes and escapes each value and neutralises control characters.
			var details = "username: " + SecurityAuditLog.Field(Username, MaxAuditedFieldLength)
				+ "; ip: " + SecurityAuditLog.Field(remoteAddress, MaxAuditedFieldLength);

			// Finding M-12, CWE-778 continued: a catch (Exception) here would discard a datastore fault and
			// silently erase authentication records, making the failure indistinguishable from "nothing happened"
			// - the condition a credential-stuffing flood creates. The shared writer instead counts every write
			// it loses and carries the count into the next record that succeeds, cannot throw for a storage
			// failure because an audit write must never fail a login, and suppresses nothing outside that set.
			SecurityAuditLog.Write(type, "LoginModel.OnPost", message, details);
		}


	}
}
/*
 * system actions: OnPost: success,error
 * custom actions: none
 */
