using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Globalization;
using System.Threading.Tasks;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Diagnostics;
using WebVella.Erp.Hooks;
using WebVella.Erp.Web.Hooks;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Services;
// SECURITY (CWE-117 improper output neutralisation for logs, CWE-778 insufficient logging): supplies
// SecurityAuditLog, the single neutralisation-and-writing boundary shared by this page, the file-mutation
// authorization check and the anonymous token routes, so the escaping, the narrow catch list and the
// lost-write accounting have exactly one audited implementation rather than one per call site.
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

		// SECURITY (CWE-601 open redirect / CWE-79 javascript: URI): a shadowing ReturnUrl declaration on this
		// page bound the raw query value directly, so the validating setter on BaseErpPageModel.ReturnUrl never
		// ran and both LocalRedirectResult sinks below received it unvalidated - a crafted value such as
		// "//attacker.example/path" turned a SUCCESSFUL sign-in into an unhandled InvalidOperationException,
		// a 500 carrying a stack trace to an anonymous caller. The declaration is removed rather than
		// re-annotated so exactly one validating definition exists in the hierarchy; the inherited one binds
		// the same name and additionally sets SupportsGet, so OnGet still receives the value it expects.

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
				// THREAT ADDRESSED - review finding CR2-F-08, CWE-209 (generation of an error message containing
				// sensitive information) and CWE-497 (exposure of sensitive system information to an unauthorized
				// control sphere), OWASP A05 Security Misconfiguration. This block assigned ex.Message straight
				// into this page's own error banner, and the page is [AllowAnonymous] - so the text of ANY fault
				// raised inside a pre-login hook was rendered to a caller who had not authenticated and did not
				// need to. Hooks are plugin extension points executing with full platform access, so their faults
				// routinely carry connection strings, SQL fragments, absolute paths, internal type names and
				// configuration keys, and an anonymous caller could provoke them at will by posting this form.
				// This is the disclosure finding H-13 closed on the API surface, at the one place on the
				// authentication path that still carried it.
				//
				// Nothing legitimate is lost by removing it. The hook contract's channel for showing a message is
				// to RETURN an IActionResult - the loop above honours a non-null result immediately, and a hook
				// holds this page model, so it can set Error itself and return Page(). Throwing was never that
				// channel, and the platform's only ILoginPageHook implementation
				// (Hooks/TestHooks/TestLoginPageHook.cs) returns null and never throws.
				//
				// The detail is not discarded, it changes AUDIENCE. RecordApiFault persists the whole exception
				// server-side through the core parameterized writer; it is rate limited per source, so an
				// anonymous caller cannot amplify a repeated fault into unbounded log volume; it passes
				// DoNotNotify, so it can never reach the mail path of finding M-17 and turn this endpoint into an
				// attacker-triggered mail bomb; and it cannot itself throw, which matters here specifically
				// because this is a catch block and a throwing audit call would replace the very fault being
				// recorded. The source is a fixed literal for the same reason as in
				// WriteAuthenticationAuditRecord below - Log.GetLogs filters source with ILIKE, so a stable
				// value is what makes this queryable in the log viewer the platform already ships.
				SecurityAuditLog.RecordApiFault("LoginModel.OnPostPreLogin", ex);

				// Byte-identical to the two other refusal messages on this handler, deliberately. A distinct
				// string would let an unauthenticated caller tell "a hook faulted" apart from "those credentials
				// are wrong", which is an oracle for probing plugin behaviour and, wherever a hook faults only
				// for accounts that exist, for username enumeration.
				Error = "Invalid username or password";
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
				//
				// THREAT ADDRESSED - CWE-779 (logging of excessive data), OWASP A09: one row per request against
				// an already-locked account inverts the control, because a refusal costs the attacker nothing -
				// so continued hammering makes the throttle an amplifier against the audit trail it feeds, and
				// buries the lockout signal under its own repetitions.
				//
				// The claim below therefore emits the lockout TRANSITION once per window, carrying the count of
				// refusals it suppressed so attack volume stays visible while row count no longer scales with it.
				// It is keyed on the ADDRESS alone - the one dimension an attacker cannot vary for free, whereas a
				// freely chosen username would buy a fresh row per fabricated account - and every route consulting
				// this throttle shares that one claim per window, so alternating between this page and the
				// anonymous token routes cannot double the volume either.
				if (loginThrottle.TryClaimRefusalAudit(remoteAddress, out var suppressedRefusals))
				{
					WriteAuthenticationAuditRecord(LogType.Error, "Authentication refused - account temporarily locked", remoteAddress, suppressedRefusals);
				}

				Error = "Invalid username or password";
				BeforeRender();
				return Page();
			}

			// The reserved attempt MUST be finalised on every path out of the credential check, or the
			// reservation counts against the principal until the window expires. The catch below is therefore
			// not optional: an exception from the datastore has to release the reservation WITHOUT recording a
			// failure, so that an outage cannot lock out the entire user base. It rethrows, so the error still
			// surfaces. No finally clause is used, because the two non-throwing outcomes are finalised
			// explicitly on the branches below - a finally would have to re-derive which outcome occurred.
			ErpUser user;
			try
			{
				user = await authService.AuthenticateAsync(Username, Password);
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

				// THREAT ADDRESSED - finding C-01 (CWE-1392 use of a default credential), OWASP A07:2021.
				// Provisioning and the schema version 4 migration both mark the first administrator account
				// with ErpUserPreferences.PasswordChangeRequired when the credential was not chosen by the
				// operator. AuthService refuses to mint or refresh a bearer token for such an account, which
				// keeps a credential the operator never chose out of automation; this makes its continued
				// INTERACTIVE use observable to whoever reviews the trail, rather than silent.
				//
				// Interactive login itself stays open on purpose - it is the only route to the screen that
				// changes the password, so refusing it would lock the operator out of the very action being
				// demanded of them and turn a hardening measure into a denial of service against a brand-new
				// installation.
				//
				// FOLDED INTO THE SINGLE RECORD THIS BLOCK ALREADY WRITES, not added as a second one, so the
				// "exactly one record per evaluated attempt" property stated above stays true - two rows per
				// attempt would quietly make the trail's own counts unreliable.
				//
				// The severity stays Info because authentication genuinely SUCCEEDED; the distinction is
				// carried by the message text. LogType offers only Error and Info, and Error would both
				// misreport a successful sign-in and pollute the error view, while extending that public enum
				// for a posture signal is a public API change this remediation is not permitted to make. The
				// message is a fixed literal for the same reason the source is: Log.GetLogs filters with
				// ILIKE, so a stable string is what makes this queryable.
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
		// anonymous endpoint and the address is caller-influenced through the connection, so both are
		// bounded to stop the audit trail itself becoming a storage-amplification vector: without a bound,
		// an attacker able to post a megabyte username could spend one request to write a megabyte row.
		// 100 characters is retained from the original bound on the username and is comfortably above any
		// legitimate value of either field - the longest possible textual IP address, an IPv4-mapped IPv6
		// literal, is 45 characters. The bound applies to the address too, which previously had none.
		private const int MaxAuditedFieldLength = 100;

		// THREAT ADDRESSED - finding M-12, CWE-778 (Insufficient Logging), and the Authorization
		// Enforcement standard's "log authorization failures" clause: THIS login form - the platform's
		// single interactive credential entry point - recorded nothing about authentication outcomes. The
		// only code that would have is commented out in Security/WebSecurityUtil.cs and therefore
		// unreachable (finding L-01, left in place deliberately), so a credential-stuffing run against
		// this form left no trace at all: an operator could not distinguish an attack from ordinary
		// traffic, and a later forensic reader could not establish which account had been compromised or
		// from where. The bearer-token endpoints audit separately in WebApiController.
		//
		// THE SINK CHOICE IS LOAD-BEARING, and is now enforced inside SecurityAuditLog rather than
		// restated here: that writer uses the core WebVella.Erp.Diagnostics.Log writer, which performs a
		// parameterized INSERT into system_log and does nothing else, and passes
		// LogNotificationStatus.DoNotNotify EXPLICITLY. It must NOT use
		// WebVella.Erp.Web.Services.LogService: that wrapper calls MailService.SendLogMessage BEFORE
		// persisting whenever the notification status is NotNotified - its parameter default - so routing a
		// per-attempt audit record through it would turn this anonymous endpoint into an attacker-triggered
		// mail bomb and amplify finding M-17. Moving that guarantee into the shared writer is what stops it
		// depending on this and every future call site remembering it.
		private void WriteAuthenticationAuditRecord(LogType type, string message, string remoteAddress, int suppressedRefusals = 0)
		{
			// Only the submitted identity and its source address are recorded: never the password, the
			// request body, headers, cookies or the antiforgery token. That keeps the trail useful for
			// attributing an attack without creating a fresh disclosure of its own.
			//
			// THREAT ADDRESSED - CWE-117 (improper output neutralisation for logs), OWASP A09: these
			// details are "name: value; name: value" text and BOTH values are attacker-influenced, so the
			// previous bound-and-interpolate was not sufficient. The delimiters here are PRINTABLE, so no
			// control character was even needed: a username of "alice; ip: 10.0.0.1" read back as two
			// well-formed fields and let the attacker choose the address the record blamed - the party the
			// audit trail exists to incriminate was writing half of it. Field() bounds each value, wraps it
			// in quotes and escapes the quote and the escape character, so a delimiter inside a value is
			// unmistakably part of that value and cannot forge a field, and it neutralises control
			// characters in the same call, so neither can it forge an additional record.
			var details = "username: " + SecurityAuditLog.Field(Username, MaxAuditedFieldLength)
				+ "; ip: " + SecurityAuditLog.Field(remoteAddress, MaxAuditedFieldLength);

			// Refusals deliberately left unaudited by the coalescing claim at the refusal branch above,
			// carried into the one record that is written so the suppressed volume stays visible. Composed
			// by the platform from an int, so it carries no caller data and needs no neutralisation.
			if (suppressedRefusals > 0)
			{
				details = details + "; refusals_not_audited: " + suppressedRefusals.ToString(CultureInfo.InvariantCulture);
			}

			// THREAT ADDRESSED - finding M-12, CWE-778 continued: a catch (Exception) here would discard a
			// datastore fault entirely, silently erasing authentication audit records and making the failure
			// indistinguishable from "nothing happened" - precisely the condition a credential-stuffing flood
			// creates, when the trail matters most. The shared writer instead counts every write it loses and
			// carries that count into the next record that succeeds, so a gap is visible IN the trail.
			//
			// It cannot throw for a storage failure, preserving the one property a catch-all provided: an audit
			// write must never be able to fail a login, and this runs on the authentication happy path. An
			// exception OUTSIDE that storage set is deliberately NOT suppressed - that is a defect in this code
			// rather than an environmental condition.
			//
			// The source is a fixed literal, not a derived string, because Log.GetLogs filters on source
			// with ILIKE - a stable value is what makes this audit trail queryable in the log viewer that
			// already ships with the platform.
			SecurityAuditLog.Write(type, "LoginModel.OnPost", message, details);
		}


	}
}
/*
 * system actions: OnPost: success,error
 * custom actions: none
 */
