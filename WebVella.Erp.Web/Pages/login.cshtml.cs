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
			// THREAT ADDRESSED - review finding OBS-05, CWE-778 (insufficient logging), OWASP A09:2021.
			// Resolved FIRST, before any branch can leave this handler, because every exit path below now has
			// to be able to attribute its outcome to a source address. It used to be read only just before the
			// throttle was consulted, which is precisely why the four branches that exit above that point
			// recorded nothing at all: there was nothing to attribute them to.
			var remoteAddress = HttpContext?.Connection?.RemoteIpAddress?.ToString();

			// THREAT ADDRESSED - review finding OBS-05, CWE-778, OWASP A09:2021. An invalid model state means the
			// submission could not be bound or validated, which is an authentication ATTEMPT that was refused,
			// so the audit trail must contain an outcome for it. It previously threw without recording anything,
			// so the "exactly one outcome per attempt" property the trail is read for was false at the very
			// first branch of the handler.
			//
			// WHAT THIS BRANCH IS NOT, verified at runtime rather than inferred, because the message the throw
			// below carries says otherwise and would mislead the next reader: it is NOT the antiforgery gate.
			// Razor Pages applies AutoValidateAntiforgeryTokenAuthorizationFilter to every POST handler, and a
			// missing or invalid token is refused by that FILTER with HTTP 400 before this handler is entered -
			// observed directly: a token-less POST to /login answers 400 and never reaches this line. Auditing
			// that refusal would require a filter of its own, which is a new component rather than a fix to this
			// one, so the gap is recorded in docs/security/risk-register.md instead of closed here. The record
			// below therefore names what actually happened - model validation - rather than repeating the
			// throw's inaccurate wording.
			//
			// The throw is DELIBERATELY RETAINED, unchanged, including its message: it is the platform's shipped
			// behaviour for this branch and rewriting it is not what this finding is about. The record is added
			// ahead of it rather than in place of it.
			if (!ModelState.IsValid)
			{
				WriteAuthenticationAuditRecord(LogType.Error, "Authentication attempt rejected - request model validation failed", remoteAddress);
				throw new Exception("Antiforgery check failed.");
			}

			// OBS-05: deliberately NOT audited, and the omission is reasoned rather than overlooked. Init
			// resolves this page's application, area and node from the request path; a non-null result means the
			// login PAGE did not resolve, so no credential submission was processed and there is no
			// authentication outcome to record. Auditing it would put routing failures into the authentication
			// trail, where a reader counting attempts would then over-count them.
			var initResult = Init();
			if (initResult != null) return initResult;

			var globalHookInstances = HookManager.GetHookedInstances<IPageHook>(HookKey);
			foreach (IPageHook inst in globalHookInstances)
			{
				var result = inst.OnPost(this);
				if (result != null)
				{
					// OBS-05: a page hook that short-circuits the request ENDS an authentication attempt without
					// the credential ever being evaluated, and that is an outcome. Recording nothing here left a
					// plugin able to make attempts disappear from the trail entirely - silently, and without any
					// indication in the record that a hook had intervened. The message names the hook stage so a
					// reader can tell this apart from a credential decision.
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
						// OBS-05: same reasoning as the page-hook branch above, and the same requirement. This is
						// the hook contract's own documented way to short-circuit a login, so it is an expected
						// outcome rather than a fault - hence Info - but it is still an attempt that ended.
						WriteAuthenticationAuditRecord(LogType.Info, "Authentication attempt ended by a pre-login hook before the credential was evaluated", remoteAddress);
						return result;
					}
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

				// OBS-05: the fault record above is a DIAGNOSTIC, not an authentication outcome - it is written
				// under a different source, is rate limited per source, and carries the exception rather than the
				// attempt. Neither property is what an authentication trail needs, and relying on it meant a
				// reader counting outcomes per attempt found this branch missing: a hook that faults for every
				// post would show as one rate-limited fault rather than as N refused attempts. The outcome row
				// is therefore written as well as the fault, not instead of it, and it carries no exception text
				// - a hook's fault message routinely contains connection strings and internal paths, which is
				// exactly why this branch stopped rendering it to the caller.
				WriteAuthenticationAuditRecord(LogType.Error, "Authentication attempt failed - a pre-login hook raised a fault", remoteAddress);

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
			if (!loginThrottle.TryBeginAttempt(Username, remoteAddress))
			{
				// Audited even though no credential was checked: a refusal is the signal that a lockout
				// threshold has actually been reached, which is the strongest brute-force indicator this
				// endpoint can emit. Recording it server-side leaks nothing to the caller - see the
				// deliberately generic response below.
				//
				// THREAT ADDRESSED - review finding OBS-05, CWE-778 (insufficient logging), OWASP A09:2021.
				// EXACTLY ONE ROW PER REFUSAL, and the sampling this replaces is the reason the requirement is
				// stated that way. Refusals used to be coalesced - the first of a window, then one per hundred -
				// which meant the trail recorded that a lockout had begun but not how many times it was tested,
				// by whom, or when it stopped. An audit trail whose cardinality does not match the attempt
				// cardinality cannot be used to reconstruct an attack, and rate-based detection reading it
				// undercounts by a factor of a hundred - so the control that was supposed to protect the trail
				// was degrading the evidence instead.
				//
				// THE VOLUME OBJECTION IS ANSWERED BY A CONTROL THAT DOES NOT COST EVIDENCE. Every request
				// reaching this handler has already passed the framework's global fixed-window rate limiter,
				// registered in ErpMvcExtensions at 600 permits per source address per minute with no queueing,
				// so the rows one source can provoke are bounded by the transport layer at a value three orders
				// of magnitude below what an unbounded write would allow - and each row is bounded in size by
				// MaxAuditedFieldLength. Bounding volume at the transport and keeping the evidence complete is
				// strictly better than discarding evidence to bound volume in the application.
				//
				// The throttle's coalescing claim is retained for the anonymous bearer-token refresh route,
				// which has no principal to attribute an attempt to and is therefore aggregate telemetry rather
				// than an authentication outcome. See LoginThrottleService.TryClaimRefusalAudit.
				WriteAuthenticationAuditRecord(LogType.Error, "Authentication refused - account temporarily locked", remoteAddress);

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
				// OBS-05: an attempt that ends in a fault is still an attempt, and it was the one branch of this
				// handler that recorded nothing whatsoever - not even the diagnostic, because the rethrow leaves
				// it to the global error middleware. A reader of the trail could therefore not distinguish "the
				// datastore was down and nobody could sign in" from "nobody tried", which is the worst time for
				// the trail to be silent. Written BEFORE the reservation is released and before the rethrow, so
				// the record exists whatever happens to the exception afterwards.
				//
				// It carries no exception text: this runs on an anonymous endpoint and a credential-path fault
				// message can quote connection strings and SQL fragments. The exception itself is not discarded -
				// the rethrow below hands it to the error pipeline, which records it under its own source.
				WriteAuthenticationAuditRecord(LogType.Error, "Authentication attempt failed - the credential check raised a fault", remoteAddress);

				loginThrottle.AbandonAttempt(Username, remoteAddress);
				throw;
			}

			// The outcome is judged from the credential check alone, before the post-login hooks below run,
			// so that a hook returning a short-circuit result can neither swallow a failed attempt nor
			// fabricate a successful one.
			// The audit record is written from this same block, and for the same reason: it is the only
			// point on the request path that has seen the true outcome of the credential check and that
			// no hook can bypass. Exactly one record is written per evaluated attempt - and, since review
			// finding OBS-05, exactly one is written per UNEVALUATED attempt too, on each of the branches
			// above that leave this handler before the credential is checked, so the trail's cardinality
			// matches the attempt cardinality with no gaps.
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
		// WebVella.Erp.Web.Services.LogService: that wrapper sends an operator notification whenever the
		// notification status is NotNotified - its parameter default - so routing a per-attempt audit record
		// through it would turn this anonymous endpoint into an attacker-triggered mail bomb and amplify
		// finding M-17. Before the finding M-OPEN-03 remediation it also mailed the full record BEFORE
		// persisting it; that ordering is now reversed and the notification carries only the severity, the
		// source and the stored record's identifier, but one message per attempt is still one message per
		// attempt, so this choice stands. Moving that guarantee into the shared writer is what stops it
		// depending on this and every future call site remembering it.
		// OBS-05: the suppressedRefusals parameter this signature used to carry has been removed along with the
		// refusal sampling it existed to report. A count of records the trail deliberately did not write is only
		// meaningful while records are being withheld; now that every attempt and every refusal writes its own
		// outcome, carrying it would have been a field that was structurally always zero.
		private void WriteAuthenticationAuditRecord(LogType type, string message, string remoteAddress)
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
