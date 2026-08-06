using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
// SECURITY (CWE-117): supplies SecurityAuditLog.Normalize, the single shared implementation of the
// bound-and-neutralise routine SanitizeForLog delegates to, so this class and the login and token-route
// audit paths cannot drift apart on what counts as neutralised.
using WebVella.Erp.Web.Utils;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace WebVella.Erp.Web.Services
{
	public class AuthService
	{
		private const double JWT_TOKEN_EXPIRY_DURATION_MINUTES = 1440;
		private const double JWT_TOKEN_FORCE_REFRESH_MINUTES = 120;

		// H-02 (CWE-613, OWASP A07): THREAT ADDRESSED - unbounded session renewal. Refresh minted a brand new 24h
		// token from any still-valid token, so an attacker holding one captured token could refresh it shortly before
		// each expiry and keep it alive for ever; the credential never had to be presented again. This is the absolute
		// horizon past which no amount of refreshing can carry a session, stamped once at authentication and then
		// carried verbatim across every refresh rather than recomputed. Seven days: long enough that ordinary use is
		// undisturbed, short enough that a stolen token dies without operator intervention.
		private const double JWT_ABSOLUTE_SESSION_HORIZON_MINUTES = 10080;

		// Claim carrying that horizon. The value format is DateTime.ToBinary() rendered invariantly, deliberately
		// identical to the token_refresh_after idiom below, because the WebAssembly client parses that claim shape
		// with DateTime.FromBinary(long.Parse(..)) at Client/Services/TokenManagerService.cs:L49 and a different
		// encoding would throw inside the browser.
		private const string CLAIM_SESSION_ABSOLUTE_EXPIRY = "session_absolute_expiry";

		// H-03 (CWE-613, OWASP A07): bound for the cookie authentication ticket.
		//
		// THREAT ADDRESSED - review finding M-REV-09: this and the hosts' ExpireTimeSpan are not peers.
		// CookieAuthenticationHandler applies ExpireTimeSpan ONLY when the ticket carries no explicit ExpiresUtc, so the
		// value here always wins and the hosts' declaration is inert unless the two agree. They had drifted apart - the
		// hosts declared 8 hours while the frozen session contract is 24 - so the number here is now 1440 and the single
		// place the hosts get their window from is ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie, which
		// declares the same 1440. Keep the two in step: they are one contract expressed twice because the framework
		// requires it in two places, not two independent settings.
		//
		// 1440 minutes is an IDLE window, not a session cap: sliding expiration is enabled per the mandated contract,
		// so activity slides it forward. The cap is AUTH_TICKET_ABSOLUTE_SESSION_HORIZON_MINUTES below.
		private const double AUTH_TICKET_EXPIRY_DURATION_MINUTES = 1440;

		// Absolute ceiling on a cookie session, past which no amount of activity can carry it.
		//
		// THREAT ADDRESSED - CWE-613 (insufficient session expiration), OWASP A07. Sliding expiration is mandated by
		// Agent Action Plan section 0.6.1 Class 6, and it is a real idle-timeout control, but on its own it is also an
		// indefinite-renewal primitive: CookieAuthenticationHandler slides the window forward on any request past the
		// halfway point, so an attacker holding a stolen cookie need only poll it to keep it alive for ever, and the
		// ExpiresUtc bound is never actually reached. Enabling sliding expiration WITHOUT this ceiling would therefore
		// have traded one session-expiry weakness for a strictly worse one.
		//
		// Seven days deliberately matches JWT_ABSOLUTE_SESSION_HORIZON_MINUTES, so a cookie session and a bearer
		// session die on the same schedule and an operator has one number to reason about rather than two. Long enough
		// that ordinary use is undisturbed; short enough that a stolen cookie expires without operator intervention.
		private const double AUTH_TICKET_ABSOLUTE_SESSION_HORIZON_MINUTES = 10080;

		// Authentication-property item carrying that horizon.
		//
		// It is stamped into AuthenticationProperties.Items rather than into a claim on purpose. Items round-trip
		// through sliding renewal untouched - CookieAuthenticationHandler reuses the decrypted properties and rewrites
		// only IssuedUtc and ExpiresUtc - so the horizon is fixed at the moment of authentication and cannot be pushed
		// forward by the very renewal it is there to bound. It also travels inside the encrypted, signed ticket, so a
		// client can neither read it nor forge a later one. A claim would additionally be visible to every consumer of
		// the principal, which this value has no reason to be.
		private const string AUTH_TICKET_ABSOLUTE_EXPIRY_ITEM = "wv_session_absolute_expiry";

		// SECURITY - finding F7 (CWE-613 insufficient session expiration), OWASP A07.
		// THREAT ADDRESSED: the two JWT validators in this platform disagreed about how much clock drift to
		// tolerate. This one passed an explicit one-minute skew, while both hosts' AddJwtBearer registrations
		// omitted ClockSkew entirely and so kept IdentityModel's FIVE-MINUTE default. Framework authorization -
		// every [Authorize] endpoint reached with a bearer token - runs the HOST's parameters, not these, so an
		// expired bearer principal stayed authorized for up to four minutes longer than the platform believed,
		// on exactly the paths where the extra window is worth the most to an attacker holding a stale token.
		// PUBLIC AND SHARED DELIBERATELY: the mismatch existed because the value was written twice and could
		// drift. Both hosts now consume THIS member, so parity is compile-time coupled rather than a convention
		// a future edit can silently break. One minute is retained rather than raised - it is the value the
		// platform already chose, and shortening a tolerance is the correct direction for an expiry finding.
		public static readonly TimeSpan JwtClockSkew = TimeSpan.FromMinutes(1);

		// SECURITY - finding F8 (session hijacking): claim carrying the per-sign-in session identifier that
		// makes a cookie ticket revocable. Shared rather than private because the cookie validation hook that
		// enforces revocation is wired centrally in ErpMvcExtensions, so the mint site and the check site must
		// name the SAME claim; a private constant would have forced a duplicated literal, which is exactly how
		// such pairs drift apart. Internal rather than public because both of those sites live in this one
		// assembly, so internal is the narrowest visibility that works - and it keeps the claim name out of the
		// library's public surface, which the no-API-change constraint requires.
		// THREAT ADDRESSED - finding F-02 (session hijacking via a non-revocable bearer token; CWE-613), OWASP
		// A07. This claim used to be stamped into cookie tickets ONLY, on the reasoning that "a bearer credential
		// has no server-side session to end". That reasoning inverted the problem: a bearer token has no
		// server-side session to end precisely BECAUSE nothing identified the session, and the consequence was
		// that a stolen token could not be revoked by any means - logging out, disabling the account and rotating
		// the password all left it working until it expired, and the refresh endpoint would keep minting
		// successors for it up to the seven-day horizon. The identifier is therefore now minted into every token
		// as well (BuildTokenAsync), carried verbatim across refresh, and consulted by both bearer validators, so
		// ONE claim name and ONE store cover both credential kinds. It remains internal: the mint sites and the
		// two check sites are all in this assembly, and the hosts consult it only through the public
		// IsBearerSessionRevoked predicate below, so no claim name enters the library's public surface.
		internal const string CLAIM_SESSION_ID = "erp_session_id";

		// Suppression window for the token-validation failure log in GetValidSecurityTokenAsync, guarded by the plain
		// lock idiom this project already uses (Services/CodeEvalService.cs), so a request flood cannot flood the log.
		private const double TOKEN_VALIDATION_LOG_INTERVAL_MINUTES = 1;
		private static readonly object tokenValidationLogLock = new object();

		// THREAT ADDRESSED - review finding OBS-09, CWE-778 (insufficient logging), OWASP A09:2021. The window
		// above used to be a single PROCESS-GLOBAL slot, and that made it a monitoring blind spot rather than a
		// rate limit: one high-volume failure category - an expired token replayed in a loop, say - claimed the
		// slot and then hid EVERY OTHER token-validation failure for the rest of the minute, including the ones
		// an operator most needs to see, such as a token signed with an unknown key. The slot is therefore
		// PARTITIONED, so a flood of one category cannot mask a single occurrence of another.
		//
		// THE PARTITION KEY IS THE EXCEPTION TYPE NAME, and the choice is deliberate on both counts.
		//   * It is CLR metadata from a loaded assembly, so it carries no payload from the rejected token and
		//     cannot itself become a log-injection or disclosure vector (CWE-117, CWE-532).
		//   * Its cardinality is bounded by the types that can actually reach the two narrowed catch clauses -
		//     SecurityTokenException and ArgumentException subclasses - so this dictionary cannot be grown by a
		//     caller (CWE-770). Partitioning by remote address WOULD have been caller-controlled and unbounded,
		//     which is why it is not used: the reporting gap this closes is about failure CATEGORY, not source.
		// Each partition carries its own suppressed-occurrence count, reported in the next record written for
		// that partition exactly as Middleware/JwtMiddleware.cs does, so the bound stays honest about how much
		// it withheld instead of silently discarding it.
		private static readonly Dictionary<string, TokenValidationReportSlot> tokenValidationLogSlots =
			new Dictionary<string, TokenValidationReportSlot>(StringComparer.Ordinal);

		/// <summary>
		/// Per-category reporting window and suppressed-occurrence count for the token-validation audit log.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding OBS-09. A mutable holder rather than two parallel dictionaries, so a
		/// category's window and its suppressed count cannot be updated inconsistently. Every field is read and
		/// written under <see cref="tokenValidationLogLock"/>, which is why no member needs to be volatile or
		/// interlocked.
		/// </remarks>
		private sealed class TokenValidationReportSlot
		{
			internal DateTime LastWrittenUtc;
			internal int SuppressedOccurrences;
		}

		// P4-07 (CWE-117 improper output neutralisation for logs, CWE-532 information exposure through log files).
		// The token-validation failure log used to persist the raw exception message. IdentityModel builds its messages
		// from the token being rejected - IDX10214 embeds the audience, IDX10205 the issuer, IDX10223 and IDX10225 the
		// expiry and current times, IDX10501 the key identifier - so the raw message copies token-derived values, and
		// potentially a caller-chosen value, verbatim into a persisted record with no length bound and no control-character
		// handling. Details are therefore rebuilt from a fixed table below instead of being echoed.
		private const int MaxLogDetailLength = 200;

		// Upper bound on how much of a message is inspected while looking for a leading IDXnnnnn code: 'IDX' plus at most
		// nine digits. It bounds the scan so a hostile message length cannot buy work here.
		private const int MaxDiagnosticCodeLength = 12;

		// SECURITY (H-02, CWE-778): fallback counter for token-validation audit entries that could not be persisted.
		// Writing the audit record needs the database, so an outage there would otherwise make the loss of the
		// authorization-failure audit trail completely invisible. The count is carried into the next audit entry that
		// does succeed, and is only ever mutated through Interlocked/Volatile so recording a loss can never itself
		// throw and can never turn token validation into a server error.
		private static int tokenValidationAuditWriteFailures;

		private IServiceProvider serviceProvider;

		public AuthService(IServiceProvider serviceProvider)
		{
			this.serviceProvider = serviceProvider;
		}

		// M-03 (OWASP A07): asynchronous because the sign-in below must be awaited - a fire-and-forget sign-in can
		// return before the authentication cookie is written. The sole caller repository-wide is the login page
		// handler in Pages/login.cshtml.cs, which awaits this method.
		//
		// BACKWARD COMPATIBILITY - review finding API-01. This method carried the name Authenticate while returning
		// Task<ErpUser>, which changed the return type of a member the previous release published as
		// "public ErpUser Authenticate(string, string)". A return-type change is both a source and a binary break
		// for every external plugin or package compiled against this assembly, and the engagement forbids API
		// contract changes. The awaited implementation therefore lives here under the -Async name and the original
		// signature is preserved verbatim by the blocking wrapper immediately below.
		public async Task<ErpUser> AuthenticateAsync(string email, string password)
		{
			var user = new SecurityManager().GetUser(email, password);
			if (user != null && user.Enabled)
			{
				var claims = new List<Claim>();
				claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
				claims.Add(new Claim(ClaimTypes.Email, user.Email));
				user.Roles.ForEach(role => claims.Add(new Claim(ClaimTypes.Role.ToString(), role.Name)));

				// SECURITY - finding F8 (session hijacking; CWE-613, CWE-384), OWASP A07.
				// THREAT ADDRESSED: the ticket carried nothing that identified the SIGN-IN, only the user, so
				// there was no handle by which a single session could ever be ended. Logging out could therefore
				// only delete the cookie from the one browser that asked, and any copy of it stayed valid for the
				// full ticket lifetime. This identifier is that handle: LogoutAsync records it as revoked and the
				// cookie pipeline refuses any ticket carrying a revoked one, so the copy dies on its next request.
				// A fresh value per sign-in, never derived from the user, so revoking one session cannot end
				// another and a captured identifier is not predictable from a previous one. Guid.NewGuid is
				// cryptographically strong on every platform .NET supports, which is the CSPRNG requirement.
				claims.Add(new Claim(CLAIM_SESSION_ID, Guid.NewGuid().ToString()));

				var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

				// THREAT ADDRESSED - review finding M-REV-09 (CWE-613, OWASP A07): the frozen session contract is a
				// 24-hour SLIDING window, and sliding renewal requires BOTH the host's SlidingExpiration and this flag.
				// This was false, so the mandated sliding half of the contract was unreachable no matter what the hosts
				// declared. It is now true, and the indefinite-renewal weakness that made disabling it look attractive is
				// closed properly instead - by the absolute horizon stamped immediately below and enforced on every
				// request in ValidateSessionHorizonAsync. Those two changes are one change: do not enable this without
				// the horizon, and do not remove the horizon while this is enabled.
				DateTimeOffset issuedUtc = DateTimeOffset.UtcNow;
				var authProperties = new AuthenticationProperties
				{
					AllowRefresh = true,
					// H-03 (CWE-613, OWASP A07): this was a 100-year expiry, so a stolen authentication cookie never became
					// useless. An explicit ExpiresUtc wins over the host's ExpireTimeSpan, so this value IS the idle window.
					ExpiresUtc = issuedUtc.AddMinutes(AUTH_TICKET_EXPIRY_DURATION_MINUTES),
					IsPersistent = false,
					IssuedUtc = issuedUtc,
				};

				// Stamped once, here, and never recomputed. Rendered as Unix seconds in the invariant culture so the
				// value is culture-independent and parses back without ambiguity; a malformed or absent stamp is treated
				// as an expired session by the validator, which fails closed.
				authProperties.Items[AUTH_TICKET_ABSOLUTE_EXPIRY_ITEM] =
					issuedUtc.AddMinutes(AUTH_TICKET_ABSOLUTE_SESSION_HORIZON_MINUTES).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);

				IHttpContextAccessor httpContextAccesor = (IHttpContextAccessor)serviceProvider.GetService(typeof(IHttpContextAccessor));
				// M-03 (OWASP A07): the discarded Task raced the response, so the authentication cookie could be absent from
				// it and any sign-in exception went unobserved. Awaited, so the cookie is written before we return.
				await httpContextAccesor.HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);
				return user;
			}
			else
				return null;
		}

		/// <summary>
		/// Authenticates a set of credentials and establishes the authentication cookie, preserving the
		/// signature published by earlier releases. New code should call
		/// <see cref="AuthenticateAsync(string, string)"/> directly.
		/// </summary>
		/// <param name="email">The account's e-mail address.</param>
		/// <param name="password">The candidate password.</param>
		/// <returns>The authenticated user, or <c>null</c> when the credentials are rejected or the account is disabled.</returns>
		/// <remarks>
		/// BACKWARD COMPATIBILITY - review finding API-01. Earlier releases published this exact signature, so
		/// removing it or changing its return type would break source and binary compatibility for external
		/// plugins and packages built against this assembly. It is retained as a thin shim over
		/// <see cref="AuthenticateAsync(string, string)"/> so that no caller loses the security fixes carried by
		/// that method: the sign-in is genuinely awaited to completion before this method returns, which is the
		/// whole of finding M-03, and every credential, session-identifier and ticket-lifetime control applies
		/// unchanged because there is exactly one implementation.
		/// <para>
		/// Blocking on the task is safe in this application and is not a latent deadlock. ASP.NET Core installs
		/// no <c>SynchronizationContext</c>, so the continuation inside
		/// <see cref="AuthenticateAsync(string, string)"/> never needs to re-enter the thread that is waiting
		/// here; and this method cannot be reached outside a request, because the implementation resolves
		/// <c>IHttpContextAccessor</c> and signs in on the current <c>HttpContext</c>.
		/// <c>GetAwaiter().GetResult()</c> is used rather than <c>.Result</c> so that a failure surfaces as the
		/// original exception instead of an <c>AggregateException</c>, preserving the exception contract the
		/// synchronous member had before it was made asynchronous.
		/// </para>
		/// </remarks>
		public ErpUser Authenticate(string email, string password)
		{
			return AuthenticateAsync(email, password).GetAwaiter().GetResult();
		}

		// Enforces the absolute session horizon on every authenticated request. Wired once, for all seven hosts, by
		// ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie.
		//
		// THREAT ADDRESSED - CWE-613 (insufficient session expiration), OWASP A07. Sliding expiration is mandated, and
		// it is what turns the 24-hour window into an idle timeout; but the framework's renewal is unbounded, so
		// without this check a cookie could be slid forward for ever by anything that merely keeps touching it - which
		// is exactly what an attacker holding a stolen cookie does. This is the ceiling that renewal cannot cross.
		//
		// Rejection is deliberately silent. An expired session is a normal lifecycle event, not an authorization
		// failure, and this handler runs on an anonymous, unauthenticated-reachable path - a caller replaying one
		// expired cookie in a loop would otherwise be able to drive unbounded log growth for no security value. The
		// security-relevant events on this path, a failed credential check and a failed token validation, are audited
		// elsewhere in this class and in the login page.
		//
		// The method is written so it cannot throw: an exception escaping principal validation would surface as a 500
		// on every request carrying a cookie, turning a session-lifetime control into an outage.
		public static async Task ValidateSessionHorizonAsync(CookieValidatePrincipalContext context)
		{
			if (context == null)
				return;

			// THREAT ADDRESSED - finding F-01 (CWE-613 insufficient session expiration, CWE-636 not failing
			// securely), OWASP A07. This check used to RETURN, accepting the ticket, whenever the horizon stamp
			// was absent - and that made the entire absolute-session ceiling optional from the ticket's own point
			// of view. The reasoning it rested on does not hold:
			//   * "such tickets can only predate this control" is an assumption about what a ticket contains, and
			//     a session-lifetime control must not depend on one. Anything that can produce a ticket without
			//     the stamp - an older build still running behind the same load balancer, a ticket restored from
			//     a backup, a re-used data-protection key ring, or a future code path that signs in without
			//     going through Authenticate - produced a session with NO ceiling at all;
			//   * "they also carry AllowRefresh = false, so they cannot slide" is inferred, not verified. Nothing
			//     here reads AllowRefresh, so the branch granted unbounded acceptance on the strength of a
			//     property it never checked.
			// FAILING CLOSED instead. Authenticate stamps this item in the same operation that mints the ticket,
			// so every ticket this platform issues carries it; a ticket without it is therefore not a ticket this
			// build would produce, and the correct response to an unrecognised session shape is to end it rather
			// than to exempt it. The stamp travels inside the encrypted, signed ticket, so no client can strip it
			// to reach this path deliberately.
			// COST, stated plainly: any session still held from before this deployment is signed out once and its
			// owner signs in again. That is a single re-authentication, which is the accepted price of the fix -
			// the alternative is a documented, permanently reachable bypass of the ceiling.
			if (context.Properties == null
				|| !context.Properties.Items.TryGetValue(AUTH_TICKET_ABSOLUTE_EXPIRY_ITEM, out string stampedHorizon)
				|| stampedHorizon == null)
			{
				await RejectAndSignOutAsync(context);
				return;
			}

			// Present but unreadable is treated as expired. This is unreachable from outside - the value is written by
			// this class alone, inside a signed ticket - so failing closed here costs nothing and leaves no shape of
			// stamp that silently disables the ceiling.
			bool expired;
			if (!long.TryParse(stampedHorizon, NumberStyles.Integer, CultureInfo.InvariantCulture, out long horizonUnixSeconds))
			{
				expired = true;
			}
			else
			{
				expired = DateTimeOffset.UtcNow >= DateTimeOffset.FromUnixTimeSeconds(horizonUnixSeconds);
			}

			if (!expired)
				return;

			await RejectAndSignOutAsync(context);
		}

		// F-01: the single rejection path for ticket validation, extracted so that the two refusals above - an
		// unrecognised ticket shape and an expired horizon - cannot drift apart in behaviour. Rejects FIRST and
		// clears the cookie afterwards, so the current request is already unauthenticated even if the cookie
		// cannot be cleared from the response; the security outcome never depends on the cleanup succeeding.
		private static async Task RejectAndSignOutAsync(CookieValidatePrincipalContext context)
		{
			context.RejectPrincipal();

			try
			{
				await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
			}
			catch (Exception)
			{
				// The principal has already been rejected, so the request is unauthenticated regardless of whether the
				// expired cookie could be cleared from the response. Swallowing here keeps a failed cookie deletion
				// from becoming a server error on a path that every authenticated request travels.
			}
		}

		// SECURITY - finding F8 (session hijacking; CWE-613 insufficient session expiration), OWASP A07.
		// THREAT ADDRESSED, three distinct defects in four lines of code:
		//   (1) FIRE AND FORGET. The returned Task was discarded, so sign-out raced the response. The
		//       cookie-deletion header could be written after the response had already begun, in which case it
		//       was silently dropped and the user stayed signed in with no error anywhere.
		//   (2) SCHEME NAMED BY HAND, not enumerated. Sign-out cleared exactly one scheme, hard-coded as the
		//       cookie scheme as a literal. Today the only second scheme any host adds is JwtBearer, which
		//       implements no sign-out handler and so holds no state to clear, so nothing is currently left
		//       behind - but a hard-coded scheme name would miss a future sign-out-capable scheme silently.
		//       Sign-out therefore enumerates the registered schemes and clears every one whose handler can
		//       actually sign out (see the loop below), falling back to the cookie scheme if none resolves.
		//   (3) NO SERVER-SIDE INVALIDATION. Deleting a cookie is a request to one browser. A COPY of that
		//       cookie - from a shared machine, a backup, a proxy log or a cross-site scripting payload -
		//       remained a fully valid credential for the rest of the ticket's lifetime, which pre-remediation
		//       was set 100 years ahead (finding H-03), and the legitimate user had no way at all to end it.
		//
		// RENAMED rather than merely made async, and the distinction is load-bearing: a method still called
		// Logout() that RETURNED Task would leave every existing `authService.Logout();` call site compiling
		// unchanged and STILL fire-and-forget, reintroducing defect (1) invisibly. Renaming makes the compiler
		// find every caller.
		//
		// BACKWARD COMPATIBILITY - review finding API-01. Renaming alone deleted a published member, which is a
		// source and binary break for external plugins, so the original `public void Logout()` is restored below
		// as a blocking wrapper over this method. That restoration does NOT reintroduce defect (1): the wrapper
		// returns void and waits for this task to complete, so sign-out is finished before control returns to the
		// caller. It is specifically a Task-returning Logout() that would have been unsafe, and that is not what
		// was added.
		public async Task LogoutAsync()
		{
			IHttpContextAccessor httpContextAccesor = (IHttpContextAccessor)serviceProvider.GetService(typeof(IHttpContextAccessor));
			HttpContext httpContext = httpContextAccesor?.HttpContext;
			if (httpContext == null)
				return;

			// Ordered first on purpose. Revocation reads the claim off the CURRENT principal, and signing out
			// below replaces it, so doing this afterwards would find nothing to revoke.
			RevokeCurrentSession(httpContext);

			// Every registered scheme whose handler can actually sign out, resolved from the scheme provider
			// rather than hard-coded, so a host that adds a second cookie scheme is covered without editing
			// this method. Two exclusions, both deterministic rather than defensive:
			//   * a handler that does not implement IAuthenticationSignOutHandler has nothing to sign out -
			//     JwtBearer is the case that matters here, because SignOutAsync cannot withdraw a bearer token:
			//     there is no server-side artifact for it to delete. That is NOT the same statement as "the
			//     session cannot be ended", which is what this comment used to claim and what made the residual
			//     look permanent. RevokeCurrentSession above has already recorded THIS session as revoked, and
			//     all three bearer decision points refuse a revoked identifier, so the bearer half of RISK-007
			//     is closed rather than accepted. Do not remove that call as dead code on the strength of this
			//     exclusion - it is the only thing that ends a bearer session (review findings CR2-F-02 for the
			//     mechanism and B3-SEAM-01 for reaching it from the shipped WebAssembly client);
			//   * PolicySchemeHandler only FORWARDS, and the JWT_OR_COOKIE policy scheme these hosts register
			//     configures no sign-out forward target, so naming it would raise rather than sign anything out.
			// Enumerating instead of guessing is what makes this exhaustive; the explicit fallback below keeps
			// the behaviour correct even if scheme resolution yields nothing at all.
			var schemeProvider = (IAuthenticationSchemeProvider)serviceProvider.GetService(typeof(IAuthenticationSchemeProvider));
			var signedOutAtLeastOneScheme = false;
			if (schemeProvider != null)
			{
				foreach (var scheme in await schemeProvider.GetAllSchemesAsync())
				{
					if (scheme.HandlerType == null)
						continue;
					if (!typeof(IAuthenticationSignOutHandler).IsAssignableFrom(scheme.HandlerType))
						continue;
					if (typeof(PolicySchemeHandler).IsAssignableFrom(scheme.HandlerType))
						continue;

					await httpContext.SignOutAsync(scheme.Name);
					signedOutAtLeastOneScheme = true;
				}
			}

			if (!signedOutAtLeastOneScheme)
				await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
		}

		/// <summary>
		/// Signs the current user out, preserving the signature published by earlier releases. New code should
		/// call <see cref="LogoutAsync"/> directly.
		/// </summary>
		/// <remarks>
		/// BACKWARD COMPATIBILITY - review finding API-01. Earlier releases published <c>void Logout()</c>, so
		/// removing it in favour of <see cref="LogoutAsync"/> alone would break source and binary compatibility
		/// for external plugins and packages built against this assembly.
		/// <para>
		/// This wrapper carries the full finding F8 remediation rather than the behaviour it replaces, because
		/// there is exactly one implementation: the current session is recorded as revoked, every sign-out-capable
		/// scheme is signed out, and - critically - all of it is COMPLETE before this method returns. That is the
		/// difference between this wrapper and the fire-and-forget defect the original method had: the original
		/// discarded a task, whereas this one waits for it. Returning void rather than Task is what makes that
		/// guarantee unavoidable at every call site.
		/// </para>
		/// <para>
		/// Blocking is safe for the same reason as in <see cref="Authenticate(string, string)"/>: ASP.NET Core
		/// installs no <c>SynchronizationContext</c>, and this path requires an active <c>HttpContext</c>.
		/// <c>GetAwaiter().GetResult()</c> preserves the original exception rather than wrapping it - though
		/// <see cref="LogoutAsync"/> is written not to throw, so this is contract hygiene rather than a live path.
		/// </para>
		/// </remarks>
		public void Logout()
		{
			LogoutAsync().GetAwaiter().GetResult();
		}

		// SECURITY - finding F8. Records the current sign-in as revoked so that any OTHER copy of the same
		// cookie is refused from its next request onwards.
		//
		// Every exit is silent and non-throwing by design: this runs on the sign-out path, where a failure to
		// record a revocation must not turn logging out into a server error that leaves the user signed in. An
		// absent or malformed claim means there is no session identity to record, so there is nothing this method
		// could revoke; both validators now REFUSE credentials of that shape outright (findings F-01 and F-02), so
		// returning early here leaves nothing accepted.
		//
		// F-02: this now revokes BEARER sessions as well as cookie ones, with no change to the code that does it.
		// Middleware/JwtMiddleware.cs assigns HttpContext.User from the presented token's claims, and
		// BuildTokenAsync now stamps the same session identifier into every token, so "the identifier the current
		// principal carries" resolves correctly whichever credential the caller signed out with.
		private static void RevokeCurrentSession(HttpContext httpContext)
		{
			var sessionIdClaim = httpContext.User?.FindFirst(CLAIM_SESSION_ID);
			if (sessionIdClaim == null || !Guid.TryParse(sessionIdClaim.Value, out var sessionId))
				return;

			// THREAT ADDRESSED - review finding OBS-06, CWE-778 (insufficient logging), OWASP A09:2021, and the
			// user-specified Authentication Hardening standard's "proper logout with session invalidation"
			// clause. Ending a session is a security-relevant state change and NOTHING recorded it: neither
			// Razor logout handler, nor the bearer revocation route, nor this method wrote an audit entry, so a
			// forensic reader could establish that a session had been revoked only by inference from the
			// absence of later activity. Read BEFORE the revocation, so the record describes a transition that
			// was actually made rather than one that was merely requested.
			//
			// AUDITED ON THE TRANSITION ONLY - live to revoked - and that is the bound, not an optimisation.
			// Revocation is idempotent and /logout is reachable by an authenticated caller as often as they
			// like, so an unconditional write here would let that caller drive unbounded log growth one
			// idempotent request at a time (CWE-779). A second logout with the same credential finds the
			// identifier already revoked and writes nothing.
			var alreadyRevoked = SessionRevocationService.IsSessionIdentifierRevoked(sessionId);

			// F-02: written through the process-wide store rather than through a resolved service instance. The
			// previous lookup returned null on any host that had not registered the service and then RETURNED, so a
			// logout silently recorded nothing while reporting success - the worst possible shape for a revocation
			// control, failing open at the exact moment the user is asking for protection. The store cannot be
			// absent, so that branch no longer exists.
			//
			// A full ticket lifetime measured from NOW, rather than the credential's own remaining time. It is a
			// deliberate over-estimate: reading the real ExpiresUtc would cost a second authenticate call, and
			// retaining a revocation slightly longer than the credential it kills is the safe direction to err -
			// the store clamps it to its own ceiling either way. The same value covers bearer credentials, whose
			// individual token lifetime is the same 24 hours (JWT_TOKEN_EXPIRY_DURATION_MINUTES), so no live token
			// can outlast its own revocation; the seven-day horizon is longer, but no token may be MINTED against a
			// revoked identifier, so the chain cannot be extended past the entry that ends it.
			//
			// THREAT ADDRESSED - review finding CR3-H-03, CWE-613 (insufficient session expiration) / session
			// hijacking, OWASP A07. The lifetime alone was NOT a sufficient over-estimate, and the error was in the
			// unsafe direction. A bearer credential is accepted until exp PLUS JwtClockSkew, so a token minted at T
			// is honoured until T + 1440 min + 1 min, while a revocation written at T + e expired at T + e + 1440
			// min. For every e shorter than the skew - that is, for a sign-out inside the first minute of a
			// credential's life, which is exactly what an "I logged in by mistake" or "log me out everywhere now"
			// action produces - the revocation lapsed BEFORE the credential stopped being accepted, leaving a
			// window of up to one minute in which the copied token worked again. Adding the skew closes it by
			// construction: no credential in existence when RevokeCurrentSession runs can have been minted later
			// than now (minting requires a non-revoked identifier), so its acceptance horizon is at most
			// now + AUTH_TICKET_EXPIRY_DURATION_MINUTES + JwtClockSkew, which is precisely the retention requested
			// here. Cookie tickets need no separate accounting: cookie authentication applies no skew, and sliding
			// expiration can only renew a ticket that is still being accepted, so their horizon is the strictly
			// smaller now + AUTH_TICKET_EXPIRY_DURATION_MINUTES.
			// SessionRevocationService.MaxRetention is the ceiling this value must stay under, and it was raised in
			// the same change for the same reason - at exactly 24 hours it would have clamped the skew straight back
			// off again, silently reinstating the defect. The two are one contract expressed in two files; keep them
			// in step.
			bool revocationRecorded = SessionRevocationService.RevokeSessionIdentifier(sessionId,
				DateTime.UtcNow.AddMinutes(AUTH_TICKET_EXPIRY_DURATION_MINUTES + JwtClockSkew.TotalMinutes));

			// THREAT ADDRESSED - review finding H-OPEN-01 (CWE-613 insufficient session expiration,
			// CWE-636 not failing securely), OWASP A07. The revocation is now DURABLE, which means it can
			// also FAIL - and a sign-out whose revocation was not recorded has deleted this browser's
			// cookie while leaving every copy of the credential working. That outcome used to be
			// unreportable because the write could not fail visibly; it is recorded here rather than
			// swallowed, because it is the one event that distinguishes "this session is closed
			// everywhere" from "this browser forgot its cookie". Recorded whatever the audit outcome, and
			// BEFORE the transition record below, so a reader sees the failure even if the trail then
			// shows nothing else. No exception is raised: the sign-out itself must still complete, since
			// leaving the user signed in as well would be strictly worse.
			if (!revocationRecorded)
			{
				SecurityAuditLog.Write(Diagnostics.LogType.Error, "AuthService:Logout",
					"Session revocation could not be recorded durably; copies of this credential remain valid until it expires.",
					"user_id=" + SecurityAuditLog.Field(httpContext.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value, MaxLogDetailLength));
			}

			if (alreadyRevoked)
				return;

			// WHAT THE RECORD CARRIES, and just as importantly what it does not. The acting principal's
			// identifier is recorded, because attribution is the entire point of a sign-out record. The SESSION
			// IDENTIFIER IS NOT, deliberately: it is the value both bearer validators and the cookie validation
			// hook consult, so persisting it into a table that any account with log access can read would
			// publish a working key to the revocation store and turn a forensic record into a source of
			// session-correlation material (CWE-532). Neither the bearer token nor the cookie ticket is
			// recorded, for the stronger version of the same reason - they ARE the credential.
			//
			// Written through the shared boundary, so it is bound, neutralised, explicitly DoNotNotify - never
			// LogService's mail-before-persist path (finding M-17) - and unable to throw: a sign-out must not
			// fail because its audit record could not be stored, and the boundary counts and reports what it
			// could not persist instead. Unbounded rather than rate limited on purpose: this event requires an
			// authenticated principal and a live session, so it is not free to repeat, and a genuine sign-out
			// must never be the record that gets withheld.
			var subject = httpContext.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
			SecurityAuditLog.RecordAudit("AuthService:Logout", Diagnostics.LogType.Info,
				"Session revoked on sign-out",
				"user_id=" + SecurityAuditLog.Field(subject, MaxLogDetailLength));
		}

		public static ErpUser GetUser(ClaimsPrincipal principal)
		{
			if (principal == null || principal.Claims == null || principal.Claims.Count() <= 0)
				return null;

			try
			{
				var claims = principal.Claims;
				Guid userId = new Guid(claims.Single(x => x.Type == ClaimTypes.NameIdentifier.ToString()).Value);
				return new SecurityManager().GetUser(userId);
			}
			catch
			{
				//any failure here means the ticket carries claims this build cannot use - missing, duplicated or
				//malformed identifier claims all land here - so the principal is treated as unauthenticated
				return null;
			}
		}

		#region <--- JWT Token related methods --->

		// Sentinel for the one failure of this method that means "the credential was judged and
		// rejected", as opposed to a server-side fault such as an absent signing key. The token
		// endpoint that calls this method has to tell those two apart before it records a failed
		// attempt against the account (finding H-16, CWE-307): counting a misconfiguration as a
		// credential failure would let a broken host lock out its own users. Exposed as a constant so
		// that classification is compile-time coupled to the throw below rather than matching a
		// magic string that a later edit could silently desynchronise. The text itself is unchanged,
		// so the response body callers already produce is byte-identical.
		public const string InvalidCredentialMessage = "Invalid email or password";

		/// <summary>
		/// Sentinel thrown when the credential is CORRECT but the account still owes a first-login password
		/// rotation. Deliberately distinct from <see cref="InvalidCredentialMessage"/>.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - finding C-01 (CWE-1392 use of a default credential, CWE-798), OWASP A07:2021.
		/// The distinctness matters twice over, and in opposite directions.
		/// <para>
		/// IT MUST NOT BE THE CREDENTIAL MESSAGE, because the token endpoint counts a failed attempt against
		/// the account's lockout budget precisely when it sees that string. The credential presented here is
		/// valid, so counting it would let the legitimate operator lock themselves out of the account by
		/// retrying the automation they were trying to configure - a self-inflicted denial of service caused
		/// by a hardening control. Classified as it is, the endpoint abandons the reserved attempt instead.
		/// </para>
		/// <para>
		/// IT IS ALSO NOT SURFACED TO THE CALLER, and that is intentional rather than an oversight. The token
		/// route is anonymous, so its existing production branch collapses every non-credential fault to a
		/// generic message; this outcome falls into that branch untouched, which is why closing this finding
		/// needed no change to the endpoint at all. The operator's actionable channel is the server-side log
		/// record the endpoint already writes, together with the provisioning notice that told them to rotate
		/// in the first place - not a response body that would confirm to an anonymous caller that a guessed
		/// password was in fact the bootstrap one.
		/// </para>
		/// </remarks>
		public const string PasswordRotationRequiredMessage = "Password rotation required before token issue";

		/// <summary>
		/// True when the account still carries the first-login rotation marker set by provisioning or by the
		/// schema version 4 revocation of the credential earlier releases shipped.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding C-01. A single definition shared by both token paths, so issue and refresh can
		/// never disagree about what "still owes a rotation" means. Null-tolerant throughout: an account whose
		/// preferences column is absent or empty deserialises to a default instance and reads as false, so a
		/// missing marker fails OPEN here by design - every account predating this remediation chose its own
		/// password and owes nothing, and treating absence as "required" would demand a rotation from every
		/// existing user on upgrade.
		/// </remarks>
		private static bool IsPasswordRotationRequired(ErpUser user)
		{
			return user?.Preferences?.PasswordChangeRequired == true;
		}

		public static async ValueTask<string> GetTokenAsync(string email, string password)
		{
			// THREAT ADDRESSED - review finding M-OPEN-05 (CWE-20 improper input validation with CWE-287
			// improper authentication), OWASP A07:2021. THE SECRET IS NO LONGER TRIMMED, and the trim must
			// not come back. A secret is an exact byte sequence: normalising it before verification means
			// this path and the cookie path judge the same submission differently, because
			// AuthenticateAsync above passes what the user typed straight to the same
			// SecurityManager.GetUser. That divergence cut both ways and both ways were wrong. An account
			// whose stored password legitimately begins or ends with whitespace - the write-time policy
			// permits it, and a generated passphrase pasted from a console can easily carry it - could sign
			// in interactively but could NEVER obtain a token, because the trimmed submission hashed to a
			// different value: a permanent, undiagnosable refusal of a correct credential. In the other
			// direction the trim ACCEPTED a submission that did not match the stored secret, so a client
			// sending " secret " authenticated against a stored "secret" here while being refused at the
			// login form. One shared verifier now sees one value.
			// THE E-MAIL NORMALISATION STAYS. It is an identifier, not a secret: GetUser matches it
			// case-insensitively anyway, so trimming and lower-casing changes no outcome, and removing it
			// would be an unrelated behaviour change to the token route's tolerance of padded input.
			var user = new SecurityManager().GetUser(email?.Trim()?.ToLowerInvariant(), password);
			if (user != null && user.Enabled)
			{
				// THREAT ADDRESSED - finding C-01 (CWE-1392, CWE-798), OWASP A07:2021. A credential the
				// platform chose - the password generated at provisioning, or the replacement written when
				// the version 4 migration revoked the default that earlier releases shipped - is refused a
				// bearer token until its owner replaces it. That is where the marker's teeth are: a machine
				// chosen password read off a console is exactly the kind of value that gets pasted into a
				// deployment script and then never changed, and a JWT is the surface that makes such a value
				// durable and portable. Checked AFTER the credential is verified, so this reveals nothing to
				// a caller who has not already presented the correct password.
				//
				// Interactive sign-in is deliberately NOT gated. SecurityManager.GetUser is shared with the
				// login page, so gating it here rather than on this specific path would have locked the
				// operator out of the only screen that can clear the marker, turning first-login rotation
				// into an unrecoverable installation.
				if (IsPasswordRotationRequired(user))
					throw new InvalidOperationException(PasswordRotationRequiredMessage);

				var (tokenString, token) = await BuildTokenAsync(user);
				return tokenString;
			}
			throw new Exception(InvalidCredentialMessage);
		}

		public static async ValueTask<string> GetNewTokenAsync(string tokenString)
		{
			JwtSecurityToken jwtToken = await GetValidSecurityTokenAsync(tokenString);
			if (jwtToken == null)
				return null;

			List<Claim> claims = jwtToken.Claims.ToList();
			if (claims.Count == 0)
				return null;

			// H-02 (CWE-613, OWASP A07): the absolute horizon is read from the presented token and enforced BEFORE any new
			// token is minted. Three properties make this actually bound the session rather than merely look like it:
			// (1) Fail closed on an absent or unparseable claim. A token that carries no horizon cannot be refreshed at
			//     all, so tokens minted before this fix are not grandfathered into unlimited renewal - they simply live
			//     out their remaining <=24h and the caller re-authenticates. The WebAssembly client already handles that
			//     outcome: a null response makes it drop the stored token (TokenManagerService.cs:L84-L87).
			// (2) Refuse once the horizon has passed, which is the actual fix - renewal now has an end.
			// (3) Carry the value VERBATIM into the replacement token instead of recomputing it, which is what stops the
			//     horizon from sliding forward one refresh at a time. BuildTokenAsync also caps the new token's expiry at
			//     this instant, so a refresh performed one minute before the horizon cannot produce a token that outlives
			//     it. Consequently no valid token can ever exist past the horizon and the check is not needed anywhere
			//     else in the validation path.
			DateTime? absoluteSessionExpiryUtc = ReadUtcBinaryClaim(claims, CLAIM_SESSION_ABSOLUTE_EXPIRY);
			if (absoluteSessionExpiryUtc == null || DateTime.UtcNow >= absoluteSessionExpiryUtc.Value)
				return null;

			// THREAT ADDRESSED - finding F-02 (CWE-613), OWASP A07. Refresh is the reason a bearer token needed a
			// revocable session identity at all: without this check, ending a session stopped nothing, because the
			// holder of a still-valid token could exchange it for a fresh one and keep doing so until the horizon
			// above ran out. Two refusals, both failing closed:
			//   * no parseable session identifier - a token this build would not have minted, so it is refused
			//     rather than granted a successor. Tokens issued before this change fall here and simply live out
			//     their own remaining lifetime, exactly as the horizon fix above already established for tokens
			//     with no horizon claim;
			//   * a revoked identifier - the session was ended, so no successor may be minted for it.
			// GetValidSecurityTokenAsync above has already applied the identical pair of refusals, so this is the
			// second of two independent checks rather than the only one; it is repeated here because this method is
			// the mint site, and a mint site must never rely on a caller having validated for it.
			Guid bearerSessionId = ReadSessionIdentifierClaim(claims);
			if (bearerSessionId == Guid.Empty || SessionRevocationService.IsSessionIdentifierRevoked(bearerSessionId))
				return null;

			//validate for active user
			var nameIdentifier = claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
			if (!string.IsNullOrWhiteSpace(nameIdentifier))
			{
				var user = new SecurityManager().GetUser(new Guid(nameIdentifier));
				// THREAT ADDRESSED - finding C-01 (CWE-1392, CWE-798), OWASP A07:2021. Refresh is gated on the
				// rotation marker as well as on Enabled, which closes a grandfathering hole rather than merely
				// restating the issue-path check: a token minted BEFORE the version 4 migration marked this
				// account could otherwise have been renewed indefinitely afterwards, so the migration would
				// have revoked the password without revoking access obtained with it. Returning null rather
				// than throwing is this method's established convention for every refusal, and the caller
				// already treats null as "refuse the refresh", so the outcome needs no new handling.
				if (user is not null && user.Enabled && !IsPasswordRotationRequired(user))
				{
					// F-02: the identifier read above is carried into the successor, never regenerated, so a
					// revocation recorded at any point continues to reject every token in this chain.
					var (newTokenString, newToken) = await BuildTokenAsync(user, absoluteSessionExpiryUtc.Value, bearerSessionId);
					return newTokenString;
				}
			}

			return null;
		}

		// Reads a claim written as DateTime.ToBinary() and returns it as UTC, or null when the claim is absent, not a
		// number, or not a representable DateTime. Returning null rather than throwing is deliberate: the sole caller
		// treats null as "refuse the refresh", so a malformed security claim fails closed instead of turning the
		// anonymous refresh endpoint into a 500 that echoes a stack trace.
		// F-02: reads the bearer session identifier, returning Guid.Empty when the claim is absent, blank, not a
		// GUID, or present more than once. Returning a sentinel rather than throwing matches this class's
		// established convention for malformed security claims, and every caller treats Guid.Empty as a refusal,
		// so a malformed identifier fails closed instead of turning a token endpoint into a 500.
		// A DUPLICATED claim is refused rather than resolved by taking the first: two identifiers in one token is
		// a shape this build never mints, and picking one would let a crafted token pair a revoked identifier with
		// an unrevoked decoy. This is defence in depth - the token is signed, so a client cannot add a claim - and
		// it costs one comparison.
		private static Guid ReadSessionIdentifierClaim(List<Claim> claims)
		{
			if (claims == null)
				return Guid.Empty;

			Guid sessionId = Guid.Empty;
			int seen = 0;
			foreach (var claim in claims)
			{
				if (!string.Equals(claim.Type, CLAIM_SESSION_ID, StringComparison.Ordinal))
					continue;

				seen++;
				if (seen > 1)
					return Guid.Empty;

				if (!Guid.TryParse(claim.Value, out sessionId))
					return Guid.Empty;
			}

			return sessionId;
		}

		/// <summary>
		/// Whether a bearer principal must be refused because its session is no longer accepted.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - finding F-02 (session hijacking via a non-revocable bearer token; CWE-613
		/// insufficient session expiration), OWASP A07. Bearer tokens are validated TWICE on these hosts and by
		/// two entirely independent validators: Middleware/JwtMiddleware.cs calls GetValidSecurityTokenAsync, while
		/// framework authorization for every [Authorize] endpoint runs the host's own AddJwtBearer handler, which
		/// the JWT_OR_COOKIE policy scheme forwards to. The handler is the one that actually authorises the
		/// request, so a revocation check present only in this assembly's validator would have been decorative.
		/// This predicate is the shared decision both paths use, exposed publicly for exactly one reason: the
		/// JwtBearer handler's options type lives in a package only the two token-issuing hosts reference, so the
		/// hook must be installed in those hosts while the RULE stays here, single-sourced. It is a pure
		/// predicate - it neither signs anything out nor writes any state - so a host can only use it to refuse.
		/// FAILS CLOSED on a principal with no parseable identifier, which is what makes this a control rather
		/// than a courtesy: an absent claim previously meant "not revoked", so any token shaped differently from
		/// what this build mints was granted the benefit of the doubt.
		/// </remarks>
		public static bool IsBearerSessionRevoked(ClaimsPrincipal principal)
		{
			if (principal == null)
				return true;

			Guid sessionId = ReadSessionIdentifierClaim(principal.Claims?.ToList());
			if (sessionId == Guid.Empty)
				return true;

			return SessionRevocationService.IsSessionIdentifierRevoked(sessionId);
		}

		private static DateTime? ReadUtcBinaryClaim(List<Claim> claims, string claimType)
		{
			var rawValue = claims.FirstOrDefault(x => x.Type == claimType)?.Value;
			if (string.IsNullOrWhiteSpace(rawValue))
				return null;

			if (!long.TryParse(rawValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out long binaryValue))
				return null;

			try
			{
				DateTime value = DateTime.FromBinary(binaryValue);
				return value.Kind == DateTimeKind.Utc ? value : value.ToUniversalTime();
			}
			catch (ArgumentException)
			{
				//FromBinary rejects values outside the representable DateTime range - treat as no horizon at all
				return null;
			}
		}

#pragma warning disable 1998
		public static async ValueTask<JwtSecurityToken> GetValidSecurityTokenAsync(string token)
		{
			// THREAT ADDRESSED - finding M-REV-07 (CWE-703 improper check of exceptional conditions, CWE-778
			// insufficient logging), OWASP A07:2021 + A09:2021. Two coupled defects lived in the three lines that
			// used to open this method.
			// (1) The signing key was built BEFORE the try. Encoding.UTF8.GetBytes(null) throws
			//     ArgumentNullException and SymmetricSecurityKey rejects null and empty material, so whenever
			//     'Settings:Jwt:Key' is unusable this method threw on its very first statement, OUTSIDE the
			//     handler that exists to classify and record failures. That is not an exotic condition: the two
			//     hosts that register Middleware/JwtMiddleware.cs - WebVella.Erp.Site and
			//     WebVella.Erp.Site.Project - are the only two declaring a 'Settings:Jwt' section, and both ship
			//     that section with an EMPTY Key because the secret-scrub finding requires the value to come from
			//     the environment. So under the configuration the repository actually ships, EVERY request
			//     carrying an Authorization header on EVERY host that runs this middleware raised an exception
			//     here, which then escaped into the middleware's catch and was discarded. The audit trail the
			//     catch block below was built to guarantee was structurally unreachable, and a configuration
			//     fault was indistinguishable from a forged token: both produced nothing at all.
			// (2) Because the throw came from a null configuration value rather than from the token, no amount of
			//     logging inside the try could have described it correctly.
			// The gate below is the fix for both. ErpSettings.IsJwtConfigured is the single platform-wide switch
			// for "is bearer-token authentication usable here?" (ErpSettings.cs), resolved once at startup by the
			// same acceptability rule the two token endpoints consult at Controllers/WebApiController.cs:L5312 and
			// :L5406. Consulting it here closes the one consumer that did not, so an unconfigured host now refuses
			// bearer tokens cheaply and deterministically instead of by exception. Returning null rather than
			// throwing is the established contract of this method - every other refusal path returns null, and
			// both callers already treat null as "no valid token" - so no caller behaviour changes.
			// Deliberately NOT logged: on an unconfigured host this is the expected steady state for every request
			// that carries a header, not an anomaly, so recording it would be an attacker-triggerable log flood
			// (the very property the rate bound below exists to prevent) rather than evidence.
			if (!ErpSettings.IsJwtConfigured)
				return null;

			var tokenHandler = new JwtSecurityTokenHandler();
			try
			{
				// M-REV-07: key construction moved inside the try. After the gate above, IsAcceptableJwtKey has
				// already proven the key is non-null, at least 32 bytes once UTF-8 encoded and not a published
				// default, so neither statement can throw on any reachable path today. They are inside the handler
				// so that they cannot become an unhandled throw again if that gate is ever weakened - the same
				// class of defect this finding reports, made structurally unable to recur.
				var mySecret = Encoding.UTF8.GetBytes(ErpSettings.JwtKey);
				var mySecurityKey = new SymmetricSecurityKey(mySecret);

				// H-02 (CWE-613 + CWE-347, OWASP A07): lifetime validation was absent, so an EXPIRED token still validated;
				// with the [AllowAnonymous] refresh endpoint GetNewJwtToken in Controllers/WebApiController.cs a stolen token was
				// indefinitely renewable. Analyzer CA5404 covers this; the clock skew is explicit so drift stays bounded.
				tokenHandler.ValidateToken(token,
				new TokenValidationParameters
				{
					ValidateIssuerSigningKey = true,
					ValidateIssuer = true,
					ValidateAudience = true,
					ValidateLifetime = true,
					ValidIssuer = ErpSettings.JwtIssuer,
					ValidAudience = ErpSettings.JwtAudience,
					IssuerSigningKey = mySecurityKey,
					ClockSkew = JwtClockSkew,
				}, out SecurityToken validatedToken);

				// THREAT ADDRESSED - finding F-02 (CWE-613 insufficient session expiration), OWASP A07. Signature,
				// issuer, audience and lifetime were all verified above and the token was then accepted - so a token
				// whose session had been ENDED was still a valid credential for the remainder of its lifetime, and
				// nothing a user or an administrator could do would stop it. Consulted only AFTER validation
				// succeeds, deliberately: an unauthenticated caller must not be able to probe the revocation store
				// with forged tokens, and a token that fails signature validation has no trustworthy claims to read.
				// Refusal is the same null every other rejection on this path returns, so no caller changes.
				//
				// THREAT ADDRESSED - review finding OBS-06, CWE-778 (insufficient logging), OWASP A09:2021.
				// This refusal used to be silent, on the reasoning that the sign-out which created the
				// revocation is itself audited. That reasoning conflated two different events: the sign-out
				// record says a user ended their session, while THIS record says somebody is still presenting
				// that credential afterwards - which is the signal that a token was copied before the sign-out
				// and is being replayed. Only the second is evidence of an attack, and it was the one not being
				// kept. The record is REQUIRED here rather than optional, because a revoked token that still
				// validates cryptographically is the single strongest indicator of theft this validator can see.
				//
				// The volume objection was real and is answered rather than ignored: the write goes through
				// SecurityAuditLog.RecordRateLimitedAudit, which admits at most one record per minute for this
				// source and reports everything it withheld as suppressed_by_rate_limit, so a caller looping on
				// one revoked token produces evidence OF a loop instead of a row per request. The session
				// identifier is deliberately not recorded - see RecordRevokedSessionReplay.
				var jwtSecurityToken = validatedToken as JwtSecurityToken;
				if (jwtSecurityToken == null)
					return null;

				Guid sessionId = ReadSessionIdentifierClaim(jwtSecurityToken.Claims?.ToList());
				if (sessionId == Guid.Empty)
					return null;

				if (SessionRevocationService.IsSessionIdentifierRevoked(sessionId))
				{
					RecordRevokedSessionReplay(jwtSecurityToken);
					return null;
				}

				return jwtSecurityToken;
			}
			// SECURITY - finding F11 (CWE-396 declaration of catch for generic exception), OWASP A09.
			// THREAT ADDRESSED: this was catch (Exception), so EVERY failure inside ValidateToken - including a
			// genuine defect in this build such as a null reference, an invalid cast or a missing assembly - was
			// converted into "the token is invalid" and returned as a clean null. Two consequences, and the second
			// is the security one: a real fault was silently mislabelled as an authorization outcome, and the
			// resulting audit record asserted a credential rejection that had never actually been judged, so the
			// authorization-failure trail this validator exists to produce could be populated with fiction.
			// NARROWED to the two families ValidateToken documents, and no wider:
			//   * SecurityTokenException is the root of every IdentityModel validation outcome - expired, not yet
			//     valid, bad signature, unknown signing key, wrong issuer, wrong audience, malformed, undecryptable -
			//     so one clause covers all of them and stays correct as the library adds more;
			//   * ArgumentException covers the input contract: ArgumentNullException for a null or empty token and
			//     ArgumentException for one past MaximumTokenSizeInBytes, both of which are ordinary hostile input
			//     on this path and must stay a 401 rather than becoming a 500.
			// Everything else now propagates into the error pipeline, where a defect belongs. The two clauses share
			// one recorder rather than duplicating it, so the audit behaviour cannot diverge between them.
			catch (SecurityTokenException ex)
			{
				RecordTokenValidationFailure(ex);
				return null;
			}
			catch (ArgumentException ex)
			{
				RecordTokenValidationFailure(ex);
				return null;
			}
		}

		// SECURITY - finding H-02 / F11. Records one rate-bounded, sanitised audit entry for a token that was
		// judged and rejected. Shared by the two narrowed catch clauses above so both audit identically.
		private static void RecordTokenValidationFailure(Exception ex)
		{
			// "Log authorization failures": failures here were swallowed in silence, so expired or forged tokens left no
			// audit trail. Three properties of this block are load-bearing and MUST survive any future tidy-up:
			// (1) DoNotNotify - LogService e-mails before it persists (M-17) and Middleware/JwtMiddleware.cs:L42 runs
			//     this validator for EVERY request carrying an Authorization header, so a notifying log here would be
			//     an attacker-triggered mail bomb and DoS amplifier rather than a fix.
			// (2) Rate-bounded - each write costs a BaseService construction plus a database insert, so a flood must
			//     produce evidence of a flood instead of a flood of evidence. Bounded PER FAILURE CATEGORY, and
			//     with the withheld volume counted: review finding OBS-09 records why a single global window was
			//     a blind spot rather than a limit, and tokenValidationLogSlots records why the exception type is
			//     the right partition key.
			// (3) Exception type and a DERIVED description only - never the raw token, which is a bearer credential,
			//     never a stack trace, and (P4-07) never the raw exception message, because IdentityModel composes
			//     that message out of the rejected token's own claim values.
			try
			{
				// CLR metadata, never payload text - see tokenValidationLogSlots for why the key may not be
				// derived from the request or from the rejected token.
				var failureCategory = ex == null ? "none" : ex.GetType().FullName;

				var writeLogEntry = false;
				var suppressedOccurrences = 0;
				TokenValidationReportSlot slot;
				lock (tokenValidationLogLock)
				{
					if (!tokenValidationLogSlots.TryGetValue(failureCategory, out slot))
					{
						slot = new TokenValidationReportSlot { LastWrittenUtc = DateTime.MinValue };
						tokenValidationLogSlots.Add(failureCategory, slot);
					}

					if (DateTime.UtcNow >= slot.LastWrittenUtc.AddMinutes(TOKEN_VALIDATION_LOG_INTERVAL_MINUTES))
					{
						slot.LastWrittenUtc = DateTime.UtcNow;
						writeLogEntry = true;

						// Read and cleared under the same lock that claims the window, so a concurrent
						// suppression cannot be counted into a record that has already been composed and then
						// lost when this one clears the counter. If the write below fails the count is restored,
						// so a database outage never erases the evidence of what the rate limit hid.
						suppressedOccurrences = slot.SuppressedOccurrences;
						slot.SuppressedOccurrences = 0;
					}
					else
					{
						// OBS-09: the occurrence the rate limit withheld is COUNTED rather than dropped, which is
						// what turns "one rejection was reported" into "one rejection was reported and n more
						// occurred" - the difference between an operator seeing a probe and seeing a flood.
						if (slot.SuppressedOccurrences < int.MaxValue)
							slot.SuppressedOccurrences += 1;
					}
				}

				if (writeLogEntry)
				{
					// P4-07: ex.Message is NOT passed. DescribeTokenValidationFailure returns a fixed description for
					// the failure category, optionally suffixed with the leading IDXnnnnn code, and SanitizeForLog
					// bounds and neutralises whatever comes back. The exception type name stays in the message
					// argument: it is CLR metadata from a loaded assembly, not payload text.
					// H-02 (CWE-778): any previously unrecorded audit-write losses are carried into this entry, so a
					// database outage that suppressed the authorization-failure trail is itself visible IN that trail
					// rather than only in the absence of records. Read before the write, subtracted only after it, so a
					// loss recorded concurrently by another request is carried forward instead of being discarded.
					var unreportedWriteFailures = Volatile.Read(ref tokenValidationAuditWriteFailures);
					var details = SanitizeForLog(DescribeTokenValidationFailure(ex));
					if (suppressedOccurrences > 0)
					{
						details = details + " | " + suppressedOccurrences.ToString(CultureInfo.InvariantCulture)
							+ " further occurrence(s) of this failure category within the reporting interval are"
							+ " represented by this entry.";
					}
					if (unreportedWriteFailures > 0)
					{
						details = details + " | " + unreportedWriteFailures.ToString(CultureInfo.InvariantCulture)
							+ " earlier token-validation audit entr(ies) could not be persisted and are unrecorded.";
					}

					var persisted = SecurityAuditLog.Write(Diagnostics.LogType.Error,
						"AuthService:GetValidSecurityTokenAsync",
						"JWT validation failed: " + ex.GetType().Name, details);

					if (!persisted)
					{
						// OBS-09: the suppressed volume this record was carrying has NOT been reported, so it is
						// returned to the slot rather than lost with the failed write. Counted as a lost audit
						// entry in the same breath, so the gap is visible in the next record that succeeds.
						lock (tokenValidationLogLock)
						{
							if (suppressedOccurrences > 0 && slot.SuppressedOccurrences <= int.MaxValue - suppressedOccurrences)
								slot.SuppressedOccurrences += suppressedOccurrences;
						}

						Interlocked.Increment(ref tokenValidationAuditWriteFailures);
						return;
					}

					if (unreportedWriteFailures > 0)
					{
						Interlocked.Add(ref tokenValidationAuditWriteFailures, -unreportedWriteFailures);
					}
				}
			}
			// An audit-logging failure must never escape and turn token validation into a server error. That
			// property is now supplied by SecurityAuditLog.Write, which reports a storage failure through its
			// RETURN VALUE and cannot throw: it narrows its own handling to the six storage families this write
			// can actually produce - Npgsql's DbException, the platform's own Database.DbException,
			// TimeoutException, IOException, InvalidOperationException and the NullReferenceException that
			// Diagnostics/Log.cs raises when the ambient DbContext is absent - counts each loss and emits an
			// out-of-band trace signal. The six catch clauses this replaces were an exact duplicate of that
			// list maintained here; keeping a second copy is how two failure-isolation policies drift apart,
			// which is the defect review finding OBS-04 reports across this codebase. This clause therefore
			// covers only what remains inside the try that is NOT the write itself - composing the description,
			// neutralising it and updating the reporting slot - none of which touches storage. Everything
			// outside that set, notably OutOfMemoryException, StackOverflowException, OperationCanceledException
			// and SecurityException, still propagates untouched, because a defect here is a defect and must not
			// be silently absorbed.
			catch (InvalidOperationException)
			{
				// The one non-storage fault the retained code can raise: a reporting slot mutated concurrently
				// through a path that did not take the lock would surface here rather than as a 500 on a request
				// that merely presented a bad token. Counted, never discarded, so the loss of a required
				// authorization-failure audit entry is visible in the next record that succeeds.
				Interlocked.Increment(ref tokenValidationAuditWriteFailures);
			}
		}

		/// <summary>
		/// Records that a cryptographically valid bearer token was refused because the session it names had
		/// been revoked - the observable signature of a credential copied before its owner signed out.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - review finding OBS-06, CWE-778 (insufficient logging) and CWE-613 (insufficient
		/// session expiration), OWASP A09:2021 and A07:2021.
		/// <para>
		/// This is the only place in the platform that can see the replay. The token passed signature, issuer,
		/// audience and lifetime validation, so it is genuine and unexpired; the ONLY reason it is being
		/// refused is that its session was ended. A legitimate client does not reach this state - it discards
		/// its token on sign-out - so every record here means some other holder of that credential is still
		/// using it.
		/// </para>
		/// <para>
		/// WHAT IS RECORDED, AND WHAT IS WITHHELD. The subject claim is recorded, because knowing WHICH account
		/// is being replayed is the whole forensic value; it is safe to record because the token's signature
		/// has already been verified, so the claim is not attacker-chosen. Withheld: the raw token, which IS
		/// the bearer credential; and the session identifier, which is the key the revocation store and both
		/// bearer validators consult - persisting it into a table readable by any account with log access would
		/// publish working revocation-store material and hand a reader the means to correlate sessions
		/// (CWE-532). The event is fully identified without either of them.
		/// </para>
		/// <para>
		/// RATE-BOUNDED THROUGH THE SHARED LEDGER. Replaying one token in a loop costs the caller nothing, so
		/// an unbounded write here would be an anonymous amplifier aimed at the audit trail (CWE-779).
		/// <c>RecordRateLimitedAudit</c> admits one record per minute for this source and reports the number it
		/// withheld, so attack volume stays visible while row count does not scale with it. It is explicitly
		/// non-notifying and cannot throw, which matters because this runs inside token validation: an audit
		/// failure must never turn a refusal into a server error.
		/// </para>
		/// </remarks>
		private static void RecordRevokedSessionReplay(JwtSecurityToken jwtToken)
		{
			// The subject claim is read defensively rather than assumed present: a token minted by an older
			// build, or one whose claim set was trimmed, must still be refused and still be recorded, and a
			// null here would otherwise turn the audit call into the very fault this method must not raise.
			// Field() renders an absent value as an unambiguous placeholder.
			var subject = jwtToken?.Claims?.FirstOrDefault(claim => claim.Type == ClaimTypes.NameIdentifier)?.Value;

			SecurityAuditLog.RecordRateLimitedAudit("AuthService:GetValidSecurityTokenAsync",
				Diagnostics.LogType.Error,
				"Bearer token refused - the session it names was revoked",
				"user_id=" + SecurityAuditLog.Field(subject, MaxLogDetailLength));
		}

		// H-02 (CWE-613, OWASP A07): absoluteSessionExpiryUtc is null only on a fresh credential authentication, where a
		// new horizon is opened. Every refresh passes the horizon it read from the presented token, which is what makes
		// the session bounded: the value is carried, never recomputed.
		//
		// F-02 (CWE-613, OWASP A07): bearerSessionId follows exactly the same carry-never-recompute rule, and for the
		// same reason. Null means "a fresh credential authentication", so a new identifier is minted; every refresh
		// passes the identifier it read from the presented token, which is what makes a revocation stick across
		// refreshes. Recomputing it here would let a refresh mint an unrevoked successor for a session that had just
		// been ended - the token equivalent of handing back the credential the user asked to destroy.
		private static async ValueTask<(string, JwtSecurityToken)> BuildTokenAsync(ErpUser user, DateTime? absoluteSessionExpiryUtc = null, Guid? bearerSessionId = null)
		{
			var claims = new List<Claim>();
			claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
			claims.Add(new Claim(ClaimTypes.Email, user.Email));
			user.Roles.ForEach(role => claims.Add(new Claim(ClaimTypes.Role.ToString(), role.Name)));

			// F-02: the session identity every bearer credential now carries. Guid.NewGuid is the platform's own
			// choice of session identifier at the cookie mint site and is used here for parity; it is a
			// cryptographically strong value on this runtime, and its only security requirement is that it be
			// unguessable to an attacker who cannot already read the signed token that contains it.
			// Guid.Empty is never minted: it is the value an absent or malformed claim parses to, and both
			// validators treat that as a refusal, so an identifier that collided with it would be self-revoking.
			Guid sessionId = bearerSessionId ?? Guid.NewGuid();
			if (sessionId == Guid.Empty)
				sessionId = Guid.NewGuid();
			claims.Add(new Claim(CLAIM_SESSION_ID, sessionId.ToString()));

			DateTime issuedUtc = DateTime.UtcNow;
			DateTime horizonCeiling = issuedUtc.AddMinutes(JWT_ABSOLUTE_SESSION_HORIZON_MINUTES);
			// A carried horizon is trusted only as an upper bound on itself: it is clamped to the ceiling so that the
			// policy is a hard limit rather than a value inherited from whatever a past or misconfigured build stamped.
			// For any token issued in the past the carried value is already below the ceiling, so this never extends a
			// session - it only refuses to honour an absurd one.
			DateTime absoluteExpiryUtc = absoluteSessionExpiryUtc ?? horizonCeiling;
			if (absoluteExpiryUtc > horizonCeiling)
				absoluteExpiryUtc = horizonCeiling;

			// Both timestamps are capped at the horizon so that neither the token itself nor the client's refresh hint can
			// point past it. Without the expiry cap a refresh performed just before the horizon would mint a token valid
			// for a further 24h beyond it, which would defeat the whole control.
			DateTime tokenExpiresUtc = issuedUtc.AddMinutes(JWT_TOKEN_EXPIRY_DURATION_MINUTES);
			if (tokenExpiresUtc > absoluteExpiryUtc)
				tokenExpiresUtc = absoluteExpiryUtc;

			DateTime tokenRefreshAfterDateTime = issuedUtc.AddMinutes(JWT_TOKEN_FORCE_REFRESH_MINUTES);
			if (tokenRefreshAfterDateTime > absoluteExpiryUtc)
				tokenRefreshAfterDateTime = absoluteExpiryUtc;

			claims.Add(new Claim(type: "token_refresh_after", value: tokenRefreshAfterDateTime.ToBinary().ToString(CultureInfo.InvariantCulture)));
			claims.Add(new Claim(type: CLAIM_SESSION_ABSOLUTE_EXPIRY, value: absoluteExpiryUtc.ToBinary().ToString(CultureInfo.InvariantCulture)));

			var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(ErpSettings.JwtKey));
			var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
			// M-04 (CWE-613, OWASP A07): expiry came from server-local time, so 'exp' shifted with the host's UTC offset
			// and across DST - real slack now that lifetime is enforced above. UTC, matching tokenRefreshAfterDateTime.
			var tokenDescriptor = new JwtSecurityToken(ErpSettings.JwtIssuer, ErpSettings.JwtAudience, claims,
						expires: tokenExpiresUtc, signingCredentials: credentials);
			return (new JwtSecurityTokenHandler().WriteToken(tokenDescriptor), tokenDescriptor);
		}
#pragma warning restore 1998

		/// <summary>
		/// Maps a token-validation exception onto a fixed description of WHY the token was rejected, optionally suffixed
		/// with the leading IdentityModel diagnostic code.
		/// </summary>
		/// <remarks>
		/// P4-07 (CWE-117, CWE-532). Every value this returns is a compile-time constant except the allow-listed
		/// IDXnnnnn code, so no part of the rejected token can reach the persisted record. Observability is not merely
		/// preserved but sharpened: the failure CATEGORY is now stable text an operator can group and alert on, rather
		/// than a message whose wording shifts between IdentityModel versions.
		/// Dispatch is on the EXACT type name rather than on type patterns, for two deliberate reasons. First, these
		/// exception types form an inheritance chain - SecurityTokenExpiredException derives from
		/// SecurityTokenValidationException, which derives from SecurityTokenException - so a pattern-matching switch
		/// silently depends on its own case ORDER, and a later reordering would quietly collapse specific categories into
		/// a general one. Name matching cannot be broken that way. Second, the set of types differs across IdentityModel
		/// versions; naming them as strings means an entry for a type absent from the referenced version simply never
		/// matches, instead of failing to compile.
		/// </remarks>
		private static string DescribeTokenValidationFailure(Exception ex)
		{
			var description = ex.GetType().Name switch
			{
				"SecurityTokenExpiredException" => "The token's lifetime has ended.",
				"SecurityTokenNotYetValidException" => "The token is not valid yet; its not-before time is in the future.",
				"SecurityTokenInvalidLifetimeException" => "The token's not-before and expiry times are inconsistent.",
				"SecurityTokenNoExpirationException" => "The token carries no expiry claim.",
				"SecurityTokenInvalidSignatureException" => "The token's signature did not verify.",
				"SecurityTokenSignatureKeyNotFoundException" => "No configured signing key matched the token's key identifier.",
				"SecurityTokenInvalidSigningKeyException" => "The token's signing key was rejected.",
				"SecurityTokenInvalidAlgorithmException" => "The token's signing algorithm is not permitted.",
				"SecurityTokenInvalidIssuerException" => "The token's issuer is not accepted.",
				"SecurityTokenInvalidAudienceException" => "The token's audience is not accepted.",
				"SecurityTokenInvalidTypeException" => "The token's type header is not accepted.",
				"SecurityTokenReplayDetectedException" => "The token was replayed.",
				"SecurityTokenReplayAddFailedException" => "The token could not be recorded for replay detection.",
				"SecurityTokenDecryptionFailedException" => "The token could not be decrypted.",
				"SecurityTokenEncryptionKeyNotFoundException" => "No configured key matched the token's encryption key identifier.",
				"SecurityTokenKeyWrapException" => "The token's content encryption key could not be unwrapped.",
				"SecurityTokenMalformedException" => "The token is not well formed.",
				"SecurityTokenValidationException" => "The token failed validation.",
				"SecurityTokenException" => "The token was rejected.",
				"SecurityTokenArgumentException" => "The token was not supplied in a usable form.",
				"ArgumentNullException" => "No token was supplied.",
				"ArgumentException" => "The token is not a well-formed JSON Web Token.",
				_ => "The token was rejected for a reason this service does not classify.",
			};

			var code = ExtractDiagnosticCode(ex.Message);
			return code is null ? description : string.Concat(description, " (", code, ")");
		}

		/// <summary>
		/// Returns the leading IdentityModel diagnostic code of a message - 'IDX' followed by digits - or null when the
		/// message does not begin with one.
		/// </summary>
		/// <remarks>
		/// P4-07. This is the ONE fragment of the original message that is still retained, and it is retained because it
		/// is the most diagnostically valuable part while being provably non-sensitive: IdentityModel always emits the
		/// code as the very first token, BEFORE any interpolated value, so reading only a leading 'IDX' plus digits
		/// cannot capture an issuer, audience, key identifier or timestamp. It is allow-listed by construction - the
		/// prefix is compared ordinally and every subsequent character must be an ASCII digit - and the scan stops at
		/// <see cref="MaxDiagnosticCodeLength"/>, so a hostile message length buys no work here.
		/// </remarks>
		private static string ExtractDiagnosticCode(string message)
		{
			if (string.IsNullOrEmpty(message) || !message.StartsWith("IDX", StringComparison.Ordinal))
			{
				return null;
			}

			var length = 3;
			while (length < message.Length && length < MaxDiagnosticCodeLength && char.IsAsciiDigit(message[length]))
			{
				length++;
			}

			// 'IDX' with no digits after it is not a code, so nothing is retained rather than retaining a bare prefix.
			return length > 3 ? message.Substring(0, length) : null;
		}

		/// <summary>
		/// Bounds a value destined for a persisted log record and replaces control characters with spaces.
		/// </summary>
		/// <remarks>
		/// P4-07 (CWE-117). Applied at the LOGGING BOUNDARY rather than inside the table, so the guarantee holds
		/// structurally: it does not depend on every present and future entry of
		/// <see cref="DescribeTokenValidationFailure(Exception)"/> being individually short and clean. Newlines and
		/// carriage returns are what let a crafted value forge additional entries in a line-oriented log, and they are
		/// control characters, so replacing rather than stripping them keeps the text readable while removing the
		/// injection primitive.
		/// <para>
		/// DELEGATED, not reimplemented. The identical bound-then-neutralise logic is required by the login audit and
		/// by both anonymous token routes, so it now lives once in <see cref="SecurityAuditLog.Normalize"/> and this
		/// method is the thin binding of that helper to this class's own <see cref="MaxLogDetailLength"/>. Two copies
		/// of a neutralisation routine are two things that can drift apart, and a divergence here would be silent -
		/// the log would still look correct while one of the two paths had stopped neutralising. Behaviour is
		/// unchanged: the helper bounds before scanning and replaces control characters with spaces, exactly as the
		/// body it replaces did.
		/// </para>
		/// </remarks>
		private static string SanitizeForLog(string value)
		{
			return SecurityAuditLog.Normalize(value, MaxLogDetailLength);
		}



		#endregion

	}
}
