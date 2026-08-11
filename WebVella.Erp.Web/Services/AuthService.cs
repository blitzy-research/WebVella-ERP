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
// SECURITY (CWE-117): supplies SecurityAuditLog.Normalize, the single shared bound-and-neutralise routine
// SanitizeForLog delegates to, so this class and the login and token-route audit paths cannot drift apart.
using WebVella.Erp.Web.Utils;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace WebVella.Erp.Web.Services
{
	public class AuthService
	{
		private const double JWT_TOKEN_EXPIRY_DURATION_MINUTES = 1440;
		private const double JWT_TOKEN_FORCE_REFRESH_MINUTES = 120;

		// H-02 (CWE-613, OWASP A07): unbounded session renewal. Refresh minted a brand new 24h token from any
		// still-valid token, so an attacker holding one captured token could keep it alive for ever without ever
		// presenting the credential again. This is the absolute horizon, stamped once at authentication and carried
		// verbatim across every refresh rather than recomputed.
		private const double JWT_ABSOLUTE_SESSION_HORIZON_MINUTES = 10080;

		// Claim carrying that horizon, written as DateTime.ToBinary() rendered invariantly - deliberately identical
		// to the token_refresh_after idiom below, because the WebAssembly client parses that claim shape with
		// DateTime.FromBinary(long.Parse(..)) and a different encoding would throw inside the browser.
		private const string CLAIM_SESSION_ABSOLUTE_EXPIRY = "session_absolute_expiry";

		// H-03 (CWE-613, OWASP A07): bound for the cookie authentication ticket, and NOT a peer of the hosts'
		// ExpireTimeSpan. CookieAuthenticationHandler applies ExpireTimeSpan ONLY when the ticket carries no explicit
		// ExpiresUtc, so the value here always wins and the hosts' declaration is inert unless the two agree. The
		// single place the hosts get their window from is
		// ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie, which declares the same 1440; keep them in step.
		// 1440 minutes is an IDLE window, not a session cap - the cap is the horizon below.
		private const double AUTH_TICKET_EXPIRY_DURATION_MINUTES = 1440;

		// Absolute ceiling on a cookie session, past which no amount of activity can carry it.
		//
		// CWE-613, OWASP A07. Sliding expiration is mandated by Agent Action Plan section 0.6.1 Class 6 and is a real
		// idle-timeout control, but on its own it is also an indefinite-renewal primitive: the handler slides the
		// window forward on any request past the halfway point, so a stolen cookie need only be polled to live for
		// ever. Seven days matches JWT_ABSOLUTE_SESSION_HORIZON_MINUTES, so cookie and bearer sessions die together.
		private const double AUTH_TICKET_ABSOLUTE_SESSION_HORIZON_MINUTES = 10080;

		// Authentication-property item carrying that horizon. Stamped into AuthenticationProperties.Items rather than
		// into a claim on purpose: Items round-trip through sliding renewal untouched, because the handler rewrites
		// only IssuedUtc and ExpiresUtc, so the horizon is fixed at authentication and cannot be pushed forward by
		// the very renewal it bounds. It also travels inside the encrypted, signed ticket.
		private const string AUTH_TICKET_ABSOLUTE_EXPIRY_ITEM = "wv_session_absolute_expiry";

		// SECURITY (CWE-613 insufficient session expiration), OWASP A07. The two JWT validators disagreed about clock
		// drift: this one passed an explicit one-minute skew while both hosts' AddJwtBearer registrations omitted
		// ClockSkew and kept IdentityModel's FIVE-MINUTE default. Framework authorization runs the HOST's parameters,
		// not these, so an expired bearer principal stayed authorized for up to four minutes longer than the platform
		// believed. PUBLIC AND SHARED so both hosts consume THIS member and parity is compile-time coupled.
		public static readonly TimeSpan JwtClockSkew = TimeSpan.FromMinutes(1);

		// SECURITY (session hijacking; CWE-613), OWASP A07: the claim carrying the per-sign-in session identifier
		// that makes a credential revocable. Internal, not private, because the cookie validation hook that enforces
		// revocation is wired centrally in ErpMvcExtensions, so the mint site and the check site must name the SAME
		// claim; internal, not public, because all those sites are in this assembly, which keeps the claim name out
		// of the library's public surface as the no-API-change constraint requires.
		//
		// THREAT ADDRESSED: this used to be stamped into cookie tickets ONLY, on the reasoning that "a bearer
		// credential has no server-side session to end" - which inverted the problem, since it had none precisely
		// BECAUSE nothing identified the session. A stolen token could then not be revoked by any means, and refresh
		// kept minting successors up to the seven-day horizon. It is now minted into every token, carried verbatim
		// across refresh, and consulted by both bearer validators.
		internal const string CLAIM_SESSION_ID = "erp_session_id";

		// Suppression window for the token-validation failure log in GetValidSecurityTokenAsync, guarded by the
		// plain lock idiom this project already uses, so a request flood cannot flood the log.
		private const double TOKEN_VALIDATION_LOG_INTERVAL_MINUTES = 1;
		private static readonly object tokenValidationLogLock = new object();

		// CWE-778 (insufficient logging), OWASP A09. This window used to be a single PROCESS-GLOBAL slot, which made
		// it a monitoring blind spot rather than a rate limit: one high-volume failure category claimed the slot and
		// hid EVERY OTHER token-validation failure for the rest of the minute. THE PARTITION KEY IS THE EXCEPTION
		// TYPE NAME, deliberately: it is CLR metadata, so it carries no payload from the rejected token and cannot
		// become a log-injection or disclosure vector (CWE-117, CWE-532), and its cardinality is bounded by the types
		// that can reach the two narrowed catch clauses, so a caller cannot grow this dictionary (CWE-770).
		// Partitioning by remote address WOULD have been caller-controlled and unbounded.
		private static readonly Dictionary<string, TokenValidationReportSlot> tokenValidationLogSlots =
			new Dictionary<string, TokenValidationReportSlot>(StringComparer.Ordinal);

		/// <summary>
		/// Per-category reporting window and suppressed-occurrence count for the token-validation audit log.
		/// </summary>
		/// <remarks>
		/// A mutable holder rather than two parallel dictionaries, so a category's window and its suppressed count
		/// cannot be updated inconsistently. Every field is read and written under
		/// <see cref="tokenValidationLogLock"/>, which is why no member needs to be volatile or interlocked.
		/// </remarks>
		private sealed class TokenValidationReportSlot
		{
			internal DateTime LastWrittenUtc;
			internal int SuppressedOccurrences;
		}

		// CWE-117 (improper output neutralisation for logs), CWE-532. The failure log used to persist the raw
		// exception message, and IdentityModel builds its messages from the token being rejected - embedding the
		// audience, issuer, expiry or key identifier - so the raw message copied token-derived values verbatim into a
		// persisted record with no length bound. Details are rebuilt from a fixed table below instead.
		private const int MaxLogDetailLength = 200;

		// Upper bound on how much of a message is inspected while looking for a leading IDXnnnnn code: 'IDX' plus at
		// most nine digits, so a hostile message length cannot buy work here.
		private const int MaxDiagnosticCodeLength = 12;

		// SECURITY (H-02, CWE-778): fallback counter for token-validation audit entries that could not be persisted.
		// Writing the audit record needs the database, so an outage there would otherwise make the loss of the
		// authorization-failure trail completely invisible. The count is carried into the next audit entry that does
		// succeed, and is only ever mutated through Interlocked/Volatile so recording a loss can never itself throw.
		private static int tokenValidationAuditWriteFailures;

		private IServiceProvider serviceProvider;

		public AuthService(IServiceProvider serviceProvider)
		{
			this.serviceProvider = serviceProvider;
		}

		/// <summary>
		/// Normalises the credential IDENTIFIER - and only the identifier - so both entry points judge one
		/// submission identically.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding N33, and the correction of record for finding CK-09. CK-09's remediation
		/// stated that both paths "verify the identical byte sequence". That was true of the PASSWORD, which is
		/// never trimmed anywhere in this file, and false of the identifier: the bearer path trimmed and
		/// case-folded it while the cookie path passed it through untouched, so " user@example.com " obtained a
		/// bearer token yet failed interactive sign-in. Direction of the asymmetry was permissive-for-bearer, so
		/// it was a behavioural-consistency defect rather than a privilege weakness - but a credential path whose
		/// two entry points disagree about what the submitted identifier IS cannot be reasoned about, so the
		/// normalisation now lives in exactly one place that both call.
		/// <para>
		/// TRIM ONLY, AND THE TWO OMISSIONS ARE DELIBERATE. Case folding is dropped because it is immaterial and
		/// was lossy: SecurityManager resolves candidates with <c>lower(email) = lower(@email)</c> on a BOUND
		/// parameter and then decides authoritatively with <c>StringComparison.OrdinalIgnoreCase</c>, so folding
		/// changed no matched set, while it did defeat the <c>ORDER BY (email = @email) DESC</c> exact-spelling
		/// preference that keeps a case-fold duplicate set deterministic. Trimming cannot lock any account out,
		/// because <c>SecurityManager.IsValidEmail</c> accepts an address only when
		/// <c>new MailAddress(value).Address == value</c>, and MailAddress strips surrounding whitespace - so no
		/// stored address can carry any. The SECRET is still never normalised: see the comment in
		/// <see cref="GetTokenAsync(string, string)"/> for why that must not change.
		/// </para>
		/// </remarks>
		/// <param name="email">The caller-supplied identifier, or null.</param>
		private static string NormalizeCredentialIdentifier(string email)
		{
			return email?.Trim();
		}

		// M-03 (OWASP A07): asynchronous because the sign-in below must be awaited - a fire-and-forget sign-in can
		// return before the authentication cookie is written. The -Async suffix is load-bearing: the previous release
		// published "public ErpUser Authenticate(string, string)", so changing that member's return type would be a
		// source and binary break, and the original signature is preserved by the blocking wrapper below.
		public async Task<ErpUser> AuthenticateAsync(string email, string password)
		{
			// Review finding N33 - the SAME normalisation the bearer path applies, through the SAME member, so the
			// two entry points cannot drift apart again.
			var user = new SecurityManager().GetUser(NormalizeCredentialIdentifier(email), password);
			if (user != null && user.Enabled)
			{
				var claims = new List<Claim>();
				claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
				claims.Add(new Claim(ClaimTypes.Email, user.Email));
				user.Roles.ForEach(role => claims.Add(new Claim(ClaimTypes.Role.ToString(), role.Name)));

				// SECURITY (session hijacking; CWE-613, CWE-384), OWASP A07. The ticket carried nothing identifying the
				// SIGN-IN, only the user, so there was no handle by which a single session could be ended: logging out could
				// only delete the cookie from the browser that asked, and any copy stayed valid for the full ticket lifetime.
				// A fresh value per sign-in, never derived from the user, so revoking one session cannot end another and a
				// captured identifier is not predictable from a previous one; Guid.NewGuid is the CSPRNG requirement.
				claims.Add(new Claim(CLAIM_SESSION_ID, Guid.NewGuid().ToString()));

				var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

				// CWE-613, OWASP A07: the frozen session contract is a 24-hour SLIDING window, and sliding renewal requires
				// BOTH the host's SlidingExpiration and this flag, so with this false the mandated sliding half was
				// unreachable whatever the hosts declared. The indefinite-renewal weakness that made disabling it look
				// attractive is closed properly instead, by the absolute horizon stamped below. Those are one change: do not
				// enable this without the horizon, and do not remove the horizon while this is enabled.
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

				// Stamped once, here, and never recomputed. Rendered as Unix seconds in the invariant culture so the value
				// is culture-independent and parses back without ambiguity; a malformed or absent stamp is treated as an
				// expired session by the validator, which fails closed.
				authProperties.Items[AUTH_TICKET_ABSOLUTE_EXPIRY_ITEM] =
					issuedUtc.AddMinutes(AUTH_TICKET_ABSOLUTE_SESSION_HORIZON_MINUTES).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);

				IHttpContextAccessor httpContextAccesor = (IHttpContextAccessor)serviceProvider.GetService(typeof(IHttpContextAccessor));
				// M-03 (OWASP A07): the discarded Task raced the response, so the authentication cookie could be absent
				// from it and any sign-in exception went unobserved. Awaited, so the cookie is written before we return.
				await httpContextAccesor.HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);
				return user;
			}
			else
				return null;
		}

		/// <summary>
		/// Authenticates a set of credentials and establishes the authentication cookie, preserving the signature
		/// published by earlier releases. New code should call
		/// <see cref="AuthenticateAsync(string, string)"/> directly.
		/// </summary>
		/// <param name="email">The account's e-mail address.</param>
		/// <param name="password">The candidate password.</param>
		/// <returns>The authenticated user, or <c>null</c> when the credentials are rejected or the account is disabled.</returns>
		/// <remarks>
		/// BACKWARD COMPATIBILITY: earlier releases published this exact signature, so removing it or changing its
		/// return type would be a source and binary break for external plugins. A thin shim over
		/// <see cref="AuthenticateAsync(string, string)"/>, so no caller loses the security fixes that method
		/// carries - notably the genuinely awaited sign-in, which is the whole of M-03. Blocking is not a latent
		/// deadlock: ASP.NET Core installs no <c>SynchronizationContext</c>, and this method cannot be reached
		/// outside a request. <c>GetAwaiter().GetResult()</c> rather than <c>.Result</c>, so a failure surfaces as
		/// the original exception rather than an <c>AggregateException</c>.
		/// </remarks>
		public ErpUser Authenticate(string email, string password)
		{
			return AuthenticateAsync(email, password).GetAwaiter().GetResult();
		}

		// Enforces the absolute session horizon on every authenticated request. Wired once, for all seven hosts, by
		// ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie.
		//
		// CWE-613, OWASP A07. Sliding expiration turns the 24-hour window into an idle timeout, but the framework's
		// renewal is unbounded, so without this ceiling a cookie could be slid forward for ever by anything that
		// merely keeps touching it. Rejection is deliberately silent - an expired session is a normal lifecycle event
		// on an anonymous-reachable path, so logging it would let a caller replaying one cookie drive unbounded log
		// growth - and the method is written so it cannot throw, since an exception escaping principal validation
		// would surface as a 500 on every request carrying a cookie.
		public static async Task ValidateSessionHorizonAsync(CookieValidatePrincipalContext context)
		{
			if (context == null)
				return;

			// CWE-613, CWE-636 (not failing securely), OWASP A07. This check used to RETURN, accepting the ticket,
			// whenever the horizon stamp was absent - which made the absolute-session ceiling optional from the ticket's
			// own point of view. Anything that can produce an unstamped ticket - an older build behind the same load
			// balancer, a restored backup, a re-used data-protection key ring, a future path that signs in without going
			// through Authenticate - produced a session with NO ceiling. FAILING CLOSED instead: Authenticate stamps this
			// item in the same operation that mints the ticket, and the stamp travels inside the encrypted, signed ticket
			// so no client can strip it. COST: any session held from before this deployment is signed out once.
			if (context.Properties == null
				|| !context.Properties.Items.TryGetValue(AUTH_TICKET_ABSOLUTE_EXPIRY_ITEM, out string stampedHorizon)
				|| stampedHorizon == null)
			{
				await RejectAndSignOutAsync(context);
				return;
			}

			// Present but unreadable is treated as expired. Unreachable from outside - the value is written by this
			// class alone, inside a signed ticket - so failing closed costs nothing and leaves no shape of stamp that
			// silently disables the ceiling.
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

		// The single rejection path for ticket validation, extracted so the two refusals above - an unrecognised
		// ticket shape and an expired horizon - cannot drift apart. Rejects FIRST and clears the cookie afterwards,
		// so the current request is already unauthenticated even if the cookie cannot be cleared; the security
		// outcome never depends on the cleanup succeeding.
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
				// expired cookie could be cleared from the response. Swallowing keeps a failed cookie deletion from
				// becoming a server error on a path every authenticated request travels.
			}
		}

		// SECURITY H-02 (session hijacking; CWE-613), OWASP A07. Three distinct defects in four lines: (1) FIRE AND
		// FORGET - the returned Task was discarded, so sign-out raced the response and the cookie-deletion header
		// could be silently dropped, leaving the user signed in with no error anywhere; (2) only the cookie scheme
		// was named, so a host with a second sign-out-capable scheme kept it live; (3) nothing identified the
		// sign-in, so no single session could be ended - and the ticket expiry was set 100 years ahead (H-03).
		// RENAMED rather than merely made async, and that is load-bearing: a method still called Logout() returning
		// Task would leave every call site compiling unchanged and STILL fire-and-forget.
		public async Task LogoutAsync()
		{
			IHttpContextAccessor httpContextAccesor = (IHttpContextAccessor)serviceProvider.GetService(typeof(IHttpContextAccessor));
			HttpContext httpContext = httpContextAccesor?.HttpContext;
			if (httpContext == null)
				return;

			// Ordered first on purpose. Revocation reads the claim off the CURRENT principal, and signing out below
			// replaces it, so doing this afterwards would find nothing to revoke.
			RevokeCurrentSession(httpContext);

			// Every registered scheme whose handler can actually sign out, resolved from the scheme provider rather than
			// hard-coded, so a host that adds a second cookie scheme is covered without editing this method. Two
			// deterministic exclusions: a handler not implementing IAuthenticationSignOutHandler has nothing to sign out -
			// JwtBearer, where there is no server-side artifact to delete, which is NOT the same as "the session cannot
			// be ended", since RevokeCurrentSession above has already recorded it as revoked and all three bearer
			// decision points refuse a revoked identifier (so do not remove that call as dead code on the strength of
			// this exclusion); and PolicySchemeHandler only FORWARDS, with no sign-out forward target configured.
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
		/// Signs the current user out, preserving the signature published by earlier releases. New code should call
		/// <see cref="LogoutAsync"/> directly.
		/// </summary>
		/// <remarks>
		/// BACKWARD COMPATIBILITY: earlier releases published <c>void Logout()</c>, so removing it would be a source
		/// and binary break for external plugins. Returning void rather than Task is also what makes "sign-out is
		/// complete before control returns" unavoidable at every call site.
		/// <para>
		/// EXCEPTION CONTRACT: <see cref="LogoutAsync"/> has no enclosing catch, so a fault raised while resolving
		/// the authentication schemes or while a handler signs out DOES propagate through this wrapper.
		/// <c>GetAwaiter().GetResult()</c> rather than <c>.Result</c>, so it surfaces as the original exception
		/// rather than an <c>AggregateException</c>; callers that must not fail on sign-out have to handle it.
		/// </para>
		/// </remarks>
		public void Logout()
		{
			LogoutAsync().GetAwaiter().GetResult();
		}

		// SECURITY H-02. Records the current sign-in as revoked so any OTHER copy of the credential is refused from
		// its next request onwards. Every exit is silent and non-throwing by design: a failure to record a revocation
		// must not turn logging out into a server error that leaves the user signed in, and an absent or malformed
		// claim means there is no session identity to record - both validators refuse credentials of that shape
		// outright. This covers BEARER sessions too, because BuildTokenAsync stamps the same identifier into tokens.
		private static void RevokeCurrentSession(HttpContext httpContext)
		{
			var sessionIdClaim = httpContext.User?.FindFirst(CLAIM_SESSION_ID);
			if (sessionIdClaim == null || !Guid.TryParse(sessionIdClaim.Value, out var sessionId))
				return;

			// CWE-778 (insufficient logging), OWASP A09, and the Authentication Hardening standard's "proper logout with
			// session invalidation" clause. NOTHING recorded the end of a session, so a forensic reader could establish a
			// revocation only by inference from the absence of later activity. Read BEFORE the revocation, so the record
			// describes a transition actually made. AUDITED ON THE TRANSITION ONLY - live to revoked - and that is the
			// bound, not an optimisation: revocation is idempotent and /logout is reachable as often as an authenticated
			// caller likes (CWE-779).
			var alreadyRevoked = SessionRevocationService.IsSessionIdentifierRevoked(sessionId);

			// Written through the process-wide store rather than a resolved service instance, because a lookup returning
			// null on a host that had not registered the service would RETURN - failing open at the exact moment the user
			// is asking for protection.
			//
			// SECURITY H-02 (CWE-613) / session hijacking, OWASP A07. Retention is a full ticket lifetime from NOW plus
			// the bearer clock skew. Measuring from now is a deliberate over-estimate, because erring long is the safe
			// direction; the skew is required because a bearer credential is accepted until exp PLUS JwtClockSkew, so for
			// a sign-out inside the first minute of a credential's life a revocation without it lapsed BEFORE the
			// credential stopped being accepted. SessionRevocationService.MaxRetention is the ceiling this must stay
			// under - at exactly 24 hours it would clamp the skew straight back off - so keep the two in step.
			bool revocationRecorded = SessionRevocationService.RevokeSessionIdentifier(sessionId,
				DateTime.UtcNow.AddMinutes(AUTH_TICKET_EXPIRY_DURATION_MINUTES + JwtClockSkew.TotalMinutes));

			// CWE-613 (insufficient session expiration), CWE-636 (not failing securely), OWASP A07. The revocation is
			// DURABLE, which means it can also FAIL - and a sign-out whose revocation was not recorded has deleted this
			// browser's cookie while leaving every copy of the credential working. It is recorded rather than
			// swallowed, because it is the one event that distinguishes "this session is closed everywhere" from "this
			// browser forgot its cookie". Recorded whatever the audit outcome and BEFORE the transition record below,
			// so a reader sees the failure even if the trail then shows nothing else. No exception is raised: the
			// sign-out itself must still complete, since leaving the user signed in as well would be strictly worse.
			if (!revocationRecorded)
			{
				SecurityAuditLog.Write(Diagnostics.LogType.Error, "AuthService:Logout",
					"Session revocation could not be recorded durably; copies of this credential remain valid until it expires.",
					"user_id=" + SecurityAuditLog.Field(httpContext.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value, MaxLogDetailLength));
			}

			if (alreadyRevoked)
				return;

			// WHAT THE RECORD CARRIES, and what it does not. The acting principal's identifier is recorded, because
			// attribution is the point of a sign-out record. The SESSION IDENTIFIER IS NOT: it is what both bearer
			// validators and the cookie hook consult, so persisting it into a table any account with log access can read
			// would publish a working key to the revocation store (CWE-532); neither credential is recorded either.
			// Written through the shared boundary, so it is bound, neutralised, DoNotNotify - never LogService's
			// mail-before-persist path (M-17) - and unable to throw.
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

		// Sentinel for the one failure of this method that means "the credential was judged and rejected", as
		// opposed to a server-side fault such as an absent signing key. The token endpoint has to tell those apart
		// before it records a failed attempt against the account (H-16, CWE-307): counting a misconfiguration as a
		// credential failure would let a broken host lock out its own users. Exposed as a constant so that
		// classification is compile-time coupled to the throw below rather than matching a magic string a later
		// edit could silently desynchronise.
		public const string InvalidCredentialMessage = "Invalid email or password";

		/// <summary>
		/// Sentinel thrown when the credential is CORRECT but the account still owes a first-login password rotation.
		/// Deliberately distinct from <see cref="InvalidCredentialMessage"/>.
		/// </summary>
		/// <remarks>
		/// SECURITY C-01 (CWE-1392 use of a default credential, CWE-798), OWASP A07. The distinctness matters twice
		/// over, in opposite directions. IT MUST NOT BE THE CREDENTIAL MESSAGE, because the token endpoint counts a
		/// failed attempt against the lockout budget precisely when it sees that string, and the credential here is
		/// VALID - counting it would let the operator lock themselves out by retrying the automation they were
		/// configuring. IT IS ALSO NOT SURFACED to the caller: the route is anonymous, so its production branch
		/// collapses this to a generic message, and the operator's channel is the server-side log record - not a
		/// response body confirming to an anonymous caller that a guessed password was in fact the bootstrap one.
		/// </remarks>
		public const string PasswordRotationRequiredMessage = "Password rotation required before token issue";

		/// <summary>
		/// True when the account still carries the first-login rotation marker set by provisioning or by the schema
		/// version 4 revocation of the credential earlier releases shipped.
		/// </summary>
		/// <remarks>
		/// SECURITY C-01. One definition shared by both token paths, so issue and refresh can never disagree about
		/// what "still owes a rotation" means. Null-tolerant: an absent or empty preferences column reads as false,
		/// so a missing marker fails OPEN by design - every account predating this remediation chose its own
		/// password, and treating absence as "required" would demand a rotation from every existing user on upgrade.
		/// </remarks>
		private static bool IsPasswordRotationRequired(ErpUser user)
		{
			return user?.Preferences?.PasswordChangeRequired == true;
		}

		public static async ValueTask<string> GetTokenAsync(string email, string password)
		{
			// CWE-20 (improper input validation) with CWE-287 (improper authentication), OWASP A07. THE SECRET IS NOT
			// TRIMMED, and the trim must not come back: a secret is an exact byte sequence, and normalising it here means
			// this path and the cookie path judge the same submission differently, because AuthenticateAsync passes what
			// the user typed straight to the same GetUser. That cut both ways - a stored password legitimately beginning
			// or ending with whitespace could sign in interactively but never obtain a token, while the trim ACCEPTED
			// " secret " against a stored "secret".
			// THE IDENTIFIER IS NORMALISED, BY THE SAME MEMBER THE COOKIE PATH CALLS - review finding N33. It used to be
			// trimmed and case-folded HERE and nowhere else, which reproduced on the identifier exactly the divergence
			// the paragraph above forbids for the secret; see NormalizeCredentialIdentifier for why the case fold was
			// dropped rather than copied across.
			var user = new SecurityManager().GetUser(NormalizeCredentialIdentifier(email), password);
			if (user != null && user.Enabled)
			{
				// SECURITY C-01 (CWE-1392, CWE-798), OWASP A07. A credential the platform chose - generated at provisioning,
				// or written when the version 4 migration revoked the default earlier releases shipped - is refused a bearer
				// token until its owner replaces it, because such a value is exactly what gets pasted into a deployment
				// script and never changed, and a JWT is what makes it durable and portable. Checked AFTER the credential is
				// verified, so it reveals nothing to a caller who has not already presented the correct password. Interactive
				// sign-in is deliberately NOT gated: gating the shared GetUser would lock the operator out of the only screen
				// that can clear the marker.
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

			// H-02 (CWE-613, OWASP A07): the absolute horizon is read from the presented token and enforced BEFORE any
			// new token is minted. Three properties make this actually bound the session: fail closed on an absent or
			// unparseable claim, so tokens minted before this fix live out their remaining <=24h rather than being
			// grandfathered into unlimited renewal; refuse once the horizon has passed, which is the fix itself; and carry
			// the value VERBATIM into the replacement rather than recomputing it, which is what stops the horizon sliding
			// forward one refresh at a time.
			DateTime? absoluteSessionExpiryUtc = ReadUtcBinaryClaim(claims, CLAIM_SESSION_ABSOLUTE_EXPIRY);
			if (absoluteSessionExpiryUtc == null || DateTime.UtcNow >= absoluteSessionExpiryUtc.Value)
				return null;

			// SECURITY H-02 (CWE-613), OWASP A07. Refresh is why a bearer token needed a revocable session identity at
			// all: without this check, ending a session stopped nothing, because the holder of a still-valid token could
			// exchange it for a fresh one until the horizon ran out. Two refusals, both failing closed - no parseable
			// identifier, which is a token this build would not have minted, and a revoked identifier. This is the second
			// of two independent checks, repeated because a mint site must never rely on a caller having validated for it.
			Guid bearerSessionId = ReadSessionIdentifierClaim(claims);
			if (bearerSessionId == Guid.Empty || SessionRevocationService.IsSessionIdentifierRevoked(bearerSessionId))
				return null;

			//validate for active user
			var nameIdentifier = claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
			if (!string.IsNullOrWhiteSpace(nameIdentifier))
			{
				var user = new SecurityManager().GetUser(new Guid(nameIdentifier));
				// SECURITY C-01 (CWE-1392, CWE-798), OWASP A07. Refresh is gated on the rotation marker as well as on
				// Enabled, which closes a grandfathering hole rather than restating the issue-path check: a token minted
				// BEFORE the version 4 migration marked this account could otherwise have been renewed indefinitely
				// afterwards, so the migration would have revoked the password without revoking access obtained with it.
				// Returning null is this method's established convention for every refusal.
				if (user is not null && user.Enabled && !IsPasswordRotationRequired(user))
				{
					// The identifier read above is carried into the successor, never regenerated, so a revocation recorded at
					// any point continues to reject every token in this chain.
					var (newTokenString, newToken) = await BuildTokenAsync(user, absoluteSessionExpiryUtc.Value, bearerSessionId);
					return newTokenString;
				}
			}

			return null;
		}

		// Reads a claim written as DateTime.ToBinary() and returns it as UTC, and reads the bearer session identifier
		// as a Guid, each returning a sentinel - null or Guid.Empty - when the claim is absent, malformed or, for the
		// identifier, present more than once. Every caller treats the sentinel as a refusal, so a malformed security
		// claim fails closed instead of turning an anonymous token endpoint into a 500. A DUPLICATED identifier is
		// refused rather than resolved by taking the first: two in one token is a shape this build never mints, and
		// picking one would let a crafted token pair a revoked identifier with an unrevoked decoy.
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
		/// SECURITY H-02 (session hijacking via a non-revocable bearer token; CWE-613), OWASP A07. Bearer tokens are
		/// validated TWICE by two independent validators, and the host's own AddJwtBearer handler is the one that
		/// actually authorises the request, so a revocation check present only in this assembly's validator would
		/// have been decorative. Public for exactly one reason: the JwtBearer options type lives in a package only
		/// the two token-issuing hosts reference, so the hook is installed there while the RULE stays here. A pure
		/// predicate, so a host can only use it to refuse, and it FAILS CLOSED on an unparseable identifier.
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
			// CWE-703 (improper check of exceptional conditions), CWE-778, OWASP A07 + A09. The signing key used to be
			// built BEFORE the try, and both statements throw on null or empty material, so whenever 'Settings:Jwt:Key'
			// was unusable this method threw on its first statement OUTSIDE the handler that classifies and records
			// failures. That was the shipped configuration rather than an exotic case: both hosts registering
			// JwtMiddleware ship an EMPTY Key, because the secret scrub requires the value from the environment.
			// ErpSettings.IsJwtConfigured is the single platform-wide switch, resolved once at startup by the same rule
			// the two token endpoints consult, and it is deliberately NOT logged - on an unconfigured host it is the
			// steady state for every request carrying a header, so recording it would be an attacker-triggerable flood.
			if (!ErpSettings.IsJwtConfigured)
				return null;

			var tokenHandler = new JwtSecurityTokenHandler();
			try
			{
				// Key construction sits INSIDE the try. After the gate above, IsAcceptableJwtKey has already proven the key
				// is non-null, at least 32 bytes once UTF-8 encoded and not a published default, so neither statement can
				// throw on any reachable path today; they are inside the handler so they cannot become an unhandled throw
				// again if that gate is ever weakened.
				var mySecret = Encoding.UTF8.GetBytes(ErpSettings.JwtKey);
				var mySecurityKey = new SymmetricSecurityKey(mySecret);

				// H-02 (CWE-613 + CWE-347, OWASP A07): lifetime validation was absent, so an EXPIRED token still
				// validated, and with the anonymous refresh endpoint a stolen token was indefinitely renewable. Analyzer
				// CA5404 covers this; the clock skew is explicit so drift stays bounded.
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

				// SECURITY H-02 (CWE-613), OWASP A07. Signature, issuer, audience and lifetime are verified above and the
				// token was then accepted, so a token whose session had been ENDED remained a valid credential for the rest
				// of its lifetime. Consulted only AFTER validation succeeds: an unauthenticated caller must not be able to
				// probe the revocation store with forged tokens. The refusal is RECORDED rather than silent (CWE-778) - it
				// says somebody is still presenting a credential after its owner signed out - and rate-bounded, so a loop
				// yields evidence OF a loop.
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
			// CWE-396 (declaration of catch for generic exception), OWASP A09. This was catch (Exception), so every
			// failure inside ValidateToken - including a genuine defect - became "the token is invalid" and let the
			// audit record assert a credential rejection that had never been judged. NARROWED to the two families
			// ValidateToken documents: SecurityTokenException is the root of every IdentityModel validation outcome, and
			// ArgumentException covers the input contract, which must stay a 401 rather than become a 500.
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

		// SECURITY H-02. Records one rate-bounded, sanitised audit entry for a token that was judged and rejected.
		// Shared by the two narrowed catch clauses above so both audit identically.
		private static void RecordTokenValidationFailure(Exception ex)
		{
			// "Log authorization failures": failures here were swallowed in silence, so expired or forged tokens left no
			// audit trail. Three properties are load-bearing and MUST survive any tidy-up. (1) DoNotNotify - LogService
			// e-mails before it persists (M-17) and JwtMiddleware runs this validator for EVERY request carrying an
			// Authorization header, so a notifying log would be an attacker-triggered mail bomb. (2) Rate-bounded PER
			// FAILURE CATEGORY with the withheld volume counted, so a flood produces evidence of a flood rather than a
			// flood of evidence. (3) Exception type and a DERIVED description only - never the raw token, never a stack
			// trace, and never the raw exception message, which IdentityModel composes from the token's own claim values.
			try
			{
				// CLR metadata, never payload text - see tokenValidationLogSlots for why the key may not be derived from
				// the request or from the rejected token.
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

						// Read and cleared under the same lock that claims the window, so a concurrent suppression cannot be
						// counted into a record that has already been composed and then lost when this one clears the counter. If
						// the write below fails the count is restored, so a database outage never erases the evidence of what the
						// rate limit hid.
						suppressedOccurrences = slot.SuppressedOccurrences;
						slot.SuppressedOccurrences = 0;
					}
					else
					{
						// The withheld occurrence is COUNTED rather than dropped, which is what turns "one rejection was
						// reported" into "one rejection was reported and n more occurred" - the difference between an operator
						// seeing a probe and seeing a flood.
						if (slot.SuppressedOccurrences < int.MaxValue)
							slot.SuppressedOccurrences += 1;
					}
				}

				if (writeLogEntry)
				{
					// CWE-117 / CWE-532: ex.Message is NOT passed. DescribeTokenValidationFailure returns a fixed description
					// and SanitizeForLog bounds and neutralises it; the exception type name stays, being CLR metadata rather
					// than payload. H-02 (CWE-778): unrecorded audit-write losses are carried into this entry, so a database
					// outage that suppressed the authorization-failure trail is visible IN that trail rather than only in the
					// absence of records.
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
						// The suppressed volume this record was carrying has NOT been reported, so it is returned to the slot
						// rather than lost with the failed write, and counted as a lost audit entry in the same breath so the gap
						// is visible in the next record that succeeds.
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
			// An audit-logging failure must never escape and turn token validation into a server error. That property is
			// supplied by SecurityAuditLog.Write, which reports a storage failure through its RETURN VALUE and cannot
			// throw; keeping a second copy of its storage-exception list here is how two failure-isolation policies drift
			// apart, so this clause covers only the non-storage work that remains inside the try. Everything else,
			// notably OutOfMemoryException and OperationCanceledException, still propagates untouched.
			catch (InvalidOperationException)
			{
				// The one non-storage fault the retained code can raise: a reporting slot mutated concurrently through a
				// path that did not take the lock would surface here rather than as a 500 on a request that merely
				// presented a bad token. Counted, never discarded, so the loss of a required authorization-failure audit
				// entry is visible in the next record that succeeds.
				Interlocked.Increment(ref tokenValidationAuditWriteFailures);
			}
		}

		/// <summary>
		/// Records that a cryptographically valid bearer token was refused because the session it names had been
		/// revoked - the observable signature of a credential copied before its owner signed out.
		/// </summary>
		/// <remarks>
		/// CWE-778 (insufficient logging) and CWE-613, OWASP A09 and A07. The only place that can see the replay:
		/// the token passed signature, issuer, audience and lifetime validation, so the ONLY reason it is refused is
		/// that its session was ended, and a legitimate client discards its token on sign-out. The subject claim IS
		/// recorded, because knowing which account is replayed is the forensic value and the signature is already
		/// verified. WITHHELD: the raw token, which IS the credential, and the session identifier, which is the key
		/// the revocation store and both bearer validators consult (CWE-532). Rate-bounded, non-notifying and unable
		/// to throw, because replaying one token in a loop costs the caller nothing (CWE-779).
		/// </remarks>
		private static void RecordRevokedSessionReplay(JwtSecurityToken jwtToken)
		{
			// The subject claim is read defensively rather than assumed present: a token minted by an older build, or
			// one whose claim set was trimmed, must still be refused and still be recorded, and a null here would turn
			// the audit call into the very fault this method must not raise. Field() renders an absent value as an
			// unambiguous placeholder.
			var subject = jwtToken?.Claims?.FirstOrDefault(claim => claim.Type == ClaimTypes.NameIdentifier)?.Value;

			SecurityAuditLog.RecordRateLimitedAudit("AuthService:GetValidSecurityTokenAsync",
				Diagnostics.LogType.Error,
				"Bearer token refused - the session it names was revoked",
				"user_id=" + SecurityAuditLog.Field(subject, MaxLogDetailLength));
		}

		// H-02 (CWE-613, OWASP A07): both the horizon and the session identifier are null only on a fresh credential
		// authentication. Every refresh passes the values it READ from the presented token, and that
		// carry-never-recompute rule is what bounds the session and makes a revocation stick - recomputing either
		// here would let a refresh mint an unrevoked successor for a session that had just been ended.
		private static async ValueTask<(string, JwtSecurityToken)> BuildTokenAsync(ErpUser user, DateTime? absoluteSessionExpiryUtc = null, Guid? bearerSessionId = null)
		{
			var claims = new List<Claim>();
			claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
			claims.Add(new Claim(ClaimTypes.Email, user.Email));
			user.Roles.ForEach(role => claims.Add(new Claim(ClaimTypes.Role.ToString(), role.Name)));

			// The session identity every bearer credential carries; its only security requirement is to be unguessable to
			// an attacker who cannot already read the signed token containing it. Guid.Empty is never minted, because it
			// is what an absent or malformed claim parses to and both validators treat that as a refusal, so an
			// identifier colliding with it would be self-revoking.
			Guid sessionId = bearerSessionId ?? Guid.NewGuid();
			if (sessionId == Guid.Empty)
				sessionId = Guid.NewGuid();
			claims.Add(new Claim(CLAIM_SESSION_ID, sessionId.ToString()));

			DateTime issuedUtc = DateTime.UtcNow;
			DateTime horizonCeiling = issuedUtc.AddMinutes(JWT_ABSOLUTE_SESSION_HORIZON_MINUTES);
			// A carried horizon is trusted only as an upper bound on itself, clamped to the ceiling so the policy is a
			// hard limit rather than a value inherited from whatever a past or misconfigured build stamped. For any
			// token issued in the past the carried value is already below the ceiling, so this never extends a session.
			DateTime absoluteExpiryUtc = absoluteSessionExpiryUtc ?? horizonCeiling;
			if (absoluteExpiryUtc > horizonCeiling)
				absoluteExpiryUtc = horizonCeiling;

			// Both timestamps are capped at the horizon so neither the token nor the client's refresh hint can point
			// past it. Without the expiry cap, a refresh performed just before the horizon would mint a token valid
			// for a further 24h beyond it and defeat the whole control.
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
			// SECURITY M-04 (CWE-613, OWASP A07): expiry came from server-local time, so 'exp' shifted with the host's
			// UTC offset and across DST - real slack now that lifetime is enforced above. UTC, matching the refresh hint.
			var tokenDescriptor = new JwtSecurityToken(ErpSettings.JwtIssuer, ErpSettings.JwtAudience, claims,
						expires: tokenExpiresUtc, signingCredentials: credentials);
			return (new JwtSecurityTokenHandler().WriteToken(tokenDescriptor), tokenDescriptor);
		}
#pragma warning restore 1998

		/// <summary>
		/// Maps a token-validation exception onto a fixed description of WHY the token was rejected, optionally
		/// suffixed with the leading IdentityModel diagnostic code.
		/// </summary>
		/// <remarks>
		/// CWE-117 / CWE-532. Every value returned is a compile-time constant except the allow-listed IDXnnnnn code,
		/// so no part of the rejected token reaches the persisted record. Dispatch is on the exact type NAME, not on
		/// type patterns, because these types form an inheritance chain and a pattern switch would depend on its own
		/// case order, while the type set differs across IdentityModel versions.
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
		/// Returns the leading IdentityModel diagnostic code of a message - 'IDX' followed by digits - or null when
		/// the message does not begin with one.
		/// </summary>
		/// <remarks>
		/// CWE-117 / CWE-532. The only fragment of the original message retained, and provably non-sensitive:
		/// IdentityModel emits the code as the very first token, BEFORE any interpolated value.
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
		/// CWE-117. Applied at the LOGGING BOUNDARY, so the guarantee does not depend on every description-table
		/// entry being short and clean. Delegated to <see cref="SecurityAuditLog.Normalize"/>, which the login
		/// audit and both token routes also use, because two copies of a neutralisation routine drift apart silently.
		/// </remarks>
		private static string SanitizeForLog(string value)
		{
			return SecurityAuditLog.Normalize(value, MaxLogDetailLength);
		}



		#endregion

	}
}
