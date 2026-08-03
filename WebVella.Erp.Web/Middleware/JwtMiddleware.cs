using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using System;
using Microsoft.AspNetCore.Authentication;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using WebVella.Erp.Api;
using WebVella.Erp.Web.Services;
using Microsoft.Net.Http.Headers;

namespace WebVella.Erp.Web.Middleware
{
	public class JwtMiddleware
	{
		private readonly RequestDelegate _next;

		// THREAT ADDRESSED - finding M-REV-07, part 1 of 2 (CWE-20 improper input validation).
		// The Authorization header used to be consumed by an unconditional Substring(7) guarded only by a
		// length test, so ANY authentication scheme had its first seven characters chopped off and the
		// remainder handed to the JSON Web Token validator. 'Basic dXNlcjpwYXNz' became 'dXNlcjpwYXNz',
		// 'Negotiate YII...' became 'YII...', and both were then processed as though they were bearer
		// credentials. Two consequences followed on any host holding a usable signing key. Credential material
		// belonging to a completely different scheme - for Basic, a base64 username AND PASSWORD - was carried
		// into token validation, which describes and persists what it rejects; and every such request produced
		// a validation failure indistinguishable in the audit trail from a genuine forged-token attempt, which
		// is the exact signal an authorization-failure log exists to surface.
		// RFC 7235 defines the credentials as 'scheme SP credential' and RFC 7230 section 3.2.6 makes the
		// scheme token case-insensitive, so the prefix is matched ordinal-ignore-case: a client sending
		// 'bearer ' is standards-compliant and keeps working exactly as it did.
		private const string BearerSchemePrefix = "Bearer ";

		// THREAT ADDRESSED - finding M-REV-07, part 2 of 2 (CWE-778 insufficient logging, CWE-390 detection
		// of error condition without action). Everything that went wrong inside the bearer-authentication
		// stage used to be discarded by a bare 'catch { }' whose only content was a comment. A database
		// outage that stopped user resolution, a malformed subject claim, and a deliberately forged token
		// were therefore all equally invisible: the request simply continued unauthenticated with no record
		// anywhere. The user-specified Authorization Enforcement standard requires authorization failures to
		// be logged, and this was the one authentication path on which nothing was.
		// The suppression window, the lock idiom and the DoNotNotify status below are deliberately identical
		// to Services/AuthService.cs, which handles the same concern one call away: the two halves of bearer
		// authentication must not have divergent reporting behaviour, and mirroring an already-reviewed
		// pattern is safer than inventing a second one.
		private const double BEARER_AUTHENTICATION_LOG_INTERVAL_MINUTES = 1;
		private static readonly object bearerAuthenticationLogLock = new object();
		private static DateTime bearerAuthenticationLogLastWrittenUtc = DateTime.MinValue;

		// Occurrences that the interval above declined to write, carried into the next entry so that a flood
		// produces evidence OF a flood rather than a flood of evidence - and, just as importantly, so the
		// bound cannot silently hide volume from whoever reads the trail.
		private static int bearerAuthenticationSuppressedFailures;

		// Entries that could not be persisted at all because the audit write itself failed. Reported in the
		// next entry that does succeed, so a database outage which erased part of the authorization-failure
		// trail is visible IN that trail rather than only in the absence of records.
		private static int bearerAuthenticationAuditWriteFailures;

		public JwtMiddleware(RequestDelegate next)
		{
			_next = next;
		}

		public async Task Invoke(HttpContext context)
		{
			var token = await context.GetTokenAsync("access_token");
			if (string.IsNullOrWhiteSpace(token))
			{
				// M-REV-07: the blind seven-character chop is replaced by an exact scheme match. Requests
				// carrying a non-bearer scheme are now left entirely alone - they are not bearer credentials,
				// so there is nothing here for this middleware to do with them - rather than being mangled
				// into a token-shaped string and rejected noisily.
				string authorizationHeader = context.Request.Headers[HeaderNames.Authorization];
				token = ExtractBearerToken(authorizationHeader);
			}

			if (token != null)
			{
				try
				{
					var jwtToken = await WebVella.Erp.Web.Services.AuthService.GetValidSecurityTokenAsync(token);
					if (jwtToken != null && jwtToken.Claims.Any())
					{
						// M-REV-07: was an unconditional dereference of a FirstOrDefault result, so a validly
						// signed token that carries claims but no subject claim raised NullReferenceException.
						// That defect was invisible while the bare catch below discarded everything; with the
						// failure now recorded it would have become a recurring, meaningless audit entry on
						// every such request. Null-conditional, matching the identical read at
						// Services/AuthService.cs, so an absent subject claim falls to the guard below and the
						// request simply continues unauthenticated.
						var nameIdentifier = jwtToken.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
						if (!string.IsNullOrWhiteSpace(nameIdentifier))
						{
							var user = new SecurityManager().GetUser(new Guid(nameIdentifier));
							context.Items["User"] = user;

						   var identity = new ClaimsIdentity(jwtToken.Claims, "jwt");
						   context.User = new ClaimsPrincipal(identity);
						}
					}
				}
				catch (Exception ex)
				{
					// M-REV-07: the request still continues unauthenticated - no user is attached to the
					// context, so it cannot reach a secure route - because turning a bad bearer token into a
					// server error would be a denial-of-service primitive handed to any anonymous caller.
					// What changes is that the failure is no longer silent.
					RecordBearerAuthenticationFailure(ex);
				}

			}

			await _next(context);
		}

		/// <summary>
		/// Returns the credential of an <c>Authorization: Bearer &lt;token&gt;</c> header, or null when the
		/// header is absent, uses a different authentication scheme, or carries no credential after the scheme.
		/// </summary>
		/// <remarks>
		/// M-REV-07 (CWE-20). See <see cref="BearerSchemePrefix"/> for the threat this closes. Returning null
		/// rather than throwing is required by the caller's contract: a request that carries some other
		/// scheme is not an error, it simply has no bearer token, and it must reach the rest of the pipeline
		/// exactly as it does today so that cookie authentication and any other configured handler still see it.
		/// </remarks>
		private static string ExtractBearerToken(string authorizationHeaderValue)
		{
			if (string.IsNullOrWhiteSpace(authorizationHeaderValue))
				return null;

			if (!authorizationHeaderValue.StartsWith(BearerSchemePrefix, StringComparison.OrdinalIgnoreCase))
				return null;

			// A JSON Web Token contains no whitespace, so trimming can only remove padding a client added
			// around the credential; it also stops a header of 'Bearer    ' being treated as a token that is
			// then validated, described and persisted as a failure.
			var credential = authorizationHeaderValue.Substring(BearerSchemePrefix.Length).Trim();
			return credential.Length == 0 ? null : credential;
		}

		/// <summary>
		/// Records that the bearer-authentication stage failed, at most once per reporting interval.
		/// </summary>
		/// <remarks>
		/// M-REV-07 (CWE-778). Four properties of this method are load-bearing and MUST survive any future
		/// tidy-up, and each of them mirrors the equivalent guarantee in
		/// <c>Services/AuthService.GetValidSecurityTokenAsync</c>:
		/// <para>
		/// (1) DoNotNotify. <see cref="LogService"/> sends mail BEFORE it persists (finding M-17), and this
		/// middleware runs for every request carrying an Authorization header, so a notifying entry here would
		/// be an anonymously triggerable mail bomb - a fix that manufactures a worse vulnerability than the one
		/// it closes.
		/// </para>
		/// <para>
		/// (2) Rate-bounded. Each write costs a service construction plus a database insert, so the interval is
		/// what keeps a request flood from becoming a write flood, and the suppressed counter is what keeps the
		/// bound honest about how much it hid.
		/// </para>
		/// <para>
		/// (3) Exception TYPE only - never the exception message, never a stack trace and never the token. The
		/// token is a bearer credential, so persisting it would convert an authorization-failure log into a
		/// credential store (CWE-532). The message is withheld because every exception that can reach here is
		/// raised while the pipeline is handling a caller-supplied credential - subject-claim parsing, user
		/// resolution, claims-identity construction - so its text is not PROVABLY free of values taken from
		/// that credential, and a persisted record must not rest on a property that cannot be demonstrated
		/// (CWE-117, CWE-532). A type name, by contrast, is CLR metadata from a loaded assembly and can carry
		/// no payload at all. Withholding it also keeps this path consistent with the identical decision taken
		/// in AuthService, which is the other half of the same authentication step. Nothing diagnostic is lost
		/// for the ordinary case: AuthService already records the failure CATEGORY of every token it rejects,
		/// and what reaches this method instead is a fault of the surrounding stage, for which the type IS the
		/// diagnosis.
		/// </para>
		/// <para>
		/// (4) The write cannot escape. An audit-logging failure must never turn a request into a server error
		/// - that would let an attacker convert a database hiccup into a 500 - but the bare catch that used to
		/// enforce that is exactly the defect this finding reports, so each storage failure this write can
		/// actually produce is caught INDIVIDUALLY and counted rather than discarded. Everything else, notably
		/// OutOfMemoryException, StackOverflowException, OperationCanceledException and SecurityException,
		/// propagates untouched. Recording a loss is a single interlocked increment and cannot itself throw, so
		/// no catch clause can fail in turn.
		/// </para>
		/// </remarks>
		private static void RecordBearerAuthenticationFailure(Exception ex)
		{
			try
			{
				var writeLogEntry = false;
				lock (bearerAuthenticationLogLock)
				{
					if (DateTime.UtcNow >= bearerAuthenticationLogLastWrittenUtc.AddMinutes(BEARER_AUTHENTICATION_LOG_INTERVAL_MINUTES))
					{
						bearerAuthenticationLogLastWrittenUtc = DateTime.UtcNow;
						writeLogEntry = true;
					}
				}

				if (!writeLogEntry)
				{
					Interlocked.Increment(ref bearerAuthenticationSuppressedFailures);
					return;
				}

				// Both counters are READ before the write and reduced only AFTER it succeeds, so a failure to
				// persist carries the outstanding totals forward instead of erasing them, and an occurrence
				// recorded concurrently by another request is carried forward rather than discarded.
				var suppressedFailures = Volatile.Read(ref bearerAuthenticationSuppressedFailures);
				var unreportedWriteFailures = Volatile.Read(ref bearerAuthenticationAuditWriteFailures);

				var details = "The bearer-token authentication stage raised " + ex.GetType().FullName
					+ ". No user was attached to the request, which continued unauthenticated.";
				if (suppressedFailures > 0)
				{
					details = details + " | " + suppressedFailures.ToString(CultureInfo.InvariantCulture)
						+ " further occurrence(s) within the reporting interval are represented by this entry.";
				}
				if (unreportedWriteFailures > 0)
				{
					details = details + " | " + unreportedWriteFailures.ToString(CultureInfo.InvariantCulture)
						+ " earlier bearer-authentication audit entr(ies) could not be persisted and are unrecorded.";
				}

				new LogService().Create(Diagnostics.LogType.Error, "JwtMiddleware:Invoke",
					"Bearer authentication failed: " + ex.GetType().Name, details,
					Diagnostics.LogNotificationStatus.DoNotNotify);

				if (suppressedFailures > 0)
				{
					Interlocked.Add(ref bearerAuthenticationSuppressedFailures, -suppressedFailures);
				}
				if (unreportedWriteFailures > 0)
				{
					Interlocked.Add(ref bearerAuthenticationAuditWriteFailures, -unreportedWriteFailures);
				}
			}
			catch (System.Data.Common.DbException)
			{
				// Npgsql surfaces every server-side and connection-level fault as NpgsqlException : DbException.
				// Fully qualified because the platform declares an unrelated Database/DbException.cs of the same
				// simple name, caught separately below; a future using directive must not silently repoint this.
				Interlocked.Increment(ref bearerAuthenticationAuditWriteFailures);
			}
			catch (WebVella.Erp.Database.DbException)
			{
				// The platform's own data-layer exception, raised when a connection is released out of order -
				// which this write can encounter while the request already holds one.
				Interlocked.Increment(ref bearerAuthenticationAuditWriteFailures);
			}
			catch (TimeoutException)
			{
				// Connection-pool exhaustion or command timeout while the database is saturated.
				Interlocked.Increment(ref bearerAuthenticationAuditWriteFailures);
			}
			catch (IOException)
			{
				// Transport failure writing to or reading from the database socket.
				Interlocked.Increment(ref bearerAuthenticationAuditWriteFailures);
			}
			catch (InvalidOperationException)
			{
				// Connection or transaction in an unusable state; also covers ObjectDisposedException, which
				// derives from it, when the request's database scope has already been torn down.
				Interlocked.Increment(ref bearerAuthenticationAuditWriteFailures);
			}
			catch (NullReferenceException)
			{
				// Narrowly justified: Diagnostics/Log.cs dereferences the ambient DbContext.Current without a
				// null guard. UseErpMiddleware runs before UseJwtMiddleware on both hosts that register this
				// middleware, so a context is normally present - but a host that ever ordered them differently
				// would otherwise turn a logging attempt into a server error on every failed bearer request.
				Interlocked.Increment(ref bearerAuthenticationAuditWriteFailures);
			}
		}
	}
}
