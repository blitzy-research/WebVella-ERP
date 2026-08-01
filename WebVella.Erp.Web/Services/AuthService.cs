using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace WebVella.Erp.Web.Services
{
	public class AuthService
	{
		private const double JWT_TOKEN_EXPIRY_DURATION_MINUTES = 1440;
		private const double JWT_TOKEN_FORCE_REFRESH_MINUTES = 120;

		// H-4 (CWE-613, OWASP A07): THREAT ADDRESSED - unbounded session renewal. Refresh minted a brand new 24h
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
		// H-5: this was 1440 (24h) while all seven hosts declare CookieAuthenticationOptions.ExpireTimeSpan = 8h. Those
		// two are not peers - CookieAuthenticationHandler applies ExpireTimeSpan ONLY when the ticket carries no explicit
		// ExpiresUtc, so the explicit value below silently won and every host's 8h window was inert configuration while
		// the real cookie lifetime was three times longer than any host declared. Aligned to 480 so the declared window
		// is the effective one and the invariant this comment asserts is actually true. Shortening rather than raising
		// the hosts is the correct direction for a session-lifetime finding, and it makes seven files' settings live.
		private const double AUTH_TICKET_EXPIRY_DURATION_MINUTES = 480;

		// Suppression window for the token-validation failure log in GetValidSecurityTokenAsync, guarded by the plain
		// lock idiom this project already uses (Services/CodeEvalService.cs), so a request flood cannot flood the log.
		private const double TOKEN_VALIDATION_LOG_INTERVAL_MINUTES = 1;
		private static readonly object tokenValidationLogLock = new object();
		private static DateTime tokenValidationLogLastWrittenUtc = DateTime.MinValue;

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
		// return before the authentication cookie is written. The name is deliberately unchanged; the sole caller
		// repository-wide is the login page handler in Pages/login.cshtml.cs, which must await this method.
		public async Task<ErpUser> Authenticate(string email, string password)
		{
			var user = new SecurityManager().GetUser(email, password);
			if (user != null && user.Enabled)
			{
				var claims = new List<Claim>();
				claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
				claims.Add(new Claim(ClaimTypes.Email, user.Email));
				user.Roles.ForEach(role => claims.Add(new Claim(ClaimTypes.Role.ToString(), role.Name)));

				var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

				var authProperties = new AuthenticationProperties
				{
					// H-5 (CWE-613, OWASP A07): THREAT ADDRESSED - indefinite cookie reissue. This was true, which let the
					// cookie middleware hand out a fresh 24h ticket on any activity past the halfway point, so a stolen
					// cookie could be renewed for ever and the ExpiresUtc below was never actually reached. The renewal
					// path requires BOTH the host's SlidingExpiration and this flag, so setting it false pins the ticket to
					// one immutable original-issued cutoff even if a host's cookie options are later changed - the hosts
					// already set SlidingExpiration=false, and this is the half of that pair which cannot be lost in a
					// per-host edit because it is applied once, here, for all seven of them.
					AllowRefresh = false,
					// H-03 (CWE-613, OWASP A07): this was a 100-year expiry, so a stolen authentication cookie never became
					// useless. An explicit ExpiresUtc wins over the host's ExpireTimeSpan, so this value IS the lifetime.
					ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(AUTH_TICKET_EXPIRY_DURATION_MINUTES),
					IsPersistent = false,
					IssuedUtc = DateTimeOffset.UtcNow,
				};

				IHttpContextAccessor httpContextAccesor = (IHttpContextAccessor)serviceProvider.GetService(typeof(IHttpContextAccessor));
				// M-03 (OWASP A07): the discarded Task raced the response, so the authentication cookie could be absent from
				// it and any sign-in exception went unobserved. Awaited, so the cookie is written before we return.
				await httpContextAccesor.HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);
				return user;
			}
			else
				return null;
		}

		public void Logout()
		{
			IHttpContextAccessor httpContextAccesor = (IHttpContextAccessor)serviceProvider.GetService(typeof(IHttpContextAccessor));
			httpContextAccesor.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
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

		public static async ValueTask<string> GetTokenAsync(string email, string password)
		{
			var user = new SecurityManager().GetUser(email?.Trim()?.ToLowerInvariant(), password?.Trim());
			if (user != null && user.Enabled)
			{
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

			// H-4 (CWE-613, OWASP A07): the absolute horizon is read from the presented token and enforced BEFORE any new
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

			//validate for active user
			var nameIdentifier = claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
			if (!string.IsNullOrWhiteSpace(nameIdentifier))
			{
				var user = new SecurityManager().GetUser(new Guid(nameIdentifier));
				if (user is not null && user.Enabled)
				{
					var (newTokenString, newToken) = await BuildTokenAsync(user, absoluteSessionExpiryUtc.Value);
					return newTokenString;
				}
			}

			return null;
		}

		// Reads a claim written as DateTime.ToBinary() and returns it as UTC, or null when the claim is absent, not a
		// number, or not a representable DateTime. Returning null rather than throwing is deliberate: the sole caller
		// treats null as "refuse the refresh", so a malformed security claim fails closed instead of turning the
		// anonymous refresh endpoint into a 500 that echoes a stack trace.
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
			var mySecret = Encoding.UTF8.GetBytes(ErpSettings.JwtKey);
			var mySecurityKey = new SymmetricSecurityKey(mySecret);
			var tokenHandler = new JwtSecurityTokenHandler();
			try
			{
				// H-02 (CWE-613 + CWE-347, OWASP A07): lifetime validation was absent, so an EXPIRED token still validated;
				// with the [AllowAnonymous] refresh endpoint at Controllers/WebApiController.cs:L4292 a stolen token was
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
					ClockSkew = TimeSpan.FromMinutes(1),
				}, out SecurityToken validatedToken);
				return validatedToken as JwtSecurityToken;
			}
			catch (Exception ex)
			{
				// "Log authorization failures": failures here were swallowed in silence, so expired or forged tokens left no
				// audit trail. Three properties of this block are load-bearing and MUST survive any future tidy-up:
				// (1) DoNotNotify - LogService e-mails before it persists (M-17) and Middleware/JwtMiddleware.cs:L42 runs
				//     this validator for EVERY request carrying an Authorization header, so a notifying log here would be
				//     an attacker-triggered mail bomb and DoS amplifier rather than a fix.
				// (2) Rate-bounded - each write costs a BaseService construction plus a database insert, so a flood must
				//     produce evidence of a flood instead of a flood of evidence.
				// (3) Exception type and a DERIVED description only - never the raw token, which is a bearer credential,
				//     never a stack trace, and (P4-07) never the raw exception message, because IdentityModel composes
				//     that message out of the rejected token's own claim values.
				try
				{
					var writeLogEntry = false;
					lock (tokenValidationLogLock)
					{
						if (DateTime.UtcNow >= tokenValidationLogLastWrittenUtc.AddMinutes(TOKEN_VALIDATION_LOG_INTERVAL_MINUTES))
						{
							tokenValidationLogLastWrittenUtc = DateTime.UtcNow;
							writeLogEntry = true;
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
						if (unreportedWriteFailures > 0)
						{
							details = details + " | " + unreportedWriteFailures.ToString(CultureInfo.InvariantCulture)
								+ " earlier token-validation audit entr(ies) could not be persisted and are unrecorded.";
						}

						new LogService().Create(Diagnostics.LogType.Error, "AuthService:GetValidSecurityTokenAsync",
							"JWT validation failed: " + ex.GetType().Name, details,
							Diagnostics.LogNotificationStatus.DoNotNotify);

						if (unreportedWriteFailures > 0)
						{
							Interlocked.Add(ref tokenValidationAuditWriteFailures, -unreportedWriteFailures);
						}
					}
				}
				// An audit-logging failure must never escape and turn token validation into a server error, but the bare
				// catch that previously enforced that also swallowed defects and left the loss of a required
				// authorization-failure audit entry completely invisible. Only the storage failures this write can
				// actually produce are caught, and each one is counted instead of discarded. Everything else - notably
				// OutOfMemoryException, StackOverflowException, OperationCanceledException and SecurityException -
				// propagates untouched. Writing the record reaches Services/LogService.cs:L29 -> Diagnostics/Log.cs:L53,
				// which opens an Npgsql connection at Diagnostics/Log.cs:L55, inserts into system_log and then releases the
				// connection; the DoNotNotify status above means the e-mail branch guarded at Services/LogService.cs:L20 is
				// never entered, so no mail transport failure is possible here, and the plain-Exception throws in
				// Database/DbConnection.cs:L189 and :L193 are unreachable because this path never begins a transaction on
				// the connection it opens. Recording the loss cannot throw, so no catch clause can fail in turn.
				catch (System.Data.Common.DbException)
				{
					// Npgsql surfaces every server-side and connection-level fault as NpgsqlException : DbException.
					// Fully qualified because the platform declares an unrelated Database/DbException.cs of the same
					// simple name, caught separately below; a future using directive must not silently repoint this.
					Interlocked.Increment(ref tokenValidationAuditWriteFailures);
				}
				catch (WebVella.Erp.Database.DbException)
				{
					// The platform's own data-layer exception. Database/DbContext.cs:L81 raises it when a connection is
					// released out of order, which the audit write can encounter while the request already holds one.
					Interlocked.Increment(ref tokenValidationAuditWriteFailures);
				}
				catch (TimeoutException)
				{
					// Connection-pool exhaustion or command timeout while the database is saturated.
					Interlocked.Increment(ref tokenValidationAuditWriteFailures);
				}
				catch (IOException)
				{
					// Transport failure writing to or reading from the database socket.
					Interlocked.Increment(ref tokenValidationAuditWriteFailures);
				}
				catch (InvalidOperationException)
				{
					// Connection or transaction in an unusable state; also covers ObjectDisposedException, which derives
					// from it, when the request's database scope has already been torn down.
					Interlocked.Increment(ref tokenValidationAuditWriteFailures);
				}
				catch (NullReferenceException)
				{
					// Narrowly justified: JwtMiddleware runs this validator for every request carrying an Authorization
					// header, including requests handled before or after the ERP database scope exists, and
					// Diagnostics/Log.cs:L55 dereferences the ambient DbContext.Current without a null guard. That is an
					// expected environmental condition on this path, not a defect in the code being audited.
					Interlocked.Increment(ref tokenValidationAuditWriteFailures);
				}

				return null;
			}
		}

		// H-4 (CWE-613, OWASP A07): absoluteSessionExpiryUtc is null only on a fresh credential authentication, where a
		// new horizon is opened. Every refresh passes the horizon it read from the presented token, which is what makes
		// the session bounded: the value is carried, never recomputed.
		private static async ValueTask<(string, JwtSecurityToken)> BuildTokenAsync(ErpUser user, DateTime? absoluteSessionExpiryUtc = null)
		{
			var claims = new List<Claim>();
			claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
			claims.Add(new Claim(ClaimTypes.Email, user.Email));
			user.Roles.ForEach(role => claims.Add(new Claim(ClaimTypes.Role.ToString(), role.Name)));

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
		/// </remarks>
		private static string SanitizeForLog(string value)
		{
			if (string.IsNullOrEmpty(value))
			{
				return string.Empty;
			}

			var bounded = value.Length <= MaxLogDetailLength ? value : value.Substring(0, MaxLogDetailLength);
			var builder = new StringBuilder(bounded.Length);
			foreach (var character in bounded)
			{
				builder.Append(char.IsControl(character) ? ' ' : character);
			}

			return builder.ToString();
		}



		#endregion

	}
}
