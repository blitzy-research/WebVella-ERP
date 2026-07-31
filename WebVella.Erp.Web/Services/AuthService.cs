using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
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

		// H-03 (CWE-613, OWASP A07): bound for the cookie authentication ticket, kept on the same 24h horizon as the JWT
		// above. Must stay no longer than the hosts' CookieAuthenticationOptions.ExpireTimeSpan window.
		private const double AUTH_TICKET_EXPIRY_DURATION_MINUTES = 1440;

		// Suppression window for the token-validation failure log in GetValidSecurityTokenAsync. Plain lock plus a
		// timestamp, matching the in-repo idiom in Services/CodeEvalService.cs, so a request flood cannot flood the log.
		private const double TOKEN_VALIDATION_LOG_INTERVAL_MINUTES = 1;
		private static readonly object tokenValidationLogLock = new object();
		private static DateTime tokenValidationLogLastWrittenUtc = DateTime.MinValue;

		private IServiceProvider serviceProvider;

		public AuthService(IServiceProvider serviceProvider)
		{
			this.serviceProvider = serviceProvider;
		}

		// M-03 (OWASP A07): this became async because the sign-in below is now awaited. The name is deliberately
		// unchanged, and the sole caller repository-wide, Pages/login.cshtml.cs:L92, awaits it in this same commit.
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
					AllowRefresh = true,
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
				//when exception occur that means schema is changed and cookie is not valid
				return null;
			}
		}

		#region <--- JWT Token related methods --->

		public static async ValueTask<string> GetTokenAsync(string email, string password)
		{
			var user = new SecurityManager().GetUser(email?.Trim()?.ToLowerInvariant(), password?.Trim());
			if (user != null && user.Enabled)
			{
				var (tokenString, token) = await BuildTokenAsync(user);
				return tokenString;
			}
			throw new Exception("Invalid email or password");
		}

		public static async ValueTask<string> GetNewTokenAsync(string tokenString)
		{
			JwtSecurityToken jwtToken = await GetValidSecurityTokenAsync(tokenString);
			if (jwtToken == null)
				return null;

			List<Claim> claims = jwtToken.Claims.ToList();
			if (claims.Count == 0)
				return null;

			//validate for active user
			var nameIdentifier = claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier).Value;
			if (!string.IsNullOrWhiteSpace(nameIdentifier))
			{
				var user = new SecurityManager().GetUser(new Guid(nameIdentifier));
				if (user is not null && user.Enabled)
				{
					var (newTokenString, newToken) = await BuildTokenAsync(user);
					return newTokenString;
				}
			}

			return null;
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
				// (3) Exception type and message only - never the raw token, which is a bearer credential, and never a
				//     stack trace, so the audit record cannot itself disclose a secret.
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
						new LogService().Create(Diagnostics.LogType.Error, "AuthService:GetValidSecurityTokenAsync",
							"JWT validation failed: " + ex.GetType().Name, ex.Message,
							Diagnostics.LogNotificationStatus.DoNotNotify);
					}
				}
				catch
				{
					//an audit-logging failure must never escape and turn token validation into a server error
				}

				return null;
			}
		}

		private static async ValueTask<(string, JwtSecurityToken)> BuildTokenAsync(ErpUser user)
		{
			var claims = new List<Claim>();
			claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
			claims.Add(new Claim(ClaimTypes.Email, user.Email));
			user.Roles.ForEach(role => claims.Add(new Claim(ClaimTypes.Role.ToString(), role.Name)));

			DateTime tokenRefreshAfterDateTime = DateTime.UtcNow.AddMinutes(JWT_TOKEN_FORCE_REFRESH_MINUTES);
			claims.Add(new Claim(type: "token_refresh_after", value: tokenRefreshAfterDateTime.ToBinary().ToString()));

			var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(ErpSettings.JwtKey));
			var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
			// M-04 (CWE-613, OWASP A07): expiry came from server-local time, so 'exp' shifted with the host's UTC offset
			// and across DST - real slack now that lifetime is enforced above. UTC, matching tokenRefreshAfterDateTime.
			var tokenDescriptor = new JwtSecurityToken(ErpSettings.JwtIssuer, ErpSettings.JwtAudience, claims,
						expires: DateTime.UtcNow.AddMinutes(JWT_TOKEN_EXPIRY_DURATION_MINUTES), signingCredentials: credentials);
			return (new JwtSecurityTokenHandler().WriteToken(tokenDescriptor), tokenDescriptor);
		}
#pragma warning restore 1998



		#endregion

	}
}
