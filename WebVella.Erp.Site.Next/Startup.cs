using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO.Compression;
using WebVella.Erp.Plugins.Next;
using WebVella.Erp.Web;
using WebVella.Erp.Web.Middleware;
using WebVella.TagHelpers;

namespace WebVella.Erp.Site.Next
{
	public class Startup
	{
		public Startup()
		{
		}

		// This method gets called by the runtime. Use this method to add services to the container.
		public void ConfigureServices(IServiceCollection services)
		{
			//legacy until we fix system tables
			AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);
			services.Configure<GzipCompressionProviderOptions>(options => options.Level = CompressionLevel.Optimal);
			services.AddResponseCompression(options => { options.Providers.Add<GzipCompressionProvider>(); });
			services.AddRouting(options => { options.LowercaseUrls = true; });

			//CORS policy declaration
			// DELIBERATELY UNCHANGED - finding H-14 (CWE-942, overly permissive cross-domain policy), OWASP
			// A05, scopes that remediation to the two hosts that called AllowAnyOrigin: WebVella.Erp.Site and
			// WebVella.Erp.Site.Project. This host is one of the five that already name their origins, so it
			// is outside H-14 and the named policy below is retained verbatim - tightening a policy that is
			// already restrictive would change working behaviour for no security gain.
			//
			// The hard-coded http://localhost origins are a KNOWN low-severity note, documented rather than
			// fixed: they are development-time Node.js origins, and because HTTPS redirection below is
			// guarded to non-Development it never rewrites the plaintext preflight they depend on. Do not
			// "complete" the CORS work here - there is none outstanding for this host.
			services.AddCors(options =>
			{
				options.AddPolicy("AllowNodeJsLocalhost",
					builder => builder.WithOrigins("http://localhost:3000", "http://localhost").AllowAnyMethod().AllowCredentials());
			});

			services.AddDetection();

			services.AddMvc()

				.AddRazorPagesOptions(options =>
				{
					options.Conventions.AuthorizeFolder("/");
					options.Conventions.AllowAnonymousToPage("/login");
				})
				.AddNewtonsoftJson(options =>
				{
					options.SerializerSettings.Converters.Add(new ErpDateTimeJsonConverter());
				});

			services.AddControllersWithViews();
			services.AddRazorPages().AddRazorRuntimeCompilation();

			//adds global datetime converter for json.net
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings
			{
				Converters = new List<JsonConverter> { new ErpDateTimeJsonConverter() }
			};

			services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
					.AddCookie(options =>
					{
						options.Cookie.Name = "erp_auth_next";
						options.LoginPath = new PathString("/login");
						options.LogoutPath = new PathString("/logout");
						options.AccessDeniedPath = new PathString("/error?access_denied");
						options.ReturnUrlParameter = "returnUrl";

						// THREAT ADDRESSED - finding H-15 (CWE-614 sensitive cookie without the 'Secure' attribute,
						// CWE-319 cleartext transmission of sensitive information) and review finding M-REV-09
						// (CWE-1275 improper SameSite attribute, CWE-613 insufficient session expiration), OWASP
						// A02 / A05, and Agent Action Plan section 0.6.1 Class 6, which mandates "an always-secure policy, a
						// same-site policy, an explicit expiry window and sliding expiration".
						//
						// H-15's cookie half is closed by the four attributes the call below applies: HttpOnly, an
						// always-secure policy, SameSite and a bounded window. SameSite is Lax and MUST NOT be
						// "upgraded" to Strict - Strict withholds the cookie on the return-URL round trip back
						// from /login that options.ReturnUrlParameter above depends on, which would break a working
						// sign-in. The window is 24 hours, matching AuthService.AUTH_TICKET_EXPIRY_DURATION_MINUTES: because
						// AuthService issues its ticket with an explicit ExpiresUtc, CookieAuthenticationHandler never
						// consults ExpireTimeSpan at all - not for the initial expiry, and not on a sliding renewal, which
						// re-issues using the ticket's own original span. The two are kept equal so the value configured
						// here and the value actually enforced cannot diverge.
						//
						// The four attributes live in ONE place rather than being duplicated per host, because seven copies
						// are what let them drift apart; see ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie for
						// the full rationale, including why sliding expiration is safe only when paired with an absolute
						// session horizon. Called LAST in this lambda deliberately, so the platform contract wins over
						// anything a host sets; nothing above this line is a security attribute.
						ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie(options);
					});

			services.AddErp();
		}

		// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
		public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
		{
			// THREAT ADDRESSED - review finding M-REV-08 (CWE-348 use of a less trusted source, CWE-290
			// authentication bypass by spoofing, CWE-307 improper restriction of excessive authentication
			// attempts), OWASP A05 Security Misconfiguration. No forwarded-header processing existed anywhere in
			// the platform, so behind the reverse proxy this application is designed to run behind three separate
			// controls degraded silently and simultaneously: the request-rate partition collapsed onto the proxy's
			// own address so every caller shared one budget, the per-address half of the login lockout counted one
			// attacker's failures against every other user of that proxy, and Request.IsHttps read false for
			// requests the client had actually made over TLS - which is what HTTPS redirection and the Secure
			// cookie policy both read.
			//
			// FIRST in the pipeline, and that position is load-bearing rather than stylistic: every middleware
			// below reads either the scheme or the remote address this one corrects - UseSecurityHeaders,
			// UseHsts, UseHttpsRedirection and UseRateLimiter among them - so anything ordered above it would see
			// the uncorrected values. It trusts nobody until an operator names their proxies in
			// Settings:ForwardedHeaders; until then it is not even added to the pipeline, which is the only
			// configuration that genuinely ignores X-Forwarded-*. See UseErpForwardedHeaders for why an empty
			// allow-list would have been the opposite of no trust.
			app.UseErpForwardedHeaders();

			app.UseRequestLocalization(new RequestLocalizationOptions
			{
				DefaultRequestCulture = new Microsoft.AspNetCore.Localization.RequestCulture(CultureInfo.GetCultureInfo("en-US"))
			});

			//env.EnvironmentName = EnvironmentName.Production;
			// Add the following to the request pipeline only in development environment.
			if (string.Equals(env.EnvironmentName, "Development", StringComparison.OrdinalIgnoreCase))
			{
				app.UseDeveloperExceptionPage();
			}
			else
			{
				// Add Error handling middleware which catches all application specific errors and
				// send the request to the following path or controller action.
				app.UseErrorHandlingMiddleware();
				app.UseExceptionHandler("/error");
				app.UseStatusCodePagesWithReExecute("/error");
			}

			//Should be before Static files
			// THREAT ADDRESSED - finding M-01 (OWASP A05: Security Misconfiguration):
			// SecurityHeadersMiddleware existed but was never inserted into any pipeline, so not one of the
			// seven mandated security response headers was emitted. It is placed ahead of BOTH UseStaticFiles
			// calls because UseStaticFiles TERMINATES the pipeline for a matched asset: anything registered
			// after it never runs for a static-file response, so those responses would ship bare. The default
			// policy is report-only and HSTS is suppressed in Development; see SecurityHeadersMiddleware.
			app.UseSecurityHeaders();

			app.UseResponseCompression();

			app.UseCors("AllowNodeJsLocalhost"); //Enable CORS -> should be before static files to enable for it too

			// THREAT ADDRESSED - finding H-15, CWE-319 (cleartext transmission of sensitive information)
			// and CWE-614: no host enforced HTTPS or published an HSTS policy, so a session could be
			// downgraded to plaintext and its cookie intercepted. Guarded to non-Development because local
			// development runs over plain HTTP.
			//
			// HSTS must precede the redirect: UseHttpsRedirection short-circuits a plaintext request, so
			// anything after it never runs for that request. HstsMiddleware itself writes nothing on a
			// plaintext request, but UseSecurityHeaders() ran earlier and has already attached
			// Strict-Transport-Security, so the redirect response does carry it - inertly, because a user
			// agent must ignore the header when it arrives over plaintext (RFC 6797 section 7.2).
			//
			// Both sit AFTER UseCors, deliberately: the CORS middleware short-circuits cross-origin
			// preflight, so an OPTIONS request is answered before it can reach the redirect. Moving them
			// above UseCors reintroduces the documented failure where redirection answers a preflight with a
			// redirect the browser rejects as invalid.
			//
			// app.UseHsts() alone does not publish the mandated policy: it emits whatever HstsOptions holds,
			// and the framework default is thirty days without subdomains ("max-age=2592000"). The mandated
			// one-year, subdomain-inclusive values are configured once in AddErp, so both writers emit the
			// identical string. Do not give this call site per-host options.
			if (!string.Equals(env.EnvironmentName, "Development", StringComparison.OrdinalIgnoreCase))
			{
				app.UseHsts();
				app.UseHttpsRedirection();
			}

			app.UseStaticFiles(new StaticFileOptions
			{
				ServeUnknownFileTypes = false,
				OnPrepareResponse = ctx =>
				{
					const int durationInSeconds = 60 * 60 * 24 * 30 * 12;
					ctx.Context.Response.Headers[HeaderNames.CacheControl] = "public,max-age=" + durationInSeconds;
					ctx.Context.Response.Headers[HeaderNames.Expires] = new[] { DateTime.UtcNow.AddYears(1).ToString("R") }; // Format RFC1123
					}
			});
			app.UseStaticFiles(); //Workaround for blazor to work - https://github.com/dotnet/aspnetcore/issues/9588
			app.UseRouting();

			// THREAT ADDRESSED - finding H-16, CWE-307 (improper restriction of excessive authentication
			// attempts): activates the per-remote-address fixed window registered in AddErp. Positioned
			// after both UseStaticFiles calls so static assets are never throttled, and after UseRouting so
			// endpoint metadata is available to the limiter. The mandated five-attempt per-account lockout
			// is a separate control in LoginThrottleService.
			app.UseRateLimiter();
			app.UseAuthentication();
			app.UseAuthorization();

			app
			.UseErpPlugin<NextPlugin>()
			.UseErp()
			.UseErpMiddleware();

			app.UseEndpoints(endpoints =>
			{
				endpoints.MapRazorPages();
				endpoints.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");
			});
		}
	}
}

