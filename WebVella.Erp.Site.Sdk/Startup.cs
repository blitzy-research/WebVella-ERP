using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO.Compression;
using WebVella.Erp.Plugins.Next;
using WebVella.Erp.Plugins.SDK;
using WebVella.Erp.Web;
using WebVella.Erp.Web.Middleware;

namespace WebVella.Erp.Site.Sdk
{
	public class Startup
	{
		// This method gets called by the runtime. Use this method to add services to the container.
		public void ConfigureServices(IServiceCollection services)
		{
			//legacy until we fix system tables
			AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);
			services.Configure<GzipCompressionProviderOptions>(options => options.Level = CompressionLevel.Optimal);
			services.AddResponseCompression(options => { options.Providers.Add<GzipCompressionProvider>(); });
			services.AddRouting(options => { options.LowercaseUrls = true; });

			//CORS policy declaration
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

					// ACCEPTED RISK, NOT AN OVERSIGHT - finding M-09 (CWE-306, missing authentication for a
					// critical function), OWASP A07 Identification and Authentication Failures. AuthorizeFolder("/")
					// above is deny-by-default, so the line below is an EXPLICIT exemption: it publishes the SDK
					// developer page to unauthenticated callers, and this host is the only one of the seven that
					// grants it. Deliberately RETAINED rather than removed, under Minimal Change guideline 8
					// ("document out-of-scope concerns but do not fix unless Critical") - it is a Medium that does
					// not meet the compensating-control test, so removing it here would be unrequested scope and
					// would break the SDK development workflow that depends on reaching /dev without a session.
					// Recorded as a recommendation in docs/security/risk-register.md; close it there, not here.
					options.Conventions.AllowAnonymousToPage("/dev");
				})
				.AddNewtonsoftJson(options =>
				{
					options.SerializerSettings.Converters.Add(new ErpDateTimeJsonConverter());
				});

			services.AddControllersWithViews();
			services.AddRazorPages().AddRazorRuntimeCompilation();
			services.AddServerSideBlazor().AddCircuitOptions(options => {  options.DetailedErrors = true; });
			//adds global datetime converter for json.net
			JsonConvert.DefaultSettings = () => new JsonSerializerSettings
			{
				Converters = new List<JsonConverter> { new ErpDateTimeJsonConverter() }
			};

			services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
					.AddCookie(options =>
					{
						options.Cookie.Name = "erp_auth_sdk";
						options.LoginPath = new PathString("/login");
						options.LogoutPath = new PathString("/logout");
						options.AccessDeniedPath = new PathString("/error?access_denied");
						options.ReturnUrlParameter = "returnUrl";

						// THREAT ADDRESSED - review finding M-REV-09 (CWE-614 sensitive cookie without the 'Secure'
						// attribute, CWE-1275 improper SameSite attribute, CWE-613 insufficient session expiration), OWASP
						// A02 / A05, and Agent Action Plan section 0.6.1 Class 6, which mandates "an always-secure policy, a
						// same-site policy, an explicit expiry window and sliding expiration".
						//
						// This host used to carry its own copy of those four settings, as did the other six, and the copies
						// had drifted from the frozen session contract in two ways that mattered: the secure policy
						// downgraded itself to SameAsRequest whenever the host environment name read "Development", and
						// sliding expiration was disabled. Seven duplicated copies is the ROOT CAUSE of that drift rather
						// than merely where it surfaced, so the contract now lives in exactly one place - see
						// ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie for the full rationale, including why the
						// Development relaxation was unnecessary and why sliding expiration is safe here only because it is
						// paired with an absolute session horizon. Six hosts can no longer desynchronise from the seventh
						// because there is one place left to edit.
						//
						// Called LAST in this lambda deliberately: the platform contract must win over anything a host sets,
						// and nothing above this line is a security attribute - only the cookie name and the sign-in paths.
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
			// THREAT ADDRESSED - finding H-08 / M-01 (OWASP A05: Security Misconfiguration):
			// SecurityHeadersMiddleware existed but was never inserted into any pipeline, so not one of the
			// seven mandated security response headers was emitted. It is placed first - ahead of
			// UseResponseCompression and ahead of BOTH UseStaticFiles calls - because ordering decides which
			// responses the headers reach: registered after compression or after static files, compressed
			// responses and static assets would be served bare.
			app.UseSecurityHeaders();

			app.UseResponseCompression();

			app.UseCors("AllowNodeJsLocalhost"); //Enable CORS -> should be before static files to enable for it too

			// THREAT ADDRESSED - finding H-08 / H-15, CWE-319 (cleartext transmission of sensitive
			// information) and CWE-614: no host enforced HTTPS or published an HSTS policy, so a session
			// could be downgraded to plaintext and its cookie intercepted. Guarded to non-Development
			// because local development runs over plain HTTP. UseHsts adds the policy to HTTPS responses
			// only - HstsMiddleware returns without writing a header when Request.IsHttps is false - so the
			// header is published on the secured responses that FOLLOW the redirect, never on the redirect
			// itself. Ordering HSTS first is still correct, because the two calls must not be transposed:
			// UseHttpsRedirection short-circuits a plaintext request, so anything after it never runs for
			// that request at all.
			//
			// Ordering is deliberate and load-bearing: this sits AFTER UseCors. The CORS middleware
			// short-circuits cross-origin preflight, so an OPTIONS request is answered before it can reach
			// the redirect. That is what avoids the documented failure where HTTPS redirection answers a
			// preflight with a redirect the browser rejects as invalid. Moving this above UseCors would
			// reintroduce it.
			//
			// THREAT ADDRESSED - finding F-06: app.UseHsts() alone does NOT publish the mandated policy. It
			// emits whatever HstsOptions holds, and the framework defaults are thirty days with subdomains
			// excluded - "max-age=2592000". Because HstsMiddleware assigns the header by indexer and runs
			// after UseSecurityHeaders(), it overwrote the mandated value rather than agreeing with it. The
			// exact one-year, subdomain-inclusive values are now configured once in AddErp through
			// services.AddHsts(), so both writers emit the identical string. This call site must not be
			// given per-host options, and AddErp's registration must not be removed, or this line silently
			// reverts to the thirty-day header.
			if (!string.Equals(env.EnvironmentName, "Development", StringComparison.OrdinalIgnoreCase))
			{
				app.UseHsts();
				app.UseHttpsRedirection();
			}

			app.UseStaticFiles(new StaticFileOptions
			{
				ServeUnknownFileTypes = true,
				OnPrepareResponse = ctx =>
				{
					const int durationInSeconds = 60 * 60 * 24 * 30 * 12;
					ctx.Context.Response.Headers[HeaderNames.CacheControl] = "public,max-age=" + durationInSeconds;
					ctx.Context.Response.Headers[HeaderNames.Expires] = new[] { DateTime.UtcNow.AddYears(1).ToString("R") }; // Format RFC1123
				}
			});
			app.UseStaticFiles(); //Workaround for blazor to work - https://github.com/dotnet/aspnetcore/issues/9588
			app.UseRouting();

			// THREAT ADDRESSED - finding H-08 / H-16, CWE-307 (improper restriction of excessive
			// authentication attempts), OWASP A07 Identification and Authentication Failures: activates the
			// per-remote-address fixed window registered in AddErp.
			// Positioned after both UseStaticFiles calls so static assets are never throttled, and after
			// UseRouting so endpoint metadata is available to the limiter.
			//
			// This is the TRANSPORT-LEVEL layer only, and it is deliberately not the primary control. The
			// mandated five-attempt account lockout is a separate, per-account mechanism in
			// WebVella.Erp.Web/Services/LoginThrottleService.cs, consulted from the login page handler; a
			// volumetric limiter cannot substitute for it because an attacker spread thinly across many
			// addresses stays under any per-address budget. Consequently the registered permit limit is
			// deliberately GENEROUS: a single ERP page load fans out into many requests (Razor Pages, the
			// Blazor hub, API and inline-edit calls), so a tight window would break legitimate interactive
			// use - a far worse outcome than the marginal benefit, and a breach of the requirement that
			// existing functionality be preserved exactly. Tune the limit in AddErp, never per host.
			app.UseRateLimiter();
			app.UseAuthentication();
			app.UseAuthorization();

			app
			//.UseErpPlugin<NextPlugin>()
			.UseErpPlugin<SdkPlugin>()
			.UseErp()
			.UseErpMiddleware();

			app.UseEndpoints(endpoints =>
			{
				endpoints.MapBlazorHub(); 
				endpoints.MapRazorPages();
				endpoints.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");
			});
		}
	}
}

