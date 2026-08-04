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
		// THREAT ADDRESSED - review finding CR2-F-07 (CWE-489 active debug code, CWE-209 generation of an
		// error message containing sensitive information, CWE-306 missing authentication for a critical
		// function), OWASP A05 Security Misconfiguration. Two of the three disclosures that finding covers
		// are configured in ConfigureServices, which - unlike Configure below - was handed no
		// IWebHostEnvironment, so neither could be made conditional on the environment without one.
		// Constructor injection is how the framework supplies it to a Startup class (StartupLoader resolves
		// IWebHostEnvironment, IHostEnvironment and IConfiguration constructor parameters), and it is the
		// pattern this solution already uses - see WebVella.Erp.Site/Startup.cs, which takes the same
		// parameter for the same reason.
		private readonly IWebHostEnvironment environment;

		public Startup(IWebHostEnvironment environment)
		{
			this.environment = environment;
		}

		// Single definition of the environment test used three times below. The comparison idiom is copied
		// verbatim from the guards Configure already carries, rather than switched to IsDevelopment(), so
		// that every environment decision in this file reads identically. It fails SECURE: any environment
		// name that is not exactly "Development" - including one that is misspelled, empty or absent -
		// yields false and therefore selects the hardened branch.
		private bool IsDevelopment => string.Equals(environment.EnvironmentName, "Development", StringComparison.OrdinalIgnoreCase);

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

					// THREAT ADDRESSED - review finding CR2-F-07 (CWE-306 missing authentication for a critical
					// function, CWE-209 generation of an error message containing sensitive information), OWASP
					// A05 / A07. AuthorizeFolder("/") above is deny-by-default, so the line below is an EXPLICIT
					// exemption publishing the SDK developer page, and this host is the only one of the seven that
					// grants it.
					//
					// It was previously granted UNCONDITIONALLY and recorded as accepted risk M-09 on the grounds
					// that an anonymous developer page is a Medium failing the compensating-control test. That
					// reasoning no longer holds, and the reason it broke is worth stating precisely: /dev renders a
					// Blazor Server component, and this host configured CircuitOptions.DetailedErrors = true. The
					// anonymous page was therefore not merely reachable - it was the DELIVERY VEHICLE for full
					// server exception text, message and stack trace alike, to a caller who had not authenticated.
					// That composition is an information disclosure rather than a missing-authentication Medium,
					// and it does meet the compensating-control test.
					//
					// The exemption is ENVIRONMENT-GATED rather than deleted, which is both the smaller change and
					// the one that keeps two requirements true at once. Agent Action Plan section 0.3.2 declined to
					// REMOVE this line because removal "would break the SDK development workflow that depends on
					// reaching /dev without a session"; gating preserves that workflow exactly where it is used - a
					// developer machine running the Development environment - while a deployed host falls back to
					// the deny-by-default AuthorizeFolder("/") above and answers with the configured LoginPath.
					// Nothing is left accepted-but-unaddressed: see docs/security/risk-register.md for the closure
					// of M-09's Production half and the residual it keeps in Development.
					if (IsDevelopment)
					{
						options.Conventions.AllowAnonymousToPage("/dev");
					}
				})
				.AddNewtonsoftJson(options =>
				{
					options.SerializerSettings.Converters.Add(new ErpDateTimeJsonConverter());
				});

			services.AddControllersWithViews();
			services.AddRazorPages().AddRazorRuntimeCompilation();
			// THREAT ADDRESSED - review finding CR2-F-07 (CWE-209 generation of an error message containing
			// sensitive information, CWE-489 active debug code), OWASP A05 Security Misconfiguration.
			// DetailedErrors was hard-coded true in a host that ships to Production, and
			// CircuitOptions.DetailedErrors is precisely the switch deciding whether an unhandled exception
			// inside a Blazor Server component is returned to the browser complete with message and stack
			// trace, or replaced by an opaque circuit-error identifier. Paired with the anonymous /dev page
			// above it disclosed internal type names, file paths and call stacks to an unauthenticated caller
			// - the same class of disclosure finding H-13 closed on the API surface.
			//
			// This is the only host in the solution that configures Blazor Server at all, so the value is set
			// here and nowhere else, and it follows the environment: full detail on a developer machine, none
			// on a deployed one. It is deliberately NOT read from configuration - a configuration key would
			// let the disclosure be switched back on in Production by an operator with no way to know what it
			// exposes, which is how this defect would return.
			services.AddServerSideBlazor().AddCircuitOptions(options => { options.DetailedErrors = IsDevelopment; });
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
				// THREAT ADDRESSED - review finding CR2-F-07 (CWE-548 exposure of information through static
				// file serving, CWE-200 exposure of sensitive information to an unauthorized actor), OWASP A05
				// Security Misconfiguration. This host was the ONLY one of the seven to set this true - the
				// other six set false, upstream included - so it was a divergence rather than a requirement.
				// While true, StaticFileMiddleware serves any file under the web root whose extension is absent
				// from FileExtensionContentTypeProvider, and because DefaultContentType is left unset it serves
				// that file with no Content-Type at all. Anything a build step, an operator or a future asset
				// pipeline leaves in the web root - .config, .pem, .bak, .cs, .cshtml, .pdb, all of them
				// unmapped - was downloadable without a session.
				//
				// Verified non-load-bearing before changing rather than assumed. Of the 600 files in this host's
				// published web root exactly one extension is unmapped, .br (Brotli pre-compression); every .br
				// and .gz file has an uncompressed sibling of the same name, and no published asset references a
				// .br URL. Nothing requests one directly either, because this pipeline negotiates compression
				// through UseResponseCompression above rather than by extension. Every other extension present -
				// js, css, map, ttf, woff, woff2, eot, png, gif, ico, txt, gz - is mapped, so no asset stops
				// being served and no request that succeeded before now fails.
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
			// attempts), OWASP A07: activates the per-remote-address fixed window registered in AddErp.
			// Positioned after both UseStaticFiles calls so static assets are never throttled, and after
			// UseRouting so endpoint metadata is available to the limiter.
			//
			// TRANSPORT-LEVEL layer only, and deliberately not the primary control: the mandated five-attempt
			// account lockout lives in WebVella.Erp.Web/Services/LoginThrottleService.cs and is consulted
			// from the login page handler, because a volumetric limiter cannot stop an attacker spread thinly
			// across many addresses. The permit limit is therefore deliberately generous - one ERP page load
			// fans out into many requests - so tune it in AddErp, never per host.
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
				// THREAT ADDRESSED - review finding CR2-F-07 (CWE-306 missing authentication for a critical
				// function), OWASP A05 / A07. MapBlazorHub carries no authorization metadata of its own, so the
				// circuit endpoint was anonymous even for components hosted on pages that do require a session:
				// it is a SEPARATE endpoint from the page that starts it, and AuthorizeFolder("/") governs Razor
				// Pages only. Gating the /dev page alone would therefore have left the hub itself reachable, and
				// the hub is where component code - and any exception it raises - actually executes.
				//
				// Guarded to non-Development for the same reason the /dev exemption is: in Development that page
				// is deliberately anonymous, and a circuit it cannot open would make it useless. Outside
				// Development the only Blazor component this platform hosts is
				// WebVella.Erp.Web/Components/PcApplications/Display.cshtml, which sits under
				// AuthorizeFolder("/") and is therefore only ever rendered for a caller who already holds the
				// authentication cookie - the same cookie the browser sends on the hub's negotiate and WebSocket
				// requests - so requiring authorization here changes nothing for legitimate use.
				var blazorHub = endpoints.MapBlazorHub();
				if (!IsDevelopment)
				{
					blazorHub.RequireAuthorization();
				}
				endpoints.MapRazorPages();
				endpoints.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");
			});
		}
	}
}

