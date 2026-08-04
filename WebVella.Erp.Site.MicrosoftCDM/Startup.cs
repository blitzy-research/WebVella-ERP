using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO.Compression;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using WebVella.Erp.Web;
using WebVella.Erp.Web.Middleware;
using WebVella.Erp.Plugins.SDK;
using WebVella.Erp.Plugins.MicrosoftCDM;

namespace WebVella.Erp.Site.MicrosoftCDM
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
						// THREAT ADDRESSED - review finding CR2-F-11 (CWE-565 reliance on cookies without validation
						// and integrity checking, CWE-488 exposure of data element to wrong session), OWASP A05:2021
						// Security Misconfiguration. This host shipped the cookie name "erp_auth_crm" - byte-identical
						// to the one WebVella.Erp.Site.Crm uses - and the collision is UPSTREAM rather than introduced
						// here: git show origin/master carries the same literal in both hosts, so it is a copy-paste
						// inheritance that has always been present.
						//
						// A cookie name is scoped by domain and path, NOT by port or by application, so two hosts served
						// from one hostname overwrite each other's authentication cookie. Whichever host wrote last owns
						// the browser's single "erp_auth_crm" cookie, and the other host is handed a ticket it cannot
						// decrypt once the application discriminator differs - which it now explicitly does, see
						// ErpMvcExtensions - producing an authentication failure or a redirect loop rather than a clean
						// session. Before the discriminator was set explicitly the failure mode was worse than a loop:
						// where two co-hosted applications happened to share a key ring AND a content root, one host
						// could DECRYPT and accept a ticket minted by the other, silently carrying an identity across an
						// application boundary it was never issued for.
						//
						// The rename is applied to this host alone rather than to both participants, because that is the
						// minimal change that makes the pair unique: "erp_auth_crm" is the correct, descriptive name for
						// the CRM host, and renaming that host too would log out its users for no security gain.
						// Existing sessions on THIS host end once, at deployment, because the browser's old cookie is no
						// longer read - a one-time re-login, recorded in the remediation log.
						options.Cookie.Name = "erp_auth_mscdm";
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
			// attempts), OWASP A07: unlimited request rates left credential stuffing unthrottled. Activates the
			// per-remote-address fixed window registered in AddErp. Positioned after both UseStaticFiles calls
			// so static assets are never throttled, and after UseRouting so endpoint metadata is available.
			//
			// This is the coarse TRANSPORT-level layer only; the mandated five-attempt per-account lockout is a
			// complementary control in LoginThrottleService, which still stops a guess spread thinly across many
			// addresses. Permit counts are single-sourced in AddErp - tune them there, never per host.
			app.UseRateLimiter();
			app.UseAuthentication();
			app.UseAuthorization();

			app
			.UseErpPlugin<MicrosoftCDMPlugin>()
			.UseErpPlugin<SdkPlugin>()
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
