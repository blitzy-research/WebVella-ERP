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
		// Injected so ConfigureServices can make its two environment-dependent security decisions below -
		// the /dev anonymous exemption and Blazor DetailedErrors - which Configure's own env parameter
		// cannot reach. Constructor injection is how StartupLoader supplies it, as in WebVella.Erp.Site.
		private readonly IWebHostEnvironment environment;

		public Startup(IWebHostEnvironment environment)
		{
			this.environment = environment;
		}

		// Single definition of the environment test used three times below, in the same comparison idiom the
		// guards in Configure use. It fails SECURE: any name that is not exactly "Development" - misspelled,
		// empty or absent - yields false and therefore selects the hardened branch.
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

					// THREAT ADDRESSED - CWE-306 missing authentication for a critical function and CWE-209 error message
					// containing sensitive information, OWASP A05 / A07. AuthorizeFolder("/") above is deny-by-default, so
					// the line below is an EXPLICIT exemption publishing the SDK developer page - the only such exemption
					// in the seven hosts. Unconditional, it delivered full server exception text to an unauthenticated
					// caller, /dev being a Blazor Server component in the host that set CircuitOptions.DetailedErrors.
					// Gating it keeps the developer workflow that needs /dev without a session while a deployed host falls
					// back to deny-by-default; the residual Development risk is in docs/security/risk-register.md.
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
			// THREAT ADDRESSED - CWE-209 error message containing sensitive information and CWE-489 active debug
			// code, OWASP A05. DetailedErrors was hard-coded true in a host that ships to Production, and it
			// decides whether an unhandled Blazor Server exception reaches the browser with its stack trace. This
			// is the only host configuring Blazor Server, so it is set here alone and follows the environment. It
			// is deliberately NOT configuration-driven: a key would let the disclosure be switched back on.
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

						// THREAT ADDRESSED - CWE-614 cookie without 'Secure', CWE-1275 improper SameSite, CWE-613
						// insufficient session expiration, OWASP A02 / A05. Single-sourced in
						// ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie; called LAST so it wins over the above.
						ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie(options);
					});

			services.AddErp();
		}

		// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
		public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
		{
			// THREAT ADDRESSED - CWE-348 less trusted source, CWE-290 spoofing, CWE-307 excessive authentication
			// attempts, OWASP A05: behind a reverse proxy the rate-limit partition and the per-address half of the
			// login lockout collapsed onto the proxy's address and Request.IsHttps read false. FIRST is
			// load-bearing, and no proxy is trusted until Settings:ForwardedHeaders names one.
			app.UseErpForwardedHeaders();

			app.UseRequestLocalization(new RequestLocalizationOptions
			{
				DefaultRequestCulture = new Microsoft.AspNetCore.Localization.RequestCulture(CultureInfo.GetCultureInfo("en-US"))
			});

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
			// THREAT ADDRESSED - finding M-01, missing security response headers (OWASP A05). ORDERING IS THE
			// REMEDIATION: a matched static asset TERMINATES the pipeline, so this must precede both
			// UseStaticFiles calls. Registered once in AddErp but ordered per host, UseErp() running later.
			app.UseSecurityHeaders();

			app.UseResponseCompression();

			app.UseCors("AllowNodeJsLocalhost"); //Enable CORS -> should be before static files to enable for it too

			// THREAT ADDRESSED - finding H-15, CWE-319 cleartext transmission and CWE-614, OWASP A02: no host
			// enforced HTTPS or published an HSTS policy, so a session could be downgraded and its cookie
			// intercepted. Guarded to non-Development, which runs over plain HTTP. HSTS precedes the redirect,
			// which short-circuits plaintext requests, and both follow UseCors because redirection answers a
			// preflight with a redirect browsers reject. HstsOptions are set to the mandated year in AddErp.
			if (!string.Equals(env.EnvironmentName, "Development", StringComparison.OrdinalIgnoreCase))
			{
				app.UseHsts();
				app.UseHttpsRedirection();
			}

			app.UseStaticFiles(new StaticFileOptions
			{
				// THREAT ADDRESSED - CWE-548 exposure of information through static file serving and CWE-200, OWASP
				// A05. This host alone set it true, a divergence rather than a requirement: while true the middleware
				// serves any web-root file whose extension is unmapped, and with DefaultContentType unset serves it
				// with no Content-Type, so anything left there was downloadable without a session. Verified
				// non-load-bearing - the only unmapped extension present is .br, and every .br file has a sibling.
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

			// THREAT ADDRESSED - finding H-16, CWE-307 excessive authentication attempts, OWASP A07: activates the
			// per-remote-address window registered in AddErp, after both UseStaticFiles calls so assets are never
			// throttled and after UseRouting for endpoint metadata. TRANSPORT layer only - the mandated
			// five-attempt account lockout is LoginThrottleService. Tune the permit limit in AddErp, never here.
			app.UseRateLimiter();
			app.UseAuthentication();
			app.UseAuthorization();

			app
			.UseErpPlugin<SdkPlugin>()
			.UseErp()
			.UseErpMiddleware();

			app.UseEndpoints(endpoints =>
			{
				// THREAT ADDRESSED - CWE-306 missing authentication for a critical function, OWASP A05 / A07.
				// MapBlazorHub carries no authorization metadata and is a SEPARATE endpoint from the page that starts
				// it, so gating /dev alone would have left the hub - where component code executes - anonymous.
				// Guarded to non-Development for the same reason as that exemption; outside Development every hosted
				// component sits under AuthorizeFolder("/") and needs the cookie the hub's requests already carry.
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

