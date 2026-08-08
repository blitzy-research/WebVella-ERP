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
			// DELIBERATELY UNCHANGED - finding H-14 (CWE-942 permissive cross-domain policy) scopes that
			// remediation to the two hosts that called AllowAnyOrigin. This host already names its origins, so the
			// named policy below is retained verbatim; the hard-coded localhost origins are a documented
			// low-severity note, and HTTPS redirection below is guarded to non-Development so it never rewrites
			// the plaintext preflight they depend on.
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

						// THREAT ADDRESSED - finding H-15 (CWE-614 cookie without 'Secure', CWE-319 cleartext transmission),
						// plus CWE-1275 improper SameSite and CWE-613 insufficient session expiration, OWASP A02 / A05. H-15's
						// cookie half is closed by the four attributes the call below applies. SameSite is Lax and MUST NOT be
						// "upgraded" to Strict: Strict withholds the cookie on the return-URL round trip back from /login that
						// ReturnUrlParameter above depends on. The window is kept equal to
						// AuthService.AUTH_TICKET_EXPIRY_DURATION_MINUTES because AuthService issues an explicit ExpiresUtc, so
						// ExpireTimeSpan is never consulted and the configured and enforced values could otherwise diverge.
						// All four are single-sourced in ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie; called
						// LAST so it wins over the above.
						ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie(options);
					});

			services.AddErp();
		}

		// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
		public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
		{
			// THREAT ADDRESSED - CWE-348 less trusted source, CWE-290 spoofing, CWE-307 excessive authentication
			// attempts, OWASP A05: behind a reverse proxy the rate-limit partition and the per-address half of the
			// login lockout collapsed onto the proxy's address and Request.IsHttps read false for TLS requests.
			// FIRST is load-bearing, and no proxy is trusted until Settings:ForwardedHeaders names one.
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

			// THREAT ADDRESSED - finding H-16, CWE-307 excessive authentication attempts: activates the
			// per-remote-address window registered in AddErp, after both UseStaticFiles calls so assets are never
			// throttled and after UseRouting for endpoint metadata. The mandated five-attempt per-account lockout
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

