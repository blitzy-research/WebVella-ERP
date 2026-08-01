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
using WebVella.Erp.Plugins.Crm;
using WebVella.Erp.Plugins.Next;
using WebVella.Erp.Plugins.SDK;
using WebVella.Erp.Web;
using WebVella.Erp.Web.Middleware;

namespace WebVella.Erp.Site.Crm
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
						options.Cookie.HttpOnly = true;
						options.Cookie.Name = "erp_auth_crm";
						options.LoginPath = new PathString("/login");
						options.LogoutPath = new PathString("/logout");
						options.AccessDeniedPath = new PathString("/error?access_denied");
						options.ReturnUrlParameter = "returnUrl";

						// THREAT ADDRESSED - finding H-08 / H-15, CWE-614 (sensitive cookie without the 'Secure'
						// attribute) and CWE-1275 (sensitive cookie with an improper SameSite attribute), OWASP A05:
						// the authentication cookie was HttpOnly but carried neither Secure nor SameSite and had no
						// bounded lifetime, so it could travel in cleartext, be attached to cross-site requests, and
						// be renewed indefinitely.
						//
						// SecurePolicy is Always outside Development. It relaxes to SameAsRequest in Development only,
						// because HTTPS redirection is likewise disabled there and an unconditionally Secure cookie
						// would make local HTTP sign-in impossible - breaking the functionality-preservation
						// requirement. Reading ASPNETCORE_ENVIRONMENT directly is exactly equivalent to
						// IWebHostEnvironment.EnvironmentName here, because no host calls UseEnvironment, and it fails
						// secure: an unset variable is not "Development", so the policy becomes Always.
						options.Cookie.SecurePolicy = string.Equals(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"), "Development", StringComparison.OrdinalIgnoreCase)
							? CookieSecurePolicy.SameAsRequest
							: CookieSecurePolicy.Always;

						// Lax, deliberately not Strict: Strict drops the cookie on the return-URL round trip back from
						// the login page, which would break a working flow. Lax is the framework's own default posture
						// and still withholds the cookie from cross-site POST requests.
						// The type is named in full because Microsoft.Net.Http.Headers and Microsoft.AspNetCore.Http
						// both declare a SameSiteMode and this file imports both; CookieBuilder.SameSite is the latter.
						options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;

						// An explicit, absolute session window. SlidingExpiration is false so the window cannot be
						// extended: with sliding enabled a stolen cookie is renewed on every request and never expires
						// while it is being used, so the credential is never re-presented.
						options.ExpireTimeSpan = TimeSpan.FromHours(8);
						options.SlidingExpiration = false;
					});

			services.AddErp();
		}

		// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
		public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
		{
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
			// because local development runs over plain HTTP. HSTS precedes redirection so the policy is
			// published on the very response that performs the redirect.
			//
			// Ordering is deliberate and load-bearing: this sits AFTER UseCors. The CORS middleware
			// short-circuits cross-origin preflight, so an OPTIONS request is answered before it can reach
			// the redirect. That is what avoids the documented failure where HTTPS redirection answers a
			// preflight with a redirect the browser rejects as invalid. Moving this above UseCors would
			// reintroduce it.
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

			// THREAT ADDRESSED - finding H-08 / H-16, CWE-307 (improper restriction of excessive
			// authentication attempts): activates the per-remote-address fixed window registered in AddErp.
			// Positioned after both UseStaticFiles calls so static assets are never throttled, and after
			// UseRouting so endpoint metadata is available to the limiter.
			app.UseRateLimiter();
			app.UseAuthentication();
			app.UseAuthorization();

			app
			.UseErpPlugin<NextPlugin>()
			.UseErpPlugin<SdkPlugin>()
			.UseErpPlugin<CrmPlugin>()
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

