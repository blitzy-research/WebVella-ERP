using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Threading.Tasks;
using WebVella.Erp.Plugins.Next;
using WebVella.Erp.Plugins.Project;
using WebVella.Erp.Plugins.SDK;
using WebVella.Erp.Web;
using WebVella.Erp.Web.Middleware;

namespace WebVella.Erp.Site.Project
{

	public class Startup
	{
		// Both separators are accepted because the allow-list arrives either through a single environment
		// variable (';' is idiomatic there) or through JSON (','), as in ErpMvcExtensions.
		private static readonly char[] CorsAllowedOriginsSeparators = new[] { ',', ';' };

		// DEVELOPMENT-ONLY default for the allow-list below: this host's local client contract, never
		// deployment configuration. Four origins where the sibling WebVella.Erp.Site names three, because
		// the shipped Project Stencil bundles compile http://localhost:2202 in as their siteRootUrl.
		private static readonly string[] CorsDevelopmentDefaultOrigins = new[] { "http://localhost:3333", "http://localhost:3000", "http://localhost", "http://localhost:2202" };

		public IConfigurationRoot Configuration { get; private set; } = null;
		// This method gets called by the runtime. Use this method to add services to the container.
		public void ConfigureServices(IServiceCollection services)
		{
			//legacy until we fix system tables
			AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);

			// SECURITY - CWE-178 improper handling of case sensitivity, OWASP A05: the published name is
			// "Config.json", and the field workaround for a missing lowercase name - a hand-made copy - would
			// substitute unscrubbed configuration for the audited file.
			string configPath = "Config.json";

			// Lowercase is a FALLBACK only, probed against AppContext.BaseDirectory - the base the builder sets -
			// because probing the current directory would let a plantable file decide the choice (CWE-706).
			if (!System.IO.File.Exists(System.IO.Path.Combine(AppContext.BaseDirectory, configPath))
				&& System.IO.File.Exists(System.IO.Path.Combine(AppContext.BaseDirectory, "config.json")))
				configPath = "config.json";

			// SECURITY - findings H-04 and H-05 (CWE-798 hard-coded credentials, CWE-321 hard-coded key), OWASP
			// A05: this Configuration supplies the JWT signing key to AddJwtBearer below, and with only a JSON
			// provider that key could come from nowhere but a tracked file. Base path is AppContext.BaseDirectory,
			// not the current directory, so the launcher cannot choose which secrets are read (CWE-706).
			//
			// SECURITY - CWE-1188 insecure default initialization: the PROVIDER ORDER is load-bearing here
			// because this host resolves the signing key over TWO Configuration instances - this one validates
			// tokens, the one ErpSettings builds signs them - and the last provider to define a key wins. A
			// divergent order would let them resolve different keys, so the host would reject tokens it had just
			// issued. The order matches ErpMvcExtensions exactly: JSON, environment, development-only secrets.
			var configurationBuilder = new ConfigurationBuilder().SetBasePath(AppContext.BaseDirectory).AddJsonFile(configPath);

			configurationBuilder.AddEnvironmentVariables();

			// Development only, added LAST - the same position it holds in the shared chain, which is what keeps
			// this host's signing and validating halves on one key. User secrets are unencrypted and outside the
			// repository, so outside Development the provider is not registered at all and the guard fails secure.
			// Passing optional: true keeps a developer who has set no secret yet reporting the gap through
			// ErpSettings' validation rather than through a provider fault.
			if (string.Equals(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"), "Development", StringComparison.OrdinalIgnoreCase))
				configurationBuilder.AddUserSecrets(typeof(Startup).Assembly, optional: true);

			Configuration = configurationBuilder.Build();


			services.Configure<GzipCompressionProviderOptions>(options => options.Level = CompressionLevel.Optimal);
			services.AddResponseCompression(options => { options.Providers.Add<GzipCompressionProvider>(); });
			services.AddRouting(options => { options.LowercaseUrls = true; });

			// THREAT ADDRESSED - finding H-14 (CWE-942 permissive cross-domain policy), OWASP A05: the policy
			// called AllowAnyOrigin(), so any site a signed-in user visited could read this host's responses.
			// Deny-by-default now - the list is EMPTY outside Development unless an operator supplies
			// Settings__Cors__AllowedOrigins, one ','/';'-delimited string because an array cannot arrive through
			// a single environment variable. The KEY is read rather than its content, so supplied-but-empty means
			// "allow nothing" while an absent key lets Development fall back; origins are used verbatim after
			// trimming, because matching is exact. The Development-only default is load-bearing: no shipped file
			// supplies the key, so a configuration-only list refused every preflighted call from this host's own
			// Stencil clients, while compiling those origins into every environment would keep CWE-942 narrowed
			// only to origins an operator cannot change. AllowCredentials() stays out, the framework rejecting it
			// alongside AllowAnyOrigin(); AllowAnyHeader() is required because those clients attach a stray
			// Access-Control-Allow-Origin request header their preflight then asks permission for.
            string configuredCorsOrigins = Configuration["Settings:Cors:AllowedOrigins"];
            string[] allowedCorsOrigins;
            if (configuredCorsOrigins != null)
            {
                allowedCorsOrigins = configuredCorsOrigins.Split(CorsAllowedOriginsSeparators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            }
            else if (string.Equals(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"), "Development", StringComparison.OrdinalIgnoreCase))
            {
                allowedCorsOrigins = CorsDevelopmentDefaultOrigins;
            }
            else
            {
                allowedCorsOrigins = Array.Empty<string>();
            }

            services.AddCors(options =>
            {
                // WithOrigins on an empty array is legal, adds no origin and emits no Access-Control-Allow-Origin,
                // which is the intended state whenever the list resolves empty.
                options.AddDefaultPolicy(policy =>
                    policy.WithOrigins(allowedCorsOrigins)
                        .AllowAnyMethod()
                        .AllowAnyHeader());
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

			services.AddAuthentication(options =>
			{
				options.DefaultScheme = "JWT_OR_COOKIE";
				options.DefaultChallengeScheme = "JWT_OR_COOKIE";
			})
			.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            {
				options.Cookie.Name = "erp_auth_project";
				options.LoginPath = new PathString("/login");
				options.LogoutPath = new PathString("/logout");
				options.AccessDeniedPath = new PathString("/error?access_denied");
				options.ReturnUrlParameter = "returnUrl";

				// THREAT ADDRESSED - CWE-614 cookie without 'Secure', CWE-1275 improper SameSite, CWE-613
				// insufficient session expiration, OWASP A02 / A05. Single-sourced in
				// ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie; called LAST so it wins over the above.
				ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie(options);
			})
			 .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
			 {
				 // SECURITY - finding H-04 (CWE-798, CWE-321), OWASP A05 / A07: the raw value went straight into
				 // Encoding.UTF8.GetBytes, so this repository's published example key was accepted and anyone who read
				 // the public source could mint an administrator token. Screened by the SAME predicate ErpSettings uses
				 // to gate the token routes, and pure so it is callable before ErpSettings.Initialize has run.
				 var configuredSigningKey = Configuration["Settings:Jwt:Key"];

				 options.TokenValidationParameters = new TokenValidationParameters
				 {
					 ValidateIssuer = true,
					 ValidateAudience = true,
					 ValidateLifetime = true,
					 ValidateIssuerSigningKey = true,
					 ValidIssuer = Configuration["Settings:Jwt:Issuer"],
					 ValidAudience = Configuration["Settings:Jwt:Audience"],

					 // THREAT ADDRESSED - CWE-613 insufficient session expiration, OWASP A07: omitting ClockSkew left this
					 // validator on IdentityModel's five-minute default while AuthService used one, and the looser of the
					 // two authorises the request. Reading it from AuthService makes parity a compile-time dependency.
					 ClockSkew = WebVella.Erp.Web.Services.AuthService.JwtClockSkew,

					 // Left null when the key is unacceptable: ValidateIssuerSigningKey stays true, so every token fails
					 // signature validation and gets a 401. The scheme stays REGISTERED even then - JWT_OR_COOKIE
					 // forwards every "Bearer " request to it and an unregistered target would be a 500.
					 IssuerSigningKey = ErpSettings.IsAcceptableJwtKey(configuredSigningKey)
						 ? new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuredSigningKey))
						 : null
				 };

				 // THREAT ADDRESSED - session hijacking through a non-revocable bearer token (CWE-613), OWASP A07: a
				 // token passing signature, issuer, audience and lifetime was still accepted after its session had
				 // ENDED. This handler is what framework authorization runs for a bearer request, so the HOOK belongs
				 // here while the RULE stays single-sourced in AuthService. Fails CLOSED, Fail() yielding a 401.
				 options.Events = new JwtBearerEvents
				 {
					 OnTokenValidated = tokenValidatedContext =>
					 {
						 if (WebVella.Erp.Web.Services.AuthService.IsBearerSessionRevoked(tokenValidatedContext.Principal))
							 tokenValidatedContext.Fail("The session this token belongs to is no longer accepted.");

						 return Task.CompletedTask;
					 }
				 };
			 })
			  .AddPolicyScheme("JWT_OR_COOKIE", "JWT_OR_COOKIE", options =>
			  {
				  options.ForwardDefaultSelector = context =>
				  {
					  string authorization = context.Request.Headers[HeaderNames.Authorization];

					  // THREAT ADDRESSED - CWE-178 improper handling of case sensitivity bypassing the intended scheme.
					  // RFC 7235 makes the scheme token case-INSENSITIVE, so "bearer <jwt>" was forwarded to the COOKIE
					  // handler and a correctly authenticated API caller got a login redirect. Matches JwtMiddleware.
					  if (!string.IsNullOrEmpty(authorization) && authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
						  return JwtBearerDefaults.AuthenticationScheme;

					  return CookieAuthenticationDefaults.AuthenticationScheme;
				  };
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

            app.UseCors(); //Enable CORS -> should be before static files to enable for it too

            // THREAT ADDRESSED - finding H-15, CWE-319 cleartext transmission and CWE-614, OWASP A02: no host
            // enforced HTTPS or published an HSTS policy, so a session could be downgraded and its cookie
            // intercepted. Guarded to non-Development, which runs over plain HTTP. HSTS precedes the redirect,
            // which short-circuits plaintext requests, and both follow UseCors because redirection answers a
            // preflight with a redirect browsers reject. HstsOptions are set to the mandated year once in AddErp.
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
			.UseErpPlugin<SdkPlugin>()
			.UseErpPlugin<ProjectPlugin>()
			.UseErp()
			.UseErpMiddleware()
			.UseJwtMiddleware();



			app.UseEndpoints(endpoints =>
			{
				endpoints.MapRazorPages();
				endpoints.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");
			});
		}
	}
}

