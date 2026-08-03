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
using WebVella.Erp.Plugins.Next;
using WebVella.Erp.Plugins.Project;
using WebVella.Erp.Plugins.SDK;
using WebVella.Erp.Web;
using WebVella.Erp.Web.Middleware;

namespace WebVella.Erp.Site.Project
{

	public class Startup
	{
		// Separators accepted between entries in the cross-origin allow-list. Both are accepted for the
		// same reason ErpMvcExtensions.ForwardedHeadersListSeparators accepts both: operators supply this
		// value through an environment variable, where a semicolon is the more familiar separator, and
		// through JSON, where a comma is. Held in a static field rather than allocated inline at the call
		// site, matching that established idiom.
		private static readonly char[] CorsAllowedOriginsSeparators = new[] { ',', ';' };

		public IConfigurationRoot Configuration { get; private set; } = null;
		// This method gets called by the runtime. Use this method to add services to the container.
		public void ConfigureServices(IServiceCollection services)
		{
			//legacy until we fix system tables
			AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);

			// SECURITY - CWE-178 improper handling of case sensitivity, OWASP A05 Security Misconfiguration.
			// THREAT: the tracked and published file is named "Config.json", so the lowercase spelling this
			// replaced does not resolve on a case-sensitive filesystem and this NON-OPTIONAL source aborted
			// startup on every Linux and container deployment. The obvious field workaround - hand-placing a
			// lowercase copy beside the binaries - silently substitutes an unreviewed, unscrubbed
			// configuration file for the audited one, so the exact on-disk name is used here.
			string configPath = "Config.json";

			// THE LOWERCASE NAME IS ACCEPTED ONLY AS A FALLBACK, so existing deployments whose publish
			// output carries only a lowercase copy keep starting while the audited file still wins whenever
			// it is present. The probe resolves against AppContext.BaseDirectory - the SAME base path the
			// builder below sets - so it tests the directory the provider will actually read. Probing
			// Directory.GetCurrentDirectory() or env.ContentRootPath instead would test whatever working
			// directory the process was launched with, which both misses a lowercase-only output and lets a
			// file in an attacker-writable directory decide the selection - the CWE-706 defect the base path
			// below exists to avoid. System.IO is fully qualified rather than imported, matching this
			// repository's idiom for a single path call.
			if (!System.IO.File.Exists(System.IO.Path.Combine(AppContext.BaseDirectory, configPath))
				&& System.IO.File.Exists(System.IO.Path.Combine(AppContext.BaseDirectory, "config.json")))
				configPath = "config.json";

			// SECURITY - finding M-2 (CWE-20, CWE-798), OWASP A05 Security Misconfiguration.
			// THREAT: identical to WebVella.Erp.Site - this Configuration instance supplies the JWT signing key
			// to AddJwtBearer below, and with only a JSON provider that key could come from nowhere but a
			// tracked file, making the repository's published example key the effective key of every
			// unmodified deployment. Environment variables are added LAST so an operator-supplied value wins.
			//
			// SECURITY - CWE-706 use of an incorrectly resolved name, same OWASP A05 category. The base path
			// is AppContext.BaseDirectory, the directory the entry assembly was loaded from and exactly where
			// the build and publish outputs place Config.json - NOT Directory.GetCurrentDirectory(), which
			// resolves against whatever working directory the process was launched with and would let the
			// launcher choose which Config.json supplies the connection string, the data-at-rest encryption
			// key and the token signing key. IWebHostEnvironment.ContentRootPath is no safer, because
			// WebHost.CreateDefaultBuilder defaults it to the current directory too.
			var configurationBuilder = new ConfigurationBuilder().SetBasePath(AppContext.BaseDirectory).AddJsonFile(configPath);

			// Development only, and fails secure - an unset ASPNETCORE_ENVIRONMENT is not "Development", so the
			// developer-only provider stays out. Same idiom as the cookie and HSTS guards further down this file.
			// optional: true because this project declares no UserSecretsId; a developer who wants the store
			// runs 'dotnet user-secrets init' and it starts working, while startup never throws without it.
			if (string.Equals(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"), "Development", StringComparison.OrdinalIgnoreCase))
				configurationBuilder.AddUserSecrets(typeof(Startup).Assembly, optional: true);

			configurationBuilder.AddEnvironmentVariables();

			Configuration = configurationBuilder.Build();


			services.Configure<GzipCompressionProviderOptions>(options => options.Level = CompressionLevel.Optimal);
			services.AddResponseCompression(options => { options.Providers.Add<GzipCompressionProvider>(); });
			services.AddRouting(options => { options.LowercaseUrls = true; });

			//CORS policy declaration
			//services.AddCors(options =>
			//{
			//	options.AddPolicy("AllowNodeJsLocalhost",
			//		builder => builder.WithOrigins("http://localhost:3333", "http://localhost:3000", "http://localhost", "http://localhost:2202").AllowAnyMethod().AllowCredentials());
			//});
            // THREAT ADDRESSED - finding H-14 (CWE-942 permissive cross-domain policy with untrusted domains),
            // OWASP A05 Security Misconfiguration: the default policy called AllowAnyOrigin(), so ANY website a
            // signed-in user visited could issue cross-origin requests to this host and read the responses.
            //
            // The allow-list is now read from configuration and is EMPTY unless an operator supplies it, which
            // is the deny-by-default posture the Authorization Enforcement standard mandates. The four
            // http://localhost origins this replaced were the ones named in the restrictive policy kept in
            // comment form immediately above, and taking them as the fix was itself the residual defect:
            // they are DEVELOPMENT origins compiled into every production build, so on any host where another
            // process can bind those ports - a container sibling, a co-tenant, a developer tool, anything
            // running as another user on the same machine - that process obtained cross-origin read access to
            // this ERP host, and no operator could remove them or add a legitimate origin without a rebuild.
            //
            // Supplied as a single ','/';'-delimited string through Settings__Cors__AllowedOrigins rather than
            // as a JSON array, because an array cannot be provided through one environment variable - it would
            // need Settings__Cors__AllowedOrigins__0, __1 and so on - and the environment is the supply
            // channel the scrubbed Config.json leaves. The key is deliberately NOT added to Config.json: an
            // absent key already means deny-by-default, so adding one would only invite a checked-in origin
            // list. Origins are trimmed and otherwise used exactly as written, because origin matching is
            // exact and "helpful" normalisation would silently widen or narrow the set.
            //
            // AllowCredentials() is deliberately NOT added: the framework rejects it alongside AllowAnyOrigin(),
            // so credentialed cross-origin requests were never actually permitted here and adding it now would
            // WIDEN behaviour rather than preserve it. AllowAnyMethod()/AllowAnyHeader() are retained because
            // the finding is an over-broad ORIGIN set - narrowing methods or headers as well would be
            // unrequested hardening that could break working clients.
            // AddDefaultPolicy is kept rather than converted to a named policy so the app.UseCors() call in
            // Configure needs no change at all, which also preserves the load-bearing UseCors-before-HTTPS-
            // redirection ordering documented at that call site.
            string configuredCorsOrigins = Configuration["Settings:Cors:AllowedOrigins"];
            string[] allowedCorsOrigins = string.IsNullOrWhiteSpace(configuredCorsOrigins)
                ? Array.Empty<string>()
                : configuredCorsOrigins.Split(CorsAllowedOriginsSeparators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            services.AddCors(options =>
            {
                // WithOrigins on an empty array is legal and adds no origin, so the policy matches nothing and
                // the middleware emits no Access-Control-Allow-Origin at all. That is the intended unconfigured
                // state: same-origin requests are untouched, every cross-origin one is refused.
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
			})
			 .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
			 {
				 // SECURITY - finding M-2 (CWE-20, CWE-798), OWASP A05 / A07.
				 // THREAT: identical to WebVella.Erp.Site - the raw configured value went straight into
				 // Encoding.UTF8.GetBytes, so a null key crashed ConfigureServices and this repository's
				 // published example key was accepted without challenge, letting anyone who read the public
				 // source mint a valid administrator token.
				 // Screened by the same predicate ErpSettings uses to decide whether the token routes stay
				 // enabled, so the handler and the routes can never disagree. It is a pure function over the raw
				 // value because ConfigureServices runs before ErpSettings.Initialize.
				 var configuredSigningKey = Configuration["Settings:Jwt:Key"];

				 options.TokenValidationParameters = new TokenValidationParameters
				 {
					 ValidateIssuer = true,
					 ValidateAudience = true,
					 ValidateLifetime = true,
					 ValidateIssuerSigningKey = true,
					 ValidIssuer = Configuration["Settings:Jwt:Issuer"],
					 ValidAudience = Configuration["Settings:Jwt:Audience"],

					 // THREAT ADDRESSED - finding F7 (CWE-613, insufficient session expiration), OWASP A07.
					 // ClockSkew was omitted here, so this validator silently used the IdentityModel default of FIVE
					 // MINUTES while the platform's own secondary validator
					 // (WebVella.Erp.Web/Services/AuthService.cs, GetValidSecurityTokenAsync) used ONE. Two validators
					 // judging the same token disagreed about when it expires, and the looser of the two is the one that
					 // authorises the request: an expired bearer principal stayed authorised for up to four minutes
					 // longer than the platform's own policy allows.
					 // Read FROM the same member the secondary validator consumes rather than restated as a literal, so
					 // the two hosts and the platform cannot drift apart - parity is a compile-time dependency.
					 ClockSkew = WebVella.Erp.Web.Services.AuthService.JwtClockSkew,

					 // Left null when the key is unacceptable. ValidateIssuerSigningKey stays true, so every
					 // presented token fails signature validation and gets a clean 401 rather than being
					 // accepted. The scheme stays registered even then, because the JWT_OR_COOKIE policy scheme
					 // below forwards any "Bearer " request to it and an unregistered target would be a 500.
					 IssuerSigningKey = ErpSettings.IsAcceptableJwtKey(configuredSigningKey)
						 ? new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuredSigningKey))
						 : null
				 };
			 })
			  .AddPolicyScheme("JWT_OR_COOKIE", "JWT_OR_COOKIE", options =>
			  {
				  options.ForwardDefaultSelector = context => 
				  {
					  string authorization = context.Request.Headers[HeaderNames.Authorization];
					  if (!string.IsNullOrEmpty(authorization) && authorization.StartsWith("Bearer "))
						  return JwtBearerDefaults.AuthenticationScheme;

					  return CookieAuthenticationDefaults.AuthenticationScheme;
				  };
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

            //app.UseCors("AllowNodeJsLocalhost"); //Enable CORS -> should be before static files to enable for it too
            app.UseCors(); //Enable CORS -> should be before static files to enable for it too

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

