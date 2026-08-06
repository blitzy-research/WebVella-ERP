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
		// Separators accepted between entries in the cross-origin allow-list. Both are accepted for the
		// same reason ErpMvcExtensions.ForwardedHeadersListSeparators accepts both: operators supply this
		// value through an environment variable, where a semicolon is the more familiar separator, and
		// through JSON, where a comma is. Held in a static field rather than allocated inline at the call
		// site, matching that established idiom.
		private static readonly char[] CorsAllowedOriginsSeparators = new[] { ',', ';' };

		// The origins named in this host's own commented-out policy below, used as the allow-list default in
		// DEVELOPMENT ONLY. They are this host's documented development client contract, not deployment
		// configuration: http://localhost:2202 is the siteRootUrl the shipped Project Stencil bundles under
		// WebVella.Erp.Plugins.Project/wwwroot/js compile in as their default, which is why this host names
		// four origins where the sibling WebVella.Erp.Site names three. See the allow-list comment below.
		private static readonly string[] CorsDevelopmentDefaultOrigins = new[] { "http://localhost:3333", "http://localhost:3000", "http://localhost", "http://localhost:2202" };

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

			// SECURITY - findings H-04 and H-05 (CWE-798, CWE-321), OWASP A05 Security Misconfiguration.
			// THREAT: identical to WebVella.Erp.Site - this Configuration instance supplies the JWT signing key
			// to AddJwtBearer below, and with only a JSON provider that key could come from nowhere but a
			// tracked file, making the repository's published example key the effective key of every
			// unmodified deployment. Environment variables are therefore added straight after the JSON file.
			//
			// SECURITY - CWE-1188 insecure default initialization of a resource, same OWASP A05 category.
			// THREAT: the PROVIDER ORDER here is load-bearing, not cosmetic. This host resolves the signing key
			// twice over two different Configuration instances: this one feeds AddJwtBearer, which VALIDATES
			// incoming tokens, while ErpSettings - built by ErpMvcExtensions.AddErp with the chain JSON ->
			// environment -> user secrets - feeds AuthService, which SIGNS them. In ASP.NET Core the last
			// provider to define a key wins, so a chain that ended with user secrets while the shared chain
			// ended with environment variables would let the two instances resolve DIFFERENT keys on a
			// developer machine that defined both: the host would then reject the tokens it had just issued,
			// and - far worse for an audit - the key actually in force would depend on which consumer was
			// asked. The order below is therefore identical to ErpMvcExtensions, WebVella.Erp.Site and the
			// console host: JSON file, then environment variables, then development-only user secrets.
			//
			// SECURITY - CWE-706 use of an incorrectly resolved name, same OWASP A05 category. The base path
			// is AppContext.BaseDirectory, the directory the entry assembly was loaded from and exactly where
			// the build and publish outputs place Config.json - NOT Directory.GetCurrentDirectory(), which
			// resolves against whatever working directory the process was launched with and would let the
			// launcher choose which Config.json supplies the connection string, the data-at-rest encryption
			// key and the token signing key. IWebHostEnvironment.ContentRootPath is no safer, because
			// WebHost.CreateDefaultBuilder defaults it to the current directory too.
			var configurationBuilder = new ConfigurationBuilder().SetBasePath(AppContext.BaseDirectory).AddJsonFile(configPath);

			configurationBuilder.AddEnvironmentVariables();

			// Development only, and added last so a developer's own local store wins on their own machine - the
			// same position it occupies in the shared chain, which is what keeps the signing and validating
			// halves of this host on one key. User secrets live unencrypted outside the repository: a developer
			// convenience, never a production channel - outside Development this provider is never registered
			// at all, leaving environment variables as the last word wherever it matters. The guard fails
			// secure: an unset ASPNETCORE_ENVIRONMENT is not "Development", so the developer-only provider
			// stays out. Same idiom as the cookie and HSTS guards further down this file.
			//
			// THREAT ADDRESSED - review finding CR3-M-07 (secret management, OWASP A05:2021). This used to
			// read "optional: true because this project declares no UserSecretsId; a developer who wants the
			// store runs 'dotnet user-secrets init'". That instruction did not work: 'user-secrets init'
			// WRITES a UserSecretsId into the manifest, so following it modified a tracked file, and until
			// someone did, this provider resolved no store and silently loaded nothing while the operator
			// documentation advertised it as available. The manifest now declares a stable id, so the store
			// resolves for every developer without editing anything. optional: true is retained because a
			// developer who has not yet run 'dotnet user-secrets set' has no store FILE, and startup must
			// report the missing secret through ErpSettings' validation rather than through a provider fault.
			if (string.Equals(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"), "Development", StringComparison.OrdinalIgnoreCase))
				configurationBuilder.AddUserSecrets(typeof(Startup).Assembly, optional: true);

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
            // The allow-list is read from configuration and is EMPTY outside Development unless an operator
            // supplies it, which is the deny-by-default posture the Authorization Enforcement standard
            // mandates. Taking the four http://localhost origins named in the restrictive policy kept in
            // comment form immediately above and compiling them in unconditionally - the first attempt at
            // this fix - was itself a residual defect: they are DEVELOPMENT origins, so on any production
            // host where another process can bind those ports - a container sibling, a co-tenant, a developer
            // tool, anything running as another user on the same machine - that process obtained cross-origin
            // read access to this ERP host, and no operator could remove them or add a legitimate origin
            // without a rebuild.
            //
            // Sourcing the list from configuration ALONE was the opposite defect and is the regression this
            // guard repairs (review finding FRONTEND-01): no file in this repository, no shipped Config.json
            // and no documented setup step supplies the key, so the list resolved EMPTY in Development too and
            // every cross-origin call from this host's own shipped clients was refused. Those clients are not
            // hypothetical - the Stencil bundles under WebVella.Erp.Plugins.Project/wwwroot/js compile
            // http://localhost:2202 in as their default siteRootUrl and POST application/json to
            // /api/v3.0/p/project/pc-post-list/{create,delete} and pc-timelog-list/{create,delete}, which are
            // preflighted requests - so an empty list broke a documented, working workflow. Restoring those
            // origins as a DEVELOPMENT-ONLY default leaves the production posture untouched: an unset
            // ASPNETCORE_ENVIRONMENT is not "Development", so the default fails secure, and this file already
            // gates its user-secrets provider and its HSTS/HTTPS-redirection pair on the same comparison.
            //
            // A supplied value ALWAYS wins, in every environment, and is supplied as a single ','/';'-delimited
            // string through Settings__Cors__AllowedOrigins rather than as a JSON array, because an array
            // cannot be provided through one environment variable - it would need
            // Settings__Cors__AllowedOrigins__0, __1 and so on - and the environment is the supply channel the
            // scrubbed Config.json leaves. Supplying the key EMPTY is an explicit "allow nothing" and is
            // honoured as written even in Development, so the strict posture stays reproducible without
            // changing the environment name. The key is deliberately NOT added to Config.json: an absent key
            // already has a defined meaning, so adding one would only invite a checked-in origin list. Origins
            // are trimmed and otherwise used exactly as written, because origin matching is exact and
            // "helpful" normalisation would silently widen or narrow the set.
            //
            // AllowCredentials() is deliberately NOT added: the framework rejects it alongside AllowAnyOrigin(),
            // so credentialed cross-origin requests were never actually permitted here and adding it now would
            // WIDEN behaviour rather than preserve it. AllowAnyMethod()/AllowAnyHeader() are retained because
            // the finding is an over-broad ORIGIN set - narrowing methods or headers as well would be
            // unrequested hardening that could break working clients. AllowAnyHeader() is load-bearing here in
            // particular: the Project clients attach a stray Access-Control-Allow-Origin request header, so
            // their preflight asks permission for a header no narrower list would have named.
            // AddDefaultPolicy is kept rather than converted to a named policy so the app.UseCors() call in
            // Configure needs no change at all, which also preserves the load-bearing UseCors-before-HTTPS-
            // redirection ordering documented at that call site.
            //
            // Configuration is consulted for the KEY, not merely for a non-blank value, so that a supplied but
            // empty Settings__Cors__AllowedOrigins reads as the explicit "allow nothing" described above while
            // an entirely absent key still lets Development fall back. No provider materialises a key nobody
            // supplied, so null here means exactly "unconfigured".
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
                // WithOrigins on an empty array is legal and adds no origin, so the policy matches nothing and
                // the middleware emits no Access-Control-Allow-Origin at all. That is the intended state
                // whenever the list resolves empty - unconfigured outside Development, or explicitly emptied -
                // and it leaves same-origin requests untouched while refusing every cross-origin one.
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
				// The four attributes live in ONE place rather than being duplicated per host, because seven copies
				// are what let them drift apart; see ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie for
				// the full rationale, including why sliding expiration is safe only when paired with an absolute
				// session horizon. Called LAST in this lambda deliberately, so the platform contract wins over
				// anything a host sets; nothing above this line is a security attribute.
				ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie(options);
			})
			 .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
			 {
				 // SECURITY - finding H-04 (CWE-798, CWE-321), OWASP A05 / A07.
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

				 // THREAT ADDRESSED - finding F-02 (session hijacking via a non-revocable bearer token;
				 // CWE-613 insufficient session expiration), OWASP A07. Signature, issuer, audience and
				 // lifetime are all verified above - and a token that passed all four was then accepted even if
				 // the session it represents had been ENDED. Logging out, disabling the account or rotating the
				 // password left a stolen token working, because nothing in this handler consulted any
				 // server-side state at all.
				 //
				 // THIS handler is the one that matters: framework authorization runs it for every [Authorize]
				 // endpoint reached with a bearer token, because the JWT_OR_COOKIE policy scheme below forwards
				 // any request carrying a "Bearer " header to it. The platform's own validator in
				 // WebVella.Erp.Web.Services.AuthService applies the identical check, but it authorises nothing
				 // by itself, so a revocation check present only there would have been decorative.
				 //
				 // The RULE lives in the platform, single-sourced with the other token-issuing host, and only
				 // the HOOK lives here: the handler's options type ships in a package that only this host and
				 // WebVella.Erp.Site reference, so the platform assembly cannot install this itself without a
				 // new package dependency, which the remediation constraints forbid. Assigning Events is safe
				 // because nothing else assigns it - this registration configured only TokenValidationParameters.
				 //
				 // Fails CLOSED: the predicate also refuses a principal carrying no parseable session
				 // identifier, so a token shaped differently from what this build mints is rejected rather than
				 // given the benefit of the doubt. Fail() turns the outcome into a clean 401.
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

					  // THREAT ADDRESSED - CWE-178 (improper handling of case sensitivity) leading to an
					  // authentication bypass of the intended scheme. Review finding C-02. RFC 7235 defines
					  // the authorization scheme token as case-INSENSITIVE, so "bearer <jwt>" is a valid
					  // credential that this ordinal, case-sensitive test did not recognise. Such a request
					  // was forwarded to the COOKIE handler instead, which finds no cookie, so a correctly
					  // authenticated API caller was answered as anonymous - and, because the cookie handler
					  // owns the challenge, was issued a login redirect rather than a 401. The platform's own
					  // JwtMiddleware already compares this prefix with StringComparison.OrdinalIgnoreCase;
					  // this brings the scheme selector into line with it rather than inventing a new rule.
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

            //app.UseCors("AllowNodeJsLocalhost"); //Enable CORS -> should be before static files to enable for it too
            app.UseCors(); //Enable CORS -> should be before static files to enable for it too

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

