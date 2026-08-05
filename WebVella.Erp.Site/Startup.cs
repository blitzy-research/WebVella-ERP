using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.IO.Compression;
using WebVella.Erp.Plugins.SDK;
using WebVella.Erp.Web;
using WebVella.Erp.Web.Middleware;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace WebVella.Erp.Site
{
    public class Startup
    {
        // Separators accepted between entries in the cross-origin allow-list. Both are accepted for the
        // same reason ErpMvcExtensions.ForwardedHeadersListSeparators accepts both: operators supply this
        // value through an environment variable, where a semicolon is the more familiar separator, and
        // through JSON, where a comma is. Held in a static field rather than allocated inline at the call
        // site, matching that established idiom and the sibling WebVella.Erp.Site.Project host.
        private static readonly char[] CorsAllowedOriginsSeparators = new[] { ',', ';' };

        // The three origins named in this host's own commented-out policy below, used as the allow-list
        // default in DEVELOPMENT ONLY. They are this host's documented development client contract, not
        // deployment configuration. This host names three where the sibling WebVella.Erp.Site.Project
        // names four: it has no Stencil client compiling http://localhost:2202 in as a siteRootUrl, so
        // adding that origin here would widen the set beyond anything this host actually serves.
        private static readonly string[] CorsDevelopmentDefaultOrigins = new[] { "http://localhost:3333", "http://localhost:3000", "http://localhost" };

        public IConfigurationRoot Configuration { get; private set; } = null;

        private readonly IWebHostEnvironment environment;

        public Startup(IWebHostEnvironment environment)
        {
            this.environment = environment;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            //legacy until we fix system tables
            AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);

            // THREAT ADDRESSED - CWE-178 improper handling of case sensitivity, OWASP A05 Security
            // Misconfiguration. The tracked and published file is named "Config.json", so on a case-sensitive
            // filesystem - every Linux and container deployment - a lowercase "config.json" does not exist and
            // this NON-OPTIONAL source aborts startup with FileNotFoundException. That failure mode is a
            // security problem and not merely an inconvenience: the obvious field workaround is to drop a
            // hand-made lowercase copy next to the binaries, which silently substitutes an unreviewed,
            // unscrubbed configuration file for the one the remediation hardened. The exact on-disk name is
            // used here so the only file that can ever be loaded is the one that was audited.
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

            // THREAT ADDRESSED - findings H-05 and H-04 (CWE-798 use of hard-coded credentials, CWE-321 use of
            // a hard-coded cryptographic key), OWASP A05 Security Misconfiguration; also the enabler for C-04.
            // Configuration was read from this JSON file and nothing else, so the connection string, the
            // encryption key and the JWT signing key that AddJwtBearer consumes below could only ever come from
            // a file tracked in source control - anyone reading the public repository held the effective secrets
            // of every deployment that did not edit it.
            // Extending the provider chain is the ENABLER that has to land before those values are blanked. The
            // JSON source deliberately stays FIRST, so an operator-supplied environment variable overrides the
            // blanked value rather than being clobbered by it, and it deliberately stays NON-OPTIONAL, so
            // Config.json must be scrubbed rather than deleted. Operators supply Settings__ConnectionString,
            // Settings__EncryptionKey, Settings__Jwt__Key and Settings__EmailSMTPPassword - "__" is the
            // framework's section separator, so these land on exactly the paths Config.json already defines.
            // No value is defaulted, substituted, echoed or logged here: ErpSettings owns the fail-fast check.
            //
            // THREAT ADDRESSED - CWE-706 use of an incorrectly resolved name, same OWASP A05 category. The base
            // path is AppContext.BaseDirectory - the directory the entry assembly was loaded from, which is
            // exactly where the build and publish outputs place Config.json - and NOT
            // Directory.GetCurrentDirectory(), which resolves against whatever working directory the process
            // happened to be launched with. A CWD-relative base lets the file that supplies the connection
            // string, the data-at-rest encryption key and the token signing key be chosen by the launcher: run
            // the same binaries from a different directory and a different, attacker-plantable Config.json is
            // read, or none is found at all. Note that IWebHostEnvironment.ContentRootPath is no safer here,
            // because WebHost.CreateDefaultBuilder defaults it to Directory.GetCurrentDirectory() as well.
            var configurationBuilder = new ConfigurationBuilder().SetBasePath(AppContext.BaseDirectory).AddJsonFile(configPath);

            configurationBuilder.AddEnvironmentVariables();

            // Development only, and added last so a developer's own local store wins on their own machine. User
            // secrets live unencrypted outside the repository: a developer convenience, never a production
            // channel - outside Development this provider is never registered at all, leaving environment
            // variables as the last word wherever it matters. The guard reuses this file's own comparison idiom
            // (see Configure below) rather than IWebHostEnvironment.IsDevelopment() so no further import is
            // needed, and it fails secure - anything that is not "Development" leaves the provider out.
            // optional: true keeps startup working if this project's UserSecretsId is ever removed, and the
            // entry assembly is null-guarded for hosts that expose none.
            if (string.Equals(environment.EnvironmentName, "Development", StringComparison.OrdinalIgnoreCase))
            {
                var hostAssembly = System.Reflection.Assembly.GetEntryAssembly() ?? typeof(Startup).Assembly;
                configurationBuilder.AddUserSecrets(hostAssembly, optional: true);
            }

            Configuration = configurationBuilder.Build();

            services.AddLocalization(options => options.ResourcesPath = "Resources");
            services.Configure<RequestLocalizationOptions>(options => { options.DefaultRequestCulture = new RequestCulture(Configuration["Settings:Locale"]); });

            services.Configure<GzipCompressionProviderOptions>(options => options.Level = CompressionLevel.Optimal);
            services.AddResponseCompression(options => { options.Providers.Add<GzipCompressionProvider>(); });
            services.AddRouting(options => { options.LowercaseUrls = true; });

            //CORS policy declaration
            //services.AddCors(options =>
            //{
            //    options.AddPolicy("AllowNodeJsLocalhost",
            //        builder => builder.WithOrigins("http://localhost:3333", "http://localhost:3000", "http://localhost").AllowAnyMethod().AllowCredentials());
            //});
            // THREAT ADDRESSED - finding H-14 (CWE-942 permissive cross-domain policy with untrusted
            // domains), OWASP A05 Security Misconfiguration: the default policy called AllowAnyOrigin(), so
            // ANY website a signed-in user visited could issue cross-origin requests to this host and read
            // the responses.
            //
            // The allow-list is read from configuration and is EMPTY outside Development unless an operator
            // supplies it, which is the deny-by-default posture the Authorization Enforcement standard
            // mandates. Compiling the three http://localhost origins named in the commented-out policy
            // immediately above into EVERY environment - the first attempt at this fix - was itself a
            // residual defect: they are DEVELOPMENT origins, so on any production host where another
            // process can bind those ports (a container sibling, a co-tenant, a developer tool, anything
            // running as another user on the same machine) that process obtained cross-origin read access
            // to this ERP host, and no operator could remove them or add a legitimate origin without a
            // rebuild. That is precisely the "untrusted domains" half of CWE-942, merely narrowed from
            // "any" to "three an operator cannot change".
            //
            // A supplied value ALWAYS wins, in every environment, and is supplied as a single ','/';'-
            // delimited string through Settings__Cors__AllowedOrigins rather than as a JSON array, because
            // an array cannot be provided through one environment variable - it would need
            // Settings__Cors__AllowedOrigins__0, __1 and so on - and the environment is the supply channel
            // the scrubbed Config.json leaves. Supplying the key EMPTY is an explicit "allow nothing" and
            // is honoured as written even in Development, so the strict posture stays reproducible without
            // changing the environment name. The key is deliberately NOT added to Config.json: an absent
            // key already has a defined meaning, so adding one would only invite a checked-in origin list.
            // Origins are trimmed and otherwise used exactly as written, because origin matching is exact
            // and "helpful" normalisation would silently widen or narrow the set.
            //
            // Restoring the three localhost origins as a DEVELOPMENT-ONLY default keeps the documented
            // local workflow working while leaving the production posture deny-by-default. The guard fails
            // secure: an unset ASPNETCORE_ENVIRONMENT is not "Development", so the default stays out. It
            // reuses the injected IWebHostEnvironment and the same comparison this file already applies to
            // its user-secrets provider and to its HSTS/HTTPS-redirection pair.
            //
            // Configuration is consulted for the KEY, not merely for a non-blank value, so that a supplied
            // but empty Settings__Cors__AllowedOrigins reads as the explicit "allow nothing" described
            // above while an entirely absent key still lets Development fall back. No provider
            // materialises a key nobody supplied, so null here means exactly "unconfigured".
            //
            // AllowCredentials() is deliberately NOT added: the framework rejects it alongside
            // AllowAnyOrigin(), so credentialed cross-origin requests were never permitted here and adding
            // it now would WIDEN behaviour rather than preserve it. AllowAnyMethod()/AllowAnyHeader() are
            // retained because the finding is an over-broad ORIGIN set - narrowing methods or headers as
            // well would be unrequested hardening that could break working clients. AddDefaultPolicy is
            // kept so the app.UseCors() call in Configure needs no change at all, which also preserves the
            // load-bearing UseCors-before-HTTPS-redirection ordering documented at that call site.
            string configuredCorsOrigins = Configuration["Settings:Cors:AllowedOrigins"];
            string[] allowedCorsOrigins;
            if (configuredCorsOrigins != null)
            {
                allowedCorsOrigins = configuredCorsOrigins.Split(CorsAllowedOriginsSeparators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            }
            else if (string.Equals(environment.EnvironmentName, "Development", StringComparison.OrdinalIgnoreCase))
            {
                allowedCorsOrigins = CorsDevelopmentDefaultOrigins;
            }
            else
            {
                allowedCorsOrigins = Array.Empty<string>();
            }

            services.AddCors(options =>
            {
                // WithOrigins on an empty array is legal and adds no origin, so the policy matches nothing
                // and the middleware emits no Access-Control-Allow-Origin at all. That is the intended
                // state whenever the list resolves empty - unconfigured outside Development, or explicitly
                // emptied - and it leaves same-origin requests untouched while refusing every cross-origin
                // one.
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
                options.Cookie.Name = "erp_auth_base";
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
                 // THREAT: this line previously passed the raw configured value straight into
                 // Encoding.UTF8.GetBytes. A null value threw during ConfigureServices, so the host would not
                 // start at all; an empty value threw inside SymmetricSecurityKey for the same reason; and this
                 // repository's published example key was accepted without challenge, which meant every
                 // unmodified deployment validated tokens against a signing key printed in the public source
                 // tree - anyone could mint an administrator token.
                 //
                 // The key is now screened by the SAME predicate ErpSettings uses to decide whether the token
                 // ROUTES stay enabled, so the handler and the routes can never disagree about what counts as a
                 // usable key. The predicate is a pure function over the raw value precisely because it has to
                 // be callable here: ConfigureServices runs before ErpSettings.Initialize, so ErpSettings.JwtKey
                 // is still null at this point and only the value read from Configuration is available.
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
                     // ClockSkew was omitted here, so this validator silently used the IdentityModel default of
                     // FIVE MINUTES while the platform's own secondary validator
                     // (WebVella.Erp.Web/Services/AuthService.cs, GetValidSecurityTokenAsync) used ONE. Two
                     // validators judging the same token disagreed about when it expires, and the looser of the two
                     // is the one that authorises the request: an expired bearer principal stayed authorised for up
                     // to four minutes longer than the platform's own policy allows, which is exactly the window a
                     // stolen or replayed token needs.
                     //
                     // The skew is not restated as a literal here. It is READ FROM the same member the secondary
                     // validator consumes, so the two can no longer drift apart - parity is a compile-time
                     // dependency rather than a convention someone has to remember when changing one of them.
                     ClockSkew = WebVella.Erp.Web.Services.AuthService.JwtClockSkew,

                     // Deliberately left null when the key is unacceptable, rather than substituted or omitted.
                     // ValidateIssuerSigningKey stays true, so with no key present EVERY presented token fails
                     // signature validation and the request gets a clean 401 - it cannot be accepted. The scheme
                     // itself must still be registered even in that state, because the JWT_OR_COOKIE policy
                     // scheme below forwards any request carrying a "Bearer " header to it; removing the
                     // registration would turn that forward into an unhandled-scheme 500.
                     IssuerSigningKey = ErpSettings.IsAcceptableJwtKey(configuredSigningKey)
                         ? new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuredSigningKey))
                         : null
                 };

                 // THREAT ADDRESSED - finding F-02 (session hijacking via a non-revocable bearer token;
                 // CWE-613 insufficient session expiration), OWASP A07. Signature, issuer, audience and
                 // lifetime are all verified above - and a token that passed all four was then accepted even
                 // if the session it represents had been ENDED. Logging out, disabling the account or rotating
                 // the password left a stolen token working, because nothing in this handler consulted any
                 // server-side state at all.
                 //
                 // THIS handler is the one that matters. It is what framework authorization runs for every
                 // [Authorize] endpoint reached with a bearer token, because the JWT_OR_COOKIE policy scheme
                 // below forwards any request carrying a "Bearer " header to it. The platform's own validator
                 // in WebVella.Erp.Web.Services.AuthService performs the identical check, but it authorises
                 // nothing on its own, so a revocation check present only there would have been decorative.
                 //
                 // The RULE lives in the platform, single-sourced, and only the HOOK lives here: the handler's
                 // options type ships in a package that only this host and WebVella.Erp.Site.Project reference,
                 // so the platform assembly cannot install this itself without taking a new package dependency,
                 // which the remediation constraints forbid. Assigning Events is safe because nothing else
                 // assigns it - this registration configured only TokenValidationParameters.
                 //
                 // Fails CLOSED: the predicate also refuses a principal carrying no parseable session
                 // identifier, so a token shaped differently from what this build mints is rejected rather than
                 // given the benefit of the doubt. Fail() turns the outcome into a clean 401, which is exactly
                 // what an ended session should produce.
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
            var supportedCultures = new[] { new CultureInfo(Configuration["Settings:Locale"]) };

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
                DefaultRequestCulture = new RequestCulture(supportedCultures[0]),
                // Formatting numbers, dates, etc.
                SupportedCultures = supportedCultures,
                // UI strings that we have localized.
                SupportedUICultures = supportedCultures
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
            // THREAT ADDRESSED - finding M-01, missing security response headers (OWASP A05 Security
            // Misconfiguration): not one of the seven mandated security response headers was emitted by this
            // host, leaving clickjacking, MIME-sniffing and referrer-leak defences entirely absent.
            //
            // ORDERING IS THE ENTIRE REMEDIATION HERE - do not move this call further down the pipeline. It is
            // placed ahead of BOTH UseStaticFiles calls because UseStaticFiles TERMINATES the pipeline for a
            // matched asset, so anything registered after it never runs for a static-file response and those
            // responses would ship bare. The middleware is registered ONCE centrally (AddErp owns
            // SecurityHeadersOptions) but ordered per host precisely because UseErp() runs much later in this
            // method - after both static-file registrations. The default policy is report-only and HSTS is
            // suppressed in Development; see SecurityHeadersMiddleware for both qualifications.
            app.UseSecurityHeaders();

            app.UseResponseCompression();

            //app.UseCors("AllowNodeJsLocalhost"); //Enable CORS -> should be before static files to enable for it too
            app.UseCors(); //Enable CORS -> should be before static files to enable for it too

            // THREAT ADDRESSED - finding H-15 (CWE-319 cleartext transmission of sensitive information),
            // OWASP A02: this host neither enforced HTTPS nor published an HSTS policy, so a session could be
            // downgraded to plaintext and the authentication cookie intercepted. Guarded to non-Development
            // because local development is served over plain HTTP and redirecting it would make the
            // application unreachable there; the cookie's Secure attribute, by contrast, is applied
            // unconditionally by ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie, because
            // http://localhost is a potentially trustworthy origin and browsers accept a Secure cookie over it.
            //
            // HSTS must precede the redirect: UseHttpsRedirection short-circuits a plaintext request, so
            // anything after it never runs for that request. HstsMiddleware itself writes nothing on a plaintext
            // request, but UseSecurityHeaders() ran earlier and has already attached Strict-Transport-Security,
            // so the redirect response does carry it - inertly, because a user agent must ignore the header when
            // it arrives over plaintext (RFC 6797 section 7.2).
            //
            // Both sit AFTER UseCors, and that pairing is required: HTTPS redirection answers a cross-origin
            // preflight with a redirect the browser rejects as invalid, so the CORS middleware must
            // short-circuit the OPTIONS preflight first. They still precede both UseStaticFiles calls, so no
            // content is served over plaintext.
            //
            // app.UseHsts() alone does not publish the mandated policy: it emits whatever HstsOptions holds, and
            // the framework default is thirty days without subdomains ("max-age=2592000"). The mandated
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
            // attempts), OWASP A07: unlimited request rates left credential stuffing unthrottled. Activates
            // the per-remote-address fixed window registered in AddErp. Positioned after both UseStaticFiles
            // calls so static assets are never throttled, and after UseRouting so endpoint metadata is
            // available to the limiter.
            //
            // This is the coarse TRANSPORT-level layer only; the mandated five-attempt per-account lockout is
            // a complementary control in LoginThrottleService, consulted at the login entry point.
            app.UseRateLimiter();

			app.UseAuthentication();
			app.UseAuthorization();

			app
			.UseErpPlugin<SdkPlugin>()
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

