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
            // THREAT ADDRESSED - finding H-14 (CWE-942 permissive cross-domain policy with untrusted domains),
            // OWASP A05 Security Misconfiguration: the default policy called AllowAnyOrigin(), so ANY website a
            // signed-in user visited could issue cross-origin requests to this host and read the responses. The
            // allow-list below reuses the origins from the restrictive policy kept in comment form immediately
            // above, which is this repository's own documented intent for this host.
            // AllowCredentials() is deliberately NOT added: the framework rejects it alongside AllowAnyOrigin(),
            // so credentialed cross-origin requests were never actually permitted here and adding it now would
            // WIDEN behaviour rather than preserve it. AllowAnyMethod()/AllowAnyHeader() are retained because
            // the finding is an over-broad ORIGIN set - narrowing methods or headers as well would be
            // unrequested hardening that could break working clients.
            // AddDefaultPolicy is kept rather than converted to a named policy so the app.UseCors() call in
            // Configure needs no change at all.
            services.AddCors(options =>
            {
                options.AddDefaultPolicy(policy =>
                    policy.WithOrigins("http://localhost:3333", "http://localhost:3000", "http://localhost")
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
            // placed ahead of UseResponseCompression and ahead of BOTH UseStaticFiles calls, because position
            // decides which responses the headers reach: registered after either, compressed responses and
            // static assets would be served bare. The middleware is registered ONCE centrally (AddErp owns
            // SecurityHeadersOptions) but ordered per host precisely because UseErp() runs much later in this
            // method - after compression and after both static-file registrations - so registration alone could
            // never protect those response classes.
            app.UseSecurityHeaders();

            app.UseResponseCompression();

            //app.UseCors("AllowNodeJsLocalhost"); //Enable CORS -> should be before static files to enable for it too
            app.UseCors(); //Enable CORS -> should be before static files to enable for it too

            // THREAT ADDRESSED - finding H-15 (CWE-319 cleartext transmission of sensitive information),
            // OWASP A02 Cryptographic Failures: this host neither enforced HTTPS nor published an HSTS policy,
            // so a session could be downgraded to plaintext and the authentication cookie intercepted in
            // transit. Guarded to non-Development because local development is served over plain HTTP, and
            // redirecting it would make the application unreachable there. That guard now stands on its own
            // rationale: the cookie's Secure attribute is applied UNCONDITIONALLY by
            // ErpMvcServicesExtensions.ConfigureErpAuthenticationCookie, including in Development, because
            // http://localhost is a potentially trustworthy origin and browsers accept a Secure cookie over it -
            // so there is no longer a paired SecurePolicy guard here for this one to match. The remaining
            // Development-guarded controls are these two and the strict-transport header, which
            // SecurityHeadersMiddleware suppresses in Development for the reason documented there. UseHsts adds
            // the policy to HTTPS responses only - HstsMiddleware returns without writing a header when
            // Request.IsHttps is false - so the header is published on the secured responses that FOLLOW the
            // redirect, never on the redirect itself. Ordering HSTS first is still correct, because the two
            // calls must not be transposed: UseHttpsRedirection short-circuits a plaintext request, so
            // anything after it never runs for that request at all.
            //
            // Redirection ships in the SAME change as the CORS allow-list above, and that pairing is required:
            // HTTPS redirection answers a cross-origin preflight with a redirect, which the browser rejects as
            // invalid. Ordering here is therefore deliberate and load-bearing - this sits AFTER UseCors so the
            // CORS middleware short-circuits the OPTIONS preflight before it can ever reach the redirect.
            // Moving this above UseCors would reintroduce exactly that failure. It still precedes both
            // UseStaticFiles calls, so no content is served over plaintext.
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

            // THREAT ADDRESSED - finding H-16 (CWE-307 improper restriction of excessive authentication
            // attempts), OWASP A07 Identification and Authentication Failures: nothing limited request volume,
            // so credential stuffing and brute-force password guessing were unthrottled. This activates the
            // global per-remote-address fixed window; following the register-once/order-per-host pattern it is
            // registered a single time in AddErp so all seven hosts share one definition, and each host only
            // positions it. This is the transport-level layer ONLY - the five-attempt account lockout is a
            // separate, narrower control provided by LoginThrottleService at the login entry point.
            // Positioned after both UseStaticFiles calls so static assets are never throttled, and after
            // UseRouting so endpoint metadata is available to the limiter, but before UseAuthentication so an
            // attacker cannot spend authentication work to exhaust it.
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

