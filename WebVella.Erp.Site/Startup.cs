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
using System.IO;
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

            string configPath = "config.json";
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
            var configurationBuilder = new ConfigurationBuilder().SetBasePath(Directory.GetCurrentDirectory()).AddJsonFile(configPath);

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
                options.Cookie.HttpOnly = true;
                options.Cookie.Name = "erp_auth_base";
                options.LoginPath = new PathString("/login");
                options.LogoutPath = new PathString("/logout");
                options.AccessDeniedPath = new PathString("/error?access_denied");
                options.ReturnUrlParameter = "returnUrl";

                // THREAT ADDRESSED - finding H-15 (CWE-614 sensitive cookie without the 'Secure' attribute,
                // CWE-319 cleartext transmission of sensitive information), OWASP A02 Cryptographic Failures /
                // A05 Security Misconfiguration: the authentication cookie set HttpOnly and nothing else, so it
                // carried neither Secure nor SameSite and had no bounded lifetime - it could travel in
                // cleartext, be attached to cross-site requests, and be renewed indefinitely.
                //
                // SecurePolicy is Always in every deployed environment. It relaxes to SameAsRequest in
                // Development ONLY, for exactly the reason HTTPS redirection is also guarded to non-Development
                // further down: local development is served over plain HTTP, and an unconditionally Secure
                // cookie would make local sign-in impossible, breaking functionality preservation. The guard
                // fails secure - anything that is not "Development" yields Always.
                options.Cookie.SecurePolicy = string.Equals(environment.EnvironmentName, "Development", StringComparison.OrdinalIgnoreCase)
                    ? CookieSecurePolicy.SameAsRequest
                    : CookieSecurePolicy.Always;

                // Lax, DELIBERATELY NOT Strict - do not "upgrade" this. Strict withholds the cookie on the
                // return-URL round trip back from the login page (see LoginPath and ReturnUrlParameter set just
                // above), which would break a working sign-in flow. Lax is the framework's own default posture
                // and still withholds the cookie from cross-site POST requests.
                // The type is named in full because Microsoft.Net.Http.Headers and Microsoft.AspNetCore.Http
                // both declare a SameSiteMode and this file imports both; unqualified it is CS0104-ambiguous.
                options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;

                // An explicit, bounded session window replacing the previously unbounded cookie. 8h is not an
                // arbitrary choice: AuthService sets AuthenticationProperties.ExpiresUtc explicitly, and an
                // explicit ExpiresUtc takes PRECEDENCE over ExpireTimeSpan, so this value must equal
                // AuthService.AUTH_TICKET_EXPIRY_DURATION_MINUTES (480) or the window declared here would be
                // inert configuration while the real lifetime differed. Keep the two in step if either changes.
                // SlidingExpiration stays false to match: AuthService sets AllowRefresh = false for every host,
                // and CookieAuthenticationHandler renews only when SlidingExpiration AND AllowRefresh are both
                // set - so enabling it here would have no effect while implying a sliding window that does not
                // exist, and a bounded absolute window is the stronger posture for a session-lifetime finding.
                options.ExpireTimeSpan = TimeSpan.FromHours(8);
                options.SlidingExpiration = false;
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
            // transit. Guarded to non-Development because local development is served over plain HTTP, matching
            // the SecurePolicy guard above. HSTS precedes redirection so the policy is published on the very
            // response that performs the redirect.
            //
            // Redirection ships in the SAME change as the CORS allow-list above, and that pairing is required:
            // HTTPS redirection answers a cross-origin preflight with a redirect, which the browser rejects as
            // invalid. Ordering here is therefore deliberate and load-bearing - this sits AFTER UseCors so the
            // CORS middleware short-circuits the OPTIONS preflight before it can ever reach the redirect.
            // Moving this above UseCors would reintroduce exactly that failure. It still precedes both
            // UseStaticFiles calls, so no content is served over plaintext.
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

