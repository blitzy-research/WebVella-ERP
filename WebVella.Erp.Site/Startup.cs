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
        // Both separators are accepted because the allow-list arrives either through a single environment
        // variable (';' is idiomatic there) or through JSON (','), as in ErpMvcExtensions.
        private static readonly char[] CorsAllowedOriginsSeparators = new[] { ',', ';' };

        // DEVELOPMENT-ONLY default for the allow-list below: this host's local client contract, never
        // deployment configuration.
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

            // THREAT ADDRESSED - CWE-178 improper handling of case sensitivity, OWASP A05: the published file is
            // "Config.json", and on a case-sensitive filesystem the field workaround for a missing lowercase
            // name - a hand-made copy - substitutes unscrubbed configuration for the audited file.
            string configPath = "Config.json";

            // Lowercase is accepted only as a FALLBACK, so an output carrying only that name still starts.
            // Probed against AppContext.BaseDirectory, the base the builder sets, because probing the current
            // directory would let a file in an attacker-writable directory decide the choice (CWE-706).
            if (!System.IO.File.Exists(System.IO.Path.Combine(AppContext.BaseDirectory, configPath))
            	&& System.IO.File.Exists(System.IO.Path.Combine(AppContext.BaseDirectory, "config.json")))
            	configPath = "config.json";

            // THREAT ADDRESSED - findings H-05 and H-04 (CWE-798 hard-coded credentials, CWE-321 hard-coded
            // cryptographic key), OWASP A05, and the enabler for C-04: configuration came from this JSON file
            // alone. The chain must be extended BEFORE those values are blanked - the JSON source stays FIRST so
            // an operator's Settings__* variable overrides the blank, and NON-OPTIONAL so Config.json is scrubbed
            // rather than deleted. Base path AppContext.BaseDirectory, not the current directory, so the launcher
            // cannot choose which secrets are read (CWE-706); ContentRootPath defaults to it and is no safer.
            var configurationBuilder = new ConfigurationBuilder().SetBasePath(AppContext.BaseDirectory).AddJsonFile(configPath);

            configurationBuilder.AddEnvironmentVariables();

            // Development only, added LAST so a developer's local store wins on their own machine. User secrets
            // are unencrypted and outside the repository, so outside Development this provider is not registered
            // at all and environment variables have the last word; the comparison fails secure.
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

            // THREAT ADDRESSED - finding H-14 (CWE-942 permissive cross-domain policy), OWASP A05: the policy
            // called AllowAnyOrigin(), so any site a signed-in user visited could read this host's responses.
            // Deny-by-default now - the list is EMPTY outside Development unless an operator supplies
            // Settings__Cors__AllowedOrigins, one ','/';'-delimited string because an array cannot arrive through
            // a single environment variable. The KEY is read rather than its content, so supplied-but-empty means
            // "allow nothing" while an absent key lets Development fall back; origins are used verbatim after
            // trimming, because matching is exact. AllowCredentials() stays out - the framework rejects it
            // alongside AllowAnyOrigin(), so adding it would widen behaviour - and method and header breadth is
            // unchanged, the finding being the ORIGIN set.
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
                options.Cookie.Name = "erp_auth_base";
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
                 // Encoding.UTF8.GetBytes, so this repository's published example key was accepted and every
                 // unmodified deployment validated tokens against a key printed in public source. Screened by the SAME
                 // predicate ErpSettings uses to gate the token ROUTES, and pure so it is callable before Initialize.
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

                     // Deliberately null when the key is unacceptable: ValidateIssuerSigningKey stays true, so every token
                     // fails signature validation and gets a 401. The scheme must still be REGISTERED - JWT_OR_COOKIE
                     // forwards every "Bearer " request to it and an unhandled scheme is a 500.
                     IssuerSigningKey = ErpSettings.IsAcceptableJwtKey(configuredSigningKey)
                         ? new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuredSigningKey))
                         : null
                 };

                 // THREAT ADDRESSED - session hijacking through a non-revocable bearer token (CWE-613), OWASP A07: a
                 // token passing signature, issuer, audience and lifetime was still accepted after its session had
                 // ENDED, so logout, disabling the account or rotating the password left a stolen token working. This
                 // handler is what framework authorization runs for a bearer request, so the HOOK belongs here while
                 // the RULE stays single-sourced in AuthService. Fails CLOSED, and Fail() yields a clean 401.
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
            var supportedCultures = new[] { new CultureInfo(Configuration["Settings:Locale"]) };

            // THREAT ADDRESSED - CWE-348 less trusted source, CWE-290 spoofing, CWE-307 excessive authentication
            // attempts, OWASP A05: behind a reverse proxy the rate-limit partition and the per-address half of
            // the login lockout both collapsed onto the proxy's address, and Request.IsHttps read false for TLS
            // requests. FIRST is load-bearing - every middleware below reads what this one corrects - and it
            // trusts no proxy until Settings:ForwardedHeaders names one.
            app.UseErpForwardedHeaders();

            app.UseRequestLocalization(new RequestLocalizationOptions
            {
                DefaultRequestCulture = new RequestCulture(supportedCultures[0]),
                // Formatting numbers, dates, etc.
                SupportedCultures = supportedCultures,
                // UI strings that we have localized.
                SupportedUICultures = supportedCultures
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

            // THREAT ADDRESSED - finding H-15 (CWE-319 cleartext transmission), OWASP A02: neither HTTPS
            // enforcement nor an HSTS policy existed, so a session could be downgraded and the authentication
            // cookie intercepted. Guarded to non-Development, which is served over plain HTTP; the cookie's
            // Secure attribute is unconditional instead. HSTS precedes the redirect because the redirect
            // short-circuits plaintext requests, and both follow UseCors - HTTPS redirection answers a preflight
            // with a redirect browsers reject - while preceding both UseStaticFiles calls. HstsOptions, whose
            // framework default is thirty days, are set to the mandated year once in AddErp: none belong here.
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

            // THREAT ADDRESSED - finding H-16, CWE-307 excessive authentication attempts, OWASP A07: unlimited
            // request rates left credential stuffing unthrottled. After both UseStaticFiles calls so assets are
            // never throttled and after UseRouting for endpoint metadata. Transport layer only - the mandated
            // five-attempt per-account lockout is LoginThrottleService.
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

