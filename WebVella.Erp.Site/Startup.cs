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
            // SECURITY - finding M-2 (CWE-20, CWE-798), OWASP A05 Security Misconfiguration.
            // THREAT: this host's own configuration was read from the JSON file alone, and it is this
            // Configuration instance that supplies the JWT signing key to AddJwtBearer below. With no
            // environment-variable provider the signing key could only ever come from a tracked file, so the
            // key shipped in this repository was the effective key for every deployment that did not edit it -
            // and anyone reading the public source could forge tokens. Environment variables are added LAST so
            // an operator-supplied value overrides the committed one, matching the framework's own precedence.
            var configurationBuilder = new ConfigurationBuilder().SetBasePath(Directory.GetCurrentDirectory()).AddJsonFile(configPath);

            // Development only: user secrets are unencrypted on disk and are a developer convenience, never a
            // production channel. This project already declares a UserSecretsId, so the store resolves without
            // any further setup; optional: true keeps startup working if that entry is ever removed.
            // ASPNETCORE_ENVIRONMENT is read directly rather than through IWebHostEnvironment.IsDevelopment()
            // for consistency with the cookie and HSTS guards further down this file, and it fails secure: an
            // unset variable is not "Development", so the developer-only provider stays out.
            if (string.Equals(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"), "Development", StringComparison.OrdinalIgnoreCase))
                configurationBuilder.AddUserSecrets(typeof(Startup).Assembly, optional: true);

            configurationBuilder.AddEnvironmentVariables();

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
            services.AddCors(options =>
            {
                options.AddDefaultPolicy(policy =>
                    policy.AllowAnyOrigin()
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

