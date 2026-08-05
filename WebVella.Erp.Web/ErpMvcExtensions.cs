using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Threading.RateLimiting;
using System.Threading.Tasks;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models.AutoMapper;
using WebVella.Erp.Database;
using WebVella.Erp.Jobs;
using WebVella.Erp.Web.Middleware;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Models.AutoMapper;
using WebVella.Erp.Web.Services;
using WebVella.TagHelpers;

namespace WebVella.Erp.Web
{
	public static class ErpMvcServicesExtensions
	{
		// The single configuration key that selects the Content-Security-Policy delivery mode. Held as
		// a constant so the lookup and the diagnostic message that names it can never drift apart -
		// a message quoting a key the code does not actually read would send an operator to fix the
		// wrong setting. Declared private because it is a binding detail of AddErp, not public API.
		private const string ContentSecurityPolicyReportOnlyConfigurationKey = "SecurityHeaders:ContentSecurityPolicyReportOnly";

		// Configuration section carrying the trusted reverse-proxy declaration consumed by
		// UseErpForwardedHeaders.
		private const string ForwardedHeadersConfigurationSection = "Settings:ForwardedHeaders";

		// Separators accepted between entries in the KnownProxies and KnownNetworks lists. Both are
		// accepted because operators supply these through environment variables, where a semicolon is
		// the more familiar separator, and through JSON, where a comma is.
		private static readonly char[] ForwardedHeadersListSeparators = new[] { ',', ';' };

		// Default number of forwarded entries consumed from a single X-Forwarded-For header.
		//
		// THREAT ADDRESSED - CWE-348 (use of less trusted source): X-Forwarded-For is a LIST, appended to
		// by every hop. Only the entry appended by the trusted proxy nearest to this application is
		// trustworthy; every entry to its left was supplied by something further out, ultimately
		// including the caller itself. Consuming one entry per hop is therefore the whole control - raise
		// this only when a KNOWN number of trusted proxies sit in front of the application, and never to
		// a value larger than that number.
		private const int DefaultForwardedHeadersForwardLimit = 1;

		// The platform's session contract, applied identically by all seven hosts through
		// ConfigureErpAuthenticationCookie so no host can drift from it.
		private const double AuthenticationCookieLifetimeMinutes = 1440;

		// Directory holding the Data Protection key ring. Deliberately OPTIONAL: when the key is absent
		// the framework's own default location stands unchanged, so configuring nothing cannot break a
		// deployment that already works. Held as a constant for the same reason as the key above - the
		// lookup and the documentation that names it must not drift apart.
		private const string DataProtectionKeyDirectoryConfigurationKey = "Settings:DataProtectionKeyDirectory";

		// The configuration key the framework's HTTPS redirection middleware reads to learn the public
		// HTTPS port. Held as a constant so the transport-posture check below and the diagnostic it
		// produces cannot drift from the key the middleware actually consults. Both
		// ASPNETCORE_HTTPS_PORT and HTTPS_PORT land on it, as does an ANCM-hosted site's
		// ASPNETCORE_ANCM_HTTPS_PORT; the PLURAL spelling ASPNETCORE_HTTPS_PORTS is a Kestrel
		// default-binding key that this application's WebHost pipeline never reads at all, which is
		// exactly why the diagnostic names it as a non-remedy rather than staying silent about it.
		private const string HttpsRedirectionPortConfigurationKey = "HTTPS_PORT";

		// Kestrel's declarative endpoint section. Consulted alongside the bound addresses so that an
		// operator who declares an HTTPS endpoint there, rather than through ASPNETCORE_URLS, is never
		// told they have no HTTPS request path.
		private const string KestrelEndpointsConfigurationSection = "Kestrel:Endpoints";

		// Scheme prefix identifying an endpoint that can carry an HTTPS request.
		private const string HttpsUriSchemePrefix = "https://";

		public static IServiceCollection AddErp(this IServiceCollection services)
		{
			services.AddSingleton<IErpService, ErpService>();
			services.AddTransient<AuthService>();
			services.AddScoped<ErpRequestContext>();

			// THREAT ADDRESSED - finding M-01 (OWASP A05: Security Misconfiguration):
			// SecurityHeadersMiddleware existed but was never reachable - no host registered its
			// options and no host inserted it into a pipeline - so not one of the seven mandated
			// security response headers was actually emitted. Registering the options here, at the
			// platform's single canonical service-registration extension, means all seven hosts
			// inherit it from one edit. The options type carries the mandated Content-Security-Policy
			// as a compile-time const with no setter, so this registration cannot be used to weaken
			// it; only the report-only/enforcing switch is settable.
			//
			// Registration only. The middleware's pipeline POSITION is deliberately NOT set here and must
			// never be: UseErp runs late in every host pipeline, whereas UseStaticFiles terminates the
			// pipeline for a matched asset, so the headers have to be emitted ahead of both
			// UseStaticFiles calls or static-file responses ship bare. Each host therefore calls
			// UseSecurityHeaders() early in its own Configure method. This extension registers; the
			// hosts order.
			//
			// THREAT ADDRESSED - finding CFG-02 (OWASP A05: Security Misconfiguration): the mandated
			// report-then-enforce Content-Security-Policy rollout is operator-controlled, so the switch
			// selecting the mode must actually be bound - AddOptions<T>() alone materialises the type
			// with its compiled defaults only, and an operator setting the key would have been silently
			// ignored while believing the policy was enforcing.
			//
			// Exactly ONE member is bound - the report-only/enforce switch - from
			// "SecurityHeaders:ContentSecurityPolicyReportOnly" (environment variable
			// SecurityHeaders__ContentSecurityPolicyReportOnly). The policy TEXT stays unbindable so no
			// configuration source can inject 'unsafe-inline' or "default-src *" and void the header.
			//
			// The two failure directions differ deliberately: ABSENT or blank keeps the compiled
			// report-only default, which is the mandated shipping posture; PRESENT but unparseable
			// ABORTS startup, because either guess is wrong - report-only leaves the policy unenforced
			// while the operator believes otherwise, and enforcing blocks the four components that
			// deliberately emit inline script. The supplied value is never echoed, only the key name
			// and the accepted values, so a value pasted into the wrong variable cannot leak into a log.
			services.AddOptions<SecurityHeadersOptions>()
				.Configure<IConfiguration>((securityHeadersOptions, configuration) =>
				{
					string configuredReportOnly = configuration?[ContentSecurityPolicyReportOnlyConfigurationKey];
					if (string.IsNullOrWhiteSpace(configuredReportOnly))
					{
						return;
					}

					if (!bool.TryParse(configuredReportOnly, out bool contentSecurityPolicyReportOnly))
					{
						throw new InvalidOperationException(
							$"WebVella ERP startup aborted - configuration key '{ContentSecurityPolicyReportOnlyConfigurationKey}' " +
							$"(environment variable '{ContentSecurityPolicyReportOnlyConfigurationKey.Replace(":", "__", StringComparison.Ordinal)}') " +
							"must be either 'true' (emit Content-Security-Policy-Report-Only) or 'false' (emit the enforcing " +
							"Content-Security-Policy). The supplied value could not be interpreted as a boolean and has been " +
							"rejected rather than guessed, because either guess would be wrong: assuming report-only would leave " +
							"the policy unenforced while the operator believed otherwise, and assuming enforcing would block the " +
							"platform's inline scripts. Remove the key to keep the shipping default of report-only. See " +
							"docs/security/secure-configuration.md.");
					}

					securityHeadersOptions.ContentSecurityPolicyReportOnly = contentSecurityPolicyReportOnly;
				});

			// THREAT ADDRESSED - finding H-15, CWE-319 (cleartext transmission of sensitive information)
			// and CWE-614 (sensitive cookie without 'Secure' attribute), OWASP A02 / A05. Every host calls
			// app.UseHsts() but none configured HstsOptions, and the framework defaults to thirty days
			// with subdomains excluded rather than the mandated one year including subdomains.
			// HstsMiddleware and SecurityHeadersMiddleware both assign Strict-Transport-Security by
			// indexer, and HstsMiddleware runs later in every host pipeline, so it decided the wire
			// value: "max-age=2592000" overwrote the mandated one. Pinning the framework's own options
			// here makes both writers emit the identical string, so there is exactly ONE HSTS value in
			// the application and the overwrite is a no-op in either order.
			//
			// Registered at the platform's single canonical service-registration extension so all seven
			// hosts inherit it from one edit, matching how the header middleware's own options are
			// registered immediately above. Values are the mandated ones, single-sourced conceptually with
			// SecurityHeadersMiddleware.StrictTransportSecurityValue ("max-age=31536000; includeSubDomains"):
			//   MaxAge            365 days = 31536000 seconds
			//   IncludeSubDomains true, which the mandated value requires
			//   Preload           false - deliberately. Preload is NOT in the mandated value, and submitting
			//                     an origin to the browser preload list is effectively irreversible, so it
			//                     must never be switched on implicitly by a security fix.
			// ExcludedHosts is left at the framework default (localhost, 127.0.0.1, [::1]): it suppresses
			// the header only for loopback, which is the same protection the Development guard in
			// SecurityHeadersMiddleware provides, and narrowing or clearing it would pin developers' whole
			// localhost origin to HTTPS for a year.
			services.AddHsts(hstsOptions =>
			{
				hstsOptions.MaxAge = TimeSpan.FromDays(365);
				hstsOptions.IncludeSubDomains = true;
				hstsOptions.Preload = false;
			});

			// THREAT ADDRESSED - finding M-02, CWE-614 (sensitive cookie in HTTPS session without the
			// 'Secure' attribute) and CWE-1004, OWASP A05: the antiforgery cookie was left entirely at
			// the framework default, which is CookieSecurePolicy.None. Only the authentication cookie was
			// hardened, so the request-verification token travelled over plaintext whenever a client
			// reached the site over HTTP - and because that token is what authorises every state-changing
			// Razor Pages POST, including the login form, an attacker on the network path could capture it
			// and pair it with a captured session.
			//
			// Configured here rather than per host for the same register-once reason as the header and
			// HSTS options above: no host calls AddAntiforgery at all, so a single IConfigureOptions
			// registration is the only edit that reaches all seven of them. Only SecurePolicy is set; the
			// token validation behaviour, the cookie name and its SameSite=Strict default are all left
			// exactly as the framework and the existing clients expect them, so no working request is
			// affected.
			//
			// Always OUTSIDE Development - that is the M-02 remediation, and it is the posture every
			// deployed host runs under. SameAsRequest INSIDE Development, because an unconditional
			// Always makes the platform UNUSABLE over plain HTTP there, and not merely less convenient:
			// the antiforgery system does not simply mark the cookie, it VALIDATES its own configuration
			// on every token issue. Microsoft.AspNetCore.Antiforgery.DefaultAntiforgery.CheckSSLConfig
			// throws InvalidOperationException("The antiforgery system has the configuration value
			// AntiforgeryOptions.Cookie.SecurePolicy = Always, but the current request is not an SSL
			// request.") whenever Request.IsHttps is false, so EVERY Razor Pages form - the login form
			// included - answered HTTP 500 in Development over HTTP, leaving no way to authenticate at
			// all. An earlier revision of this comment reasoned only about whether BROWSERS accept a
			// Secure cookie on http://localhost (they do, it is a potentially trustworthy origin) and
			// therefore concluded no carve-out was needed; that reasoning missed this server-side throw,
			// which fires on the scheme alone and never reaches the browser.
			//
			// The carve-out is the SAME guard, in the same direction, that every host already applies to
			// app.UseHsts()/app.UseHttpsRedirection() and that SecurityHeadersMiddleware applies to
			// Strict-Transport-Security: Development is served over plain HTTP by design, so a control
			// that hard-requires TLS is suppressed there and nowhere else. It is therefore not a new
			// class of environment-dependent security attribute - it is consistency with the platform's
			// existing Development posture, and it is why the production hardening this finding asked
			// for stays fully in force. SameAsRequest rather than None deliberately: a Development
			// request that IS over HTTPS still gets the Secure attribute, so the relaxation applies only
			// to the plaintext requests that would otherwise 500.
			//
			// IHostEnvironment is taken through Configure<T> - the same overload the DataProtection
			// registration below uses - rather than captured from a field, so the environment is
			// resolved from the container exactly once, when options are materialised.
			services.AddOptions<Microsoft.AspNetCore.Antiforgery.AntiforgeryOptions>()
				.Configure<IHostEnvironment>((antiforgeryOptions, hostEnvironment) =>
				{
					// Fail-safe direction: an unresolvable environment is treated as NOT Development, so
					// the hardened value is the default and a missing or misspelled ASPNETCORE_ENVIRONMENT
					// can never silently relax the production posture.
					bool isDevelopment = hostEnvironment != null
						&& string.Equals(hostEnvironment.EnvironmentName, "Development", StringComparison.OrdinalIgnoreCase);

					antiforgeryOptions.Cookie.SecurePolicy = isDevelopment
						? CookieSecurePolicy.SameAsRequest
						: CookieSecurePolicy.Always;
				});

			// THREAT ADDRESSED - finding H-16, CWE-307 (Improper Restriction of Excessive
			// Authentication Attempts), OWASP A07: LoginThrottleService existed but was never
			// registered and never resolved, so the mandated five-attempt account lockout was dead
			// code and every credential-verification entry point still accepted unlimited attempts.
			// Registering it here, at the platform's single canonical service-registration extension,
			// means all seven hosts inherit it from one edit.
			//
			// Singleton is required, not merely convenient: the failure counters live in the
			// service's own in-process store, so a transient or scoped lifetime would hand every
			// request a brand new, empty set of counters and the threshold would never be reached.
			// The service holds one process-lifetime WebVella.Erp.Web.Utils.Cache and exposes no
			// disposal surface, matching the platform's own cache usage in ErpAppContext; the store is
			// released with the process.
			services.AddSingleton<LoginThrottleService>();

			// THREAT ADDRESSED - review finding CR2-F-11 (CWE-522 insufficiently protected credentials,
			// CWE-565 reliance on cookies without validation and integrity checking), OWASP A05:2021
			// Security Misconfiguration. Nothing in this repository configured Data Protection at all - a
			// repository-wide search for AddDataProtection, SetApplicationName, PersistKeysTo or
			// ProtectKeysWith returned ZERO hits - so the key ring protecting every authentication ticket,
			// every antiforgery token and every Blazor circuit descriptor was left entirely to framework
			// defaults. Two of those defaults are the finding, and they fail in opposite directions.
			//
			// FIRST, the application discriminator defaults to the CONTENT ROOT PATH. That is a deployment
			// location, not an identity. Republishing a host to a different directory silently changes the
			// purpose chain and invalidates every outstanding ticket, while two hosts that happen to share
			// a content root become mutually decryptable - one host able to accept a ticket minted by the
			// other, carrying an identity across an application boundary it was never issued for. Binding
			// the discriminator to the host's application name makes isolation a property of WHICH
			// APPLICATION this is rather than of where it happens to be installed, and the seven hosts have
			// seven distinct application names. It is set here, at the platform's single canonical
			// service-registration extension, so all seven inherit it from one edit.
			//
			// SECOND, the default key ring is written unencrypted under the running account's profile - the
			// live host log reads "keys will not be encrypted at rest". In a container that directory is
			// frequently not persisted, so every restart mints a fresh ring and logs every user out; where
			// it IS persisted it is shared with every other application running as that account. An
			// explicitly configured directory addresses both.
			//
			// The persistence half is deliberately OPT-IN while the discriminator half is unconditional,
			// and the asymmetry is the point: a discriminator is free and cannot break anything, whereas
			// redirecting the key ring to a path this code invented would move an existing deployment's
			// keys out from under it and log every user out. Encrypting the ring AT REST needs platform key
			// material - a certificate - which this registration cannot conjure or safely assume; it is
			// documented in docs/security/secure-configuration.md and carried as a residual in
			// docs/security/risk-register.md rather than half-implemented here.
			services.AddDataProtection();

			services.AddOptions<DataProtectionOptions>()
				.Configure<IHostEnvironment>((dataProtectionOptions, hostEnvironment) =>
				{
					// Guarded rather than assigned unconditionally. An empty application name would produce
					// an EMPTY discriminator, which is materially WORSE than the default it replaces,
					// because every application with an empty discriminator shares one purpose chain.
					// Leaving the framework default in place is the fail-safe direction.
					if (!string.IsNullOrWhiteSpace(hostEnvironment?.ApplicationName))
					{
						dataProtectionOptions.ApplicationDiscriminator = hostEnvironment.ApplicationName;
					}
				});

			services.AddOptions<KeyManagementOptions>()
				.Configure<IConfiguration, ILoggerFactory>((keyManagementOptions, configuration, loggerFactory) =>
				{
					string configuredKeyDirectory = configuration?[DataProtectionKeyDirectoryConfigurationKey];
					if (string.IsNullOrWhiteSpace(configuredKeyDirectory))
					{
						return;
					}

					// Created when absent so a fresh deployment need not pre-create it, and deliberately
					// NOT wrapped in a catch: a key ring that silently fell back to the profile directory
					// would leave an operator believing the ring is durable when it is not - the same class
					// of false assurance as CR2-F-09, where a control measured one thing while the
					// mechanism consumed another.
					DirectoryInfo keyDirectory = Directory.CreateDirectory(configuredKeyDirectory);
					keyManagementOptions.XmlRepository = new FileSystemXmlRepository(keyDirectory, loggerFactory);
				});

			// THREAT ADDRESSED - finding F8 (session hijacking), CWE-613 (insufficient session
			// expiration), OWASP A07: the cookie authentication ticket is entirely self-contained, so
			// signing out only deleted the cookie in the browser that asked for it. A ticket copied
			// beforehand - lifted from a shared machine, a proxy or reverse-proxy log, a backup, or
			// exfiltrated by script - stayed valid for the whole eight-hour ticket lifetime, and nothing
			// the user or an administrator could do would stop it. Logging out did not end the session;
			// it only forgot one copy of it.
			//
			// NO REGISTRATION IS NEEDED FOR THE REVOCATION STORE, and its absence here is deliberate.
			//
			// F-02: the store used to be an injected singleton, which is precisely what confined the control
			// to consumers able to resolve a service. The bearer-token validators cannot resolve one - they
			// are static code with no service provider in reach - so the store is now process-wide static
			// (Services/SessionRevocationService.cs). Two properties follow, and both are improvements rather
			// than consequences to be tolerated: there is exactly ONE store per process rather than one per
			// service provider, and no consumer has to interpret an unresolvable service, which used to be
			// indistinguishable from "this session is not revoked". Re-adding a registration here would
			// reintroduce the impression of per-provider state that no longer exists.

			// THREAT ADDRESSED - finding F8, continued. Registering the service is inert on its own; the
			// control only exists once the identifier is CONSULTED, which has to happen on every
			// authenticated request rather than at the login page. This is that consultation point: the
			// framework's own ticket-validation hook, which runs for each request that presents a cookie,
			// before the endpoint sees the principal. AuthService.Authenticate mints a fresh
			// CLAIM_SESSION_ID into every ticket and AuthService.LogoutAsync revokes it, so after a sign-out
			// every other copy of the same ticket is rejected on its next request no matter which browser
			// holds it. That is what turns "delete my cookie" into "end this session".
			//
			// PostConfigureAll is chosen deliberately over Configure, for three reasons:
			//   * it applies to EVERY named cookie options instance, so a host that registers an additional
			//     cookie scheme is covered without a further edit - the seven hosts each name their own
			//     cookie (erp_auth_base, erp_auth_mail and so on) and must not have to remember this;
			//   * post-configuration runs AFTER each host's own AddCookie callback, so a host cannot
			//     accidentally overwrite the hook by assigning Events itself;
			//   * it keeps the control in the single canonical registration extension, so all seven hosts
			//     inherit it from one edit, exactly as the headers middleware and the throttle do.
			// The previously configured delegate is captured and invoked FIRST, so this composes with the
			// handler already in place instead of replacing it. THAT CHAINING IS LOAD-BEARING, NOT
			// DEFENSIVE: ConfigureErpAuthenticationCookie - which all seven hosts pass to AddCookie -
			// assigns AuthService.ValidateSessionHorizonAsync, the absolute session horizon that stops a
			// slid cookie living for ever. Post-configuration runs after that assignment, so dropping the
			// capture-and-invoke would overwrite the horizon check and silently reduce the sliding
			// 24-hour idle window back to an unbounded session, trading one session-expiry finding for a
			// worse one. Order matters too: the horizon runs first, and its rejection is honoured by the
			// Principal null check below.
			services.PostConfigureAll<CookieAuthenticationOptions>(cookieOptions =>
			{
				cookieOptions.Events ??= new CookieAuthenticationEvents();

				var previouslyConfigured = cookieOptions.Events.OnValidatePrincipal;
				cookieOptions.Events.OnValidatePrincipal = async validationContext =>
				{
					if (previouslyConfigured != null)
						await previouslyConfigured(validationContext);

					// A principal the host's own delegate already rejected is left rejected. RejectPrincipal
					// nulls Principal, so this is the check for "someone upstream already said no".
					if (validationContext.Principal == null)
						return;

					// THREAT ADDRESSED - finding F-01 (CWE-613 insufficient session expiration, CWE-636 not
					// failing securely), OWASP A07. This pair of checks used to RETURN - accepting the
					// principal - whenever the ticket carried no parseable session identifier, and that made
					// revocation opt-in from the ticket's own point of view: any ticket without the claim was
					// simply never revocable, so "log out everywhere" silently did not apply to it. The two
					// justifications given have both stopped holding:
					//   * "tickets minted before this change carry no claim" - AuthService.Authenticate stamps
					//     the identifier in the same operation that mints the ticket, so a ticket without it is
					//     not one this build issues. Accepting an unrecognised session shape for ever, to spare
					//     one re-authentication at deployment, is the wrong trade for a session control;
					//   * "bearer principals never carry one at all" - they do now (finding F-02), and they are
					//     refused by their own validators rather than here. This hook is reached for COOKIE
					//     schemes only, so it is not the place that decides bearer outcomes either way.
					// FAILING CLOSED instead, with the same rejection the horizon check performs, so the two
					// controls on this path behave identically. Cost, stated plainly: sessions held from before
					// this deployment are signed out once. The claim travels inside the encrypted, signed ticket,
					// so a client can neither strip it to reach this branch nor forge one to avoid it.
					var sessionClaim = validationContext.Principal.FindFirst(AuthService.CLAIM_SESSION_ID);
					if (sessionClaim == null || !Guid.TryParse(sessionClaim.Value, out var sessionId) || sessionId == Guid.Empty)
					{
						validationContext.RejectPrincipal();
						await SignOutQuietlyAsync(validationContext);
						return;
					}

					// F-01: consulted through the process-wide store rather than a resolved service instance. The
					// previous lookup treated an unresolvable service as "not revoked" - so a host that had not
					// registered it accepted every revoked ticket while appearing to enforce revocation, and the
					// absence of the control was indistinguishable from the control passing. The store cannot be
					// absent, so there is no longer a null case to interpret.
					if (!SessionRevocationService.IsSessionIdentifierRevoked(sessionId))
						return;

					// Reject first, then clear the cookie. Ordered this way the CURRENT request is already
					// unauthenticated even if the sign-out itself fails, so the security outcome does not
					// depend on the cleanup succeeding.
					validationContext.RejectPrincipal();
					await SignOutQuietlyAsync(validationContext);
				};
			});

			// THREAT ADDRESSED - finding H-16, CWE-307 (improper restriction of excessive
			// authentication attempts) and CWE-770 (allocation without limits), OWASP A07: no
			// transport-level request throttling existed anywhere in the platform, so a single client
			// could issue unlimited requests - including unlimited POSTs to the login page and to the
			// anonymous token endpoints. This is the transport-level layer only; the per-account login
			// lockout is a separate, narrower control applied at the login entry point.
			//
			// A fixed window partitioned by remote address is chosen as the least invasive option that
			// closes the gap: it comes from the shared framework, so it adds no package, and it needs
			// no store, no schema change and no configuration. The permit limit is deliberately
			// generous - a single page in this application issues on the order of twenty-five requests -
			// so that ordinary interactive use, including rapid navigation, is never throttled while
			// automated abuse still meets a ceiling.
			//
			// THREAT ADDRESSED - review finding M-REV-08 (CWE-348, use of less trusted source; CWE-307):
			// the partition key was read straight off the transport connection with no forwarded-header
			// processing anywhere in the platform. Behind the reverse proxy this application is designed
			// to run behind - WebVella.Erp.Site ships a web.config for IIS hosting - every caller
			// therefore collapsed into ONE partition keyed on the proxy's own address, which inverts the
			// control completely: ordinary users starve each other out of a shared 600-request budget
			// while a single abusive client is indistinguishable from the crowd it is hidden behind. The
			// key is now taken from DescribeRemoteAddress, which reads the address AFTER the trusted
			// forwarded-headers middleware has had its chance to replace it, and normalises the two
			// spellings of the same IPv4 caller so a client cannot buy a second budget by connecting
			// over IPv4-mapped IPv6.
			//
			// The trust half of that fix lives in UseErpForwardedHeaders, which every host calls FIRST in
			// its pipeline and which refuses to honour a forwarded address at all until an operator names
			// the proxies that may send one. Nothing here trusts a header directly.
			services.AddRateLimiter(rateLimiterOptions =>
			{
				rateLimiterOptions.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
				rateLimiterOptions.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
					RateLimitPartition.GetFixedWindowLimiter(
						// A missing remote address is bucketed under a single shared key rather than
						// being waved through, so an unidentifiable caller cannot escape the limit.
						partitionKey: DescribeRemoteAddress(httpContext),
						factory: _ => new FixedWindowRateLimiterOptions
						{
							PermitLimit = 600,
							Window = TimeSpan.FromMinutes(1),
							// No queueing: a caller over the limit is refused immediately rather than
							// parked, because holding requests open is itself a resource-exhaustion
							// vector.
							QueueLimit = 0,
							QueueProcessingOrder = QueueProcessingOrder.OldestFirst
						}));
			});
			services.Configure<RazorViewEngineOptions>(options => { options.ViewLocationExpanders.Add(new ErpViewLocationExpander()); });
			services.ConfigureOptions(typeof(WebConfigurationOptions));
			services.AddSingleton<IHostedService, ErpJobScheduleService>();
			services.AddSingleton<IHostedService, ErpJobProcessService>();
			services.AddScoped<CircuitHandler, SecuritityCircuitHandler>();
			return services;
		}

		// F-01: the single cookie-clearing step used by both refusals in the ticket-validation hook above, so the
		// two cannot diverge. The principal is ALREADY rejected before this is called, which is what makes
		// swallowing safe here: the current request is unauthenticated whether or not the deletion header reaches
		// the response, and letting an exception escape a validation hook would turn a session control into a 500
		// on every request that presents a cookie - trading a session finding for an outage.
		private static async Task SignOutQuietlyAsync(CookieValidatePrincipalContext validationContext)
		{
			try
			{
				await validationContext.HttpContext.SignOutAsync(validationContext.Scheme.Name);
			}
			catch (Exception)
			{
				// Deliberately silent - see above. Rejection has already taken effect.
			}
		}

		public static IApplicationBuilder UseErp(this IApplicationBuilder app, List<JobType> additionalJobTypes = null, string configFolder = null)
		{
			using (var secCtx = SecurityContext.OpenSystemScope())
			{
				IConfiguration configuration = app.ApplicationServices.GetService<IConfiguration>();
				IWebHostEnvironment env = app.ApplicationServices.GetService<IWebHostEnvironment>();

				if (!ErpSettings.IsInitialized) {
					// DEFECT ADDRESSED - review finding F30 (Configuration / Availability), CWE-16, OWASP
					// A05:2021 Security Misconfiguration. Same defect as WebVella.Erp.ConsoleApp/Program.cs,
					// and this is the single initialization path for all seven hosts, so it matters more here.
					// THREAT: the tracked file is Config.json and that is the name the SDK copies to the output,
					// but this chain asked for lower-case config.json. On a case-insensitive filesystem they are
					// the same file; on Linux they are not, and because this JSON source is deliberately
					// NON-optional - the shipped files are blanked rather than deleted, so an absent file must
					// fail loudly - the host aborted before AddEnvironmentVariables below could supply any
					// secret. Deployments only worked because publish tooling wrote a lower-case duplicate. That
					// duplicate is why the probe PREFERS the correctly cased name and falls back rather than
					// switching: every existing deployment carrying only config.json must keep starting.
					string configPath = "Config.json";
					string lowerCaseConfigPath = "config.json";
					if (!string.IsNullOrWhiteSpace(configFolder))
					{
						configPath = System.IO.Path.Combine(configFolder, configPath);
						lowerCaseConfigPath = System.IO.Path.Combine(configFolder, lowerCaseConfigPath);
					}

					// Resolved against AppContext.BaseDirectory, which is EXACTLY the base path the builder
					// below sets - so the probe tests the same location the provider will actually read. It
					// deliberately does NOT use env.ContentRootPath: WebHost.CreateDefaultBuilder defaults that
					// to Directory.GetCurrentDirectory(), so probing it would test whatever working directory
					// the process happened to be launched with while the provider read from the assembly
					// directory. The two disagree in every deployment launched from anywhere other than the
					// application folder, which would make this fallback both unreliable (a lower-case-only
					// publish output goes undetected, and the host still aborts) and unsound (a file found in
					// an attacker-writable working directory decides which path is selected). An absolute
					// configFolder is honoured unchanged by Path.Combine, matching the pre-existing behaviour
					// of that parameter.
					if (!System.IO.File.Exists(System.IO.Path.Combine(AppContext.BaseDirectory, configPath))
						&& System.IO.File.Exists(System.IO.Path.Combine(AppContext.BaseDirectory, lowerCaseConfigPath)))
						configPath = lowerCaseConfigPath;

					// SECURITY - findings C-04, H-04 and H-05 (CWE-798 use of hard-coded credentials, CWE-321
					// use of a hard-coded cryptographic key, CWE-20 improper input
					// validation), OWASP A05 Security Misconfiguration.
					// THREAT: this is the single initialization path that feeds ErpSettings for every one of the
					// seven hosts, and it consumed the JSON file and nothing else. Config.json was therefore the
					// ONLY channel through which a secret could ever be supplied, which had two consequences:
					// the platform's own startup errors named environment variables that no provider could
					// satisfy, and blanking those files - the paired step of this remediation - would have left
					// every host permanently unstartable with no way to supply a replacement value.
					//
					// Provider ORDER is the control, not an incidental detail. Later providers win, so the
					// tracked JSON file stays FIRST and environment variables come immediately AFTER it: the
					// shipped secret values are blanked to empty strings rather than removed, so only a later
					// provider can put a real secret back. Reverse the two and the blank JSON string would
					// clobber the operator's environment variable and every host would abort on ErpSettings'
					// fail-fast validation. Keys use the framework's section separator - for example
					// Settings__ConnectionString, Settings__EncryptionKey and Settings__Jwt__Key; the complete
					// list is in docs/security/secure-configuration.md. Nothing is defaulted or logged here.
					// The JSON source stays NON-optional on purpose: the Config.json files are blanked, never
					// deleted, so an absent file must still fail loudly rather than yield a silently empty
					// configuration.
					//
					// SECURITY - CWE-706 use of an incorrectly resolved name, same OWASP A05 category. The
					// base path is AppContext.BaseDirectory, the directory the entry assembly was loaded
					// from and exactly where both the build and the publish output place Config.json. It is
					// NOT env.ContentRootPath, which WebHost.CreateDefaultBuilder defaults to
					// Directory.GetCurrentDirectory() - so the file supplying the connection string, the
					// data-at-rest encryption key and the token signing key would otherwise be selected by
					// whatever working directory the process was launched with. That lets a launcher, or
					// anyone able to write to a directory the service is started from, decide which
					// Config.json the platform trusts.
					var configurationBuilder = new ConfigurationBuilder().SetBasePath(AppContext.BaseDirectory).AddJsonFile(configPath);
					configurationBuilder.AddEnvironmentVariables();

					if (env.IsDevelopment())
					{
						// User secrets come LAST, and only in Development, so a developer's own store takes
						// precedence over an ambient machine-wide environment variable - which is the whole
						// reason the store exists. It is never load-bearing: outside Development this provider is
						// not added at all, because the store sits unencrypted on disk and must never be a
						// production supply channel. Every non-development chain is therefore exactly
						// JSON file then environment variables.
						// The entry assembly is the host executable, so each host resolves its own store rather
						// than this library's - this library declares no UserSecretsId and must not.
						// optional: true is stated EXPLICITLY rather than left to an overload default, because
						// only ONE of the seven hosts declares a UserSecretsId at all and every AddUserSecrets
						// overload given optional: false throws InvalidOperationException when that attribute is
						// absent - which would abort startup for the other six hosts and the console
						// application, turning a secret-management fix into an outage. Pinning the value here
						// means the tolerant behaviour is a contract at this call site rather than an
						// invisible default that a later overload change could silently flip.
						var entryAssembly = Assembly.GetEntryAssembly();
						if (entryAssembly != null)
							configurationBuilder.AddUserSecrets(entryAssembly, optional: true);
					}

					ErpSettings.Initialize(configurationBuilder.Build());
				}

				// THREAT ADDRESSED - review finding F12 (OWASP A05: Security Misconfiguration): force the
				// security-header options to materialise here, immediately after the configuration provider
				// chain is in place, so that the Content-Security-Policy posture is parsed and validated at
				// startup. Without this the binding delegate would first run when the pipeline is built, and a
				// malformed value would surface as an opaque middleware construction failure on the first
				// request rather than as an actionable startup error naming the key and the bad value.
				//
				// The resolved instance is inspected rather than discarded so that a container misconfiguration
				// - options registered but resolving to null - is caught here too, instead of silently falling
				// back inside the middleware constructor and leaving an operator unable to tell whether their
				// configured posture took effect.
				IOptions<Middleware.SecurityHeadersOptions> securityHeaderOptions =
					app.ApplicationServices.GetService<IOptions<Middleware.SecurityHeadersOptions>>();

				if (securityHeaderOptions?.Value == null)
				{
					throw new InvalidOperationException(
						"Security response header options could not be resolved. AddErp() must be called during ConfigureServices before UseErp() is called, so that the Content-Security-Policy posture configured through '"
						+ ContentSecurityPolicyReportOnlyConfigurationKey
						+ "' is applied.");
				}

				// THREAT ADDRESSED - QA finding "Production hosts bound to HTTP only return HTTP 500 on
				// every form-bearing page, including /login" (CWE-16 configuration, CWE-1188 insecure
				// default, OWASP A05:2021 Security Misconfiguration), and the availability half of
				// findings M-02 and H-15. The antiforgery cookie and the authentication cookie are both
				// Secure-only by design - relaxing either is the CWE-614 vulnerability those findings
				// remediate - so a deployment that gives this process no HTTPS request path answers 500
				// from DefaultAntiforgery.CheckSSLConfig on EVERY page carrying a form, /login included,
				// while still starting healthy, answering / with a redirect and emitting all seven
				// security headers. Health probes and header audits therefore pass while nobody can sign
				// in. This consults the transport posture at startup, in the same place and the same
				// shape as ErpSettings' required-secret validation, so the misconfiguration is reported
				// once and actionably instead of once per request as an opaque 500.
				//
				// Deliberately ordered AFTER ErpSettings.Initialize above: a deployment missing both a
				// secret and an HTTPS path must still fail on the secret, because that is the failure the
				// operator has to fix first and the one the continuous gate asserts.
				ValidateTransportSecurityPosture(app, configuration, env);

				var defaultThreadCulture = CultureInfo.DefaultThreadCurrentCulture;
				var defaultThreadUICulture = CultureInfo.DefaultThreadCurrentUICulture;

				CultureInfo customCulture = new CultureInfo("en-US");
				customCulture.NumberFormat.NumberDecimalSeparator = ".";

				IErpService service = null;
				try
				{
					DbContext.CreateContext(ErpSettings.ConnectionString);

					service = app.ApplicationServices.GetService<IErpService>();

					var cfg = ErpAutoMapperConfiguration.MappingExpressions; // var cfg = new AutoMapper.Configuration.MapperConfigurationExpression();
					ErpAutoMapperConfiguration.Configure(cfg);
					ErpWebAutoMapperConfiguration.Configure(cfg);

					//this method append plugin automapper configuration
					service.SetAutoMapperConfiguration();

					//this should be called after plugin init
					ErpAutoMapper.Initialize(cfg);

					//we used en-US based culture settings for initialization and patch execution
					{
						CultureInfo.DefaultThreadCurrentCulture = customCulture;
						CultureInfo.DefaultThreadCurrentUICulture = customCulture;

						service.InitializeSystemEntities();

						CultureInfo.DefaultThreadCurrentCulture = defaultThreadCulture;
						CultureInfo.DefaultThreadCurrentUICulture = defaultThreadUICulture;
					}

					CheckCreateHomePage();

					service.InitializeBackgroundJobs(additionalJobTypes);

					ErpAppContext.Init(app.ApplicationServices);

					{
						//switch culture for patch executions and initializations
						CultureInfo.DefaultThreadCurrentCulture = customCulture;
						CultureInfo.DefaultThreadCurrentUICulture = customCulture;

						//this is called after automapper setup
						service.InitializePlugins(app.ApplicationServices);

						CultureInfo.DefaultThreadCurrentCulture = defaultThreadCulture;
						CultureInfo.DefaultThreadCurrentUICulture = defaultThreadUICulture;
					}

				}
				finally
				{
					DbContext.CloseContext();
					CultureInfo.DefaultThreadCurrentCulture = defaultThreadCulture;
					CultureInfo.DefaultThreadCurrentUICulture = defaultThreadUICulture;
				}

				//this is handled by background services now
				//if (service != null)
				//	service.StartBackgroundJobProcess();

				return app;
			}
		}

		// Enables trusted reverse-proxy forwarded-header processing, and nothing else.
		//
		// THREAT ADDRESSED - review finding M-REV-08 (CWE-348 use of less trusted source, CWE-290
		// authentication bypass by spoofing, CWE-307 improper restriction of excessive attempts), OWASP
		// A05 Security Misconfiguration. No forwarded-header processing existed anywhere in the platform,
		// so behind a reverse proxy - the topology WebVella.Erp.Site's own web.config describes - three
		// separate security controls silently degraded at once:
		//   * the request-rate partition collapsed onto the proxy's address, so every caller shared one
		//     budget and no individual abuser could be isolated;
		//   * the per-address half of the login lockout keyed on the proxy too, so one attacker's failures
		//     counted against every other user of that proxy;
		//   * Request.IsHttps read false for requests the client actually made over TLS, which is what
		//     HTTPS redirection and the Secure cookie policy both read.
		//
		// DENY BY DEFAULT, AND WHY IT IS EXPRESSED AS "DO NOT REGISTER" RATHER THAN "REGISTER WITH AN
		// EMPTY LIST". This is the load-bearing detail of the whole fix. ForwardedHeadersMiddleware
		// decides whether to check the peer against the trusted lists with, in effect,
		// `checkKnownIps = KnownIPNetworks.Count > 0 || KnownProxies.Count > 0`. Registering it with BOTH
		// lists empty therefore disables the check altogether and the middleware honours X-Forwarded-For
		// from ANY peer on the internet - the exact spoofing primitive this finding is about, installed by
		// the fix meant to prevent it. The only configuration that genuinely trusts nobody is not to add
		// the middleware, so that is what an unconfigured deployment gets: X-Forwarded-* is ignored
		// entirely and Connection.RemoteIpAddress stays the true transport peer.
		//
		// Operators opt in by naming their proxies - Settings__ForwardedHeaders__KnownProxies and/or
		// Settings__ForwardedHeaders__KnownNetworks. When they do, the framework's own defaults
		// (loopback only) are CLEARED first, so the effective trust set is exactly what was declared and
		// never that plus something inherited.
		//
		// Pipeline position is the caller's responsibility and is documented at every call site: this must
		// run before UseSecurityHeaders, UseHsts, UseHttpsRedirection and UseRateLimiter, because each of
		// those reads either the scheme or the remote address that this middleware corrects.
		public static IApplicationBuilder UseErpForwardedHeaders(this IApplicationBuilder app)
		{
			ArgumentNullException.ThrowIfNull(app);

			IConfiguration configuration = app.ApplicationServices.GetService<IConfiguration>();
			ForwardedHeadersOptions options = BuildForwardedHeadersOptions(configuration);

			// No trusted proxy declared: forwarded headers are not processed at all. See above for why
			// this is a non-registration rather than an empty allow-list.
			if (options == null)
				return app;

			app.UseForwardedHeaders(options);
			return app;
		}

		// Builds the forwarded-header options from configuration, or returns null when no proxy is
		// trusted. Malformed entries abort startup rather than being skipped: silently dropping a
		// mistyped proxy address would leave an operator believing the caller's real address was being
		// recovered while the rate limiter and the login lockout continued to key on the proxy. The
		// offending entry is named in the message because a network address is operator-supplied topology,
		// not a secret, and naming it is the difference between an actionable error and a guessing game.
		private static ForwardedHeadersOptions BuildForwardedHeadersOptions(IConfiguration configuration)
		{
			if (configuration == null)
				return null;

			IConfiguration section = configuration.GetSection(ForwardedHeadersConfigurationSection);

			List<IPAddress> knownProxies = ParseKnownProxies(section["KnownProxies"]);
			List<System.Net.IPNetwork> knownNetworks = ParseKnownNetworks(section["KnownNetworks"]);

			if (knownProxies.Count == 0 && knownNetworks.Count == 0)
				return null;

			var options = new ForwardedHeadersOptions
			{
				// Only the two headers the platform actually consumes are honoured. X-Forwarded-Host is
				// deliberately NOT included: accepting it would let a trusted proxy - or anything that
				// compromised it - rewrite the host this application believes it is serving, which is a
				// host-header injection and absolute-URL poisoning primitive with no offsetting benefit
				// here, because nothing in this platform builds absolute URLs from Request.Host for
				// security decisions.
				ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor
					| Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto,
				ForwardLimit = ParseForwardLimit(section["ForwardLimit"])
			};

			// The framework seeds these with loopback entries. They are cleared so that the trust set is
			// exactly the declared one - an inherited entry nobody wrote down is precisely the kind of
			// implicit trust this finding is about.
			options.KnownProxies.Clear();
			options.KnownIPNetworks.Clear();

			foreach (IPAddress knownProxy in knownProxies)
				options.KnownProxies.Add(knownProxy);

			foreach (System.Net.IPNetwork knownNetwork in knownNetworks)
				options.KnownIPNetworks.Add(knownNetwork);

			return options;
		}

		private static List<IPAddress> ParseKnownProxies(string configuredValue)
		{
			var parsed = new List<IPAddress>();
			foreach (string entry in SplitForwardedHeadersList(configuredValue))
			{
				if (!IPAddress.TryParse(entry, out IPAddress address))
					throw new InvalidOperationException($"{ForwardedHeadersConfigurationSection}:KnownProxies contains '{entry}', which is not a valid IP address. Supply a comma or semicolon separated list of the reverse-proxy addresses this application may trust, or remove the setting to disable forwarded-header processing entirely.");

				parsed.Add(address);
			}

			return parsed;
		}

		private static List<System.Net.IPNetwork> ParseKnownNetworks(string configuredValue)
		{
			var parsed = new List<System.Net.IPNetwork>();
			foreach (string entry in SplitForwardedHeadersList(configuredValue))
			{
				// System.Net.IPNetwork is used rather than the Microsoft.AspNetCore.HttpOverrides type of
				// the same name, and KnownIPNetworks rather than KnownNetworks, because both of the older
				// spellings are marked obsolete in this framework version and using them would introduce
				// new build warnings.
				if (!System.Net.IPNetwork.TryParse(entry, out System.Net.IPNetwork network))
					throw new InvalidOperationException($"{ForwardedHeadersConfigurationSection}:KnownNetworks contains '{entry}', which is not a valid CIDR network. Supply a comma or semicolon separated list such as '10.0.0.0/8;192.168.0.0/16', or remove the setting to disable forwarded-header processing entirely.");

				parsed.Add(network);
			}

			return parsed;
		}

		private static int ParseForwardLimit(string configuredValue)
		{
			if (string.IsNullOrWhiteSpace(configuredValue))
				return DefaultForwardedHeadersForwardLimit;

			// A non-positive or unparseable limit is rejected rather than coerced. ForwardLimit is
			// nullable in the framework and null means "consume every entry in the header", which hands
			// the caller control of the address this application believes it is talking to; that value is
			// unreachable from configuration on purpose.
			if (!int.TryParse(configuredValue.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int limit) || limit < 1)
				throw new InvalidOperationException($"{ForwardedHeadersConfigurationSection}:ForwardLimit must be a positive whole number naming how many trusted proxies sit in front of this application. Remove the setting to use the default of {DefaultForwardedHeadersForwardLimit}.");

			return limit;
		}

		private static IEnumerable<string> SplitForwardedHeadersList(string configuredValue)
		{
			if (string.IsNullOrWhiteSpace(configuredValue))
				return Enumerable.Empty<string>();

			return configuredValue
				.Split(ForwardedHeadersListSeparators, StringSplitOptions.RemoveEmptyEntries)
				.Select(entry => entry.Trim())
				.Where(entry => entry.Length > 0);
		}

		// Refuses - or at minimum reports - a deployment in which no request can ever reach this
		// application over HTTPS. The threat is stated at the call site in UseErp.
		//
		// The decision is evidence-based rather than heuristic: any ONE of the four channels below gives
		// this process a way to see an HTTPS request, and finding one ends the check silently. Nothing is
		// inferred from the environment name alone, and no cookie policy is weakened.
		//
		// The refusal is deliberately narrow, because a check that aborts a deployment which would have
		// worked is worse than the failure it prevents. It fires only when the endpoints were DECLARED -
		// through ASPNETCORE_URLS, UseUrls or a host binding, all of which reach
		// IServerAddressesFeature.Addresses before Configure runs - and every declared endpoint is
		// plaintext. When nothing is declared the endpoints come from the server's own defaults or from
		// host code this method cannot inspect, so the identical diagnosis is WRITTEN AS A WARNING
		// instead: the condition is never silent, but an unknown posture is never grounds to refuse.
		// Development is exempt from the refusal because its antiforgery cookie follows the request
		// scheme, so local plaintext sign-in remains supported while the warning keeps an absent HTTPS
		// path visible. The authentication cookie remains Secure-only in every environment.
		private static void ValidateTransportSecurityPosture(IApplicationBuilder app, IConfiguration configuration, IWebHostEnvironment env)
		{
			ICollection<string> declaredEndpoints = app?.ServerFeatures
				?.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()?.Addresses;

			// 1. An HTTPS endpoint this process binds itself.
			if (declaredEndpoints != null && declaredEndpoints.Any(endpoint =>
				endpoint != null && endpoint.StartsWith(HttpsUriSchemePrefix, StringComparison.OrdinalIgnoreCase)))
				return;

			// 2. An HTTPS endpoint declared in Kestrel's own configuration section instead.
			if (IsKestrelHttpsEndpointDeclared(configuration))
				return;

			// 3. A public HTTPS port. This counts even though the process binds no HTTPS endpoint,
			// because UseHttpsRedirection answers a plaintext request with a redirect to that port
			// before it can reach a form - which is precisely the behaviour that is silently inert
			// while the key is absent.
			if (!string.IsNullOrWhiteSpace(configuration?[HttpsRedirectionPortConfigurationKey]))
				return;

			// 4. A trusted reverse proxy that terminates TLS and forwards the scheme. The forwarded-header
			// option builder is REUSED rather than its keys re-read, so "a proxy is trusted" here means
			// exactly what UseErpForwardedHeaders acts on; a null result is that method's own encoding of
			// "nothing is trusted". Whether the proxy actually sends X-Forwarded-Proto cannot be known at
			// startup, which is why the diagnosis below says so explicitly.
			if (BuildForwardedHeadersOptions(configuration) != null)
				return;

			bool endpointsWereDeclared = declaredEndpoints != null && declaredEndpoints.Count > 0;
			bool isDevelopment = env != null && env.IsDevelopment();

			// The endpoint list is operator-supplied deployment topology, not a secret - the same
			// reasoning that lets the KnownProxies diagnostic name the offending address - so quoting it
			// turns this message from a rule restatement into an actionable one. No configuration VALUE
			// is ever echoed (CWE-532).
			string observedEndpoints = endpointsWereDeclared
				? string.Join(", ", declaredEndpoints)
				: "none declared, so the server's own defaults decide them";

			// One sentence explaining why this message is a refusal or a report, so the two paths can never
			// be confused for one another in a log.
			string closingNote;
			if (isDevelopment)
			{
				closingNote = "Development is exempt from this startup refusal, so the host will start and its antiforgery cookie will follow the request scheme; local plaintext sign-in remains supported. Configure HTTPS to exercise the production transport posture.";
			}
			else if (endpointsWereDeclared)
			{
				closingNote = "Startup is refused rather than left to fail one request at a time, which is how this misconfiguration used to surface. Development is exempt from the refusal.";
			}
			else
			{
				closingNote = "The endpoints this process will bind are not declared in configuration, so this is reported rather than refused; if they resolve to plaintext only, no sign-in will be possible.";
			}

			string diagnosis = "no HTTPS request path was found in the transport configuration visible at startup."
				+ $"{Environment.NewLine}  Observed endpoints: " + observedEndpoints + "."
				+ $"{Environment.NewLine}  Outside Development, the antiforgery cookie is Secure-only BY DESIGN (finding M-02 - CWE-614, CWE-319), so if this host resolves to plaintext only, form generation fails inside DefaultAntiforgery.CheckSSLConfig with 'the current request is not an SSL request' and every form-bearing page - '/login' included - answers HTTP 500. The authentication cookie remains Secure-only in every environment (finding H-15 - CWE-614, CWE-1004, CWE-319). Development deliberately makes only the antiforgery cookie follow the request scheme so local plaintext forms remain usable. Weakening the non-Development antiforgery policy or the authentication-cookie policy is NOT the remedy: it reinstates the vulnerability those findings closed."
				+ $"{Environment.NewLine}  Supply ANY ONE of the following, then restart:"
				+ $"{Environment.NewLine}    - an HTTPS endpoint of this process: 'ASPNETCORE_URLS' including an https:// address, together with 'Kestrel__Certificates__Default__Path' and 'Kestrel__Certificates__Default__Password' - or a '"
				+ KestrelEndpointsConfigurationSection
				+ "' entry whose Url is https;"
				+ $"{Environment.NewLine}    - the public HTTPS port, when TLS is terminated in front of this process and plaintext requests should be redirected: 'ASPNETCORE_HTTPS_PORT' or 'HTTPS_PORT' (configuration key '"
				+ HttpsRedirectionPortConfigurationKey
				+ "'). 'ASPNETCORE_HTTPS_PORTS' - plural - is a Kestrel default-binding key that this application never reads: it neither binds an endpoint nor arms the redirect;"
				+ $"{Environment.NewLine}    - trust for the reverse proxy that terminates TLS: '"
				+ ForwardedHeadersConfigurationSection.Replace(":", "__", StringComparison.Ordinal)
				+ "__KnownProxies' or '"
				+ ForwardedHeadersConfigurationSection.Replace(":", "__", StringComparison.Ordinal)
				+ "__KnownNetworks', AND configure that proxy to forward 'X-Forwarded-Proto: https' - trusting a proxy that does not send it leaves this failure in place."
				+ $"{Environment.NewLine}  See docs/security/secure-configuration.md for the complete transport-security configuration."
				+ $"{Environment.NewLine}  " + closingNote;

			if (endpointsWereDeclared && !isDevelopment)
				throw new InvalidOperationException("WebVella ERP startup aborted - " + diagnosis);

			// Reported in the same shape as the platform's other startup security notice - the disabled
			// token-route warning in ErpSettings - so both read alike in a host log and an operator has
			// one idiom to recognise rather than two.
			Console.Error.WriteLine("warn: WebVella.Erp.Web.ErpMvcServicesExtensions[1] SECURITY - " + diagnosis);
		}

		// True when Kestrel's configuration declares at least one endpoint whose Url is https. Read
		// directly rather than through KestrelServerOptions because this runs while the pipeline is being
		// built, before the server has bound anything, and because the configuration section is the only
		// declaration that is knowable at that point.
		private static bool IsKestrelHttpsEndpointDeclared(IConfiguration configuration)
		{
			IConfiguration endpointsSection = configuration?.GetSection(KestrelEndpointsConfigurationSection);
			if (endpointsSection == null)
				return false;

			foreach (IConfigurationSection endpoint in endpointsSection.GetChildren())
			{
				string url = endpoint["Url"];
				if (!string.IsNullOrWhiteSpace(url) && url.TrimStart().StartsWith(HttpsUriSchemePrefix, StringComparison.OrdinalIgnoreCase))
					return true;
			}

			return false;
		}

		// The single normalisation of a caller's address used by every per-source security control in the
		// platform - the request-rate partition above and the Content-Security-Policy report budget in
		// SecurityHeadersMiddleware.
		//
		// THREAT ADDRESSED - review findings M-REV-08 and L-REV-03: two distinct evasions are closed
		// here. First, the address is read from Connection.RemoteIpAddress, which
		// UseErpForwardedHeaders has already replaced with the real caller when - and only when - a
		// trusted proxy supplied it, so a per-source budget behind a proxy is per CALLER rather than per
		// PROXY. Second, an IPv4 caller reaching the server over IPv4-mapped IPv6 presents as
		// "::ffff:203.0.113.7" while the same caller over IPv4 presents as "203.0.113.7"; keying on the
		// raw string would give one client two independent budgets, so the mapped form is folded back to
		// its IPv4 spelling.
		//
		// An unresolvable address is bucketed under one shared key rather than being waved through: an
		// unidentifiable caller must not be the only caller with no limit.
		internal static string DescribeRemoteAddress(HttpContext httpContext)
		{
			IPAddress address = httpContext?.Connection?.RemoteIpAddress;
			if (address == null)
				return "unknown";

			if (address.IsIPv4MappedToIPv6)
				address = address.MapToIPv4();

			return address.ToString();
		}

		// Applies the platform's authentication-cookie security contract.
		//
		// THREAT ADDRESSED - review finding M-REV-09 (CWE-614 sensitive cookie without the Secure
		// attribute, CWE-1275 improper SameSite attribute, CWE-613 insufficient session expiration),
		// OWASP A02 / A05, and Agent Action Plan section 0.6.1 Class 6, which mandates "an always-secure
		// policy, a same-site policy, an explicit expiry window and sliding expiration". Each of the seven
		// hosts previously carried its own copy of these settings, and the copies had drifted from the
		// frozen contract in two ways that mattered: the secure policy relaxed itself to SameAsRequest
		// whenever ASPNETCORE_ENVIRONMENT read "Development", and sliding expiration was disabled. Seven
		// duplicated copies is also the ROOT CAUSE of that drift, not merely where it showed up, so the
		// settings now live here once and every host delegates to them. A future edit cannot desynchronise
		// six hosts from the seventh because there is only one place left to edit.
		//
		// SecurePolicy is Always UNCONDITIONALLY, including in Development. The previous Development
		// relaxation was justified by local development being served over plaintext, but that
		// justification does not hold: http://localhost is a "potentially trustworthy origin" under the
		// W3C Secure Contexts specification, and every current browser therefore accepts a Secure cookie
		// over it - Chromium since 89, Firefox since 75. The relaxation bought nothing and cost the
		// mandated attribute, and worse, it keyed off a raw environment variable read, so an unset or
		// misspelled variable silently decided a security attribute.
		//
		// SameSite is Lax and must not be "upgraded" to Strict: Strict withholds the cookie on the
		// return-URL round trip back from the login page, which would break a working sign-in. Lax is the
		// framework's own default posture and still withholds the cookie from cross-site POSTs.
		//
		// SlidingExpiration is true, per the mandated contract, and the 24-hour window is therefore an
		// IDLE timeout rather than an absolute one. Sliding renewal on its own would let a stolen cookie
		// be kept alive for ever, so it is paired with an absolute session horizon enforced in
		// AuthService.ValidateSessionHorizonAsync - the same ceiling the bearer-token path already
		// applies. Enabling one without the other would trade a session-expiry finding for a worse one.
		public static void ConfigureErpAuthenticationCookie(CookieAuthenticationOptions options)
		{
			ArgumentNullException.ThrowIfNull(options);

			options.Cookie.HttpOnly = true;
			options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
			options.Cookie.SameSite = SameSiteMode.Lax;

			// The declared window and the ticket's explicit ExpiresUtc must agree, because an explicit
			// ExpiresUtc overrides ExpireTimeSpan and would otherwise make this line inert configuration.
			// AuthService.AUTH_TICKET_EXPIRY_DURATION_MINUTES is the other half of that pair.
			options.ExpireTimeSpan = TimeSpan.FromMinutes(AuthenticationCookieLifetimeMinutes);
			options.SlidingExpiration = true;

			// Events is null until the framework's post-configuration step runs, which is after this
			// method, so it is created here when absent rather than dereferenced. No host sets a
			// principal-validation handler of its own - verified across all seven - so assigning this one
			// cannot displace host behaviour.
			CookieAuthenticationEvents events = options.Events ?? new CookieAuthenticationEvents();
			events.OnValidatePrincipal = AuthService.ValidateSessionHorizonAsync;
			options.Events = events;
		}

		public static IApplicationBuilder UseErpPlugin<T>(this IApplicationBuilder app) where T : ErpPlugin, new()
		{
			using (var secCtx = SecurityContext.OpenSystemScope())
			{
				var plugin = new T();
				var service = app.ApplicationServices.GetService<IErpService>();
				service.Plugins.Add(plugin);
				return app;
			}
		}

		private static void CheckCreateHomePage()
		{
			var pageSrv = new PageService();

			var pageId = new Guid("560e77c5-6184-418e-8d49-51ae83c9773d");
			var name = @"home";
			var label = "Home";
			string iconClass = null;
			var system = false;
			var layout = @"";
			var weight = 10;
			var type = (PageType)((int)0);
			var isRazorBody = false;
			Guid? appId = null;
			Guid? entityId = null;
			Guid? nodeId = null;
			Guid? areaId = null;
			string razorBody = null;
			var labelTranslations = new List<TranslationResource>();

			using (var connection = DbContext.Current.CreateConnection())
			{
				try
				{
					connection.BeginTransaction();
					if (!pageSrv.GetAll(transaction: DbContext.Current.Transaction, useCache: false).Any(x => x.Id == pageId))
					{
						pageSrv.CreatePage(pageId, name, label, labelTranslations, iconClass, system, weight, type, appId, entityId, nodeId, areaId, isRazorBody, razorBody, layout, WebVella.Erp.Database.DbContext.Current.Transaction);
						pageSrv.CreatePageBodyNode(new Guid("3a4e8154-9f48-4ba5-9e11-36fa5e7a80c9"), null, pageId, null, 1, "WebVella.Erp.Web.Components.PcApplications", "", @"""{}""", WebVella.Erp.Database.DbContext.Current.Transaction);
					}
					connection.CommitTransaction();
				}
				catch
				{
					connection.RollbackTransaction();
					throw;
				}
			}
		}
	}
}
