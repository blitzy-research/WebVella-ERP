using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace WebVella.Erp.Web.Middleware
{
	// Emits the platform's mandated security response headers on every response.
	//
	// THREAT ADDRESSED - finding M-01 (OWASP A05: Security Misconfiguration): not one of the seven
	// security headers was emitted by any of the seven host applications before this middleware
	// existed. Their absence left the application exposed to clickjacking (no X-Frame-Options),
	// MIME-type sniffing (no X-Content-Type-Options), referrer leakage to third-party origins (no
	// Referrer-Policy) and unrestricted browser-feature access - geolocation, microphone and camera
	// (no Permissions-Policy).
	public class SecurityHeadersMiddleware
	{
		private const string ContentSecurityPolicyHeaderName = "Content-Security-Policy";
		private const string ContentSecurityPolicyReportOnlyHeaderName = "Content-Security-Policy-Report-Only";
		private const string StrictTransportSecurityHeaderName = "Strict-Transport-Security";
		private const string XContentTypeOptionsHeaderName = "X-Content-Type-Options";
		private const string XFrameOptionsHeaderName = "X-Frame-Options";
		private const string XXssProtectionHeaderName = "X-XSS-Protection";
		private const string ReferrerPolicyHeaderName = "Referrer-Policy";
		private const string PermissionsPolicyHeaderName = "Permissions-Policy";

		private const string StrictTransportSecurityValue = "max-age=31536000; includeSubDomains";
		private const string XContentTypeOptionsValue = "nosniff";
		private const string XFrameOptionsValue = "DENY";
		private const string XXssProtectionValue = "0";
		private const string ReferrerPolicyValue = "strict-origin-when-cross-origin";
		private const string PermissionsPolicyValue = "geolocation=(), microphone=(), camera=()";

		private readonly RequestDelegate next;
		private readonly SecurityHeadersOptions options;
		private readonly bool emitStrictTransportSecurity;

		public SecurityHeadersMiddleware(RequestDelegate next, IOptions<SecurityHeadersOptions> options, IWebHostEnvironment environment)
		{
			this.next = next;
			// Secure by default in every registration order: if the options type was never registered,
			// or resolves to null, fall back to a defaulted instance carrying the mandated values.
			this.options = options?.Value ?? new SecurityHeadersOptions();

			// Strict-Transport-Security is the one header of the mandated seven that is deliberately
			// NOT emitted in the Development environment. This guard mirrors, rather than duplicates,
			// the one every host already applies to app.UseHsts()/app.UseHttpsRedirection(); without
			// it this middleware would emit the header unconditionally and thereby silently defeat
			// that host-level guard.
			//
			// Why the header is harmful in Development: HSTS is sticky and browser-persisted. A
			// developer who loads the app once over https://localhost is pinned to HTTPS for the whole
			// localhost origin - shared with every other locally served project - for the full
			// max-age of one year, and clearing that state requires manual browser surgery.
			//
			// Why the guard tests the environment rather than Request.IsHttps: production deployments
			// commonly terminate TLS at a reverse proxy and forward plaintext, so the application sees
			// IsHttps == false for requests the client actually made over HTTPS. Guarding on IsHttps
			// would drop a mandated header in exactly that topology; guarding on the environment keeps
			// it unconditional wherever the application is really deployed.
			//
			// Fail-safe direction: if the environment cannot be resolved the header IS emitted. A
			// spurious HSTS header is inert over plaintext - RFC 6797 section 7.2 requires user agents
			// to ignore it - whereas a missing one is a real gap in the mandated header set.
			this.emitStrictTransportSecurity = environment == null
				|| !string.Equals(environment.EnvironmentName, "Development", StringComparison.OrdinalIgnoreCase);
		}

		public async Task Invoke(HttpContext context)
		{
			// THREAT ADDRESSED - finding CFG-04 (incomplete security-header coverage) and CWE-693
			// (protection mechanism failure): this method previously short-circuited on a
			// violation-report collector path and returned 204 No Content BEFORE any of the seven
			// headers were attached, so the all-responses guarantee this middleware exists to provide
			// was false for that one path. The collector has been removed outright rather than merely
			// re-ordered, which makes the bypass structurally impossible: there is now exactly one
			// path through Invoke and it always attaches every mandated header. Removal also retires
			// an anonymous, unauthenticated POST endpoint that was reachable on all seven hosts ahead
			// of routing and authentication, and with it the CWE-400 body-size and CWE-779
			// log-flooding exposures that endpoint had to be defended against. Do not reintroduce a
			// collector branch here: per-path variation of the mandated header set is the defect
			// itself, not an optimisation.
			//
			// Headers are attached before the response starts, because mutating them once the response
			// has begun throws InvalidOperationException. Every write below uses indexer assignment
			// rather than Add(): Add() throws ArgumentException on an already-present key, which would
			// turn this hardening change into a 500 the moment anything else set the same header.
			var headers = context.Response.Headers;

			// THREAT ADDRESSED - finding H-15, CWE-319 (cleartext transmission of sensitive
			// information) and CWE-614 (sensitive cookie without 'Secure' attribute), OWASP A02:
			// Cryptographic Failures: with no HSTS an attacker can downgrade the connection to
			// plaintext and intercept session cookies. An indexer write cannot produce a second
			// header, so this middleware never duplicates the one the hosts add separately.
			//
			// CO-EXISTENCE WITH THE FRAMEWORK'S OWN WRITER - load-bearing, and it depends on a
			// registration outside this file. Every host also calls app.UseHsts(), and HstsMiddleware
			// assigns this same header by indexer too, so whichever runs LAST decides the wire value.
			// UseSecurityHeaders() is deliberately ordered early - ahead of response compression and
			// static files - which means HstsMiddleware always runs after it and always wins. With
			// HstsOptions left at its framework defaults that made the wire value "max-age=2592000":
			// thirty days, no includeSubDomains, so the mandated one-year subdomain-inclusive value
			// never reached a single HTTPS response even though this middleware wrote it correctly.
			// The agreement between the two writers is created by services.AddHsts() in
			// ErpMvcExtensions.AddErp, which pins MaxAge to 365 days and IncludeSubDomains to true.
			// Both writers then emit the identical string and the overwrite is a genuine no-op in
			// either order. Removing that registration silently reinstates the thirty-day header, so
			// this comment must not be read as evidence that the two values agree on their own.
			//
			// The emission is suppressed in Development only; see the constructor for why that guard
			// exists, why it tests the environment rather than the scheme, and which way it fails.
			if (emitStrictTransportSecurity)
			{
				headers[StrictTransportSecurityHeaderName] = StrictTransportSecurityValue;
			}

			headers[XContentTypeOptionsHeaderName] = XContentTypeOptionsValue;
			headers[XFrameOptionsHeaderName] = XFrameOptionsValue;

			// '0' is intentional and must not be "modernised" to '1; mode=block': it disables the
			// legacy browser XSS auditors, which are themselves exploitable to selectively suppress
			// legitimate script.
			headers[XXssProtectionHeaderName] = XXssProtectionValue;

			headers[ReferrerPolicyHeaderName] = ReferrerPolicyValue;
			headers[PermissionsPolicyHeaderName] = PermissionsPolicyValue;

			// The mandated policy value is emitted verbatim and is never weakened: the value carries
			// exactly the three mandated fetch directives and no fourth directive of any kind. It ships
			// under the report-only header name because four components deliberately emit inline script
			// or markup - Components/PcHtmlBlock/Display.cshtml:L10, Components/PcHtmlBlock/Design.cshtml:L10,
			// Components/Nav/Nav.Default.cshtml:L48 and, in the SDK plugin,
			// Components/WvSdkPageSitemap/Form.cshtml:L92 - so enforcing script-src 'self' on the first
			// deployment would break them and violate the functionality-preservation requirement. An
			// operator flips ContentSecurityPolicyReportOnly to false - now a bound configuration
			// setting, see ErpMvcExtensions.AddErp - once violation reports are clean.
			//
			// THREAT ADDRESSED - finding CFG-02, CWE-1032: the emitted value is byte-identical to the
			// mandated policy, with no reporting directive appended. No blank-value fallback is needed
			// or present because ContentSecurityPolicy is a compile-time constant: it cannot be null,
			// blank, weakened or replaced by any host, plugin or configuration source.
			const string contentSecurityPolicy = SecurityHeadersOptions.ContentSecurityPolicy;

			// Exactly one of the two policy header names is emitted, never both.
			if (options.ContentSecurityPolicyReportOnly)
			{
				headers[ContentSecurityPolicyReportOnlyHeaderName] = contentSecurityPolicy;
			}
			else
			{
				headers[ContentSecurityPolicyHeaderName] = contentSecurityPolicy;
			}

			await next(context);
		}
	}

	// Configuration for SecurityHeadersMiddleware, carrying the Content-Security-Policy value and its
	// report-only switch. Deliberately a plain class with a public parameterless constructor and
	// settable properties so that services.Configure<SecurityHeadersOptions>() and
	// IOptions<SecurityHeadersOptions> can materialise it; a positional record could not.
	public class SecurityHeadersOptions
	{
		// The mandated Content-Security-Policy fetch directives, verbatim and single-sourced. This is
		// the shipping value of the property below and also the fallback the middleware applies when an
		// operator override is absent or blank, so the mandated directives are the only value that can
		// ever be emitted unless an operator deliberately supplies a different one.
		public const string DefaultContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'";

		// THREAT ADDRESSED - finding CFG-02 (the mandated Content-Security-Policy value was altered)
		// and CWE-1032: the emitted value must be byte-identical to the specified policy. It
		// previously appended "; report-uri /csp-violation-report" to the mandated directives, which
		// both deviated from the specified value and required an anonymous collector endpoint inside
		// the middleware. Both the directive and the collector are gone: this const now IS the
		// mandated policy, with nothing appended, prepended or interpolated.
		//
		// Retained as a public const with no setter for the reason it was made one in the first
		// place: a settable policy is a downgrade primitive - any host, plugin, or stray
		// services.Configure<SecurityHeadersOptions>() call could assign "default-src *" or append
		// 'unsafe-inline'/'unsafe-eval' and silently void the entire header, with nothing in the build
		// or at startup objecting. Immutability is therefore enforced by the compiler at every call
		// site: there is no setter, no backing field, and no instance to reconfigure. Only the
		// report-only/enforce switch below is bindable, and that switch cannot weaken the policy.
		public const string ContentSecurityPolicy = DefaultContentSecurityPolicy;

		// True - the shipping default - emits Content-Security-Policy-Report-Only; false emits the
		// enforcing Content-Security-Policy. This stays settable because it is the mandated staged
		// rollout switch, and unlike the policy text it cannot weaken the policy: it selects which of
		// the two header names carries the identical value. Flipping it to false strengthens the
		// control by turning reporting into blocking.
		//
		// THREAT ADDRESSED - finding CFG-02 (a documented rollout switch that no configuration source
		// could actually reach): this is the ONLY member bound from configuration, by
		// ErpMvcExtensions.AddErp, from the key SecurityHeaders:ContentSecurityPolicyReportOnly. The
		// binding fails safe - an absent, blank or unparseable value leaves report-only mode in force
		// - so a typo can never silently drop the platform out of the staged rollout it documents.
		public bool ContentSecurityPolicyReportOnly { get; set; } = true;
	}

	public static class SecurityHeadersMiddlewareExtensions
	{
		// Pipeline position is deliberately left to each host rather than fixed inside UseErp: the
		// headers must reach static-file and compressed responses too, so each host inserts this
		// early - ahead of UseResponseCompression and ahead of UseStaticFiles.
		public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app)
		{
			app.UseMiddleware<SecurityHeadersMiddleware>();
			return app;
		}

		// Alias of UseSecurityHeaders, published for naming consistency with the Use<X>Middleware
		// convention that AppBuilderExtensions already establishes in this folder.
		public static IApplicationBuilder UseSecurityHeadersMiddleware(this IApplicationBuilder app)
		{
			return app.UseSecurityHeaders();
		}
	}
}
