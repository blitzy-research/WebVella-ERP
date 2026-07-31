using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
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

		public SecurityHeadersMiddleware(RequestDelegate next, IOptions<SecurityHeadersOptions> options)
		{
			this.next = next;
			// Secure by default in every registration order: if the options type was never registered,
			// or resolves to null, fall back to a defaulted instance carrying the mandated values.
			this.options = options?.Value ?? new SecurityHeadersOptions();
		}

		public async Task Invoke(HttpContext context)
		{
			// Headers are attached before the response starts, because mutating them once the response
			// has begun throws InvalidOperationException. Every write below uses indexer assignment
			// rather than Add(): Add() throws ArgumentException on an already-present key, which would
			// turn this hardening change into a 500 the moment anything else set the same header.
			var headers = context.Response.Headers;

			// THREAT ADDRESSED - finding H-15, CWE-319 (cleartext transmission of sensitive
			// information) and CWE-614 (sensitive cookie without 'Secure' attribute), OWASP A02:
			// Cryptographic Failures: with no HSTS an attacker can downgrade the connection to
			// plaintext and intercept session cookies. Duplicate avoidance - the hosts separately add
			// the framework's UseHsts() - is by unconditional indexer assignment of exactly the
			// mandated value: an indexer write cannot produce a second header, and the value is
			// identical to the one the hosts configure, so an overwrite either way is a no-op.
			headers[StrictTransportSecurityHeaderName] = StrictTransportSecurityValue;

			headers[XContentTypeOptionsHeaderName] = XContentTypeOptionsValue;
			headers[XFrameOptionsHeaderName] = XFrameOptionsValue;

			// '0' is intentional and must not be "modernised" to '1; mode=block': it disables the
			// legacy browser XSS auditors, which are themselves exploitable to selectively suppress
			// legitimate script.
			headers[XXssProtectionHeaderName] = XXssProtectionValue;

			headers[ReferrerPolicyHeaderName] = ReferrerPolicyValue;
			headers[PermissionsPolicyHeaderName] = PermissionsPolicyValue;

			// The mandated policy value is emitted verbatim and is never weakened. It ships under the
			// report-only header name because four components deliberately emit inline script or
			// markup - Components/PcHtmlBlock/Display.cshtml:L10, Components/PcHtmlBlock/Design.cshtml:L10,
			// Components/Nav/Nav.Default.cshtml:L48 and, in the SDK plugin,
			// Components/WvSdkPageSitemap/Form.cshtml:L92 - so enforcing script-src 'self' on the first
			// deployment would break them and violate the functionality-preservation requirement. An
			// operator flips ContentSecurityPolicyReportOnly to false once violation reports are clean.
			var contentSecurityPolicy = options.ContentSecurityPolicy;
			if (string.IsNullOrWhiteSpace(contentSecurityPolicy))
			{
				contentSecurityPolicy = SecurityHeadersOptions.DefaultContentSecurityPolicy;
			}

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
		// The mandated Content-Security-Policy value, single-sourced so the property default and the
		// middleware's fallback can never drift apart. Never weaken it: adding 'unsafe-inline' or
		// 'unsafe-eval' would defeat the very policy this header exists to express.
		public const string DefaultContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'";

		public string ContentSecurityPolicy { get; set; } = DefaultContentSecurityPolicy;

		// True - the shipping default - emits Content-Security-Policy-Report-Only; false emits the
		// enforcing Content-Security-Policy. Only the header name changes; the value never does.
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
