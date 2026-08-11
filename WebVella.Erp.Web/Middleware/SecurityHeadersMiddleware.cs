using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace WebVella.Erp.Web.Middleware
{
	// Emits the platform's mandated security response headers, with two documented qualifications: the
	// Content-Security-Policy ships under the REPORT-ONLY header name by default (see SecurityHeadersOptions
	// below) and Strict-Transport-Security is suppressed in Development (see the constructor).
	//
	// SECURITY M-01 (OWASP A05: Security Misconfiguration): not one of the seven headers was emitted by any of the
	// seven hosts before this middleware existed, leaving the application exposed to clickjacking, MIME-type
	// sniffing, referrer leakage to third-party origins and unrestricted geolocation, microphone and camera access.
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

			// Strict-Transport-Security is the one header of the mandated seven deliberately NOT emitted in Development.
			// The guard mirrors, rather than duplicates, the one every host applies to app.UseHsts() and
			// app.UseHttpsRedirection(); without it this middleware would emit unconditionally and silently defeat that
			// host-level guard. HSTS is sticky and browser-persisted: one load over https://localhost pins the whole
			// localhost origin - shared with every other locally served project - to HTTPS for the full one-year max-age.
			// It tests the ENVIRONMENT rather than Request.IsHttps because production deployments commonly terminate TLS at
			// a reverse proxy and forward plaintext. Fail-safe direction: an unresolvable environment still emits, because
			// a spurious HSTS header is inert over plaintext (RFC 6797 section 7.2) whereas a missing one is a real gap.
			this.emitStrictTransportSecurity = environment == null
				|| !string.Equals(environment.EnvironmentName, "Development", StringComparison.OrdinalIgnoreCase);
		}

		public async Task Invoke(HttpContext context)
		{
			// CWE-693 (protection mechanism failure): there is exactly ONE path through this method and it attaches the
			// same header set every time. Do not add a branch that skips or varies that set - per-path variation is the
			// defect this middleware exists to prevent. Headers are attached before the response starts, because mutating
			// them once it has begun throws InvalidOperationException, and every write uses indexer assignment rather than
			// Add(), which throws on an already-present key and would turn this hardening change into a 500.
			AttachSecurityHeaders(context.Response.Headers, onlyWhenMissing: false);

			// SECURITY M-01 again, at the ONE response class the eager pass cannot reach: a response whose headers are
			// DISCARDED after they were written. DeveloperExceptionPageMiddleware answers an unhandled fault by calling
			// Response.Clear(), which empties the whole header dictionary, and writes its own body WITHOUT re-executing the
			// pipeline, so all seven headers were silently dropped and the Development 500 shipped bare. Re-ordering the
			// hosts' app.UseSecurityHeaders() call cannot close it: a header set by a middleware registered OUTER to the
			// developer exception page is discarded exactly as one set here is. A callback registered here survives
			// Response.Clear() because it lives on the response feature rather than in the header dictionary. Production is
			// unaffected, because UseExceptionHandler and UseStatusCodePagesWithReExecute RE-EXECUTE the downstream
			// pipeline, making this callback a no-op there. CWE-693: this pass fills GAPS only - same seven names and
			// constants, indexer assignment so it cannot duplicate, and a present name left untouched.
			context.Response.OnStarting(() =>
			{
				AttachSecurityHeaders(context.Response.Headers, onlyWhenMissing: true);
				return Task.CompletedTask;
			});

			await next(context);
		}

		// Writes the mandated header set. Called twice per request against the same response: once eagerly, before the
		// pipeline continues, and once at response start with onlyWhenMissing set, so a response whose headers were
		// cleared between those two points still carries the set. One shared implementation deliberately - two copies
		// would be two places for the values, the Development HSTS suppression or the single-CSP-name invariant to drift.
		private void AttachSecurityHeaders(IHeaderDictionary headers, bool onlyWhenMissing)
		{
			// SECURITY H-15, CWE-319 (cleartext transmission), OWASP A02: with no HSTS an attacker can downgrade the
			// connection to plaintext and intercept session cookies.
			// Indexer assignment cannot produce a second header, so this never duplicates the one the hosts add separately.
			//
			// CO-EXISTENCE WITH THE FRAMEWORK'S OWN WRITER - load-bearing, and it depends on a registration OUTSIDE this
			// file. Every host also calls app.UseHsts(), HstsMiddleware assigns the same header by indexer, and
			// UseSecurityHeaders() is ordered early, so HstsMiddleware always runs last and always wins. At
			// framework-default HstsOptions its wire value is "max-age=2592000" - thirty days, no includeSubDomains - so
			// the mandated one-year subdomain-inclusive value would never reach a response even though this middleware
			// wrote it correctly. The two writers agree only because services.AddHsts() in ErpMvcExtensions.AddErp pins
			// MaxAge to 365 days and IncludeSubDomains to true; removing it silently reinstates the thirty-day header.
			// Suppressed in Development only; see the constructor.
			if (emitStrictTransportSecurity)
			{
				SetHeader(headers, StrictTransportSecurityHeaderName, StrictTransportSecurityValue, onlyWhenMissing);
			}

			SetHeader(headers, XContentTypeOptionsHeaderName, XContentTypeOptionsValue, onlyWhenMissing);
			SetHeader(headers, XFrameOptionsHeaderName, XFrameOptionsValue, onlyWhenMissing);

			// '0' is intentional and must not be "modernised" to '1; mode=block': it disables the legacy browser
			// XSS auditors, which are themselves exploitable to selectively suppress legitimate script.
			SetHeader(headers, XXssProtectionHeaderName, XXssProtectionValue, onlyWhenMissing);

			SetHeader(headers, ReferrerPolicyHeaderName, ReferrerPolicyValue, onlyWhenMissing);
			SetHeader(headers, PermissionsPolicyHeaderName, PermissionsPolicyValue, onlyWhenMissing);

			// The mandated policy value is emitted verbatim: exactly the three mandated fetch directives, no fourth
			// directive of any kind, and no blank-value fallback needed because the const cannot be null, blank, weakened or
			// replaced. It ships under the REPORT-ONLY header name because FIVE components deliberately emit inline script
			// or markup - PcHtmlBlock Display and Design, Nav.Default, the SDK plugin's WvSdkPageSitemap Form, and
			// PcJavaScriptBlock Display - so enforcing script-src 'self' on the first deployment would break them. The
			// count was four here until the channel inventory (docs/security/risk-register.md, RISK-023 and RISK-170)
			// found PcJavaScriptBlock unnamed; it is the most load-bearing of the five, since emitting author-supplied
			// script is its entire purpose. Enforcement has since been MEASURED rather than predicted, and the breakage
			// is wider than these five: 897 enforce-disposition violations, of which 806 are style-src - because
			// per-application brand colour and per-column table geometry are computed per record and can only be emitted
			// inline - plus blocked inline handlers, a blocked blob: component chunk, and dead paging, sorting and
			// navigation. See RISK-022 for the full inventory and the staged rollout it implies. An operator flips
			// ContentSecurityPolicyReportOnly to false once that work is done; this application hosts no report
			// collector, so in report-only mode a browser logs each violation to its own console.
			const string contentSecurityPolicy = SecurityHeadersOptions.ContentSecurityPolicy;

			// Exactly one of the two policy header names is emitted, never both. In the gap-filling pass the test
			// spans BOTH names rather than only the one this configuration would write: if the response already
			// carries the other name, writing this one would put two policy headers on one response.
			if (onlyWhenMissing
				&& (headers.ContainsKey(ContentSecurityPolicyReportOnlyHeaderName)
					|| headers.ContainsKey(ContentSecurityPolicyHeaderName)))
			{
				return;
			}

			if (options.ContentSecurityPolicyReportOnly)
			{
				headers[ContentSecurityPolicyReportOnlyHeaderName] = contentSecurityPolicy;
			}
			else
			{
				headers[ContentSecurityPolicyHeaderName] = contentSecurityPolicy;
			}
		}

		// Assigns one header, yielding to a value already present when the caller is filling gaps. Indexer
		// assignment for the reason stated in Invoke.
		private static void SetHeader(IHeaderDictionary headers, string name, string value, bool onlyWhenMissing)
		{
			if (onlyWhenMissing && headers.ContainsKey(name))
			{
				return;
			}

			headers[name] = value;
		}
	}

	// Configuration for SecurityHeadersMiddleware. Deliberately a plain class with a public parameterless
	// constructor and settable properties so that services.Configure<SecurityHeadersOptions>() and
	// IOptions<SecurityHeadersOptions> can materialise it; a positional record could not.
	public class SecurityHeadersOptions
	{
		// The mandated Content-Security-Policy fetch directives, verbatim and single-sourced. There is no
		// override path and no fallback: this value IS the emitted policy - see the const below.
		public const string DefaultContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'";

		// CWE-1032: the emitted value must be byte-identical to the mandated policy, so nothing is appended, prepended
		// or interpolated - in particular no report-uri, which would also require an anonymous collector endpoint. A
		// public const with no setter, and that IS the control: a settable policy is a downgrade primitive, because any
		// host, plugin or stray services.Configure<SecurityHeadersOptions>() could assign "default-src *" or append
		// 'unsafe-inline' and silently void the whole header. Immutability is enforced by the compiler.
		public const string ContentSecurityPolicy = DefaultContentSecurityPolicy;

		// True - the shipping default - emits Content-Security-Policy-Report-Only; false emits the enforcing header.
		// This stays settable because it is the mandated staged-rollout switch and it cannot weaken the policy: it
		// selects which of two header names carries the identical value. It is the ONLY member bound from configuration
		// (ErpMvcExtensions.AddErp, key SecurityHeaders:ContentSecurityPolicyReportOnly): an absent or blank value
		// leaves report-only in force, while a PRESENT but unparseable value ABORTS startup rather than being guessed.
		public bool ContentSecurityPolicyReportOnly { get; set; } = true;
	}

	public static class SecurityHeadersMiddlewareExtensions
	{
		// Pipeline position is deliberately left to each host rather than fixed inside UseErp, which runs far too late:
		// UseStaticFiles TERMINATES the pipeline for a matched asset, so anything registered after it never runs for a
		// static-file response and those responses would ship bare. Each host inserts this ahead of both calls.
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
