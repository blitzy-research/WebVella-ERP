using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
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

		// Upper bound on the violation-report body this middleware will read into memory.
		//
		// THREAT ADDRESSED - CWE-400 (uncontrolled resource consumption): the report endpoint is
		// necessarily anonymous, because browsers post Content-Security-Policy reports without
		// credentials. An unauthenticated endpoint that read an unbounded body would let anyone
		// exhaust server memory with a single large POST. 8 KB is far above the size of any real
		// report - a violation report is a small, flat JSON object - so bounding here costs nothing
		// in fidelity. Bytes beyond the cap are simply never read.
		private const int MaxViolationReportBytes = 8 * 1024;

		// Ceiling on how many violation reports are written to the log per minute.
		//
		// THREAT ADDRESSED - CWE-779 (logging of excessive data) / log flooding: the report collector
		// is handled at the very front of the pipeline so that headers reach every response, which
		// necessarily places it ahead of the rate limiter. It is therefore the one dynamic path the
		// per-address window does not cover, and without a ceiling an anonymous caller could drive
		// unbounded log growth - the log-flooding half of the same denial-of-service concern the body
		// cap addresses. Reports past the ceiling are still answered 204 and their body is never even
		// read, so the flood path costs almost nothing. The ceiling is generous relative to real
		// traffic: an unusually violation-heavy page produces on the order of thirty reports, so a
		// hundred and twenty per minute preserves genuine reporting fidelity while bounding the worst
		// case. Throttling by refusing the request was rejected: dropping reports the browser cannot
		// resend would corrupt the very evidence the report-then-enforce rollout depends on, so the
		// bound is applied to logging rather than to acceptance.
		private const int MaxLoggedReportsPerMinute = 120;

		private static long reportWindowStartTicks;
		private static int reportsLoggedInWindow;

		// Pre-compiled logging delegates. Built once at type initialisation rather than formatted per
		// call, so that a burst of violation reports on this anonymous endpoint cannot be amplified
		// into per-request boxing and string formatting work - the same resource-consumption concern
		// that bounds the report body above.
		private static readonly Action<ILogger, string, string, Exception> LogViolationReport =
			LoggerMessage.Define<string, string>(
				LogLevel.Warning,
				new EventId(1, nameof(LogViolationReport)),
				"Content-Security-Policy violation reported for origin '{RequestOrigin}': {ViolationReport}");

		private static readonly Action<ILogger, Exception> LogEmptyViolationReport =
			LoggerMessage.Define(
				LogLevel.Warning,
				new EventId(2, nameof(LogEmptyViolationReport)),
				"Content-Security-Policy violation reported with an empty body.");

		private readonly RequestDelegate next;
		private readonly SecurityHeadersOptions options;
		private readonly ILogger<SecurityHeadersMiddleware> logger;
		private readonly bool emitStrictTransportSecurity;

		public SecurityHeadersMiddleware(RequestDelegate next, IOptions<SecurityHeadersOptions> options, ILogger<SecurityHeadersMiddleware> logger, IWebHostEnvironment environment)
		{
			this.next = next;
			// Secure by default in every registration order: if the options type was never registered,
			// or resolves to null, fall back to a defaulted instance carrying the mandated values.
			this.options = options?.Value ?? new SecurityHeadersOptions();
			this.logger = logger;

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
			// THREAT ADDRESSED - finding L-01: the policy previously shipped in report-only mode with
			// no destination for the reports, so violations were computed by the browser and then
			// discarded. That made the mandated report-then-enforce rollout impossible to justify:
			// there was no evidence on which an operator could decide the policy was safe to enforce.
			// The collector is handled here, inside the middleware, rather than as a controller action
			// so that a single registration reaches all seven hosts and so that it sits ahead of
			// routing and authentication - a browser-generated report carries no credentials and must
			// not be redirected to the login page.
			if (string.Equals(context.Request.Path.Value, SecurityHeadersOptions.ContentSecurityPolicyReportPath, StringComparison.OrdinalIgnoreCase))
			{
				await HandleViolationReportAsync(context);
				return;
			}

			// Headers are attached before the response starts, because mutating them once the response
			// has begun throws InvalidOperationException. Every write below uses indexer assignment
			// rather than Add(): Add() throws ArgumentException on an already-present key, which would
			// turn this hardening change into a 500 the moment anything else set the same header.
			var headers = context.Response.Headers;

			// THREAT ADDRESSED - finding H-15, CWE-319 (cleartext transmission of sensitive
			// information) and CWE-614 (sensitive cookie without 'Secure' attribute), OWASP A02:
			// Cryptographic Failures: with no HSTS an attacker can downgrade the connection to
			// plaintext and intercept session cookies. Duplicate avoidance - the hosts separately add
			// the framework's UseHsts() - is by indexer assignment of exactly the mandated value: an
			// indexer write cannot produce a second header, and the value is identical to the one the
			// hosts configure, so an overwrite in either direction is a no-op.
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

			// The mandated policy value is emitted verbatim and is never weakened. It ships under the
			// report-only header name because four components deliberately emit inline script or
			// markup - Components/PcHtmlBlock/Display.cshtml:L10, Components/PcHtmlBlock/Design.cshtml:L10,
			// Components/Nav/Nav.Default.cshtml:L48 and, in the SDK plugin,
			// Components/WvSdkPageSitemap/Form.cshtml:L92 - so enforcing script-src 'self' on the first
			// deployment would break them and violate the functionality-preservation requirement. An
			// operator flips ContentSecurityPolicyReportOnly to false once violation reports are clean.
			// No blank-value fallback is needed or present: ContentSecurityPolicy is a compile-time
			// constant, so it cannot be null, blank or replaced. That is the finding L-01 fix - see
			// SecurityHeadersOptions below.
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

		// Collects a single Content-Security-Policy violation report and records it server-side.
		//
		// The response is always terminal: this method never calls next(), so a report POST cannot
		// reach routing, authentication, or any application endpoint. It returns 204 No Content on
		// success because the reporting specification expects no response body, and browsers ignore
		// whatever is returned.
		private async Task HandleViolationReportAsync(HttpContext context)
		{
			// Deny-by-default on method: only POST carries a report. Anything else is either a probe
			// or a mistake, and must not be treated as a report.
			if (!HttpMethods.IsPost(context.Request.Method))
			{
				context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
				context.Response.Headers["Allow"] = "POST";
				return;
			}

			// Checked before the body is read, so that a flood costs neither the 8 KB copy nor a log
			// write. The report is still acknowledged, because a browser cannot resend it.
			if (!ShouldLogReport())
			{
				context.Response.StatusCode = StatusCodes.Status204NoContent;
				return;
			}

			string report = await ReadBoundedBodyAsync(context.Request.Body);

			// Logged through the framework logger rather than the platform's database LogService on
			// purpose. THREAT ADDRESSED - CWE-400 amplification: LogService writes a row per entry and
			// e-mails exception detail off-box, so routing an anonymous, attacker-triggerable endpoint
			// into it would turn a browser report into an unauthenticated database-growth and
			// mail-flooding primitive. The framework logger has neither side effect and needs no
			// schema change.
			if (logger != null)
			{
				if (report.Length > 0)
				{
					LogViolationReport(logger, Describe(context.Request.Headers.Origin.ToString()), report, null);
				}
				else
				{
					LogEmptyViolationReport(logger, null);
				}
			}

			context.Response.StatusCode = StatusCodes.Status204NoContent;
		}

		// Advances the per-minute logging window and reports whether this violation report is within
		// the ceiling. Lock-free: the middleware is on the hot path of every request, so this must not
		// introduce contention. Only the thread that wins the window exchange resets the counter,
		// which keeps a window roll from being applied twice under concurrency.
		private static bool ShouldLogReport()
		{
			long now = DateTime.UtcNow.Ticks;
			long windowStart = Interlocked.Read(ref reportWindowStartTicks);

			if (now - windowStart > TimeSpan.TicksPerMinute)
			{
				if (Interlocked.CompareExchange(ref reportWindowStartTicks, now, windowStart) == windowStart)
				{
					Interlocked.Exchange(ref reportsLoggedInWindow, 0);
				}
			}

			return Interlocked.Increment(ref reportsLoggedInWindow) <= MaxLoggedReportsPerMinute;
		}

		// Reads at most MaxViolationReportBytes from the request body and returns it sanitised for
		// logging. Bytes past the cap are never read, so an oversized POST is truncated rather than
		// buffered.
		private static async Task<string> ReadBoundedBodyAsync(Stream body)
		{
			byte[] buffer = new byte[MaxViolationReportBytes];
			int total = 0;

			while (total < buffer.Length)
			{
				int read = await body.ReadAsync(buffer.AsMemory(total, buffer.Length - total));
				if (read == 0)
				{
					break;
				}

				total += read;
			}

			return Describe(Encoding.UTF8.GetString(buffer, 0, total));
		}

		// Renders untrusted text safe to write into a log line.
		//
		// THREAT ADDRESSED - CWE-117 (improper output neutralisation for logs): the report body and
		// the Origin header are both attacker-controlled, so a raw write would let a crafted report
		// inject carriage returns and forge additional log entries, or emit terminal escape sequences
		// that alter the display of anyone tailing the log. Every character outside printable ASCII -
		// which includes CR, LF, tab and the escape character - is replaced by a \uXXXX escape. The
		// escape digits use the invariant culture because this is a wire format that must not vary
		// with the server's locale.
		private static string Describe(string value)
		{
			if (string.IsNullOrEmpty(value))
			{
				return string.Empty;
			}

			var builder = new StringBuilder(value.Length);
			foreach (char candidate in value)
			{
				if (candidate >= ' ' && candidate <= '~')
				{
					builder.Append(candidate);
				}
				else
				{
					builder.Append("\\u").Append(((int)candidate).ToString("x4", System.Globalization.CultureInfo.InvariantCulture));
				}
			}

			return builder.ToString();
		}
	}

	// Configuration for SecurityHeadersMiddleware, carrying the Content-Security-Policy value and its
	// report-only switch. Deliberately a plain class with a public parameterless constructor and
	// settable properties so that services.Configure<SecurityHeadersOptions>() and
	// IOptions<SecurityHeadersOptions> can materialise it; a positional record could not.
	public class SecurityHeadersOptions
	{
		// The mandated Content-Security-Policy fetch directives, verbatim and single-sourced.
		public const string DefaultContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'";

		// Path the browser posts violation reports to. Deliberately a compile-time constant: a
		// settable path would be a redirect primitive, letting a misconfiguration send every
		// violation report - which names the blocked URL and the offending page - to a foreign host.
		public const string ContentSecurityPolicyReportPath = "/csp-violation-report";

		// THREAT ADDRESSED - finding L-01 (CWE-1032, incomplete design documentation of a security
		// control; and the substantive weakness behind it): this was previously
		// `public string ContentSecurityPolicy { get; set; }`. A public setter on a security policy is
		// a downgrade primitive - any host, plugin, or a stray
		// services.Configure<SecurityHeadersOptions>() call could assign "default-src *" or append
		// 'unsafe-inline'/'unsafe-eval' and silently void the entire header, with nothing in the build
		// or at startup objecting. It is now get-only and computed from constants, so the mandated
		// directives are not merely the default - they are the only reachable value.
		//
		// The mandated directives are emitted verbatim as the leading fragment. The one addition is
		// the report-uri directive, which is a *reporting* directive: it adds no source to any fetch
		// directive and therefore cannot loosen the policy in any way. It is required rather than
		// optional, because a report-only policy with no destination discards every violation and
		// leaves no evidence on which the report-then-enforce transition could ever be justified.
		// report-uri is used in preference to the newer report-to because report-to additionally
		// requires a Reporting-Endpoints response header, and the mandated header set is exactly
		// seven headers; report-uri is honoured by every current browser and needs no eighth header.
		//
		// Declared const rather than as a computed property so the immutability is enforced by the
		// compiler at every call site and the value is baked into the assembly: there is no setter, no
		// backing field, and no instance to reconfigure.
		public const string ContentSecurityPolicy = DefaultContentSecurityPolicy + "; report-uri " + ContentSecurityPolicyReportPath;

		// True - the shipping default - emits Content-Security-Policy-Report-Only; false emits the
		// enforcing Content-Security-Policy. This stays settable because it is the mandated staged
		// rollout switch, and unlike the policy text it cannot weaken the policy: it selects which of
		// the two header names carries the identical value. Flipping it to false strengthens the
		// control by turning reporting into blocking.
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
