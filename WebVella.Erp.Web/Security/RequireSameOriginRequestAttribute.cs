using System;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Net.Http.Headers;
using WebVella.Erp.Api.Models;

namespace WebVella.Erp.Web.Security
{
	/// <summary>
	/// Refuses a state-changing request that a browser reports as having been initiated by another site, when
	/// that request is authenticated by an AMBIENT credential the browser attached on its own.
	/// </summary>
	/// <remarks>
	/// SECURITY - review finding M-OPEN-02, CWE-352 cross-site request forgery, OWASP A01:2021 Broken Access
	/// Control.
	/// THREAT ADDRESSED: every mutating action on the API surface is authorised by the authentication cookie
	/// alone. A browser attaches that cookie to a request another site caused, so any page anywhere could
	/// drive a POST, PUT or DELETE against this application as whoever was signed in - creating, changing or
	/// deleting records, moving files, sending mail - and the response body did not even need to be readable
	/// for the change to have happened. The cookie's SameSite=Lax value does NOT close this: Lax is a
	/// registrable-domain test, so a sibling origin - another subdomain, or any host that can set a cookie on
	/// the parent domain - is "same-site" and its requests carry the cookie in full.
	/// <para>
	/// WHY NOT ANTIFORGERY TOKENS, which is the textbook answer and is NOT used here: the platform's own
	/// JavaScript posts to this surface without a verification token, so enabling automatic validation would
	/// refuse every existing client. The Agent Action Plan records that decision explicitly - section 0.3.2,
	/// "Enforcing antiforgery validation on the MVC API surface ... existing JavaScript clients post without a
	/// verification token, so enforcement would break working functionality" - and the AAP is the authority
	/// here. This control was chosen because it needs NO client change at all: the signal it reads is supplied
	/// by the browser, cannot be forged by the calling page, and is already present on every request current
	/// browsers make. The residual - that a token would also defend a browser too old to send the signal - is
	/// recorded in docs/security/risk-register.md rather than silently dropped.
	/// </para>
	/// <para>
	/// THE THREE EXEMPTIONS ARE EACH LOAD-BEARING, and narrowing any of them would break working callers:
	/// </para>
	/// <para>
	/// (1) SAFE METHODS PASS. GET, HEAD, OPTIONS and TRACE change no state, and OPTIONS in particular is the
	/// cross-origin preflight this application answers deliberately for its allow-listed origins.
	/// </para>
	/// <para>
	/// (2) A REQUEST CARRYING ITS OWN BEARER CREDENTIAL PASSES. A browser never attaches an Authorization
	/// header of its own accord, so a request that presents one was composed deliberately by its caller and is
	/// not the confused-deputy shape this control exists to stop. The test is the presence of the header rather
	/// than the resulting identity's authentication type, deliberately: the token pipeline can also
	/// re-authenticate a COOKIE ticket that carries a stored token, so the identity type would classify an
	/// ambient credential as a deliberate one - the exact inversion that would disable this control.
	/// </para>
	/// <para>
	/// (3) AN UNAUTHENTICATED REQUEST PASSES. There is no ambient credential to abuse, and the anonymous token
	/// endpoints are legitimately called cross-origin by the WebAssembly client, whose sign-in would otherwise
	/// fail. Cross-site protection for those endpoints is the cross-origin policy's job and the rate limiter's,
	/// not this one's.
	/// </para>
	/// <para>
	/// AN ABSENT SIGNAL IS ALLOWED, which is the one place this control is deliberately permissive. Fetch
	/// Metadata is sent by every current browser, so absence means either a browser old enough not to
	/// implement it or a client that is not a browser at all - and those two cannot be told apart from the
	/// server. Refusing on absence would therefore break non-browser cookie clients to protect a browser
	/// generation that is already unsupported, which the preservation requirement does not permit. That is
	/// also why this is defence in depth and not a replacement for a token.
	/// </para>
	/// <para>
	/// APPLIED AT <see cref="Controllers.ApiControllerBase"/> rather than globally, because a global filter
	/// would also govern Razor Pages, whose own forms already carry antiforgery tokens - adding a second,
	/// differently-shaped refusal there would be change without benefit. The attribute is inherited, so every
	/// action of every derived controller is covered and no action can be forgotten.
	/// </para>
	/// </remarks>
	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, Inherited = true, AllowMultiple = false)]
	public sealed class RequireSameOriginRequestAttribute : Attribute, IAuthorizationFilter
	{
		/// <summary>
		/// The refusal returned to a request this control declines. It names no origin and echoes no header
		/// value, matching every other refusal on this surface: the body is rendered as JSON and read by
		/// scripts, so echoing caller-supplied text would turn the refusal into the injection.
		/// </summary>
		private const string RefusalMessage = "This request was not accepted because it was initiated by another site.";

		/// <summary>
		/// Value of <c>Sec-Fetch-Site</c> for a request the browser made from a page of this same origin.
		/// </summary>
		private const string SameOriginSite = "same-origin";

		/// <summary>
		/// Value of <c>Sec-Fetch-Site</c> for a request no page caused - a typed address, a bookmark or a
		/// browser-internal navigation. An attacking page cannot produce it.
		/// </summary>
		private const string UserInitiatedSite = "none";

		/// <summary>
		/// Value of <c>Sec-Fetch-Mode</c> for a top-level navigation, which is what following a link is.
		/// </summary>
		private const string NavigateMode = "navigate";

		/// <summary>
		/// The <c>Bearer</c> scheme prefix, matched ordinal-ignore-case because RFC 7230 section 3.2.6 makes
		/// the scheme token case-insensitive. Spelled the same way as
		/// <c>Middleware/JwtMiddleware.BearerSchemePrefix</c> so the two agree on what a bearer request is.
		/// </summary>
		private const string BearerSchemePrefix = "Bearer ";

		/// <summary>
		/// Evaluates the policy before the action runs, and short-circuits the request when it is refused.
		/// </summary>
		/// <remarks>
		/// Review finding M-OPEN-02. An authorization filter rather than an action filter, so the refusal
		/// happens before model binding reads the request body: a rejected cross-site upload should cost nothing
		/// to reject. It runs after the authorization middleware, so the identity is already resolved.
		/// </remarks>
		/// <param name="context">The filter context.</param>
		public void OnAuthorization(AuthorizationFilterContext context)
		{
			if (context == null || IsAllowed(context.HttpContext))
			{
				return;
			}

			//The platform's own response envelope, so a refused caller parses this exactly as it parses every
			//other refusal from this surface and no client needs a new branch to understand it.
			var response = new BaseResponseModel
			{
				Timestamp = DateTime.UtcNow,
				Success = false,
				Message = RefusalMessage,
				StatusCode = HttpStatusCode.Forbidden
			};

			context.Result = new JsonResult(response) { StatusCode = (int)HttpStatusCode.Forbidden };
		}

		/// <summary>
		/// Reports whether a request may proceed under this policy.
		/// </summary>
		/// <remarks>
		/// Review finding M-OPEN-02. See the type-level remarks for why each exemption exists. Ordered cheapest
		/// test first, and every branch returns rather than falling through, so the decision for any one request
		/// is readable in isolation.
		/// </remarks>
		/// <param name="httpContext">The request being evaluated.</param>
		/// <returns><c>true</c> when the request is not the cross-site ambient-credential shape.</returns>
		private static bool IsAllowed(HttpContext httpContext)
		{
			if (httpContext == null)
			{
				return true;
			}

			if (!IsStateChangingMethod(httpContext.Request.Method))
			{
				return true;
			}

			if (CarriesBearerCredential(httpContext.Request))
			{
				return true;
			}

			if (httpContext.User?.Identity == null || !httpContext.User.Identity.IsAuthenticated)
			{
				return true;
			}

			return !IsBrowserReportedCrossSite(httpContext.Request);
		}

		/// <summary>
		/// Reports whether a method may change server state.
		/// </summary>
		/// <remarks>
		/// Review finding M-OPEN-02. An ALLOW-LIST of the four methods defined to be safe, so a method nobody
		/// anticipated - or one this API adds later through its AcceptVerbs routes - is treated as changing state
		/// rather than as harmless. A deny-list would have to be extended every time, and forgetting is silent.
		/// </remarks>
		/// <param name="method">The request method.</param>
		/// <returns><c>true</c> when the method is not one of the four safe methods.</returns>
		private static bool IsStateChangingMethod(string method)
		{
			return !HttpMethods.IsGet(method)
				&& !HttpMethods.IsHead(method)
				&& !HttpMethods.IsOptions(method)
				&& !HttpMethods.IsTrace(method);
		}

		/// <summary>
		/// Reports whether the request presents a bearer credential of its own.
		/// </summary>
		/// <remarks>
		/// Review finding M-OPEN-02; see exemption (2) in the type-level remarks for why this is the test.
		/// </remarks>
		/// <param name="request">The request being evaluated.</param>
		/// <returns><c>true</c> when an <c>Authorization: Bearer</c> header is present.</returns>
		private static bool CarriesBearerCredential(HttpRequest request)
		{
			string authorizationHeader = request.Headers[HeaderNames.Authorization];
			return authorizationHeader != null
				&& authorizationHeader.StartsWith(BearerSchemePrefix, StringComparison.OrdinalIgnoreCase);
		}

		/// <summary>
		/// Reports whether the browser itself says this request came from a different site.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding M-OPEN-02, CWE-352. <c>Sec-Fetch-Site</c> is set by the browser and is
		/// forbidden to scripts, so a page cannot lie about it. Only <c>same-origin</c> and <c>none</c> are
		/// treated as this site's own: <c>same-site</c> is deliberately NOT, because a sibling origin being
		/// trusted is precisely the gap SameSite=Lax leaves and this control exists to cover.
		/// <para>
		/// SHARED WITH THE SIGN-OUT HANDLER, which is why this is internal rather than private: sign-out mutates
		/// on a GET that must keep working when a user clicks a link, so it needs the same judgement about who
		/// initiated the request, and two copies of it would eventually disagree.
		/// </para>
		/// </remarks>
		/// <param name="request">The request being evaluated.</param>
		/// <returns>
		/// <c>true</c> only when the browser reported an initiator that is not this origin. An absent header
		/// returns <c>false</c> - see the type-level remarks on why absence is allowed.
		/// </returns>
		internal static bool IsBrowserReportedCrossSite(HttpRequest request)
		{
			string site = request.Headers["Sec-Fetch-Site"];
			if (string.IsNullOrEmpty(site))
			{
				return false;
			}

			return !string.Equals(site, SameOriginSite, StringComparison.OrdinalIgnoreCase)
				&& !string.Equals(site, UserInitiatedSite, StringComparison.OrdinalIgnoreCase);
		}

		/// <summary>
		/// Reports whether a request is a top-level navigation, which is what following a link or submitting a
		/// form is - as opposed to a subresource load such as an image, a script or a background fetch.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding M-OPEN-02, CWE-352. Used by the sign-out handler, which must act when a
		/// user clicks the Logout link and must NOT act when a page merely references that address as an image
		/// or fetches it in the background. An absent header is treated as a navigation, for the same
		/// compatibility reason an absent <c>Sec-Fetch-Site</c> is allowed.
		/// </remarks>
		/// <param name="request">The request being evaluated.</param>
		/// <returns><c>true</c> when the request is, or cannot be distinguished from, a navigation.</returns>
		internal static bool IsNavigation(HttpRequest request)
		{
			string mode = request.Headers["Sec-Fetch-Mode"];
			return string.IsNullOrEmpty(mode)
				|| string.Equals(mode, NavigateMode, StringComparison.OrdinalIgnoreCase);
		}
	}
}
