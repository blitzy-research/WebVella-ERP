using Microsoft.AspNetCore.Mvc;
using System;
using System.Net;
using WebVella.Erp.Api.Models;
using Microsoft.AspNetCore.Authorization;
using WebVella.Erp.Web.Security;

namespace WebVella.Erp.Web.Controllers
{
	// THREAT ADDRESSED - review finding M-OPEN-02, CWE-352 cross-site request forgery, OWASP A01:2021.
	// Every mutating action reachable through this controller and its derivatives is authorised by the
	// authentication cookie alone, and a browser attaches that cookie to a request another site caused - so
	// any page anywhere could drive a POST, PUT or DELETE as whoever was signed in. SameSite=Lax does not
	// close it, because Lax is a registrable-domain test and a sibling origin is therefore "same-site".
	// PLACED ON THE BASE CLASS, once, rather than on each action: the attribute is inherited, so no action
	// on any derived controller can be forgotten, and no existing route, verb or response envelope changes.
	// It is NOT registered globally, because Razor Pages forms already carry antiforgery tokens and a second
	// differently-shaped refusal there would be change without benefit.
	// Antiforgery tokens are deliberately NOT the mechanism; see the attribute's own remarks and the Agent
	// Action Plan section 0.3.2, which records that enforcing them here would refuse every existing client.
	[RequireSameOriginRequest]
	[Authorize]
	public class ApiControllerBase : Controller
	{
		public ApiControllerBase()
		{
		}

		public IActionResult DoResponse( BaseResponseModel response )
		{
			if (response.Errors.Count > 0 || !response.Success)
			{
				if( response.StatusCode == HttpStatusCode.OK )
					HttpContext.Response.StatusCode = (int)HttpStatusCode.BadRequest;
				else
					HttpContext.Response.StatusCode = (int)response.StatusCode;
			}

			return Json(response);
			//JsonSerializerSettings settings = new JsonSerializerSettings { DateTimeZoneHandling = DateTimeZoneHandling.Utc };
			//return Json(response, settings);

		}

		public IActionResult DoPageNotFoundResponse()
		{
			HttpContext.Response.StatusCode = (int)HttpStatusCode.NotFound;
			return Json(new { });
		}

		public IActionResult DoItemNotFoundResponse(BaseResponseModel response)
		{
			HttpContext.Response.StatusCode = (int)HttpStatusCode.NotFound;
			return Json(response);
		}

		public IActionResult DoBadRequestResponse(BaseResponseModel response, string message = null, Exception ex = null)
		{
			response.Timestamp = DateTime.UtcNow;
			response.Success = false;

			if (ErpSettings.DevelopmentMode)
			{
				if (ex != null)
					response.Message = ex.Message + ex.StackTrace;
			}
			else
			{
				if (string.IsNullOrEmpty(message))
					response.Message = "An internal error occurred!";
			}

			HttpContext.Response.StatusCode = (int)HttpStatusCode.BadRequest;
			return Json(response);
		}
	}
}
