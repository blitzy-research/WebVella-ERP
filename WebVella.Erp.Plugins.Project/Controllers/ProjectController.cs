using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Database;
using WebVella.Erp.Diagnostics;
using WebVella.Erp.Eql;
using WebVella.Erp.Plugins.Project.Services;
using WebVella.Erp.Web.Services;

namespace WebVella.Erp.Plugins.Project.Controllers
{
	[Authorize]
	public class ProjectController : Controller
	{
		private const char RELATION_SEPARATOR = '.';
		private const char RELATION_NAME_RESULT_SEPARATOR = '$';

		// THREAT ADDRESSED - review finding F27 (Anonymous Surface), CWE-20 improper input validation,
		// CWE-117 improper output neutralization for logs, CWE-779 logging of excessive data, OWASP
		// A01:2021 Broken Access Control and A09:2021 Security Logging and Monitoring Failures.
		// TimeTrackJs at the foot of this file is the only [AllowAnonymous] action in this plugin. It
		// served whatever resource name an unauthenticated caller asked for, relying on the embedded-
		// resource prefix to prevent filesystem traversal. The prefix does prevent traversal, but three
		// things still reached attacker control: the resource lookup itself, the LOG SOURCE - the
		// caller's own string was concatenated into it - and the exception path, which re-threw. Together
		// those gave an unauthenticated caller a way to write an unbounded number of log records carrying
		// text of their choosing: log injection, log-volume denial of service, and, because the platform
		// mails notification-eligible records, outbound e-mail amplification.
		// Exactly TWO embedded resources are legitimate. That is established three independent ways: both
		// files exist under Files/, both are declared as <EmbeddedResource> in this project's csproj, and
		// both are the only names the shipped page markup requests (ProjectPlugin.20190203.cs). An exact
		// allow-list is therefore complete rather than a guess, which is what the mandated Injection
		// Prevention standard's allowlist-validation clause asks for. Anything else is refused before it
		// can reach the lookup, the log or the exception path.
		// A MAP rather than a set, and that is the point: the key is what a caller may ask for and the
		// value is the exact resource name this action will look up. Comparison is case-insensitive so a
		// legitimate request with different casing still works, but the CANONICAL value is what reaches
		// GetEmbeddedTextResource - never the caller's own string. Without that canonicalisation a
		// case variant would pass the allow-list, fail the exact resource lookup, and write a log record;
		// mapping to the canonical name removes that path entirely rather than merely bounding it.
		private static readonly Dictionary<string, string> AllowedJavaScriptResources = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
		{
			{ "task-details.js", "task-details.js" },
			{ "timetrack.js", "timetrack.js" }
		};

		// One latch per CANONICAL resource name, so a genuine packaging fault is recorded once per process
		// rather than once per request. The key space is the value set of the map above - at most two
		// entries, ever, and no caller-supplied string among them - which is what makes a cache keyed off
		// a request path safe to drive from an anonymous endpoint. Concurrent because the endpoint is
		// served on the thread pool and two simultaneous first-faults must still yield one record.
		private static readonly ConcurrentDictionary<string, byte> ReportedJavaScriptResourceFaults = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);

		RecordManager recMan;
		EntityManager entMan;
		EntityRelationManager relMan;
		SecurityManager secMan;
		IErpService erpService;

		public ProjectController(IErpService erpService)
		{
			recMan = new RecordManager();
			secMan = new SecurityManager();
			entMan = new EntityManager();
			relMan = new EntityRelationManager();
			this.erpService = erpService;
		}

        public Guid? CurrentUserId
        {
            get
            {
                if (HttpContext != null && HttpContext.User != null && HttpContext.User.Claims != null)
                {
                    var nameIdentifier = HttpContext.User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);
                    if (nameIdentifier is null)
                        return null;

                    return new Guid(nameIdentifier.Value);
                }
                return null;
            }
        }

        #region << Components >>
        [Route("api/v3.0/p/project/pc-post-list/create")]
		[HttpPost]
		public ActionResult CreateNewPcPostListItem([FromBody]EntityRecord record)
		{
			var response = new ResponseModel();
			#region << Init >>
			var recordId = Guid.NewGuid();

			Guid relatedRecordId = Guid.Empty;
			if (!record.Properties.ContainsKey("relatedRecordId") || record["relatedRecordId"] == null)
			{
				throw new Exception("relatedRecordId is required");
			}
			if (Guid.TryParse((string)record["relatedRecordId"], out Guid outGuid))
			{
				relatedRecordId = outGuid;
			}
			else
			{
				throw new Exception("relatedRecordId is invalid Guid");
			}

			Guid? parentId = null;
			if (record.Properties.ContainsKey("parentId") && record["parentId"] != null)
			{
				if (Guid.TryParse((string)record["parentId"], out Guid outGuid2))
				{
					parentId = outGuid2;
				}
			}

			var scope = new List<string>() { "projects" };

			var relatedRecords = new List<Guid>();
			if (record.Properties.ContainsKey("relatedRecords") && record["relatedRecords"] != null)
			{
				relatedRecords = JsonConvert.DeserializeObject<List<Guid>>((string)record["relatedRecords"]);
			}

			var subject = "";
			if (record.Properties.ContainsKey("subject") && record["subject"] != null)
			{
				subject = (string)record["subject"];
			}

			var body = "";
			if (record.Properties.ContainsKey("body") && record["body"] != null)
			{
				body = (string)record["body"];
			}

			Guid currentUserId = SystemIds.FirstUserId; //This is for web component development to allow guest submission
			if (SecurityContext.CurrentUser != null)
				currentUserId = SecurityContext.CurrentUser.Id;

			#endregion

			try
			{
				new CommentService().Create(recordId, currentUserId, DateTime.Now, body, parentId, scope, relatedRecords);
			}
			catch (Exception)
			{
				throw;
			}

			response.Success = true;
			response.Message = "Comment successfully created";

			var eqlCommand = @"SELECT *,$user_1n_comment.image,$user_1n_comment.username
					FROM comment
					WHERE id = @recordId";
			var eqlParams = new List<EqlParameter>() {
						new EqlParameter("recordId",recordId)
					};
			var eqlResult = new EqlCommand(eqlCommand, eqlParams).Execute();

			if (eqlResult.Any())
			{
				response.Object = eqlResult.First();
			}


			return Json(response);
		}

		[Route("api/v3.0/p/project/pc-post-list/delete")]
		[HttpPost]
		public ActionResult DeletePcPostListItem([FromBody]EntityRecord record)
		{
			var response = new ResponseModel();
			#region << Init >>
			Guid recordId = Guid.Empty;
			if (!record.Properties.ContainsKey("id") || record["id"] == null)
			{
				throw new Exception("id is required");
			}
			if (Guid.TryParse((string)record["id"], out Guid outGuid))
			{
				recordId = outGuid;
			}
			else
			{
				throw new Exception("id is invalid Guid");
			}

			#endregion
			try
			{
				new CommentService().Delete(recordId);
			}
			catch (Exception)
			{
				throw;
			}
			response.Success = true;
			response.Message = "Comment successfully deleted";

			return Json(response);
		}

		[Route("api/v3.0/p/project/pc-timelog-list/create")]
		[HttpPost]
		public ActionResult CreateTimelog([FromBody]EntityRecord record)
		{
			var response = new ResponseModel();
			#region << Init >>
			var recordId = Guid.NewGuid();


			var scope = new List<string>() { "projects" };

			var relatedRecords = new List<Guid>();
			if (record.Properties.ContainsKey("relatedRecords") && record["relatedRecords"] != null)
			{
				relatedRecords = JsonConvert.DeserializeObject<List<Guid>>((string)record["relatedRecords"]);
			}

			var body = "";
			if (record.Properties.ContainsKey("body") && record["body"] != null)
			{
				body = (string)record["body"];
			}

			Guid currentUserId = SystemIds.FirstUserId; //This is for web component development to allow guest submission
			if (SecurityContext.CurrentUser != null)
				currentUserId = SecurityContext.CurrentUser.Id;


			var minutes = 0;
			if (record.Properties.ContainsKey("minutes") && record["minutes"] != null)
			{
				if (Int32.TryParse(record["minutes"].ToString(), out Int32 outInt32))
				{
					minutes = outInt32;
				}
			}

			var isBillable = false;
			if (record.Properties.ContainsKey("isBillable") && record["isBillable"] != null)
			{
				if (Boolean.TryParse(record["isBillable"].ToString(), out bool outBool))
				{
					isBillable = outBool;
				}
			}

			var loggedOn = new DateTime();
			if (record.Properties.ContainsKey("loggedOn") && record["loggedOn"] != null)
			{
				loggedOn = (DateTime)record["loggedOn"];
			}

			#endregion

			try
			{
				new TimeLogService().Create(recordId, currentUserId, DateTime.Now, loggedOn, minutes, isBillable, body, scope, relatedRecords);
			}
			catch (Exception)
			{
				throw;
			}

			response.Success = true;
			response.Message = "Timelog successfully created";

			var eqlCommand = @"SELECT *,$user_1n_timelog.image,$user_1n_timelog.username
								FROM timelog
								WHERE id = @recordId";
			var eqlParams = new List<EqlParameter>() { new EqlParameter("recordId", recordId) };
			var eqlResult = new EqlCommand(eqlCommand, eqlParams).Execute();

			if (eqlResult.Any())
			{
				response.Object = eqlResult.First();
			}

			return Json(response);
		}

		[Route("api/v3.0/p/project/pc-timelog-list/delete")]
		[HttpPost]
		public ActionResult DeleteTimelog([FromBody]EntityRecord record)
		{
			var response = new ResponseModel();
			#region << Init >>

			Guid recordId = Guid.Empty;
			if (!record.Properties.ContainsKey("id") || record["id"] == null)
			{
				throw new Exception("id is required");
			}
			if (Guid.TryParse((string)record["id"], out Guid outGuid))
			{
				recordId = outGuid;
			}
			else
			{
				throw new Exception("id is invalid Guid");
			}

			#endregion

			try
			{
				new TimeLogService().Delete(recordId);
			}
			catch (Exception)
			{
				throw;
			}
			response.Success = true;
			response.Message = "Comment successfully deleted";


			return Json(response);
		}

		[Route("api/v3.0/p/project/timelog/start")]
		[HttpPost]
		public ActionResult StartTimeLog([FromQuery]Guid taskId)
		{
			var response = new ResponseModel();
			//Validate
			var task = new TaskService().GetTask(taskId);
			if (task == null)
			{
				response.Success = false;
				response.Message = "task not found";
				return Json(response);
			}
			if (task["timelog_started_on"] != null) {
				response.Success = false;
				response.Message = "timelog for the task already started";
				return Json(response);
			}
			try
			{
				new TaskService().StartTaskTimelog(taskId);
				response.Success = true;
				response.Message = "Log Started";
				return Json(response);
			}
			catch (Exception ex)
			{
				response.Success = false;
				// THREAT ADDRESSED - finding H-13 / review finding F26, CWE-209 (generation of an
				// error message containing sensitive information), OWASP A05 Security Misconfiguration.
				// This handler previously returned the raw exception text to the caller, which discloses
				// internal type names, member names, absolute source paths and database detail. The
				// message is now gated on development posture, matching the guard the rest of the tree
				// already uses. No log call is added here: this file carries no logging idiom at any
				// revision, and choosing a source name, a rate bound and a notification posture for it
				// is design work rather than remediation. That residual is recorded as RISK-040 in
				// docs/security/risk-register.md alongside the equivalent sites in the SDK plugin.
				response.Message = ErpSettings.DevelopmentMode ? ex.Message : "An internal error occurred!";
				return Json(response);
			}
		}

		//[Route("api/v3.0/p/project/timelog/stop")]
		//[HttpPost]
		//public ActionResult StopTimeLog([FromQuery]Guid taskId)
		//{
		//	var response = new ResponseModel();
		//	//Validate

		//	using (var connection = DbContext.Current.CreateConnection())
		//	{
		//		try
		//		{
		//			connection.BeginTransaction();

		//			new TaskService().StopTaskTimelog(taskId);

		//			//Create Time log

		//			connection.CommitTransaction();

		//			response.Success = true;
		//			response.Message = "Log Stopped";
		//			return Json(response);
		//		}
		//		catch (Exception ex)
		//		{
		//			connection.RollbackTransaction();

		//			response.Success = false;
		//			response.Message = ex.Message;
		//			return Json(response);
		//		}
		//	}
		//}

		[Route("api/v3.0/p/project/task/status")]
		[HttpPost]
		public ActionResult TaskSetStatus([FromQuery]Guid taskId, [FromQuery]Guid statusId)
		{
			var response = new ResponseModel();
			//Validate
			var task = new TaskService().GetTask(taskId);
			if (task == null)
			{
				response.Success = false;
				response.Message = "task not found";
				return Json(response);
			}
			if (task["status_id"] != null && (Guid)task["status_id"] == statusId)
			{
				response.Success = false;
				response.Message = "status already set";
				return Json(response);
			}
			try
			{
				new TaskService().SetStatus(taskId, statusId);
				response.Success = true;
				response.Message = "Log Started";
				return Json(response);
			}
			catch (Exception ex)
			{
				response.Success = false;
				// THREAT ADDRESSED - finding H-13 / review finding F26, CWE-209. See the first
				// occurrence of this guard in this file for the full rationale.
				response.Message = ErpSettings.DevelopmentMode ? ex.Message : "An internal error occurred!";
				return Json(response);
			}
		}

		[Route("api/v3.0/p/project/task/watch")]
		[HttpPost]
		public ActionResult TaskSetWatch([FromQuery]Guid? taskId = null, [FromQuery]Guid? userId = null, [FromQuery]bool startWatch = true)
		{
			var response = new ResponseModel();
			if (taskId == null) {
				response.Success = false;
				response.Message = "Missing taskId query parameter";
				return Json(response);
			}
			//Validate
			var task = new TaskService().GetTask(taskId.Value);
			if (task == null)
			{
				response.Success = false;
				response.Message = "task not found";
				return Json(response);
			}
			if (userId != null)
			{
				var userRecord = new UserService().Get(userId.Value);
				if (userRecord == null)
				{
					response.Success = false;
					response.Message = "user not found";
					return Json(response);
				}
			}
			else {
				userId = SecurityContext.CurrentUser.Id;
			}

			try
			{
				var watchRelation = new EntityRelationManager().Read("user_nn_task_watchers").Object;
				if (watchRelation == null)
					throw new Exception("Watch relation not found");

				if (startWatch)
				{
					var createRelResponse = new RecordManager().CreateRelationManyToManyRecord(watchRelation.Id, userId.Value, taskId.Value);
					if (!createRelResponse.Success)
						throw new Exception(createRelResponse.Message);

					response.Message = "Task watch started";
				}
				else {
					var removeRelResponse = new RecordManager().RemoveRelationManyToManyRecord(watchRelation.Id, userId.Value, taskId.Value);
					if (!removeRelResponse.Success)
						throw new Exception(removeRelResponse.Message);

					response.Message = "Task watch stopped";
				}

				response.Success = true;
				return Json(response);
			}
			catch (Exception ex)
			{
				response.Success = false;
				// THREAT ADDRESSED - finding H-13 / review finding F26, CWE-209. See the first
				// occurrence of this guard in this file for the full rationale.
				response.Message = ErpSettings.DevelopmentMode ? ex.Message : "An internal error occurred!";
				return Json(response);
			}
		}


		[AllowAnonymous]
		[Route("api/v3.0/p/project/files/javascript")]
		[ResponseCache(NoStore = false, Duration = 30 * 24 * 3600)]
		[HttpGet]
		public ContentResult TimeTrackJs([FromQuery]string file = "")
		{
			if(String.IsNullOrWhiteSpace(file))
				return Content("", "text/javascript");

			// THREAT ADDRESSED - review finding F27. DENY BY DEFAULT: a name that is not on the allow-list
			// declared at the top of this class is answered with exactly the empty script the blank-name
			// case above already returns, and NOTHING IS LOGGED. The silence is the control, not an
			// oversight: logging refusals from an anonymous, uncredentialed, unrate-limited endpoint is
			// precisely the log-volume and mail-amplification vector this finding describes, so a refusal
			// must cost the server nothing. Refusals stay observable through the host's own request
			// telemetry, which is bounded by the web server rather than by the caller. The response shape
			// is deliberately identical to the blank-name response so the endpoint discloses nothing about
			// which resource names exist.
			if (!AllowedJavaScriptResources.TryGetValue(file, out string resourceName))
				return Content("", "text/javascript");

			try
			{
				// resourceName, not file: from here on the caller's string is out of the data flow entirely.
				var jsContent = FileService.GetEmbeddedTextResource(resourceName, "WebVella.Erp.Plugins.Project.Files", "WebVella.Erp.Plugins.Project");

				return Content(jsContent, "text/javascript");
			}
			catch (Exception ex)
			{
				// Only an allow-listed name can reach this point, so a failure here means the assembly was
				// built or deployed without a resource it declares - a packaging defect genuinely worth
				// recording. Three properties keep the record safe to write from an anonymous endpoint: the
				// source string is a FIXED literal plus an allow-listed name, so no caller-chosen text can
				// enter the log; DoNotNotify keeps it out of the outbound mail path that LogService drives;
				// and the latch caps it at one record per resource per process, so request volume cannot
				// grow either the log table or the mail queue.
				if (ReportedJavaScriptResourceFaults.TryAdd(resourceName, 0))
					new Log().Create(LogType.Error, "ProjectController.TimeTrackJs embedded resource '" + resourceName + "'", ex, null, LogNotificationStatus.DoNotNotify);

				// Deliberately NOT re-thrown. Re-throwing surfaced the platform error pipeline for what is a
				// static script request: it disclosed that a fault had occurred and let an anonymous caller
				// drive exception handling and its logging on demand. An empty script is the correct degraded
				// answer for a script asset that cannot be produced, and it matches every other response this
				// action can return, so the fault is invisible to the caller.
				return Content("", "text/javascript");
			}
		}
        #endregion

        #region << WebAssembly>>

        [Route("api/v3.0/p/project/user/get-current")]
        [HttpGet]
        public ActionResult GetCurrentUser()
        {
			var request = recMan.Find(new EntityQuery("user","*", EntityQuery.QueryEQ("id", CurrentUserId.Value))).Object.Data;
            return Json(request[0]);
        }

        #endregion

    }


}