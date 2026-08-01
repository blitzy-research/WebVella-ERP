using CsvHelper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Api.Models.AutoMapper;
using WebVella.Erp.Database;
using WebVella.Erp.Diagnostics;
using WebVella.Erp.Eql;
using WebVella.Erp.Jobs;
using WebVella.Erp.Utilities;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Service;
using WebVella.Erp.Web.Services;
using WebVella.Erp.Web.Utils;
using Wangkanai.Detection.Services;

namespace WebVella.Erp.Web.Controllers
{
	[Authorize]
	public class WebApiController : ApiControllerBase
	{
		private const char RELATION_SEPARATOR = '.';
		private const char RELATION_NAME_RESULT_SEPARATOR = '$';

		// The wording the platform already returns for a fault whose detail must not reach the client. Taken
		// verbatim from ApiControllerBase.DoBadRequestResponse (line 57) rather than invented, so every
		// generic failure in this controller reads identically to every other one in the API surface.
		private const string INTERNAL_ERROR_MESSAGE = "An internal error occurred!";

		// THREAT ADDRESSED - insecure direct object reference, OWASP A01 Broken Access Control. One single
		// refusal for the file-mutation actions, used whether the file is absent, owned by somebody else, or
		// the caller cannot be resolved. Deliberately identical in all three cases: a message that
		// distinguished "not found" from "not yours" would confirm which paths hold real files and hand an
		// attacker a file-enumeration oracle for free.
		private const string FILE_ACCESS_DENIED_MESSAGE = "You are not allowed to modify this file.";

		// Returned by the editor upload route when the callback index on the query string is not an integer.
		// It carries no script and does not echo the offending value - see BuildCKEditorCallback.
		private const string CKEDITOR_INVALID_REQUEST_BODY = "<html><body>The upload request was not valid.</body></html>";

		// Substituted when a stored file's own name cannot survive sanitisation, so the download still gets a
		// usable, inert Content-Disposition filename instead of an empty or unsafe one.
		private const string DEFAULT_DOWNLOAD_FILE_NAME = "download";

		// Upper bound on the request path recorded with an authorization failure, so a deliberately long
		// request cannot inflate the log store one refusal at a time.
		private const int MAX_LOGGED_PATH_LENGTH = 400;

		// The generic binary content type browsers fall back to when they cannot classify a file. It asserts
		// nothing about the content, so there is nothing for the consistency check below to contradict.
		private const string GENERIC_BINARY_CONTENT_TYPE = "application/octet-stream";

		// THREAT ADDRESSED - finding H-08, CWE-434 (unrestricted upload of file with dangerous type),
		// OWASP A04 Insecure Design + A03 Injection. Every upload action in this controller accepted any
		// size, so a single POST could exhaust the process: all four read the whole stream into a byte[] in
		// memory before any size was known. 25 MiB sits just below the ASP.NET Core default maximum request
		// body size of 30,000,000 bytes, which no host in this repository raises, so this cap can never be
		// the surprising limit - the request would already have been refused by the server.
		private const long MAX_UPLOAD_SIZE_BYTES = 25L * 1024L * 1024L;

		// Upper bound on a stored file name. The caller-supplied name is concatenated into a storage path and
		// later quoted into a response header, so an unbounded name is both a storage and a header concern.
		private const int MAX_UPLOAD_FILE_NAME_LENGTH = 200;

		// THREAT ADDRESSED - finding H-08, CWE-434, OWASP A04 + A03. The upload actions below accepted ANY
		// extension, and the download action then served the stored bytes inline from this application's own
		// origin - so an uploaded .html or .svg became stored script running with the victim's session. The
		// two halves are closed together: this allow-list is the front half of the chain, the attachment
		// disposition in Download is the back half. Constraining either one alone leaves the chain intact.
		//
		// DERIVATION - the set is not invented. It is exactly the file types this platform ALREADY knows how
		// to classify, so no working upload changes behaviour: the image extensions the download action's own
		// isImage test uses, widened only to the remaining non-scriptable raster formats the "image" MIME
		// family classifies on upload; the "document" extension list the two multi-upload actions declare
		// themselves; and the "video" and "audio" MIME families those same actions classify.
		//
		// TWO DELIBERATE EXCLUSIONS, and they are the entire point of the finding:
		//   .html and .htm ARE in the platform's own document list and are excluded here anyway. They are the
		//   exact payload of the stored cross-site scripting chain - markup served from this origin executes
		//   on this origin, with this application's cookies.
		//   .svg is absent from the image list and is deliberately kept absent. An SVG is an XML document
		//   that can carry <script>; the content-type provider maps it to image/svg+xml, which is precisely
		//   why the extension - not the declared media family - has to be the authority here.
		// Executable and script types (.exe .dll .bat .cmd .com .ps1 .sh .js .jsp .asp .aspx .php .cshtml
		// .razor .config) need no entry to be refused: this is an allow-list, so anything unnamed is already
		// rejected. No companion deny-list is kept - one mechanism, not two.
		// Widening this set is an owner decision; see docs/security/risk-register.md.
		private static readonly HashSet<string> ALLOWED_UPLOAD_EXTENSIONS = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
		{
			//image - the download action's inline set plus the other non-scriptable raster formats. NOT .svg.
			".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".tif", ".tiff",
			//document - the platform's own list, minus .html and .htm. .csv is the tabular sibling of the
			//already-listed .txt and is required by the CSV record import this controller serves.
			".doc", ".docx", ".odt", ".rtf", ".txt", ".csv", ".pdf", ".ppt", ".pptx", ".xls", ".xlsx", ".ods", ".odp",
			//video and audio - the two MIME families the multi-upload actions already classify.
			".mp4", ".webm", ".ogv", ".mov", ".avi", ".m4v", ".mpg", ".mpeg", ".mkv",
			".mp3", ".wav", ".ogg", ".oga", ".m4a", ".aac", ".flac"
		};

		// THREAT ADDRESSED - finding H-08 escalating to stored cross-site scripting (CWE-434 feeding CWE-79),
		// OWASP A04 + A03. Extensions the download action may serve INLINE; everything else is forced to an
		// attachment and therefore cannot execute on this origin.
		//
		// It MUST be an inline allow-list and never a blanket attachment. PcFieldImage and PcFieldFile render
		// stored images with src-prefix="/fs", i.e. <img src="/fs/...">, so forcing every response to
		// download would break image display across the whole platform. The set is therefore the download
		// action's own isImage set, extended only to the other raster formats the upload allow-list above
		// admits - keeping the two lists coherent, so every image that can be stored can still be shown -
		// plus .pdf, which browsers render in a sandboxed viewer rather than as same-origin script.
		// .html, .htm, .svg, .xhtml, .xml and .js are all absent, which is what breaks the chain.
		private static readonly HashSet<string> INLINE_DOWNLOAD_EXTENSIONS = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
		{
			".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".tif", ".tiff", ".pdf"
		};

		RecordManager recMan;
		EntityManager entMan;
		EntityRelationManager relMan;
		SecurityManager secMan;
		IErpService erpService;
		IDetectionService _detection;
		ErpRequestContext erpRequestContext;

		public WebApiController([FromServices] IErpService erpService,
			[FromServices] ErpRequestContext requestContext,
			[FromServices] IDetectionService detection)
		{
			recMan = new RecordManager();
			secMan = new SecurityManager();
			entMan = new EntityManager();
			relMan = new EntityRelationManager();
			this.erpService = erpService;
			this.erpRequestContext = requestContext;
			this._detection = detection;
		}

		[Route("api/v3/en_US/eql")]
		[HttpPost]
		public ActionResult EqlQueryAction([FromBody] EqlQuery model)
		{
			ResponseModel response = new ResponseModel();
			response.Success = true;

			if (model == null)
				return NotFound();

			try
			{
				var eqlResult = new EqlCommand(model.Eql, model.Parameters).Execute();
				response.Object = eqlResult;
			}
			catch (EqlException eqlEx)
			{
				response.Success = false;
				foreach (var eqlError in eqlEx.Errors)
				{
					response.Errors.Add(new ErrorModel("eql", "", eqlError.Message));
				}
				return Json(response);
			}
			catch (Exception ex)
			{
				response.Success = false;
				response.Message = ex.Message;
				return Json(response);
			}

			return Json(response);
		}

		[Route("api/v3/en_US/eql-ds")]
		[HttpPost]
		public ActionResult DataSourceQueryAction([FromBody] JObject submitObj)
		{
			ResponseModel response = new ResponseModel();
			response.Success = true;


			if (submitObj == null)
				return NotFound();

			EqlDataSourceQuery model = new EqlDataSourceQuery();

			#region << Init SubmitObj >>
			foreach (var prop in submitObj.Properties())
			{
				switch (prop.Name.ToLower())
				{
					case "name":
						if (!string.IsNullOrWhiteSpace(prop.Value.ToString()))
							model.Name = prop.Value.ToString();
						else
						{
							throw new Exception("DataSource Name is required");
						}
						break;
					case "parameters":
						var jParams = (JArray)prop.Value;
						model.Parameters = new List<EqlParameter>();
						foreach (JObject jParam in jParams)
						{
							var name = jParam["name"].ToString();
							var value = jParam["value"].ToString();
							var eqlParam = new EqlParameter(name, value);
							model.Parameters.Add(eqlParam);
						}
						break;
				}
			}
			#endregion


			try
			{
				DataSourceManager dsMan = new DataSourceManager();
				var dataSources = dsMan.GetAll();
				var ds = dataSources.SingleOrDefault(x => x.Name == model.Name);
				if (ds == null)
				{
					response.Success = false;
					response.Message = $"DataSource with name '{model.Name}' not found.";
					return Json(response);
				}

				if (ds is DatabaseDataSource)
				{
					var list = (EntityRecordList)dsMan.Execute(ds.Id, model.Parameters);
					response.Object = new { list, total_count = list.TotalCount };
				}
				else if (ds is CodeDataSource)
				{
					Dictionary<string, object> arguments = new Dictionary<string, object>();
					foreach (var par in model.Parameters)
						arguments[par.ParameterName] = par.Value;

					response.Object = ((CodeDataSource)ds).Execute(arguments);
				}
				else
				{
					response.Success = false;
					response.Message = $"DataSource type is not supported.";
					return Json(response);
				}
			}
			catch (EqlException eqlEx)
			{
				response.Success = false;
				foreach (var eqlError in eqlEx.Errors)
				{
					response.Errors.Add(new ErrorModel("eql", "", eqlError.Message));
				}
				return Json(response);
			}
			catch (Exception ex)
			{
				response.Success = false;
				response.Message = ex.Message;
				return Json(response);
			}

			return Json(response);
		}

		[Route("api/v3/en_US/eql-ds-select2")]
		[HttpPost]
		public ActionResult DataSourceQueryActionForSelect2([FromBody] JObject submitObj)
		{
			if (submitObj == null)
				return NotFound();

			var result = new EntityRecord();
			result["results"] = new List<EntityRecord>();
			result["pagination"] = new EntityRecord();

			EqlDataSourceQuery model = new EqlDataSourceQuery();

			#region << Init SubmitObj >>
			foreach (var prop in submitObj.Properties())
			{
				switch (prop.Name.ToLower())
				{
					case "name":
						if (!string.IsNullOrWhiteSpace(prop.Value.ToString()))
							model.Name = prop.Value.ToString();
						else
						{
							throw new Exception("DataSource Name is required");
						}
						break;
					case "parameters":
						var jParams = (JArray)prop.Value;
						model.Parameters = new List<EqlParameter>();
						foreach (JObject jParam in jParams)
						{
							var name = jParam["name"].ToString();
							var value = jParam["value"].ToString();
							var eqlParam = new EqlParameter(name, value);
							model.Parameters.Add(eqlParam);
						}
						break;
				}
			}
			#endregion
			var page = 1;
			if (model.Parameters.Count > 0)
			{
				var pageParam = model.Parameters.FirstOrDefault(x => x.ParameterName == "page");
				if (pageParam != null)
				{
					if (int.TryParse(pageParam.Value?.ToString(), out int outInt))
					{
						page = outInt;
					}
				}
			}
			var records = new List<EntityRecord>();
			int? total = 0;
			try
			{
				DataSourceManager dsMan = new DataSourceManager();
				var dataSources = dsMan.GetAll();
				var ds = dataSources.SingleOrDefault(x => x.Name == model.Name);
				if (ds == null)
				{
					return BadRequest();
				}

				if (ds is DatabaseDataSource)
				{
					var list = (EntityRecordList)dsMan.Execute(ds.Id, model.Parameters);
					records = (List<EntityRecord>)list;
					total = list.TotalCount;
				}
				else if (ds is CodeDataSource)
				{
					Dictionary<string, object> arguments = new Dictionary<string, object>();
					foreach (var par in model.Parameters)
						arguments[par.ParameterName] = par.Value;

					var dsResult = ((CodeDataSource)ds).Execute(arguments);
					if (dsResult is EntityRecordList)
					{

						records = (List<EntityRecord>)((EntityRecordList)dsResult);
						total = ((EntityRecordList)dsResult).TotalCount;
					}
					else if (dsResult is List<EntityRecord>)
					{
						records = (List<EntityRecord>)dsResult;
						total = null;
					}
					else
					{
						return Json(dsResult);
					}
				}
				else
				{
					return BadRequest();
				}
			}
			catch
			{
				return BadRequest();
			}

			//Post process records according to requiredments {id,text}
			var processedRecords = new List<EntityRecord>();
			foreach (var record in records)
			{
				var procRec = new EntityRecord();
				if (record.Properties.ContainsKey("id"))
				{
					procRec["id"] = record["id"].ToString();
				}
				else
				{
					procRec["id"] = "no-id-" + Guid.NewGuid();
				}
				if (record.Properties.ContainsKey("text"))
				{
					procRec["text"] = record["text"].ToString();
				}
				else if (record.Properties.ContainsKey("label"))
				{
					procRec["text"] = record["label"].ToString();
				}
				else if (record.Properties.ContainsKey("name"))
				{
					procRec["text"] = record["name"].ToString();
				}
				else
				{
					procRec["text"] = procRec["id"].ToString();
				}
				processedRecords.Add(procRec);
			}
			var moreRecord = new EntityRecord();
			moreRecord["more"] = false;
			if (records.Count > 0)
			{
				if (total > page * 10)
				{
					moreRecord["more"] = true;
				}
				result["results"] = processedRecords;
			}

			result["pagination"] = moreRecord;
			return Json(result);
		}


		[Route("api/v3.0/user/preferences/toggle-sidebar-size")]
		[HttpPost]
		public ActionResult ToggleSidebarSize()
		{
			//TODO: Implement. Should Check the current size in user preferences and toggle in order "","sm","md","lg"
			var currentUser = AuthService.GetUser(User);
			var currentUserPreferences = currentUser.Preferences;
			var targetSidebarSize = "";
			switch (currentUserPreferences.SidebarSize)
			{
				case "sm":
					targetSidebarSize = "lg";
					break;
				case "lg":
					targetSidebarSize = "sm";
					break;
				default:
					targetSidebarSize = "lg";
					break;
			}
			var response = new BaseResponseModel();
			try
			{
				new UserPreferencies().SetSidebarSize(currentUser.Id, targetSidebarSize);
				response.Success = true;
				response.Message = "success";
				return Json(response);
			}
			catch (Exception ex)
			{
				response.Success = false;
				response.Message = ex.Message;
				new Log().Create(LogType.Error, "ToggleSidebarSize API Method Error", ex);
				return Json(response);
			}
		}

		[Route("api/v3.0/user/preferences/toggle-section-collapse")]
		[HttpPost]
		public ActionResult ToggleSection(Guid? nodeId = null, bool isCollapsed = false)
		{
			var response = new BaseResponseModel();
			try
			{
				if (nodeId == null)
					throw new Exception("nodeId query param is required");

				var userPreferencesService = new UserPreferencies();

				var currentUser = AuthService.GetUser(User);

				EntityRecord componentData = userPreferencesService.GetComponentData(currentUser.Id, "WebVella.Erp.Web.Components.PcSection");

				var collapsedNodeIds = new List<Guid>();
				var uncollapsedNodeIds = new List<Guid>();

				if (componentData == null)
				{
					componentData = new EntityRecord();
					componentData["collapsed_node_ids"] = new List<Guid>();
					componentData["uncollapsed_node_ids"] = new List<Guid>();
				}
				else
				{
					if (componentData.Properties.ContainsKey("collapsed_node_ids") && componentData["collapsed_node_ids"] != null)
					{
						if (componentData["collapsed_node_ids"] is string)
						{
							try
							{
								collapsedNodeIds = JsonConvert.DeserializeObject<List<Guid>>((string)componentData["collapsed_node_ids"]);
							}
							catch
							{
								throw new Exception("WebVella.Erp.Web.Components.PcSection component data object in user preferences not in the correct format. collapsed_node_ids should be List<Guid>");
							}
						}
						else if (componentData["collapsed_node_ids"] is List<Guid>)
						{
							collapsedNodeIds = (List<Guid>)componentData["collapsed_node_ids"];
						}
						else if (componentData["collapsed_node_ids"] is JArray)
						{
							collapsedNodeIds = ((JArray)componentData["collapsed_node_ids"]).ToObject<List<Guid>>();
						}
						else
						{
							throw new Exception("Unknown format of collapsed_node_ids");
						}
					}
					if (componentData.Properties.ContainsKey("uncollapsed_node_ids") && componentData["uncollapsed_node_ids"] != null)
					{
						if (componentData["uncollapsed_node_ids"] is string)
						{
							try
							{
								uncollapsedNodeIds = JsonConvert.DeserializeObject<List<Guid>>((string)componentData["uncollapsed_node_ids"]);
							}
							catch
							{
								throw new Exception("WebVella.Erp.Web.Components.PcSection component data object in user preferences not in the correct format. uncollapsed_node_ids should be List<Guid>");
							}
						}
						else if (componentData["uncollapsed_node_ids"] is List<Guid>)
						{
							uncollapsedNodeIds = (List<Guid>)componentData["uncollapsed_node_ids"];
						}
						else if (componentData["uncollapsed_node_ids"] is JArray)
						{
							uncollapsedNodeIds = ((JArray)componentData["uncollapsed_node_ids"]).ToObject<List<Guid>>();
						}
						else
						{
							throw new Exception("Unknown format of uncollapsed_node_ids");
						}
					}
				}

				if (isCollapsed)
				{
					//new state is collapsed
					//1. remove if it is in uncollapsed
					uncollapsedNodeIds = uncollapsedNodeIds.FindAll(x => x != nodeId.Value).ToList();
					//2. add to collapsed
					if (!collapsedNodeIds.Contains(nodeId.Value))
						collapsedNodeIds.Add(nodeId.Value);
				}
				else
				{
					//new state is uncollapsed
					//1. remove it is in collapsed
					collapsedNodeIds = collapsedNodeIds.FindAll(x => x != nodeId.Value).ToList();
					//2. add to uncollapsed
					if (!uncollapsedNodeIds.Contains(nodeId.Value))
						uncollapsedNodeIds.Add(nodeId.Value);
				}

				componentData["collapsed_node_ids"] = collapsedNodeIds;
				componentData["uncollapsed_node_ids"] = uncollapsedNodeIds;

				userPreferencesService.SetComponentData(currentUser.Id, "WebVella.Erp.Web.Components.PcSection", componentData);
				response.Success = true;
				response.Message = "success";
				return Json(response);
			}
			catch (Exception ex)
			{
				response.Success = false;
				response.Message = ex.Message;
				new Log().Create(LogType.Error, "ToggleSidebarSize API Method Error", ex);
				return Json(response);
			}
		}

		[Route("api/v3.0/datasource/code-compile")]
		[HttpPost]
		public ActionResult DataSourceAction([FromBody] DataSourceCodeTestModel model)
		{
			try
			{
				CodeEvalService.Compile(model.CsCode);
			}
			catch (Exception ex)
			{
				new Log().Create(LogType.Error, "DataSourceAction Code compile API Method Error", ex);
				return Json(new { success = false, message = ex.Message });
			}

			return Json(new { success = true, message = "" });
		}

		[Route("api/v3.0/datasource/test")]
		[HttpPost]
		public ActionResult DataSourceAction([FromBody] DataSourceTestModel model)
		{
			if (model == null)
				return NotFound();

			string sql = string.Empty;
			string data = "";
			List<EqlError> errors = new List<EqlError>();
			try
			{
				DataSourceManager dataSourceManager = new DataSourceManager();
				if (model.Action == "sql")
					sql = dataSourceManager.GenerateSql(model.Eql, model.Parameters, model.ReturnTotal );
				if (model.Action == "data")
					data = JsonConvert.SerializeObject(dataSourceManager.Execute(model.Eql, model.Parameters, model.ReturnTotal), Formatting.Indented);
			}
			catch (EqlException eqlEx)
			{
				errors.AddRange(eqlEx.Errors);
			}
			catch (Exception ex)
			{
				new Log().Create(LogType.Error, "DataSourceAction test API Method Error", ex);
				errors.Add(new EqlError { Message = ex.Message });
			}

			return Json(new { sql, data, errors });
		}

		[Route("api/v3.0/datasource/{dataSourceId}/test")]
		[HttpPost]
		public ActionResult DataSourceAction(Guid dataSourceId, [FromBody] DataSourceTestModel model)
		{

			if (model == null)
				return NotFound();

			string sql = string.Empty;
			string data = "";
			List<EqlError> errors = new List<EqlError>();
			try
			{
				DataSourceManager dataSourceManager = new DataSourceManager();
				var dataSource = dataSourceManager.Get(dataSourceId);
				if (dataSource == null)
				{
					errors.Add(new EqlError { Message = "DataSource Not found" });
				}

				var dataSourceEql = "";
				if (dataSource is DatabaseDataSource)
				{
					dataSourceEql = ((DatabaseDataSource)dataSource).EqlText;
				}

				var compoundParams = new List<DataSourceParameter>();
				foreach (var dsParam in dataSource.Parameters)
				{
					var pageParameter = model.ParamList.FirstOrDefault(x => x.Name == dsParam.Name);
					if (pageParameter != null)
					{
						compoundParams.Add(pageParameter);
					}
					else
					{
						compoundParams.Add(dsParam);
					}
				}

				var paramText = dataSourceManager.ConvertParamsToText(compoundParams);

				if (model.Action == "sql")
					sql = dataSourceManager.GenerateSql(dataSourceEql, paramText, dataSource.ReturnTotal);
				if (model.Action == "data")
					data = JsonConvert.SerializeObject(dataSourceManager.Execute(dataSourceEql, paramText, dataSource.ReturnTotal), Formatting.Indented);
			}
			catch (EqlException eqlEx)
			{
				errors.AddRange(eqlEx.Errors);
			}
			catch (Exception ex)
			{
				new Log().Create(LogType.Error, "DataSourceAction Id test API Method Error", ex);
				errors.Add(new EqlError { Message = ex.Message });
			}

			return Json(new { sql, data, errors });
		}

		//[AllowAnonymous] //Needed only when webcomponent development
		[Route("api/v3.0/page/{pageId}/node/create")]
		[HttpPost]
		public ActionResult CreatePageBodyNode(Guid pageId, [FromBody] PageBodyNode newNode)
		{
			try
			{
				var pageSrv = new PageService();

				ErpPage page = pageSrv.GetPage(pageId);
				if (page == null) //page not found
					return NotFound();

				if (newNode == null)
					return NotFound();

				if (newNode.Id == Guid.Empty)
					newNode.Id = Guid.NewGuid();

				if (page.Body == null && newNode.ParentId != null)
					throw new Exception("Cannot create child node in page with no root node.");

				//if (page.Body != null && newNode.ParentId == null)
				//	throw new Exception("Cannot create root node in page with already existing root node.");

				pageSrv.CreatePageBodyNode(newNode.Id, newNode.ParentId, pageId, newNode.NodeId, newNode.Weight,
					newNode.ComponentName, newNode.ContainerId, newNode.Options);

				var createdNode = pageSrv.GetPageNodeById(newNode.Id);

				var currentUser = AuthService.GetUser(User);
				new UserPreferencies().SdkUseComponent(currentUser.Id, newNode.ComponentName);

				return Json(createdNode);
			}
			catch (Exception exception)
			{
				new Log().Create(LogType.Error, "CreatePageBodyNode API Method Error", exception);
				return new ContentResult
				{
					Content = $"Error: {exception.Message}",
					ContentType = "text/plain",
					// change to whatever status code you want to send out
					StatusCode = 500
				};
			}
		}

		//[AllowAnonymous] //Needed only when webcomponent development
		[Route("api/v3.0/page/{pageId}/node/{nodeId}/update")]
		[HttpPost]
		public ActionResult UpdatePageBodyNode(Guid pageId, Guid nodeId, [FromBody] PageBodyNode node)
		{
			try
			{
				var pageSrv = new PageService();

				ErpPage page = pageSrv.GetPage(pageId);
				if (page == null) //page not found
					return NotFound();

				var pageNodes = pageSrv.GetPageNodes(pageId);
				var existingNode = pageNodes.SingleOrDefault(x => x.Id == nodeId);
				if (existingNode == null)
					return NotFound();

				if (existingNode.ParentId != null && node.ParentId == null)
					throw new Exception("There is only one root node and cannot update parent to null. Check for error.");

				if (nodeId == node.ParentId)
				{
					throw new Exception("Node Id and Parent Id cannot be the same");
				}

				pageSrv.UpdatePageBodyNode(nodeId, node.ParentId, pageId, node.NodeId, node.Weight,
					node.ComponentName, node.ContainerId, node.Options);

				pageNodes = pageSrv.GetPageNodes(pageId);
				return Json(pageNodes);
			}
			catch (Exception exception)
			{
				new Log().Create(LogType.Error, "UpdatePageBodyNode API Method Error", exception);
				return new ContentResult
				{
					Content = $"Error: {exception.Message}",
					ContentType = "text/plain",
					// change to whatever status code you want to send out
					StatusCode = 500
				};
			}
		}

		//[AllowAnonymous] //Needed only when webcomponent development
		[Route("api/v3.0/page/{pageId}/node/{nodeId}/move")]
		[HttpPost]
		public ActionResult MovePageBodyNode(Guid pageId, Guid nodeId, [FromBody] MovedNodeInfo moveInfo)
		{
			try
			{
				var pageSrv = new PageService();

				ErpPage page = pageSrv.GetPage(pageId);
				if (page == null) //page not found
					return NotFound();

				if (moveInfo == null)
				{
					return BadRequest("MoveInfo cannot be restored");
				}


				var pageNodes = pageSrv.GetPageNodes(pageId);

				var movedNode = pageNodes.First(x => x.Id == nodeId);
				movedNode.ParentId = moveInfo.NewParentNodeId;
				movedNode.ContainerId = moveInfo.NewContainerId;
				movedNode.Weight = moveInfo.NewIndex + 1; //Convert index to weight
				var nodesToBeUpdated = new List<Guid>();
				pageNodes = Utils.PageUtils.RecalculateContainerNodeWeights(pageNodes, out nodesToBeUpdated, nodeId);

				//Update Nodes
				foreach (var updatedNodeId in nodesToBeUpdated)
				{
					var updatedNode = pageNodes.First(x => x.Id == updatedNodeId);

					if (updatedNodeId == updatedNode.ParentId)
					{
						throw new Exception("Node Id and Parent Id cannot be the same");
					}

					pageSrv.UpdatePageBodyNode(updatedNodeId, updatedNode.ParentId, pageId, updatedNode.NodeId,
						updatedNode.Weight, updatedNode.ComponentName, updatedNode.ContainerId, updatedNode.Options);
				}

				pageNodes = pageSrv.GetPageNodes(pageId);
				return Json(pageNodes);
			}
			catch (Exception exception)
			{
				new Log().Create(LogType.Error, "MovePageBodyNode API Method Error", exception);
				return new ContentResult
				{
					Content = $"Error: {exception.Message}",
					ContentType = "text/plain",
					// change to whatever status code you want to send out
					StatusCode = 500
				};
			}
		}

		//[AllowAnonymous] //Needed only when webcomponent development
		[Route("api/v3.0/page/{pageId}/node/{nodeId}/delete")]
		[HttpPost]
		public ActionResult DeletePageBodyNode(Guid pageId, Guid nodeId)
		{
			try
			{
				var pageSrv = new PageService();
				ErpPage page = pageSrv.GetPage(pageId);
				if (page == null) //page not found
					return NotFound();

				var pageNodes = pageSrv.GetPageNodes(pageId);
				if (!pageNodes.Any(x => x.Id == nodeId))
					return NotFound();

				pageSrv.DeletePageBodyNode(nodeId);

				pageNodes = pageSrv.GetPageNodes(pageId);
				return Json(pageNodes);
			}
			catch (Exception exception)
			{
				new Log().Create(LogType.Error, "DeletePageBodyNode API Method Error", exception);
				return new ContentResult
				{
					Content = $"Error: {exception.Message}",
					ContentType = "text/plain",
					// change to whatever status code you want to send out
					StatusCode = 500
				};
			}
		}

		//[AllowAnonymous] //Needed only when webcomponent development
		[Route("api/v3.0/page/{pageId}/node/{nodeId}/options/update")]
		[HttpPost]
		public ActionResult UpdatePageBodyNodeOptions(Guid pageId, Guid nodeId, [FromBody] JObject options)
		{
			try
			{
				if (options == null)
					return NotFound();

				var pageSrv = new PageService();

				ErpPage page = pageSrv.GetPage(pageId);
				if (page == null) //page not found
					return NotFound();

				pageSrv.UpdatePageBodyNodeOptions(nodeId, options.ToString());

				var updatedNode = pageSrv.GetPageNodeById(nodeId);
				var pageNodes = pageSrv.GetPageNodes(updatedNode.PageId);
				return Json(pageNodes);
			}
			catch (Exception exception)
			{
				new Log().Create(LogType.Error, "UpdatePageBodyNodeOptions API Method Error", exception);
				return new ContentResult
				{
					Content = $"Error: {exception.Message}",
					ContentType = "text/plain",
					// change to whatever status code you want to send out
					StatusCode = 500
				};
			}
		}

		//[AllowAnonymous] //Needed only when webcomponent development
		[Route("api/v3.0/pc/{fullComponentName}/view/{renderMode}")]
		[HttpPost]
		public ActionResult PageComponentRenderViews(string fullComponentName, string renderMode, [FromBody] JObject options,
			[FromQuery] Guid? nid = null, [FromQuery] Guid? pid = null, [FromQuery] Guid? entityId = null, [FromQuery] Guid? recordId = null)
		{
			try
			{
				if (string.IsNullOrWhiteSpace(renderMode))
					return NotFound();

				//if (nid == null)
				//	return BadRequest("The node Id is required to be set as query parameter 'nid', when requesting this component");

				if (pid == null)
					return BadRequest("The page Id is required to be set as query parameter 'pid', when requesting this component");

				var type = FileService.GetType(fullComponentName);
				if (type == null)
					return NotFound();

				var pageServ = new PageService();
				PageBodyNode pagebodyNode = null;
				ErpPage page = null;
				PageDataModel pageModel = null;

				#region << Override erpRequestContext >>
				erpRequestContext.SetSimulatedRouteData(entityId: entityId, pageId: pid, recordId: recordId);
				#endregion

				if (pid != null)
				{
					page = pageServ.GetPage(pid ?? Guid.Empty);

					if (nid != null)
					{
						pagebodyNode = pageServ.GetPageNodeById(nid ?? Guid.Empty);
					}
					else
					{
						pagebodyNode = PageUtils.GetAjaxPageBodyNode(fullComponentName, pid ?? Guid.Empty, JsonConvert.SerializeObject(options));
					}

					#region << Building simulation pageModel >>
					App app = null;
					SitemapArea area = null;
					SitemapNode node = null;
					Entity entity = null;
					EntityRecord record = null;
					//erpRequestContext
					if (page != null)
					{
						//Override 
						if (entityId != null)
							page.EntityId = entityId;

						if (page.AppId == null && page.EntityId != null)
						{
							#region << Try to get one of the attached apps >>
							var allApps = new AppService().GetAllApplications();
							foreach (var appInstance in allApps)
							{
								foreach (var areaInstance in appInstance.Sitemap.Areas)
								{
									foreach (var nodeInstance in areaInstance.Nodes)
									{
										if (nodeInstance.EntityId == page.EntityId)
										{
											page.AppId = appInstance.Id;
											if (page.Type == PageType.RecordCreate || page.Type == PageType.RecordDetails ||
											page.Type == PageType.RecordList || page.Type == PageType.RecordManage)
											{
												page.AreaId = areaInstance.Id;
												page.NodeId = nodeInstance.Id;
											}
										}
									}
								}
							}

							#endregion
						}

						if (page.AppId != null)
						{
							app = new AppService().GetApplication(page.AppId ?? Guid.Empty);
							erpRequestContext.App = app;
							if (app != null)
							{
								if (page.AreaId != null)
								{
									area = app.Sitemap.Areas.FirstOrDefault(x => x.Id == page.AreaId);
									erpRequestContext.SitemapArea = area;
									if (area != null && page.NodeId != null)
									{
										node = area.Nodes.FirstOrDefault(x => x.Id == page.NodeId);
										erpRequestContext.SitemapNode = node;
									}
								}

								if (page.EntityId != null)
								{
									entity = new EntityManager().ReadEntity(page.EntityId ?? Guid.Empty).Object;
									erpRequestContext.Entity = entity;

									//Get the first record as simulation
									if (entity != null)
									{
										QueryObject filter = null;
										if (recordId != null)
										{
											filter = EntityQuery.QueryEQ("id", recordId.Value);
										}
										var sortsList = new List<QuerySortObject>();
										sortsList.Add(new QuerySortObject("id", QuerySortType.Ascending));
										var findRecordResponse = new RecordManager().Find(new EntityQuery(entity.Name, "*", filter, sortsList.ToArray(), 0, 1));
										if (!findRecordResponse.Success)
											throw new Exception(findRecordResponse.Message);
										if (findRecordResponse.Object != null && findRecordResponse.Object.Data.Any())
										{
											record = findRecordResponse.Object.Data.First();
											erpRequestContext.RecordId = (Guid)record["id"];
										}
									}
								}
							}
						}
					}

					//currentUser
					var currentUser = AuthService.GetUser(User);


					var baseErpPageMode = BaseErpPageModel.CreatePageModelSimulation(
						erpRequestContext: erpRequestContext,
						currentUser: currentUser
					);

					pageModel = baseErpPageMode.DataModel;
					#endregion
				}

				switch (renderMode)
				{
					case "display":
						var pcContextDisplay = new PageComponentContext(pagebodyNode, pageModel, ComponentMode.Design, options);
						return ViewComponent(type, new { context = pcContextDisplay });
					case "design":
						var pcContextDesign = new PageComponentContext(pagebodyNode, pageModel, ComponentMode.Design, options);
						return ViewComponent(type, new { context = pcContextDesign });
					case "options":
						pageModel.SafeCodeDataVariable = true;
						var pcContextOptions = new PageComponentContext(pagebodyNode, pageModel, ComponentMode.Options, options);
						return ViewComponent(type, new { context = pcContextOptions });
					case "help":
						var pcContextReadme = new PageComponentContext(pagebodyNode, pageModel, ComponentMode.Help, options);
						return ViewComponent(type, new { context = pcContextReadme });
				}

				return NotFound();
			}
			catch (Exception exception)
			{
				new Log().Create(LogType.Error, "PageComponentRenderViews API Method Error", exception);
				return new ContentResult
				{
					Content = $"Error: {exception.Message}",
					ContentType = "text/plain",
					// change to whatever status code you want to send out
					StatusCode = 500
				};
			}
		}

		//[AllowAnonymous] //Needed only when webcomponent development
		[Route("api/v3.0/pc/{fullComponentName}/resource/{filename}")]
		[HttpGet]
		public ActionResult PageComponentServiceJs(string fullComponentName, string filename)
		{
			try
			{
				if (string.IsNullOrWhiteSpace(fullComponentName))
					return NotFound();

				var assembly = FileService.GetTypeAssembly(fullComponentName);
				if (assembly == null)
					return NotFound();

				if (!FileService.EmbeddedResourceExists(filename, fullComponentName, assembly))
					return NotFound();

				var content = FileService.GetEmbeddedTextResource(filename, fullComponentName, assembly);
				switch (filename)
				{
					case "service.js":
						return Content(content, "text/javascript");
					case "options.html":
					case "design.html":
						return Content(content, "text/html");
				}

				return NotFound();
			}
			catch (Exception exception)
			{
				new Log().Create(LogType.Error, "PageComponentServiceJs API Method Error", exception);
				return new ContentResult
				{
					Content = $"Error: {exception.Message}",
					ContentType = "text/plain",
					// change to whatever status code you want to send out
					StatusCode = 500
				};
			}
		}

		[AllowAnonymous]
		[Route("api/v3.0/p/core/styles.css")]
		[ResponseCache(NoStore = false, Duration = 30 * 24 * 3600)]
		[HttpGet]
		public ContentResult StylesCss()
		{
			try
			{
				var cssContent = "";

				if (String.IsNullOrWhiteSpace(ErpAppContext.Current.StylesContent))
				{
					new ThemeService().GenerateStylesContent();
				}

				cssContent = ErpAppContext.Current.StylesContent;
				return Content(cssContent, "text/css");
			}
			catch (Exception ex)
			{
				new Log().Create(LogType.Error, "StylesCss API Method Error", ex);
				throw;
			}
		}


		//[Route("api/v3.0/p/core/select/font-awesome-icons")]
		//[HttpGet]
		//public ActionResult GetSelectCases([FromQuery]string search,[FromQuery]int page = 1)
		//{
		//	var pageSize = 10;
		//	var response = new ResponseModel();
		//	response.Timestamp = DateTime.UtcNow;
		//	try
		//	{
		//		var icons = RenderService.FontAwesomeIcons;
		//		var iconTotal = icons.Count();
		//		if(!String.IsNullOrWhiteSpace(search)){
		//			var filteredIcons = icons.FindAll(x=> x.Class.Contains(search) || x.Name.Contains(search)).ToList();
		//			iconTotal = filteredIcons.Count();
		//			icons = filteredIcons.Skip((page-1)*pageSize).Take(pageSize).ToList();
		//		}
		//		else{
		//			icons = icons.Skip((page-1)*pageSize).Take(pageSize).ToList();
		//		}
		//		var result = new EntityRecord();

		//		result["results"] = icons;
		//		result["pagination"] = new EntityRecord(); // more => true, false
		//		var moreRecord = new EntityRecord();
		//		moreRecord["more"] = false;

		//		if(iconTotal > page*pageSize){
		//			moreRecord["more"] = true;
		//		}

		//		result["pagination"] = moreRecord;


		//		response.Object = result;
		//		response.Success = true;
		//		response.Message = "";
		//	}
		//	catch (Exception ex)
		//	{
		//		response.Success = false;
		//		response.Message = ex.Message;
		//	}
		//	return Json(response);
		//}

		//[AllowAnonymous]
		//[Route("api/v3.0/p/core/framework.css")]
		//[ResponseCache(NoStore = false, Duration = 30 * 24 * 3600)]
		//[HttpGet]
		//public ContentResult FrameworkCss()
		//{
		//	try
		//	{
		//		var cssContent = "";

		//		if (String.IsNullOrWhiteSpace(ErpAppContext.Current.StyleFrameworkContent))
		//		{
		//			new ThemeService().GenerateStyleFrameworkContent();
		//		}

		//		cssContent = ErpAppContext.Current.StyleFrameworkContent;
		//		return Content(cssContent, "text/css");
		//	}
		//	catch (Exception ex)
		//	{
		//		new Log().Create(LogType.Error, "FrameworkCss API Method Error", ex);
		//		throw ex;
		//	}
		//}


		#region << UI component support >>

		[Produces("application/json")]
		[Route("api/v3.0/p/core/related-field-multiselect")]
		[AcceptVerbs("GET", "POST")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult RelatedFieldMultiSelect(string entityName, string fieldName, string search = "", int page = 1)
		{
			try
			{
				var response = new TypeaheadResponse();
				var errorResponse = new ResponseModel();
				var recMan = new RecordManager();
				if (String.IsNullOrWhiteSpace(entityName))
				{
					errorResponse.Message = "entity name is required";
					Response.StatusCode = (int)HttpStatusCode.BadRequest;
					return Json(errorResponse);
				}
				if (String.IsNullOrWhiteSpace(fieldName))
				{
					errorResponse.Message = "field name is required";
					Response.StatusCode = (int)HttpStatusCode.BadRequest;
					return Json(errorResponse);
				}

				var pageSize = 5 + 1; //the extra record will tell us if there are more records
				var skipPages = (page - 1) * pageSize;
				var sortList = new List<QuerySortObject>();
				sortList.Add(new QuerySortObject(fieldName, QuerySortType.Ascending));

				var query = new EntityQuery(entityName, fieldName, null, sortList.ToArray(), skipPages, pageSize);
				if (!String.IsNullOrWhiteSpace(search))
				{
					query = new EntityQuery(entityName, fieldName, EntityQuery.QueryContains(fieldName, search), sortList.ToArray(), skipPages, pageSize);
				}

				var findResult = recMan.Find(query);
				var resultRecords = new List<EntityRecord>();
				if (!findResult.Success)
				{
					errorResponse.Message = findResult.Message;
					Response.StatusCode = (int)HttpStatusCode.BadRequest;
					return Json(errorResponse);
				}

				if (findResult.Object.Data.Count > 0)
				{
					if (findResult.Object.Data.Count == 6)
					{
						response.Pagination.More = true;
						resultRecords = findResult.Object.Data.Take(5).ToList();
					}
					else
					{
						resultRecords = findResult.Object.Data;
					}

					var entity = new EntityManager().ReadEntity(entityName).Object;
					foreach (var record in resultRecords)
					{
						response.Results.Add(new TypeaheadResponseRow
						{
							Id = record[fieldName].ToString(),
							Text = record[fieldName].ToString(),
							FieldName = fieldName,
							EntityName = entity.Label,
							Color = entity.Color,
							IconName = entity.IconName
						});
					}
				}
				return new JsonResult(response);
			}
			catch (Exception ex)
			{
				new Log().Create(LogType.Error, "RelatedFieldMultiSelect API Method Error", ex);
				throw;
			}
		}

		[Produces("application/json")]
		[Route("api/v3.0/p/core/select-field-add-option")]
		[AcceptVerbs("PUT")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult SelectFieldAddOption([FromBody] JObject submitObj)
		{
			var response = new ResponseModel();
			var recMan = new RecordManager();
			var entMan = new EntityManager();
			var entityName = "";
			var fieldName = "";
			var optionValue = "";
			try
			{
				#region << Init SubmitObj >>
				foreach (var prop in submitObj.Properties())
				{
					switch (prop.Name.ToLower())
					{
						case "entityname":
							if (!string.IsNullOrWhiteSpace(prop.Value.ToString()))
								entityName = prop.Value.ToString();
							else
							{
								throw new Exception("EntityName is required");
							}
							break;
						case "fieldname":
							if (!string.IsNullOrWhiteSpace(prop.Value.ToString()))
								fieldName = prop.Value.ToString();
							else
							{
								throw new Exception("Field name is required");
							}
							break;
						case "value":
							if (!string.IsNullOrWhiteSpace(prop.Value.ToString()))
								optionValue = prop.Value.ToString();
							else
							{
								throw new Exception("Option value is required");
							}
							break;
					}
				}
				#endregion
				var entityMeta = entMan.ReadEntity(entityName).Object;
				if (entityMeta == null)
				{
					throw new Exception("Entity not found by the provided entityName: " + entityName);
				}
				var fieldMeta = entityMeta.Fields.FirstOrDefault(x => x.Name == fieldName);
				if (fieldMeta == null)
				{
					throw new Exception("Field not found by the provided fieldName: " + fieldMeta + " in entity " + entityName);
				}
				var optionExists = false;
				if (fieldMeta.GetFieldType() == FieldType.SelectField)
				{
					var fieldOptions = ((SelectField)fieldMeta).Options.FirstOrDefault(x => x.Value.ToLowerInvariant() == optionValue.ToLowerInvariant());
					if (fieldOptions != null)
					{
						optionExists = true;
					}
				}
				else if (fieldMeta.GetFieldType() == FieldType.MultiSelectField)
				{
					var fieldOptions = ((MultiSelectField)fieldMeta).Options.FirstOrDefault(x => x.Value.ToLowerInvariant() == optionValue.ToLowerInvariant());
					if (fieldOptions != null)
					{
						optionExists = true;
					}
				}

				if (optionExists)
				{
					throw new Exception("Record not found!");
				}

				if (fieldMeta.GetFieldType() == FieldType.SelectField)
				{
					var newOption = new SelectOption
					{
						Value = optionValue,
						Label = optionValue
					};
					var newFieldMeta = (SelectField)fieldMeta;
					newFieldMeta.Options.Add(newOption);
					var updateResponse = entMan.UpdateField(entityMeta, newFieldMeta.MapTo<InputField>());
					if (!updateResponse.Success)
					{
						throw new Exception(updateResponse.Message);
					}
				}
				else if (fieldMeta.GetFieldType() == FieldType.MultiSelectField)
				{
					var newOption = new SelectOption
					{
						Value = optionValue,
						Label = optionValue
					};
					var newFieldMeta = (MultiSelectField)fieldMeta;
					newFieldMeta.Options.Add(newOption);
					var updateResponse = entMan.UpdateField(entityMeta, newFieldMeta.MapTo<InputField>());
					if (!updateResponse.Success)
					{
						throw new Exception(updateResponse.Message);
					}
				}

				response.Success = true;
				response.Message = "Record created successfully";
			}
			catch (Exception ex)
			{
				new Log().Create(LogType.Error, "RelatedFieldMultiSelect API Method Error", ex);
				response.Success = false;
				response.Message = ex.Message;
			}
			return new JsonResult(response);
		}

		[Produces("text/html")]
		[Route("api/v3.0/{lang}/p/core/ui/field-table-data/generate/preview")]
		[AcceptVerbs("POST")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult FieldTableDataPreview([FromRoute] string lang, [FromBody] JObject submitObj)
		{
			var hasHeader = true;
			var hasHeaderColumn = false;
			string csvData = "";
			string delimiterName = "";
			#region << Init SubmitObj >>
			foreach (var prop in submitObj.Properties())
			{
				switch (prop.Name.ToLower())
				{
					case "hasheader":
						if (!string.IsNullOrWhiteSpace(prop.Value.ToString()))
						{
							var hasHeaderString = prop.Value.ToString();
							if (hasHeaderString.ToLowerInvariant() == "false")
							{
								hasHeader = false;
							}
						}
						break;
					case "hasheadercolumn":
						if (!string.IsNullOrWhiteSpace(prop.Value.ToString()))
						{
							var hasHeaderColumnString = prop.Value.ToString();
							if (hasHeaderColumnString.ToLowerInvariant() == "true")
							{
								hasHeaderColumn = true;
							}
						}
						break;
					case "csv":
						if (!string.IsNullOrWhiteSpace(prop.Value.ToString()))
						{
							csvData = prop.Value.ToString();
						}
						break;
					case "delimiter":
						if (!string.IsNullOrWhiteSpace(prop.Value.ToString()))
						{
							delimiterName = prop.Value.ToString(); //Does not work if first checked for empty string
						}
						break;
				}
			}

			var records = new List<dynamic>();
			try
			{
				records = WebVella.TagHelpers.Utilities.WvHelpers.GetCsvData(csvData, hasHeader, delimiterName);
			}
			//catch (CsvHelperException ex)
			//{
			//	//ex.Data.Values has more info...

			//	if (lang == "bg")
			//	{
			//		return Content("<div class='alert alert-danger p-2'>Грешен формат на данните. Опитайте с друг разделител.</div>");
			//	}
			//	else
			//	{
			//		return Content("<div class='alert alert-danger p-2'>Error in parsing data. Check another delimiter</div>");
			//	}
			//}
			catch
			{
				if (lang == "bg")
				{
					return Content("<div class='alert alert-danger p-2'>Грешен формат на данните. Опитайте с друг разделител.</div>");
				}
				else
				{
					return Content("<div class='alert alert-danger p-2'>Error in parsing data. Check another delimiter</div>");
				}
			}

			#endregion

			var result = new EntityRecord();
			result["hasHeader"] = hasHeader;
			result["hasHeaderColumn"] = hasHeaderColumn;
			result["data"] = records;
			result["lang"] = lang;
			return PartialView("FieldTableDataPreview", result);
		}



		#endregion

		#region << Entity Meta >>

		// Get all entity definitions
		// GET: api/v3/en_US/meta/entity/list/
		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "GET" }, Route = "api/v3/en_US/meta/entity/list")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult GetEntityMetaList(string hash = null)
		{
			var bo = entMan.ReadEntities();

			//check hash and clear data if hash match
			if (bo.Success && bo.Object != null && !string.IsNullOrWhiteSpace(hash) && bo.Hash == hash)
				bo.Object = null;

			return DoResponse(bo);
		}

		// Get entity meta
		// GET: api/v3/en_US/meta/entity/id/{entityId}/
		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "GET" }, Route = "api/v3/en_US/meta/entity/id/{entityId}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult GetEntityMetaById(Guid entityId)
		{
			return DoResponse(entMan.ReadEntity(entityId));
		}

		// Get entity meta
		// GET: api/v3/en_US/meta/entity/{name}/
		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "GET" }, Route = "api/v3/en_US/meta/entity/{Name}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult GetEntityMeta(string Name)
		{
			return DoResponse(entMan.ReadEntity(Name));
		}


		// Create an entity
		// POST: api/v3/en_US/meta/entity
		[AcceptVerbs(new[] { "POST" }, Route = "api/v3/en_US/meta/entity")]
		[ResponseCache(NoStore = true, Duration = 0)]
		[Authorize(Roles = "administrator")]
		public IActionResult CreateEntity([FromBody] InputEntity submitObj)
		{
			var entity = new InputEntity
			{
				Name = submitObj.Name,
				Label = submitObj.Label,
				LabelPlural = submitObj.LabelPlural,
				System = submitObj.System,
				IconName = submitObj.IconName,
				//Weight = submitObj.Weight,
				RecordPermissions = submitObj.RecordPermissions
			};

			return DoResponse(entMan.CreateEntity(entity));
		}

		// Create an entity
		// POST: api/v3/en_US/meta/entity
		[AcceptVerbs(new[] { "PATCH" }, Route = "api/v3/en_US/meta/entity/{StringId}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		[Authorize(Roles = "administrator")]
		public IActionResult PatchEntity(string StringId, [FromBody] JObject submitObj)
		{
			FieldResponse response = new FieldResponse();
			InputEntity entity = new InputEntity();

			try
			{
				if (!Guid.TryParse(StringId, out Guid entityId))
				{
					response.Errors.Add(new ErrorModel("id", StringId, "id parameter is not valid Guid value"));
					return DoResponse(response);
				}

				DbEntity storageEntity = DbContext.Current.EntityRepository.Read(entityId);
				if (storageEntity == null)
				{
					response.Timestamp = DateTime.UtcNow;
					response.Success = false;
					response.Message = "Entity with such Name does not exist!";
					return DoBadRequestResponse(response);
				}
				entity = storageEntity.MapTo<Entity>().MapTo<InputEntity>();

				Type inputEntityType = entity.GetType();

				foreach (var prop in submitObj.Properties())
				{
					int count = inputEntityType.GetProperties().Where(n => n.Name.ToLower() == prop.Name.ToLower()).Count();
					if (count < 1)
						response.Errors.Add(new ErrorModel(prop.Name, prop.Value.ToString(), "Input object contains property that is not part of the object model."));
				}

				if (response.Errors.Count > 0)
					return DoBadRequestResponse(response);

				InputEntity inputEntity = submitObj.ToObject<InputEntity>();

				foreach (var prop in submitObj.Properties())
				{
					if (prop.Name.ToLower() == "label")
						entity.Label = inputEntity.Label;
					if (prop.Name.ToLower() == "labelplural")
						entity.LabelPlural = inputEntity.LabelPlural;
					if (prop.Name.ToLower() == "system")
						entity.System = inputEntity.System;
					if (prop.Name.ToLower() == "iconname")
						entity.IconName = inputEntity.IconName;
					if (prop.Name.ToLower() == "color")
						entity.Color = inputEntity.Color;
					//if (prop.Name.ToLower() == "weight")
					//	entity.Weight = inputEntity.Weight;
					if (prop.Name.ToLower() == "recordpermissions")
						entity.RecordPermissions = inputEntity.RecordPermissions;
					if (prop.Name.ToLower() == "recordscreenidfield")
						entity.RecordScreenIdField = inputEntity.RecordScreenIdField;
				}
			}
			catch (Exception e)
			{
				new LogService().Create(Diagnostics.LogType.Error, "TErpApi:PatchEntity", e);
				return DoBadRequestResponse(response, "Input object is not in valid format! It cannot be converted.", e);
			}

			return DoResponse(entMan.UpdateEntity(entity));
		}


		// Delete an entity
		// DELETE: api/v3/en_US/meta/entity/{id}
		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "DELETE" }, Route = "api/v3/en_US/meta/entity/{StringId}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult DeleteEntity(string StringId)
		{
			EntityResponse response = new EntityResponse();

			// Parse each string representation.
			Guid id = Guid.Empty;
			if (Guid.TryParse(StringId, out Guid newGuid))
			{
				response = entMan.DeleteEntity(newGuid);
			}
			else
			{
				response.Success = false;
				response.Message = "The entity Id should be a valid Guid";
				HttpContext.Response.StatusCode = (int)HttpStatusCode.BadRequest;
			}
			return DoResponse(response);
		}

		#endregion

		#region << Entity Fields >>

		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "POST" }, Route = "api/v3/en_US/meta/entity/{Id}/field")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult CreateField(string Id, [FromBody] JObject submitObj)
		{
			FieldResponse response = new FieldResponse();

			if (!Guid.TryParse(Id, out Guid entityId))
			{
				response.Errors.Add(new ErrorModel("id", Id, "id parameter is not valid Guid value"));
				return DoResponse(response);
			}

			InputField field = new InputGuidField();
			try
			{
				field = InputField.ConvertField(submitObj);
			}
			catch (Exception e)
			{
				new LogService().Create(Diagnostics.LogType.Error, "TErpApi:CreateField", e);
				return DoBadRequestResponse(response, "Input object is not in valid format! It cannot be converted.", e);
			}

			return DoResponse(entMan.CreateField(entityId, field));
		}

		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "PUT" }, Route = "api/v3/en_US/meta/entity/{Id}/field/{FieldId}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult UpdateField(string Id, string FieldId, [FromBody] JObject submitObj)
		{
			FieldResponse response = new FieldResponse();

			if (!Guid.TryParse(Id, out Guid entityId))
			{
				response.Errors.Add(new ErrorModel("id", Id, "id parameter is not valid Guid value"));
				return DoResponse(response);
			}

			if (!Guid.TryParse(FieldId, out Guid fieldId))
			{
				response.Errors.Add(new ErrorModel("id", FieldId, "FieldId parameter is not valid Guid value"));
				return DoResponse(response);
			}

			InputField field = new InputGuidField();
			FieldType fieldType = FieldType.GuidField;

			var fieldTypeProp = submitObj.Properties().SingleOrDefault(k => k.Name.ToLower() == "fieldtype");
			if (fieldTypeProp != null)
			{
				fieldType = (FieldType)Enum.ToObject(typeof(FieldType), fieldTypeProp.Value.ToObject<int>());
			}

			Type inputFieldType = InputField.GetFieldType(fieldType);

			foreach (var prop in submitObj.Properties())
			{
				if (prop.Name.ToLower() == "entityname")
					continue;

				int count = inputFieldType.GetProperties().Where(n => n.Name.ToLower() == prop.Name.ToLower()).Count();
				if (count < 1)
					response.Errors.Add(new ErrorModel(prop.Name, prop.Value.ToString(), "Input object contains property that is not part of the object model."));
			}

			if (response.Errors.Count > 0)
				return DoBadRequestResponse(response);

			try
			{
				field = InputField.ConvertField(submitObj);
			}
			catch (Exception e)
			{
				new LogService().Create(Diagnostics.LogType.Error, "TErpApi:UpdateField", e);
				return DoBadRequestResponse(response, "Input object is not in valid format! It cannot be converted.", e);
			}

			return DoResponse(entMan.UpdateField(entityId, field));
		}

		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "PATCH" }, Route = "api/v3/en_US/meta/entity/{Id}/field/{FieldId}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult PatchField(string Id, string FieldId, [FromBody] JObject submitObj)
		{
			FieldResponse response = new FieldResponse();
			Entity entity = new Entity();
			InputField field = new InputGuidField();

			try
			{
				if (!Guid.TryParse(Id, out Guid entityId))
				{
					response.Errors.Add(new ErrorModel("Id", Id, "id parameter is not valid Guid value"));
					return DoBadRequestResponse(response, "Field was not updated!");
				}

				if (!Guid.TryParse(FieldId, out Guid fieldId))
				{
					response.Errors.Add(new ErrorModel("FieldId", FieldId, "FieldId parameter is not valid Guid value"));
					return DoBadRequestResponse(response, "Field was not updated!");
				}

				DbEntity storageEntity = DbContext.Current.EntityRepository.Read(entityId);
				if (storageEntity == null)
				{
					response.Errors.Add(new ErrorModel("Id", Id, "Entity with such Id does not exist!"));
					return DoBadRequestResponse(response, "Field was not updated!");
				}
				entity = storageEntity.MapTo<Entity>();

				Field updatedField = entity.Fields.FirstOrDefault(f => f.Id == fieldId);
				if (updatedField == null)
				{
					response.Errors.Add(new ErrorModel("FieldId", FieldId, "Field with such Id does not exist!"));
					return DoBadRequestResponse(response, "Field was not updated!");
				}

				FieldType fieldType = FieldType.GuidField;

				var fieldTypeProp = submitObj.Properties().SingleOrDefault(k => k.Name.ToLower() == "fieldtype");
				if (fieldTypeProp != null)
				{
					fieldType = (FieldType)Enum.ToObject(typeof(FieldType), fieldTypeProp.Value.ToObject<int>());
				}
				else
				{
					response.Errors.Add(new ErrorModel("fieldType", null, "fieldType is required!"));
					return DoBadRequestResponse(response, "Field was not updated!");
				}

				Type inputFieldType = InputField.GetFieldType(fieldType);
				foreach (var prop in submitObj.Properties())
				{
					if (prop.Name.ToLower() == "entityname")
						continue;

					int count = inputFieldType.GetProperties().Where(n => n.Name.ToLower() == prop.Name.ToLower()).Count();
					if (count < 1)
						response.Errors.Add(new ErrorModel(prop.Name, prop.Value.ToString(), "Input object contains property that is not part of the object model."));
				}

				if (response.Errors.Count > 0)
					return DoBadRequestResponse(response);

				InputField inputField = InputField.ConvertField(submitObj);

				foreach (var prop in submitObj.Properties())
				{
					switch (fieldType)
					{
						case FieldType.AutoNumberField:
							{
								field = new InputAutoNumberField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputAutoNumberField)field).DefaultValue = ((InputAutoNumberField)inputField).DefaultValue;
								if (prop.Name.ToLower() == "U")
									((InputAutoNumberField)field).DisplayFormat = ((InputAutoNumberField)inputField).DisplayFormat;
								if (prop.Name.ToLower() == "startingnumber")
									((InputAutoNumberField)field).StartingNumber = ((InputAutoNumberField)inputField).StartingNumber;
							}
							break;
						case FieldType.CheckboxField:
							{
								field = new InputCheckboxField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputCheckboxField)field).DefaultValue = ((InputCheckboxField)inputField).DefaultValue;
							}
							break;
						case FieldType.CurrencyField:
							{
								field = new InputCurrencyField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputCurrencyField)field).DefaultValue = ((InputCurrencyField)inputField).DefaultValue;
								if (prop.Name.ToLower() == "minvalue")
									((InputCurrencyField)field).MinValue = ((InputCurrencyField)inputField).MinValue;
								if (prop.Name.ToLower() == "maxvalue")
									((InputCurrencyField)field).MaxValue = ((InputCurrencyField)inputField).MaxValue;
								if (prop.Name.ToLower() == "currency")
									((InputCurrencyField)field).Currency = ((InputCurrencyField)inputField).Currency;
							}
							break;
						case FieldType.DateField:
							{
								field = new InputDateField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputDateField)field).DefaultValue = ((InputDateField)inputField).DefaultValue;
								if (prop.Name.ToLower() == "format")
									((InputDateField)field).Format = ((InputDateField)inputField).Format;
								if (prop.Name.ToLower() == "usecurrenttimeasdefaultvalue")
									((InputDateField)field).UseCurrentTimeAsDefaultValue = ((InputDateField)inputField).UseCurrentTimeAsDefaultValue;
							}
							break;
						case FieldType.DateTimeField:
							{
								field = new InputDateTimeField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputDateTimeField)field).DefaultValue = ((InputDateTimeField)inputField).DefaultValue;
								if (prop.Name.ToLower() == "format")
									((InputDateTimeField)field).Format = ((InputDateTimeField)inputField).Format;
								if (prop.Name.ToLower() == "usecurrenttimeasdefaultvalue")
									((InputDateTimeField)field).UseCurrentTimeAsDefaultValue = ((InputDateTimeField)inputField).UseCurrentTimeAsDefaultValue;
							}
							break;
						case FieldType.EmailField:
							{
								field = new InputEmailField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputEmailField)field).DefaultValue = ((InputEmailField)inputField).DefaultValue;
								if (prop.Name.ToLower() == "maxlength")
									((InputEmailField)field).MaxLength = ((InputEmailField)inputField).MaxLength;
							}
							break;
						case FieldType.FileField:
							{
								field = new InputFileField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputFileField)field).DefaultValue = ((InputFileField)inputField).DefaultValue;
							}
							break;
						case FieldType.HtmlField:
							{
								field = new InputHtmlField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputHtmlField)field).DefaultValue = ((InputHtmlField)inputField).DefaultValue;
							}
							break;
						case FieldType.ImageField:
							{
								field = new InputImageField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputImageField)field).DefaultValue = ((InputImageField)inputField).DefaultValue;
							}
							break;
						case FieldType.MultiLineTextField:
							{
								field = new InputMultiLineTextField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputMultiLineTextField)field).DefaultValue = ((InputMultiLineTextField)inputField).DefaultValue;
								if (prop.Name.ToLower() == "maxlength")
									((InputMultiLineTextField)field).MaxLength = ((InputMultiLineTextField)inputField).MaxLength;
								if (prop.Name.ToLower() == "visiblelinenumber")
									((InputMultiLineTextField)field).VisibleLineNumber = ((InputMultiLineTextField)inputField).VisibleLineNumber;
							}
							break;
						case FieldType.GeographyField:
							{
								field = new InputGeographyField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputGeographyField)field).DefaultValue = ((InputGeographyField)inputField).DefaultValue;
								if (prop.Name.ToLower() == "maxlength")
									((InputGeographyField)field).MaxLength = ((InputGeographyField)inputField).MaxLength;
								if (prop.Name.ToLower() == "visiblelinenumber")
									((InputGeographyField)field).VisibleLineNumber = ((InputGeographyField)inputField).VisibleLineNumber;
								if (prop.Name.ToLower() == "format")
									((InputGeographyField)field).Format = ((InputGeographyField)inputField).Format;
								if (prop.Name.ToLower() == "srid")
									((InputGeographyField)field).SRID = ((InputGeographyField)inputField).SRID;
							}
							break;
						case FieldType.MultiSelectField:
							{
								field = new InputMultiSelectField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputMultiSelectField)field).DefaultValue = ((InputMultiSelectField)inputField).DefaultValue;
								if (prop.Name.ToLower() == "options")
									((InputMultiSelectField)field).Options = ((InputMultiSelectField)inputField).Options;
							}
							break;
						case FieldType.NumberField:
							{
								field = new InputNumberField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputNumberField)field).DefaultValue = ((InputNumberField)inputField).DefaultValue;
								if (prop.Name.ToLower() == "minvalue")
									((InputNumberField)field).MinValue = ((InputNumberField)inputField).MinValue;
								if (prop.Name.ToLower() == "maxvalue")
									((InputNumberField)field).MaxValue = ((InputNumberField)inputField).MaxValue;
								if (prop.Name.ToLower() == "decimalplaces")
									((InputNumberField)field).DecimalPlaces = ((InputNumberField)inputField).DecimalPlaces;
							}
							break;
						case FieldType.PasswordField:
							{
								field = new InputPasswordField();
								if (prop.Name.ToLower() == "maxlength")
									((InputPasswordField)field).MaxLength = ((InputPasswordField)inputField).MaxLength;
								if (prop.Name.ToLower() == "minlength")
									((InputPasswordField)field).MinLength = ((InputPasswordField)inputField).MinLength;
								if (prop.Name.ToLower() == "encrypted")
									((InputPasswordField)field).Encrypted = ((InputPasswordField)inputField).Encrypted;
							}
							break;
						case FieldType.PercentField:
							{
								field = new InputPercentField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputPercentField)field).DefaultValue = ((InputPercentField)inputField).DefaultValue;
								if (prop.Name.ToLower() == "minvalue")
									((InputPercentField)field).MinValue = ((InputPercentField)inputField).MinValue;
								if (prop.Name.ToLower() == "maxvalue")
									((InputPercentField)field).MaxValue = ((InputPercentField)inputField).MaxValue;
								if (prop.Name.ToLower() == "decimalplaces")
									((InputPercentField)field).DecimalPlaces = ((InputPercentField)inputField).DecimalPlaces;
							}
							break;
						case FieldType.PhoneField:
							{
								field = new InputPhoneField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputPhoneField)field).DefaultValue = ((InputPhoneField)inputField).DefaultValue;
								if (prop.Name.ToLower() == "format")
									((InputPhoneField)field).Format = ((InputPhoneField)inputField).Format;
								if (prop.Name.ToLower() == "maxlength")
									((InputPhoneField)field).MaxLength = ((InputPhoneField)inputField).MaxLength;
							}
							break;
						case FieldType.GuidField:
							{
								field = new InputGuidField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputGuidField)field).DefaultValue = ((InputGuidField)inputField).DefaultValue;
								if (prop.Name.ToLower() == "generatenewid")
									((InputGuidField)field).GenerateNewId = ((InputGuidField)inputField).GenerateNewId;
							}
							break;
						case FieldType.SelectField:
							{
								field = new InputSelectField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputSelectField)field).DefaultValue = ((InputSelectField)inputField).DefaultValue;
								if (prop.Name.ToLower() == "options")
									((InputSelectField)field).Options = ((InputSelectField)inputField).Options;
							}
							break;
						case FieldType.TextField:
							{
								field = new InputTextField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputTextField)field).DefaultValue = ((InputTextField)inputField).DefaultValue;
								if (prop.Name.ToLower() == "maxlength")
									((InputTextField)field).MaxLength = ((InputTextField)inputField).MaxLength;
							}
							break;
						case FieldType.UrlField:
							{
								field = new InputUrlField();
								if (prop.Name.ToLower() == "defaultvalue")
									((InputUrlField)field).DefaultValue = ((InputUrlField)inputField).DefaultValue;
								if (prop.Name.ToLower() == "maxlength")
									((InputUrlField)field).MaxLength = ((InputUrlField)inputField).MaxLength;
								if (prop.Name.ToLower() == "opentargetinnewwindow")
									((InputUrlField)field).OpenTargetInNewWindow = ((InputUrlField)inputField).OpenTargetInNewWindow;
							}
							break;
					}

					if (prop.Name.ToLower() == "label")
						field.Label = inputField.Label;
					else if (prop.Name.ToLower() == "placeholdertext")
						field.PlaceholderText = inputField.PlaceholderText;
					else if (prop.Name.ToLower() == "description")
						field.Description = inputField.Description;
					else if (prop.Name.ToLower() == "helptext")
						field.HelpText = inputField.HelpText;
					else if (prop.Name.ToLower() == "required")
						field.Required = inputField.Required;
					else if (prop.Name.ToLower() == "unique")
						field.Unique = inputField.Unique;
					else if (prop.Name.ToLower() == "searchable")
						field.Searchable = inputField.Searchable;
					else if (prop.Name.ToLower() == "auditable")
						field.Auditable = inputField.Auditable;
					else if (prop.Name.ToLower() == "system")
						field.System = inputField.System;
				}
			}
			catch (Exception e)
			{
				new LogService().Create(Diagnostics.LogType.Error, "TErpApi:PatchField", e);
				return DoBadRequestResponse(response, "Input object is not in valid format! It cannot be converted.", e);
			}

			return DoResponse(entMan.UpdateField(entity, field));
		}

		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "DELETE" }, Route = "api/v3/en_US/meta/entity/{Id}/field/{FieldId}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult DeleteField(string Id, string FieldId)
		{
			FieldResponse response = new FieldResponse();

			if (!Guid.TryParse(Id, out Guid entityId))
			{
				response.Errors.Add(new ErrorModel("id", Id, "id parameter is not valid Guid value"));
				return DoResponse(response);
			}

			if (!Guid.TryParse(FieldId, out Guid fieldId))
			{
				response.Errors.Add(new ErrorModel("id", FieldId, "FieldId parameter is not valid Guid value"));
				return DoResponse(response);
			}

			return DoResponse(entMan.DeleteField(entityId, fieldId));
		}

		#endregion

		#region << Relation Meta >>
		// Get all entity relation definitions
		// GET: api/v3/en_US/meta/relation/list/
		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "GET" }, Route = "api/v3/en_US/meta/relation/list")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult GetEntityRelationMetaList(string hash = null)
		{
			var response = new EntityRelationManager().Read();

			//check hash and clear data if hash match
			if (response.Success && response.Object != null && !string.IsNullOrWhiteSpace(hash) && response.Hash == hash)
				response.Object = null;

			return DoResponse(response);
		}

		// Get entity relation meta
		// GET: api/v3/en_US/meta/relation/{name}/
		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "GET" }, Route = "api/v3/en_US/meta/relation/{name}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult GetEntityRelationMeta(string name)
		{
			return DoResponse(new EntityRelationManager().Read(name));
		}


		// Create an entity relation
		// POST: api/v3/en_US/meta/relation
		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "POST" }, Route = "api/v3/en_US/meta/relation")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult CreateEntityRelation([FromBody] JObject submitObj)
		{
			try
			{
				if (submitObj["id"].IsNullOrEmpty())
					submitObj["id"] = Guid.NewGuid();
				var relation = submitObj.ToObject<EntityRelation>();
				return DoResponse(new EntityRelationManager().Create(relation));
			}
			catch (Exception e)
			{
				new LogService().Create(Diagnostics.LogType.Error, "TErpApi:CreateEntityRelation", e);
				return DoBadRequestResponse(new EntityRelationResponse(), null, e);
			}
		}

		// Update an entity relation
		// PUT: api/v3/en_US/meta/relation/id
		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "PUT" }, Route = "api/v3/en_US/meta/relation/{RelationIdString}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult UpdateEntityRelation(string RelationIdString, [FromBody] JObject submitObj)
		{
			FieldResponse response = new FieldResponse();

			if (!Guid.TryParse(RelationIdString, out Guid relationId))
			{
				response.Errors.Add(new ErrorModel("id", RelationIdString, "id parameter is not valid Guid value"));
				return DoResponse(response);
			}

			try
			{
				var relation = submitObj.ToObject<EntityRelation>();
				return DoResponse(new EntityRelationManager().Update(relation));
			}
			catch (Exception e)
			{
				new LogService().Create(Diagnostics.LogType.Error, "TErpApi:UpdateEntityRelation", e);
				return DoBadRequestResponse(new EntityRelationResponse(), null, e);
			}
		}

		// Delete an entity relation
		// DELETE: api/v3/en_US/meta/relation/{idToken}
		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "DELETE" }, Route = "api/v3/en_US/meta/relation/{idToken}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult DeleteEntityRelation(string idToken)
		{
			Guid id = Guid.Empty;
			if (Guid.TryParse(idToken, out Guid newGuid))
			{
				return DoResponse(new EntityRelationManager().Delete(newGuid));
			}
			else
			{
				return DoBadRequestResponse(new EntityRelationResponse(), "The entity relation Id should be a valid Guid", null);
			}

		}

		#endregion

		#region << Records >>

		// Update an entity record relation records for origin record
		// POST: api/v3/en_US/record/relation
		[AcceptVerbs(new[] { "POST" }, Route = "api/v3/en_US/record/relation")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult UpdateEntityRelationRecord([FromBody] InputEntityRelationRecordUpdateModel model)
		{

			var recMan = new RecordManager();
			var entMan = new EntityManager();
			BaseResponseModel response = new BaseResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };

			if (model == null)
			{
				response.Errors.Add(new ErrorModel { Message = "Invalid model." });
				response.Success = false;
				return DoResponse(response);
			}

			EntityRelation relation = null;
			if (string.IsNullOrWhiteSpace(model.RelationName))
			{
				response.Errors.Add(new ErrorModel { Message = "Invalid relation name.", Key = "relationName" });
				response.Success = false;
				return DoResponse(response);
			}
			else
			{
				relation = new EntityRelationManager().Read(model.RelationName).Object;
				if (relation == null)
				{
					response.Errors.Add(new ErrorModel { Message = "Invalid relation name. No relation with that name.", Key = "relationName" });
					response.Success = false;
					return DoResponse(response);
				}
			}

			var originEntity = entMan.ReadEntity(relation.OriginEntityId).Object;
			var targetEntity = entMan.ReadEntity(relation.TargetEntityId).Object;
			var originField = originEntity.Fields.Single(x => x.Id == relation.OriginFieldId);
			var targetField = targetEntity.Fields.Single(x => x.Id == relation.TargetFieldId);

			if (model.DetachTargetFieldRecordIds != null && model.DetachTargetFieldRecordIds.Any() && targetField.Required && relation.RelationType != EntityRelationType.ManyToMany)
			{
				response.Errors.Add(new ErrorModel { Message = "Cannot detach records, when target field is required.", Key = "originFieldRecordId" });
				response.Success = false;
				return DoResponse(response);
			}

			EntityQuery query = new EntityQuery(originEntity.Name, "id," + originField.Name, EntityQuery.QueryEQ("id", model.OriginFieldRecordId), null, null, null);
			QueryResponse result = recMan.Find(query);
			if (result.Object.Data.Count == 0)
			{
				response.Errors.Add(new ErrorModel { Message = "Origin record was not found. Id=[" + model.OriginFieldRecordId + "]", Key = "originFieldRecordId" });
				response.Success = false;
				return DoResponse(response);
			}

			var originRecord = result.Object.Data[0];
			object originValue = originRecord[originField.Name];

			var attachTargetRecords = new List<EntityRecord>();
			var detachTargetRecords = new List<EntityRecord>();

			foreach (var targetId in model.AttachTargetFieldRecordIds)
			{
				query = new EntityQuery(targetEntity.Name, "id," + targetField.Name, EntityQuery.QueryEQ("id", targetId), null, null, null);
				result = recMan.Find(query);
				if (result.Object.Data.Count == 0)
				{
					response.Errors.Add(new ErrorModel { Message = "Attach target record was not found. Id=[" + targetEntity.Id + "]", Key = "targetRecordId" });
					response.Success = false;
					return DoResponse(response);
				}
				else if (attachTargetRecords.Any(x => (Guid)x["id"] == targetId))
				{
					response.Errors.Add(new ErrorModel { Message = "Attach target id was duplicated. Id=[" + targetEntity.Id + "]", Key = "targetRecordId" });
					response.Success = false;
					return DoResponse(response);
				}
				attachTargetRecords.Add(result.Object.Data[0]);
			}

			foreach (var targetId in model.DetachTargetFieldRecordIds)
			{
				query = new EntityQuery(targetEntity.Name, "id," + targetField.Name, EntityQuery.QueryEQ("id", targetId), null, null, null);
				result = recMan.Find(query);
				if (result.Object.Data.Count == 0)
				{
					response.Errors.Add(new ErrorModel { Message = "Detach target record was not found. Id=[" + targetEntity.Id + "]", Key = "targetRecordId" });
					response.Success = false;
					return DoResponse(response);
				}
				else if (detachTargetRecords.Any(x => (Guid)x["id"] == targetId))
				{
					response.Errors.Add(new ErrorModel { Message = "Detach target id was duplicated. Id=[" + targetEntity.Id + "]", Key = "targetRecordId" });
					response.Success = false;
					return DoResponse(response);
				}
				detachTargetRecords.Add(result.Object.Data[0]);
			}

			using (var connection = DbContext.Current.CreateConnection())
			{
				connection.BeginTransaction();

				try
				{
					switch (relation.RelationType)
					{
						case EntityRelationType.OneToOne:
						case EntityRelationType.OneToMany:
							{
								foreach (var record in detachTargetRecords)
								{
									record[targetField.Name] = null;

									var updResult = recMan.UpdateRecord(targetEntity, record);
									if (!updResult.Success)
									{
										connection.RollbackTransaction();
										response.Errors = updResult.Errors;
										response.Message = "Target record id=[" + record["id"] + "] detach operation failed.";
										response.Success = false;
										return DoResponse(response);
									}
								}

								foreach (var record in attachTargetRecords)
								{
									var patchObject = new EntityRecord();
									patchObject["id"] = (Guid)record["id"];
									patchObject[targetField.Name] = originValue;

									var updResult = recMan.UpdateRecord(targetEntity, patchObject);
									if (!updResult.Success)
									{
										connection.RollbackTransaction();
										response.Errors = updResult.Errors;
										response.Message = "Target record id=[" + record["id"] + "] attach operation failed.";
										response.Success = false;
										return DoResponse(response);
									}
								}
							}
							break;
						case EntityRelationType.ManyToMany:
							{
								foreach (var record in detachTargetRecords)
								{
									QueryResponse updResult = recMan.RemoveRelationManyToManyRecord(relation.Id, (Guid)originValue, (Guid)record[targetField.Name]);

									if (!updResult.Success)
									{
										connection.RollbackTransaction();
										response.Errors = updResult.Errors;
										response.Message = "Target record id=[" + record["id"] + "] detach operation failed.";
										response.Success = false;
										return DoResponse(response);
									}
								}

								foreach (var record in attachTargetRecords)
								{
									QueryResponse updResult = recMan.CreateRelationManyToManyRecord(relation.Id, (Guid)originValue, (Guid)record[targetField.Name]);

									if (!updResult.Success)
									{
										connection.RollbackTransaction();
										response.Errors = updResult.Errors;
										response.Message = "Target record id=[" + record["id"] + "] attach  operation failed.";
										response.Success = false;
										return DoResponse(response);
									}
								}
							}
							break;
						default:
							{
								connection.RollbackTransaction();
								throw new Exception("Not supported relation type");
							}
					}

					connection.CommitTransaction();
				}
				catch (Exception ex)
				{
					connection.RollbackTransaction();
					new LogService().Create(Diagnostics.LogType.Error, "TErpApi:UpdateEntityRelationRecord", ex);
					response.Success = false;
					response.Message = ex.Message;
					return DoResponse(response);
				}
			}

			return DoResponse(response);
		}


		// Update an entity record relation records for target record
		// POST: api/v3/en_US/record/relation/reverse
		[AcceptVerbs(new[] { "POST" }, Route = "api/v3/en_US/record/relation/reverse")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult UpdateEntityRelationRecordReverse([FromBody] InputEntityRelationRecordReverseUpdateModel model)
		{

			var recMan = new RecordManager();
			var entMan = new EntityManager();
			BaseResponseModel response = new BaseResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };

			if (model == null)
			{
				response.Errors.Add(new ErrorModel { Message = "Invalid model." });
				response.Success = false;
				return DoResponse(response);
			}

			EntityRelation relation = null;
			if (string.IsNullOrWhiteSpace(model.RelationName))
			{
				response.Errors.Add(new ErrorModel { Message = "Invalid relation name.", Key = "relationName" });
				response.Success = false;
				return DoResponse(response);
			}
			else
			{
				relation = new EntityRelationManager().Read(model.RelationName).Object;
				if (relation == null)
				{
					response.Errors.Add(new ErrorModel { Message = "Invalid relation name. No relation with that name.", Key = "relationName" });
					response.Success = false;
					return DoResponse(response);
				}
			}

			var originEntity = entMan.ReadEntity(relation.OriginEntityId).Object;
			var targetEntity = entMan.ReadEntity(relation.TargetEntityId).Object;
			var originField = originEntity.Fields.Single(x => x.Id == relation.OriginFieldId);
			var targetField = targetEntity.Fields.Single(x => x.Id == relation.TargetFieldId);

			if (model.DetachOriginFieldRecordIds != null && model.DetachOriginFieldRecordIds.Any() && originField.Required && relation.RelationType != EntityRelationType.ManyToMany)
			{
				response.Errors.Add(new ErrorModel { Message = "Cannot detach records, when origin field is required.", Key = "originFieldRecordId" });
				response.Success = false;
				return DoResponse(response);
			}

			EntityQuery query = new EntityQuery(targetEntity.Name, "id," + targetField.Name, EntityQuery.QueryEQ("id", model.TargetFieldRecordId), null, null, null);
			QueryResponse result = recMan.Find(query);
			if (result.Object.Data.Count == 0)
			{
				response.Errors.Add(new ErrorModel { Message = "Target record was not found. Id=[" + model.TargetFieldRecordId + "]", Key = "targetFieldRecordId" });
				response.Success = false;
				return DoResponse(response);
			}

			var targetRecord = result.Object.Data[0];
			object targetValue = targetRecord[targetField.Name];

			var attachOriginRecords = new List<EntityRecord>();
			var detachOriginRecords = new List<EntityRecord>();

			foreach (var originId in model.AttachOriginFieldRecordIds)
			{
				query = new EntityQuery(originEntity.Name, "id," + originField.Name, EntityQuery.QueryEQ("id", originId), null, null, null);
				result = recMan.Find(query);
				if (result.Object.Data.Count == 0)
				{
					response.Errors.Add(new ErrorModel { Message = "Attach origin record was not found. Id=[" + originEntity.Id + "]", Key = "originRecordId" });
					response.Success = false;
					return DoResponse(response);
				}
				else if (attachOriginRecords.Any(x => (Guid)x["id"] == originId))
				{
					response.Errors.Add(new ErrorModel { Message = "Attach origin id was duplicated. Id=[" + originEntity.Id + "]", Key = "originRecordId" });
					response.Success = false;
					return DoResponse(response);
				}
				attachOriginRecords.Add(result.Object.Data[0]);
			}

			foreach (var originId in model.DetachOriginFieldRecordIds)
			{
				query = new EntityQuery(originEntity.Name, "id," + originField.Name, EntityQuery.QueryEQ("id", originId), null, null, null);
				result = recMan.Find(query);
				if (result.Object.Data.Count == 0)
				{
					response.Errors.Add(new ErrorModel { Message = "Detach origin record was not found. Id=[" + originEntity.Id + "]", Key = "originRecordId" });
					response.Success = false;
					return DoResponse(response);
				}
				else if (detachOriginRecords.Any(x => (Guid)x["id"] == originId))
				{
					response.Errors.Add(new ErrorModel { Message = "Detach origin id was duplicated. Id=[" + originEntity.Id + "]", Key = "originRecordId" });
					response.Success = false;
					return DoResponse(response);
				}
				detachOriginRecords.Add(result.Object.Data[0]);
			}

			using (var connection = DbContext.Current.CreateConnection())
			{
				connection.BeginTransaction();

				try
				{
					switch (relation.RelationType)
					{
						case EntityRelationType.OneToOne:
						case EntityRelationType.OneToMany:
							{
								foreach (var record in detachOriginRecords)
								{
									record[originField.Name] = null;

									var updResult = recMan.UpdateRecord(originEntity, record);
									if (!updResult.Success)
									{
										connection.RollbackTransaction();
										response.Errors = updResult.Errors;
										response.Message = "Origin record id=[" + record["id"] + "] detach operation failed.";
										response.Success = false;
										return DoResponse(response);
									}
								}

								foreach (var record in attachOriginRecords)
								{
									var patchObject = new EntityRecord();
									patchObject["id"] = (Guid)record["id"];
									patchObject[originField.Name] = targetValue;

									var updResult = recMan.UpdateRecord(originEntity, patchObject);
									if (!updResult.Success)
									{
										connection.RollbackTransaction();
										response.Errors = updResult.Errors;
										response.Message = "Origin record id=[" + record["id"] + "] attach operation failed.";
										response.Success = false;
										return DoResponse(response);
									}
								}
							}
							break;
						case EntityRelationType.ManyToMany:
							{
								foreach (var record in detachOriginRecords)
								{
									QueryResponse updResult = recMan.RemoveRelationManyToManyRecord(relation.Id, (Guid)record[originField.Name], (Guid)targetValue);

									if (!updResult.Success)
									{
										connection.RollbackTransaction();
										response.Errors = updResult.Errors;
										response.Message = "Origin record id=[" + record["id"] + "] detach operation failed.";
										response.Success = false;
										return DoResponse(response);
									}
								}

								foreach (var record in attachOriginRecords)
								{
									QueryResponse updResult = recMan.CreateRelationManyToManyRecord(relation.Id, (Guid)record[originField.Name], (Guid)targetValue);

									if (!updResult.Success)
									{
										connection.RollbackTransaction();
										response.Errors = updResult.Errors;
										response.Message = "Origin record id=[" + record["id"] + "] attach  operation failed.";
										response.Success = false;
										return DoResponse(response);
									}
								}
							}
							break;
						default:
							{
								connection.RollbackTransaction();
								throw new Exception("Not supported relation type");
							}
					}

					connection.CommitTransaction();
				}
				catch (Exception ex)
				{
					connection.RollbackTransaction();
					new LogService().Create(Diagnostics.LogType.Error, "TErpApi:UpdateEntityRelationRecordReverse", ex);
					response.Success = false;
					response.Message = ex.Message;
					return DoResponse(response);
				}
			}

			return DoResponse(response);
		}


		// Get an entity record list
		// GET: api/v3/en_US/record/{entityName}/list
		[AcceptVerbs(new[] { "GET" }, Route = "api/v3/en_US/record/{entityName}/{recordId}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult GetRecord(Guid recordId, string entityName, string fields = "*")
		{
			QueryObject filterObj = EntityQuery.QueryEQ("id", recordId);

			EntityQuery query = new EntityQuery(entityName, fields, filterObj, null, null, null);

			QueryResponse result = recMan.Find(query);
			if (!result.Success)
				return DoResponse(result);

			return Json(result);
		}

		// Get an entity record list
		// GET: api/v3/en_US/record/{entityName}/list
		[AcceptVerbs(new[] { "DELETE" }, Route = "api/v3/en_US/record/{entityName}/{recordId}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult DeleteRecord(Guid recordId, string entityName)
		{
			//Create transaction
			var result = new QueryResponse();
			using (var connection = DbContext.Current.CreateConnection())
			{
				try
				{
					connection.BeginTransaction();
					result = recMan.DeleteRecord(entityName, recordId);
					connection.CommitTransaction();
				}
				catch (Exception ex)
				{
					connection.RollbackTransaction();
					new LogService().Create(Diagnostics.LogType.Error, "TErpApi:DeleteRecord", ex);
					var response = new ResponseModel
					{
						Success = false,
						Timestamp = DateTime.UtcNow,
						Message = "Error while delete the record: " + ex.Message,
						Object = null
					};
					return Json(response);
				}
			}

			return DoResponse(result);
		}

		// Get an entity records by field and regex
		// GET: api/v3/en_US/record/{entityName}/regex
		[AcceptVerbs(new[] { "POST" }, Route = "api/v3/en_US/record/{entityName}/regex/{fieldName}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult GetRecordsByFieldAndRegex(string fieldName, string entityName, [FromBody] EntityRecord patternObj)
		{

			QueryObject filterObj = EntityQuery.QueryRegex(fieldName, patternObj["pattern"]);

			EntityQuery query = new EntityQuery(entityName, "*", filterObj, null, null, null);

			QueryResponse result = recMan.Find(query);
			if (!result.Success)
				return DoResponse(result);
			return Json(result);
		}


		// Create an entity record
		// POST: api/v3/en_US/record/{entityName}
		[AcceptVerbs(new[] { "POST" }, Route = "api/v3/en_US/record/{entityName}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult CreateEntityRecord(string entityName, [FromBody] EntityRecord postObj)
		{
			//Find and change properties starting with _$ to $$ - angular does not post $$ propery names
			postObj = Helpers.FixDoubleDollarSignProblem(postObj);

			if (!postObj.GetProperties().Any(x => x.Key == "id"))
				postObj["id"] = Guid.NewGuid();
			else if (string.IsNullOrEmpty(postObj["id"] as string))
				postObj["id"] = Guid.NewGuid();


			//Create transaction
			var result = new QueryResponse();
			using (var connection = DbContext.Current.CreateConnection())
			{
				try
				{
					connection.BeginTransaction();
					result = recMan.CreateRecord(entityName, postObj);
					connection.CommitTransaction();
				}
				catch (Exception ex)
				{
					connection.RollbackTransaction();
					new LogService().Create(Diagnostics.LogType.Error, "TErpApi:CreateEntityRecord", ex);
					var response = new ResponseModel
					{
						Success = false,
						Timestamp = DateTime.UtcNow,
						Message = "Error while saving the record: " + ex.Message,
						Object = null
					};
					return Json(response);
				}
			}

			return DoResponse(result);
		}

		[AcceptVerbs(new[] { "POST" }, Route = "api/v3/en_US/record/{entityName}/with-relation/{relationName}/{relatedRecordId}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult CreateEntityRecordWithRelation(string entityName, string relationName, Guid relatedRecordId, [FromBody] EntityRecord postObj)
		{
			var validationErrors = new List<ErrorModel>();

			//1.Validate relationName
			//1.1. Relation exists
			var relation = relMan.Read().Object.SingleOrDefault(x => x.Name == relationName);
			string targetEntityName = String.Empty;
			string targetFieldName = String.Empty;
			var relatedRecord = new EntityRecord();
			var relatedRecordResponse = new QueryResponse();
			if (relation == null)
			{
				var error = new ErrorModel
				{
					Key = "relationName",
					Value = relationName,
					Message = "A relation with this name, does not exist"
				};
				validationErrors.Add(error);
			}
			else
			{
				//1.2. Relation is correct - entityName is part of this relation
				if (relation.OriginEntityName != entityName && relation.TargetEntityName != entityName)
				{
					var error = new ErrorModel
					{
						Key = "relationName",
						Value = relationName,
						Message = "This is not the correct relation, as it does not include the requested entity: " + entityName
					};
					validationErrors.Add(error);
				}
				else
				{
					if (relation.OriginEntityName == entityName)
					{
						relatedRecordResponse = recMan.Find(new EntityQuery(relation.TargetEntityName, "*", EntityQuery.QueryEQ("id", relatedRecordId)));
						targetFieldName = relation.TargetFieldName;
					}
					else
					{
						relatedRecordResponse = recMan.Find(new EntityQuery(relation.OriginEntityName, "*", EntityQuery.QueryEQ("id", relatedRecordId)));
						targetFieldName = relation.OriginFieldName;
					}
					//2. Validate parentRecordId
					//2.1. parentRecordId exists

					if (!relatedRecordResponse.Object.Data.Any())
					{
						var error = new ErrorModel
						{
							Key = "parentRecordId",
							Value = relatedRecordId.ToString(),
							Message = "There is no parent record with this Id in the entity: " + entityName
						};
						validationErrors.Add(error);
					}
					else
					{
						relatedRecord = relatedRecordResponse.Object.Data.First();
						//2.2. Record has value in the related field		
						if (!relatedRecord.Properties.ContainsKey(targetFieldName) || relatedRecord[targetFieldName] == null)
						{
							var error = new ErrorModel
							{
								Key = "parentRecordId",
								Value = relatedRecordId.ToString(),
								Message = "The parent record does not have field " + targetFieldName + " or its value is null"
							};
							validationErrors.Add(error);
						}
					}
				}
			}


			if (postObj == null)
				postObj = new EntityRecord();

			if (validationErrors.Count > 0)
			{
				var response = new ResponseModel
				{
					Success = false,
					Timestamp = DateTime.UtcNow,
					Errors = validationErrors,
					Message = "Validation error occurred!",
					Object = null
				};
				return Json(response);
			}

			if (!postObj.GetProperties().Any(x => x.Key == "id"))
				postObj["id"] = Guid.NewGuid();
			else if (string.IsNullOrEmpty(postObj["id"] as string))
				postObj["id"] = Guid.NewGuid();


			//Create transaction
			var result = new QueryResponse();
			using (var connection = DbContext.Current.CreateConnection())
			{
				try
				{
					connection.BeginTransaction();

					//Add the relation field value if the relation is 1:1 or 1:N
					if (relation.RelationType == EntityRelationType.OneToOne || relation.RelationType == EntityRelationType.OneToMany)
					{
						//if currentEntity is origin -> update the parent record
						if (relation.OriginEntityName == entityName)
						{
							throw new Exception("We need a case to finish this");
						}
						else
						{
							//if currentEntity is target -> get the target field and assing the correct id value of the origin 
							postObj[relation.TargetFieldName] = relatedRecord[relation.OriginFieldName];
						}
					}

					result = recMan.CreateRecord(entityName, postObj);

					//Create a relation record if it is N:N
					if (relation.RelationType == EntityRelationType.ManyToMany)
					{
						var response = new QueryResponse();
						if (relation.OriginEntityName == entityName && relation.TargetEntityName == entityName)
						{
							throw new Exception("current entity is both target and origin, cannot find relation direction. Probably needs to be extended");
						}
						else if (relation.TargetEntityName == entityName)
						{
							//if current is target -> create relation
							response = recMan.CreateRelationManyToManyRecord(relation.Id, relatedRecordId, (Guid)postObj["id"]);
						}
						else
						{
							//if current is origin -> create relation	
							response = recMan.CreateRelationManyToManyRecord(relation.Id, (Guid)postObj["id"], relatedRecordId);
						}
						if (!response.Success)
						{
							throw new Exception(response.Message);
						}
					}

					connection.CommitTransaction();
				}
				catch (Exception ex)
				{
					connection.RollbackTransaction();
					new LogService().Create(Diagnostics.LogType.Error, "TErpApi:CreateEntityRecordWithRelation", ex);
					var response = new ResponseModel
					{
						Success = false,
						Timestamp = DateTime.UtcNow,
						Message = "Error while saving the record: " + ex.Message,
						Object = null
					};
					return Json(response);
				}
			}

			return DoResponse(result);
		}


		// Update an entity record
		// PUT: api/v3/en_US/record/{entityName}/{recordId}
		[AcceptVerbs(new[] { "PUT" }, Route = "api/v3/en_US/record/{entityName}/{recordId}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult UpdateEntityRecord(string entityName, Guid recordId, [FromBody] EntityRecord postObj)
		{
			//Find and change properties starting with _$ to $$ - angular does not post $$ propery names
			postObj = Helpers.FixDoubleDollarSignProblem(postObj);


			if (!postObj.Properties.ContainsKey("id"))
			{
				postObj["id"] = recordId;
			}

			//clear authentication cache
			if (entityName == "user")
			{
				throw new Exception("Management of user record should be implemented");
				//WebSecurityUtil.RemoveIdentityFromCache(recordId);
			}
			//Create transaction
			var result = new QueryResponse();
			using (var connection = DbContext.Current.CreateConnection())
			{
				try
				{
					connection.BeginTransaction();
					result = recMan.UpdateRecord(entityName, postObj);
					connection.CommitTransaction();
				}
				catch (Exception ex)
				{
					connection.RollbackTransaction();
					new LogService().Create(Diagnostics.LogType.Error, "TErpApi:UpdateEntityRecord", ex);
					var response = new ResponseModel
					{
						Success = false,
						Timestamp = DateTime.UtcNow,
						Message = "Error while saving the record: " + ex.Message,
						Object = null
					};
					return Json(response);
				}
			}

			return DoResponse(result);
		}

		// Patch an entity record
		// PATCH: api/v3/en_US/record/{entityName}/{recordId}
		[AcceptVerbs(new[] { "PATCH" }, Route = "api/v3/en_US/record/{entityName}/{recordId}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult PatchEntityRecord(string entityName, Guid recordId, [FromBody] EntityRecord postObj)
		{
			//clear authentication cache
			if (entityName == "user")
			{
				throw new Exception("Management of user record should be implemented");
				//WebSecurityUtil.RemoveIdentityFromCache(recordId);
			}
			postObj["id"] = recordId;

			//Create transaction
			var result = new QueryResponse();
			using (var connection = DbContext.Current.CreateConnection())
			{
				try
				{
					connection.BeginTransaction();
					result = recMan.UpdateRecord(entityName, postObj);
					connection.CommitTransaction();
				}
				catch (Exception ex)
				{
					connection.RollbackTransaction();
					new LogService().Create(Diagnostics.LogType.Error, "TErpApi:PatchEntityRecord", ex);
					var response = new ResponseModel
					{
						Success = false,
						Timestamp = DateTime.UtcNow,
						Message = "Error while saving the record: " + ex.Message,
						Object = null
					};
					return Json(response);
				}
			}

			return DoResponse(result);
		}

		// GET: api/v3/en_US/record/{entityName}/list
		[AcceptVerbs(new[] { "GET" }, Route = "api/v3/en_US/record/{entityName}/list")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult GetRecordsByEntityName(string entityName, string ids = "", string fields = "", int? limit = null)
		{
			var response = new QueryResponse();
			var recordIdList = new List<Guid>();
			var fieldList = new List<string>();

			if (!String.IsNullOrWhiteSpace(ids) && ids != "null")
			{
				var idStringList = ids.Split(',');
				var outGuid = Guid.Empty;
				foreach (var idString in idStringList)
				{
					if (Guid.TryParse(idString, out outGuid))
					{
						recordIdList.Add(outGuid);
					}
					else
					{
						response.Message = "One of the record ids is not a Guid";
						response.Timestamp = DateTime.UtcNow;
						response.Success = false;
						response.Object.Data = null;
					}
				}
			}

			if (!String.IsNullOrWhiteSpace(fields) && fields != "null")
			{
				var fieldsArray = fields.Split(',');
				var hasId = false;
				foreach (var fieldName in fieldsArray)
				{
					if (fieldName == "id")
					{
						hasId = true;
					}
					fieldList.Add(fieldName);
				}
				if (!hasId)
				{
					fieldList.Add("id");
				}
			}

			var QueryList = new List<QueryObject>();
			foreach (var recordId in recordIdList)
			{
				QueryList.Add(EntityQuery.QueryEQ("id", recordId));
			}

			QueryObject recordsFilterObj = null;
			if (QueryList.Count > 0)
			{
				recordsFilterObj = EntityQuery.QueryOR(QueryList.ToArray());
			}

			var columns = "*";
			if (fieldList.Count > 0)
			{
				if (!fieldList.Contains("id"))
				{
					fieldList.Add("id");
				}
				columns = String.Join(",", fieldList.Select(x => x.ToString()).ToArray());
			}

			//var sortRulesList = new List<QuerySortObject>();
			//var sortRule = new QuerySortObject("id",QuerySortType.Descending);
			//sortRulesList.Add(sortRule);
			//EntityQuery query = new EntityQuery(entityName, columns, recordsFilterObj, sortRulesList.ToArray(), null, null);

			EntityQuery query = new EntityQuery(entityName, columns, recordsFilterObj, null, null, null);
			if (limit != null && limit > 0)
			{
				query = new EntityQuery(entityName, columns, recordsFilterObj, null, null, limit);
			}

			var queryResponse = recMan.Find(query);
			if (!queryResponse.Success)
			{
				response.Message = queryResponse.Message;
				response.Timestamp = DateTime.UtcNow;
				response.Success = false;
				response.Object = null;
				return DoResponse(response);
			}


			response.Message = "Success";
			response.Timestamp = DateTime.UtcNow;
			response.Success = true;
			response.Object.Data = queryResponse.Object.Data;
			return DoResponse(response);
		}

		private QueryResponse CreateErrorResponse(string message)
		{
			var response = new QueryResponse
			{
				Success = false,
				Timestamp = DateTime.UtcNow,
				Message = message,
				Object = null
			};
			return response;
		}

		// Import list records to csv
		// POST: api/v3/en_US/record/{entityName}/list/{listName}/import
		[AcceptVerbs(new[] { "POST" }, Route = "api/v3/en_US/record/{entityName}/import")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult ImportEntityRecordsFromCsv(string entityName, [FromBody] JObject postObject)
		{
			string fileTempPath = "";

			if (!postObject.IsNullOrEmpty() && postObject.Properties().Any(p => p.Name == "fileTempPath"))
			{
				fileTempPath = postObject["fileTempPath"].ToString();
			}

			ImportExportManager ieManager = new ImportExportManager();
			ResponseModel response = ieManager.ImportEntityRecordsFromCsv(entityName, fileTempPath);

			return DoResponse(response);

		}


		// Import list records to csv
		// POST: api/v3/en_US/record/{entityName}/list/{listName}/import
		[AcceptVerbs(new[] { "POST" }, Route = "api/v3/en_US/record/{entityName}/import-evaluate")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult EvaluateImportEntityRecordsFromCsv(string entityName, [FromBody] JObject postObject)
		{
			ImportExportManager ieManager = new ImportExportManager();
			ResponseModel response = ieManager.EvaluateImportEntityRecordsFromCsv(entityName, postObject, controller: this);

			return DoResponse(response);
		}

		[AcceptVerbs(new[] { "GET" }, Route = "api/v3/en_US/quick-search")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult GetQuickSearch(string query = "", string entityName = "", string lookupFieldsCsv = "", string sortField = "", string sortType = "asc", string returnFieldsCsv = "",
				string matchMethod = "EQ", bool matchAllFields = false, int skipRecords = 0, int limitRecords = 5, string findType = "records", string forceFiltersCsv = "")
		{
			//forceFiltersCsv -> should be in the format "fieldName1:dataType1:eqValue1,fieldName2:dataType2:eqValue2"
			var response = new ResponseModel();
			var responseObject = new EntityRecord();
			try
			{
				if (String.IsNullOrWhiteSpace(entityName) || String.IsNullOrWhiteSpace(lookupFieldsCsv) || String.IsNullOrWhiteSpace(query) || String.IsNullOrWhiteSpace(returnFieldsCsv))
				{
					throw new Exception("missing params. All params are required");
				}

				var lookupFieldsList = new List<string>();
				foreach (var field in lookupFieldsCsv.Split(','))
				{
					lookupFieldsList.Add(field);
				}

				QueryObject matchesFilter = null;
				#region <<Generate filters >>
				switch (matchMethod.ToLowerInvariant())
				{
					case "contains":
						if (lookupFieldsList.Count > 1)
						{
							var filterList = new List<QueryObject>();
							foreach (var field in lookupFieldsList)
							{
								filterList.Add(EntityQuery.QueryContains(field, query));
							}
							if (matchAllFields)
							{
								matchesFilter = EntityQuery.QueryAND(filterList.ToArray());
							}
							else
							{
								matchesFilter = EntityQuery.QueryOR(filterList.ToArray());
							}

						}
						else
						{
							matchesFilter = EntityQuery.QueryContains(lookupFieldsList[0], query);
						}
						break;
					case "startswith":
						if (lookupFieldsList.Count > 1)
						{
							var filterList = new List<QueryObject>();
							foreach (var field in lookupFieldsList)
							{
								filterList.Add(EntityQuery.QueryStartsWith(field, query));
							}
							if (matchAllFields)
							{
								matchesFilter = EntityQuery.QueryAND(filterList.ToArray());
							}
							else
							{
								matchesFilter = EntityQuery.QueryOR(filterList.ToArray());
							}

						}
						else
						{
							matchesFilter = EntityQuery.QueryStartsWith(lookupFieldsList[0], query);
						}
						break;
					case "fts":
						if (lookupFieldsList.Count > 1)
						{
							var filterList = new List<QueryObject>();
							foreach (var field in lookupFieldsList)
							{
								filterList.Add(EntityQuery.QueryFTS(field, query));
							}
							if (matchAllFields)
							{
								matchesFilter = EntityQuery.QueryAND(filterList.ToArray());
							}
							else
							{
								matchesFilter = EntityQuery.QueryOR(filterList.ToArray());
							}

						}
						else
						{
							matchesFilter = EntityQuery.QueryFTS(lookupFieldsList[0], query);
						}
						break;
					default: // EQ
						if (lookupFieldsList.Count > 1)
						{
							var filterList = new List<QueryObject>();
							foreach (var field in lookupFieldsList)
							{
								filterList.Add(EntityQuery.QueryEQ(field, query));
							}
							if (matchAllFields)
							{
								matchesFilter = EntityQuery.QueryAND(filterList.ToArray());
							}
							else
							{
								matchesFilter = EntityQuery.QueryOR(filterList.ToArray());
							}

						}
						else
						{
							matchesFilter = EntityQuery.QueryEQ(lookupFieldsList[0], query);
						}
						break;

				}
				#endregion

				#region << Generate force filters >>
				var forceFilters = new List<QueryObject>();
				if (!String.IsNullOrWhiteSpace(forceFiltersCsv))
				{
					foreach (var forceFilter in forceFiltersCsv.Split(','))
					{
						var filterArray = forceFilter.Split(':');
						if (filterArray.Length == 3)
						{
							switch (filterArray[1].ToLowerInvariant())
							{
								case "guid":
									var filterValueGuid = new Guid(filterArray[2]);
									forceFilters.Add(EntityQuery.QueryEQ(filterArray[0], filterValueGuid));
									break;
								case "bool":
									if (filterArray[2] == "true")
									{
										forceFilters.Add(EntityQuery.QueryEQ(filterArray[0], true));
									}
									else
									{
										forceFilters.Add(EntityQuery.QueryEQ(filterArray[0], false));
									}
									break;
								case "datetime":
									var filterValueDate = Convert.ToDateTime(filterArray[2]);
									forceFilters.Add(EntityQuery.QueryEQ(filterArray[0], filterValueDate));
									break;
								case "int":
									var filterValueInt = Convert.ToInt64(filterArray[2]);
									forceFilters.Add(EntityQuery.QueryEQ(filterArray[0], filterValueInt));
									break;
								case "string":
									forceFilters.Add(EntityQuery.QueryEQ(filterArray[0], filterArray[2]));
									break;
								default:
									break;

							}
						}
					}

				}

				if (forceFilters.Count > 0)
				{
					var forceFilterQuery = EntityQuery.QueryAND(forceFilters.ToArray());
					matchesFilter = EntityQuery.QueryAND(forceFilterQuery, matchesFilter);
				}

				#endregion


				var sortsList = new List<QuerySortObject>();
				#region << Generate Sorts >>
				if (!String.IsNullOrWhiteSpace(sortField))
				{
					if (sortType.ToLowerInvariant() == "desc")
					{
						sortsList.Add(new QuerySortObject(sortField, QuerySortType.Descending));
					}
					else
					{
						sortsList.Add(new QuerySortObject(sortField, QuerySortType.Ascending));
					}
				}

				#endregion

				if (findType.ToLowerInvariant() == "records" || findType.ToLowerInvariant() == "records-and-count" || findType.ToLowerInvariant() == "records&count")
				{
					var matchQueryResponse = recMan.Find(new EntityQuery(entityName, returnFieldsCsv, matchesFilter, sortsList.ToArray(), skipRecords, limitRecords));
					if (!matchQueryResponse.Success)
					{
						throw new Exception(matchQueryResponse.Message);
					}
					responseObject["records"] = matchQueryResponse.Object.Data;
				}

				if (findType.ToLowerInvariant() == "count" || findType.ToLowerInvariant() == "records-and-count" || findType.ToLowerInvariant() == "records&count")
				{
					var matchQueryResponse = recMan.Count(new EntityQuery(entityName, returnFieldsCsv, matchesFilter));
					if (!matchQueryResponse.Success)
					{
						throw new Exception(matchQueryResponse.Message);
					}
					responseObject["count"] = matchQueryResponse.Object;
				}



				response.Success = true;
				response.Message = "Quick search success";
				response.Object = responseObject;
				return Json(response);
			}
			catch (Exception ex)
			{
				new LogService().Create(Diagnostics.LogType.Error, "TErpApi:GetQuickSearch", ex);
				response.Success = false;
				response.Message = ex.Message;
				response.Object = null;
				return Json(response);
			}
		}

		#endregion

		#region << Files >>

		[HttpGet]
		[Route("/fs/{fileName}")]
		[Route("/fs/{root}/{fileName}")]
		[Route("/fs/{root}/{root2}/{fileName}")]
		[Route("/fs/{root}/{root2}/{root3}/{fileName}")]
		[Route("/fs/{root}/{root2}/{root3}/{root4}/{fileName}")]
		public IActionResult Download([FromRoute] string root, [FromRoute] string root2, [FromRoute] string root3, [FromRoute] string root4, [FromRoute] string fileName)
		{
			//we added ROOT routing parameter as workaround for conflict with razorpages routing and wildcard controller routing
			//in particular we have problem with ApplicationNodePage where routing pattern is  "/{AppName}/{AreaName}/{NodeName}/a/{PageName?}"

			if (string.IsNullOrWhiteSpace(fileName))
				return DoPageNotFoundResponse();

			var filePathArray = new List<string>();
			if (root != null) filePathArray.Add(root);
			if (root2 != null) filePathArray.Add(root2);
			if (root3 != null) filePathArray.Add(root3);
			if (root4 != null) filePathArray.Add(root4);

			var filePath = "/" + String.Join("/", filePathArray) + "/" + fileName;

			filePath = filePath.ToLowerInvariant();

			DbFileRepository fsRepository = new DbFileRepository();
			var file = fsRepository.Find(filePath);

			if (file == null)
			{
				return DoPageNotFoundResponse();
			}
			//check for modification
			string headerModifiedSince = Request.Headers["If-Modified-Since"];
			if (headerModifiedSince != null)
			{
				if (DateTime.TryParse(headerModifiedSince, out DateTime isModifiedSince))
				{
					if (isModifiedSince <= file.LastModificationDate)
					{
						Response.StatusCode = 304;
						return new EmptyResult();
					}
				}
			}
			// MINIMAL CORRECTION, REQUIRED TO MAKE THE H-08 DOWNLOAD CONTROL BELOW REACHABLE AT ALL.
			// This header was written as a culture-formatted date via new CultureInfo("en-US"). On .NET 10 the
			// en-US short time pattern separates the AM/PM designator with U+202F (NARROW NO-BREAK SPACE), and
			// Kestrel rejects every non-ASCII character in a header value, so this line threw
			// InvalidOperationException "Invalid non-ASCII or control character in header: 0x202F" and EVERY
			// /fs/ download answered 500 - before reaching the content-disposition decision at the end of this
			// action. The H-08 remediation could therefore never execute and could not be verified, which is
			// why this one line is corrected here rather than left alone. No prior working behaviour is lost:
			// the endpoint failed for 100% of requests on this target framework, so there is nothing to
			// preserve. The value is now the RFC 1123 HTTP-date that Last-Modified is specified to carry - pure
			// ASCII, and still parseable by the DateTime.TryParse used for If-Modified-Since above, so
			// conditional-GET behaviour is retained. Indexer assignment replaces Add for the same reason the
			// disposition below uses it: IHeaderDictionary.Add throws when the key is already present.
			HttpContext.Response.Headers["last-modified"] = file.LastModificationDate.ToString("R", CultureInfo.InvariantCulture);
			const int durationInSeconds = 60 * 60 * 24 * 30; //30 days caching of these resources
			HttpContext.Response.Headers[HeaderNames.CacheControl] = "public,max-age=" + durationInSeconds;

			var extension = Path.GetExtension(filePath).ToLowerInvariant();
			new FileExtensionContentTypeProvider().Mappings.TryGetValue(extension, out string mimeType);


			IDictionary<string, StringValues> queryCollection = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(HttpContext.Request.QueryString.ToString());
			string action = queryCollection.Keys.Any(x => x == "action") ? ((string)queryCollection["action"]).ToLowerInvariant() : "";
			string requestedMode = queryCollection.Keys.Any(x => x == "mode") ? ((string)queryCollection["mode"]).ToLowerInvariant() : "";
			string width = queryCollection.Keys.Any(x => x == "width") ? ((string)queryCollection["width"]).ToLowerInvariant() : "";
			string height = queryCollection.Keys.Any(x => x == "height") ? ((string)queryCollection["height"]).ToLowerInvariant() : "";
			bool isImage = extension == ".jpg" || extension == ".jpeg" || extension == ".png" || extension == ".gif";

			int widthInt = 0;
			if (!String.IsNullOrWhiteSpace(width) && int.TryParse(width, out int outWidthInt))
			{
				widthInt = outWidthInt;
			}
			int heightInt = 0;
			if (!String.IsNullOrWhiteSpace(height) && int.TryParse(height, out int outHeightInt))
			{
				heightInt = outHeightInt;
			}

			//THREAT: H-08 (CWE-434, OWASP A04 + A03) escalating into stored cross-site scripting. Stored files
			//are served from the application's OWN origin and this action set no content-disposition at all, so
			//an uploaded markup or vector file (.html, .htm, .svg) was rendered - and therefore EXECUTED -
			//inline in the site's own security context, giving script access to the authenticated session.
			//Constraining the upload actions closes only the front half of that chain; this is the back half,
			//and both halves are required.
			//DO NOT REPLACE THIS WITH A BLANKET "attachment" DISPOSITION. /fs/ is a live inline asset origin:
			//PcFieldImage and PcFieldFile render stored files as <img src="/fs/..."> via src-prefix="/fs", so a
			//blanket disposition would break image rendering across the entire platform. The control is
			//therefore an INLINE ALLOW-LIST derived from the raster image set this action already computes on
			//the isImage line above, so every file that can legitimately render still renders while everything
			//else - notably .html, .htm, .svg, .xhtml, .xml and .js - downloads instead of executing. An
			//extension with no known media type resolves to a null mimeType and is likewise not on the
			//allow-list, so it downloads too. The complementary control is X-Content-Type-Options: nosniff,
			//which SecurityHeadersMiddleware already emits for every response, so NO header is set here:
			//nosniff defeats content-type sniffing while this disposition defeats inline rendering.
			if (mimeType == null || !INLINE_DOWNLOAD_EXTENSIONS.Contains(extension))
			{
				//the name is caller-influenced, so it is sanitised and then written through SetHttpFileName,
				//which quotes and escapes the value; a raw name could otherwise inject a quote or a CR/LF
				//sequence into the header. Indexer assignment is used rather than Add because Add throws when
				//the key is already present, which would turn a hardening change into a 500.
				var downloadName = SanitizeUploadFileName(fileName) ?? DEFAULT_DOWNLOAD_FILE_NAME;
				var contentDisposition = new ContentDispositionHeaderValue("attachment");
				contentDisposition.SetHttpFileName(downloadName);
				HttpContext.Response.Headers[HeaderNames.ContentDisposition] = contentDisposition.ToString();
			}

			return File(file.GetBytes(), mimeType);
		}


		[AcceptVerbs(new[] { "POST" }, Route = "/fs/upload/")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult UploadFile([FromForm] IFormFile file)
		{
			//var fileName = ContentDispositionHeaderValue.Parse(file.ContentDisposition).FileName.Trim('"').ToLowerInvariant();
			//Trim('"') was removed from Core2
			var fileName = ContentDispositionHeaderValue.Parse(file.ContentDisposition).FileName.ToString().Trim().ToLowerInvariant();
			if (fileName.StartsWith("\"", StringComparison.InvariantCulture))
				fileName = fileName.Substring(1);

			if (fileName.EndsWith("\"", StringComparison.InvariantCulture))
				fileName = fileName.Substring(0, fileName.Length - 1);

			DbFileRepository fsRepository = new DbFileRepository();
			var createdFile = fsRepository.CreateTempFile(fileName, ReadFully(file.OpenReadStream()));

			return DoResponse(new FSResponse(new FSResult { Url = createdFile.FilePath, Filename = fileName }));

		}

		[AcceptVerbs(new[] { "POST" }, Route = "/fs/move/")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult MoveFile([FromBody] JObject submitObj)
		{
			string source = submitObj["source"].Value<string>();
			string target = submitObj["target"].Value<string>();
			bool overwrite = false;
			if (submitObj["overwrite"] != null)
				overwrite = submitObj["overwrite"].Value<bool>();

			source = source.ToLowerInvariant();
			target = target.ToLowerInvariant();

			var fileName = target.Split(new char[] { '/' }).LastOrDefault();

			DbFileRepository fsRepository = new DbFileRepository();
			var sourceFile = fsRepository.Find(source);

			//THREAT: insecure direct object reference (OWASP A01 - Broken Access Control). This action carried
			//no object-level authorization at all, so any authenticated caller could relocate ANY stored file
			//just by guessing its path - the file the lookup above already returned was retrieved and then
			//discarded unused. The audit inventory records this finding under A01 with NO CWE assigned, so
			//none is claimed here. The guard reuses that already-retrieved object, adding no query and no
			//latency, and denies by default: an unresolved principal, a missing file, or a file with no
			//recorded owner is refused for anyone who is not an administrator. Every refusal returns the one
			//generic message, so the response cannot be used to tell "no such file" from "not yours".
			if (!IsFileMutationAuthorized(sourceFile, source, "MoveFile"))
			{
				return DoResponse(new FSResponse { Success = false, Message = FILE_ACCESS_DENIED_MESSAGE });
			}

			var movedFile = fsRepository.Move(source, target, overwrite);
			return DoResponse(new FSResponse(new FSResult { Url = movedFile.FilePath, Filename = fileName }));

		}

		[AcceptVerbs(new[] { "DELETE" }, Route = "{*filepath}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult DeleteFile([FromRoute] string filepath)
		{
			filepath = filepath.ToLowerInvariant();

			var fileName = filepath.Split(new char[] { '/' }).LastOrDefault();

			DbFileRepository fsRepository = new DbFileRepository();
			var sourceFile = fsRepository.Find(filepath);

			//THREAT: insecure direct object reference (OWASP A01 - Broken Access Control), aggravated here by
			//the catch-all "{*filepath}" route: any authenticated caller could DELETE any stored file by
			//guessing its path, with no ownership or permission check whatsoever, and the file the lookup above
			//already returned went unused. The audit inventory records this finding under A01 with NO CWE
			//assigned, so none is claimed here. The guard reuses that already-retrieved object, so no extra
			//query is issued, and it denies by default on an unresolved principal, a missing file or a file
			//with no recorded owner. The refusal text is the same generic message the move action returns, so
			//the endpoint cannot be used to enumerate which paths exist.
			if (!IsFileMutationAuthorized(sourceFile, filepath, "DeleteFile"))
			{
				return DoResponse(new FSResponse { Success = false, Message = FILE_ACCESS_DENIED_MESSAGE });
			}

			fsRepository.Delete(filepath);
			return DoResponse(new FSResponse(new FSResult { Url = filepath, Filename = fileName }));
		}

		private static byte[] ReadFully(Stream input)
		{
			byte[] buffer = new byte[16 * 1024];
			using (MemoryStream ms = new MemoryStream())
			{
				int read;
				while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
				{
					ms.Write(buffer, 0, read);
				}
				return ms.ToArray();
			}
		}

		// ===== File upload, download and file-mutation security helpers ==================================
		// Added by the OWASP Top 10 (2021) audit for findings H-08 (CWE-434, OWASP A04 + A03), H-07 (CWE-79 +
		// CWE-94, OWASP A03) and the two insecure-direct-object-reference findings recorded under OWASP A01.
		// They sit beside ReadFully because, like ReadFully, they are shared by the Files region above and the
		// UserFile region below. One audited implementation each is deliberate: the same validation is needed
		// at four upload actions, the same callback encoding at three sinks and the same ownership test at two
		// actions, and six or nine local copies would be neither reviewable nor reliably identical.

		// THREAT ADDRESSED - finding H-08, CWE-434, OWASP A04 + A03. The caller-supplied file name was
		// concatenated straight into a storage path, echoed back in a JSON response, and on the download side
		// is quoted into a Content-Disposition header. This reduces it to a bounded, inert name, returning
		// null when nothing usable remains.
		// It is NOT a path-traversal defence and must not be mistaken for one: storage in this platform is
		// database-backed, route segments cannot contain a separator, and paths are lower-cased before lookup,
		// so filesystem escape is not reachable here and no such control is added. Removing a directory
		// component is about the stored NAME, not about escaping a directory.
		private static string SanitizeUploadFileName(string fileName)
		{
			if (string.IsNullOrWhiteSpace(fileName))
			{
				return null;
			}

			//Path.GetFileName treats only '/' as a separator on Linux, so a backslash is normalised first -
			//otherwise a name such as "sub\name.png" would keep a separator on a Linux host
			var candidate = fileName.Replace('\\', '/');
			candidate = candidate.Substring(candidate.LastIndexOf('/') + 1);

			//the header form of the name may arrive wrapped in quotes
			candidate = candidate.Trim().Trim('"').Trim();

			//character allow-list. Unicode letters and digits are kept so international file names survive
			//unchanged; every other character - control characters, CR, LF, quotes, ';', '%', '<', '>', ':',
			//'*', '?', '|' and both separators - collapses to '_'
			var builder = new StringBuilder(candidate.Length);
			foreach (var character in candidate)
			{
				if (char.IsLetterOrDigit(character) || character == '.' || character == '-' || character == '_' || character == ' ')
				{
					builder.Append(character);
				}
				else
				{
					builder.Append('_');
				}
			}

			var sanitized = builder.ToString().Trim();

			//a name that is empty, or only dots and spaces, carries no usable extension; it is refused rather
			//than silently renamed into something that would slip past the extension allow-list
			if (sanitized.Length == 0 || sanitized.Trim('.', ' ').Length == 0)
			{
				return null;
			}

			if (sanitized.Length > MAX_UPLOAD_FILE_NAME_LENGTH)
			{
				//truncate the stem, never the extension - the extension is what the allow-list and the
				//inline-or-attachment decision are keyed on
				var extension = Path.GetExtension(sanitized);
				var stemLength = MAX_UPLOAD_FILE_NAME_LENGTH - extension.Length;
				if (stemLength < 1)
				{
					return null;
				}

				sanitized = string.Concat(sanitized.AsSpan(0, stemLength), extension);
			}

			return sanitized;
		}

		// THREAT ADDRESSED - finding H-08, CWE-434, OWASP A04 + A03. Stops a caller pairing an allowed
		// extension with a declaration from a different media family - labelling a payload "image/png" when
		// it will be served as text, or the reverse. The extension allow-list stays the authoritative control,
		// because the stored extension is what decides how the file is later served; this is a consistency
		// check layered on top, which is why an absent or generic declaration is accepted rather than refused.
		// Deliberately NOT magic-byte or file-signature inspection: that is deep content examination, beyond
		// what this finding requires, and it would add real per-request cost.
		private static bool IsUploadContentTypeConsistent(string fileName, string declaredContentType)
		{
			if (string.IsNullOrWhiteSpace(declaredContentType))
			{
				return true;
			}

			//drop any parameters, so "text/plain; charset=utf-8" compares as "text/plain"
			var declared = declaredContentType;
			var parameterIndex = declared.IndexOf(';');
			if (parameterIndex >= 0)
			{
				declared = declared.Substring(0, parameterIndex);
			}

			declared = declared.Trim();
			if (declared.Length == 0 || string.Equals(declared, GENERIC_BINARY_CONTENT_TYPE, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}

			//the same lookup the download action uses, with the platform's own mapper as the fallback for the
			//handful of extensions the framework provider does not carry
			new FileExtensionContentTypeProvider().Mappings.TryGetValue(Path.GetExtension(fileName), out string expected);
			if (string.IsNullOrWhiteSpace(expected))
			{
				expected = MimeMapping.MimeUtility.GetMimeMapping(fileName);
			}

			//nothing canonical to contradict
			if (string.IsNullOrWhiteSpace(expected) || string.Equals(expected, GENERIC_BINARY_CONTENT_TYPE, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}

			if (string.Equals(declared, expected, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}

			//compare only the top-level media family, so harmless browser variants such as "image/jpg" for a
			//.jpeg are accepted while a cross-family claim such as "text/html" on a .png is refused
			var declaredFamilyLength = declared.IndexOf('/');
			var expectedFamilyLength = expected.IndexOf('/');
			if (declaredFamilyLength <= 0 || expectedFamilyLength <= 0)
			{
				return false;
			}

			return string.Equals(declared.Substring(0, declaredFamilyLength), expected.Substring(0, expectedFamilyLength), StringComparison.OrdinalIgnoreCase);
		}

		// THREAT ADDRESSED - finding H-08, CWE-434, OWASP A04 + A03. The single entry point every upload
		// action calls: size cap, name sanitisation, extension allow-list and content-type consistency, in
		// that order so the cheapest refusal happens first and an oversized body is never buffered. Returns
		// null when the file is acceptable, otherwise a caller-safe reason that never echoes the submitted
		// name or any internal detail - the reason is rendered into a JSON body and into a script context, so
		// echoing the input would turn the rejection itself into the injection.
		private static string GetUploadRejectionReason(string fileName, string declaredContentType, long length, out string safeFileName)
		{
			safeFileName = null;

			if (length <= 0)
			{
				return "The uploaded file is empty.";
			}

			if (length > MAX_UPLOAD_SIZE_BYTES)
			{
				return "The uploaded file is larger than the " + (MAX_UPLOAD_SIZE_BYTES / (1024 * 1024)) + " MB limit.";
			}

			var sanitized = SanitizeUploadFileName(fileName);
			if (sanitized == null)
			{
				return "The uploaded file name is missing or cannot be used.";
			}

			var extension = Path.GetExtension(sanitized);
			if (string.IsNullOrWhiteSpace(extension) || !ALLOWED_UPLOAD_EXTENSIONS.Contains(extension))
			{
				return "Files of this type cannot be uploaded.";
			}

			if (!IsUploadContentTypeConsistent(sanitized, declaredContentType))
			{
				return "The declared content type does not match the file extension.";
			}

			safeFileName = sanitized;
			return null;
		}

		// THREAT ADDRESSED - finding H-08, CWE-434, OWASP A04 + A03. The two multi-file actions wrap their
		// loop in a database transaction, so validating file-by-file inside that loop would mean a rejection
		// arriving after earlier files had already been written - and unwinding that correctly is the easy
		// mistake to make. The whole batch is therefore validated HERE, before the connection is opened and
		// before a single byte is read, so a refusal can never leave a partially written set of records
		// behind. The sanitised names are handed back so the loop concatenates the validated name into the
		// storage path instead of re-deriving it. The dictionary is keyed by reference, which is the equality
		// IFormFile implementations use.
		private static string GetUploadBatchRejectionReason(List<IFormFile> files, Dictionary<IFormFile, string> safeFileNames)
		{
			if (files == null || files.Count == 0)
			{
				return "No files were supplied.";
			}

			foreach (var file in files)
			{
				if (file == null)
				{
					return "No files were supplied.";
				}

				var rejectionReason = GetUploadRejectionReason(GetPostedFileName(file), file.ContentType, file.Length, out string safeFileName);
				if (rejectionReason != null)
				{
					return rejectionReason;
				}

				safeFileNames[file] = safeFileName;
			}

			return null;
		}

		// Reads the posted file name exactly as the multi-file actions did inline: parse the
		// Content-Disposition header, trim, lower-case, then strip the surrounding quotes the header may carry
		// - Trim('"') was removed in Core 2, hence the explicit StartsWith/EndsWith pair, which is preserved
		// here verbatim and simply shared now so validation and the storage path agree on one value.
		// The header is caller-supplied, so a malformed one must not throw out of validation and become a 500;
		// it falls back to the name ASP.NET Core has already parsed.
		private static string GetPostedFileName(IFormFile file)
		{
			string fileName = null;
			try
			{
				if (!string.IsNullOrWhiteSpace(file.ContentDisposition))
				{
					fileName = ContentDispositionHeaderValue.Parse(file.ContentDisposition).FileName.ToString();
				}
			}
			catch (FormatException)
			{
				fileName = null;
			}

			if (string.IsNullOrWhiteSpace(fileName))
			{
				fileName = file.FileName;
			}

			if (string.IsNullOrWhiteSpace(fileName))
			{
				return null;
			}

			fileName = fileName.Trim().ToLowerInvariant();
			if (fileName.StartsWith("\"", StringComparison.InvariantCulture))
				fileName = fileName.Substring(1);

			if (fileName.EndsWith("\"", StringComparison.InvariantCulture))
				fileName = fileName.Substring(0, fileName.Length - 1);

			return fileName;
		}

		// THREAT ADDRESSED - finding H-07, CWE-79 (cross-site scripting) + CWE-94 (code injection), OWASP A03
		// Injection. The editor callback page interpolated three values into a <script> block returned as
		// text/html, one of them taken straight off the query string, so any caller could execute script on
		// this application's own origin. Every value is now in a context it cannot escape:
		//   the callback index is an int, so the bare - and therefore unquotable - numeric position carries no
		//   attacker-controlled text at all, which is exactly why validating it as an integer is both
		//   sufficient and lossless for what is simply a numeric callback index;
		//   the url and the message sit inside JavaScript string literals and are encoded with the framework
		//   JavaScript encoder, which escapes the double quote to \u0022 and also the backslash, the
		//   apostrophe, CR, LF, U+2028, U+2029 and '<' to \u003C - so neither the string literal nor the
		//   enclosing </script> element can be terminated.
		// The framework's cross-site-scripting analyzer rule governs these sinks, and no analyzer diagnostic is
		// suppressed anywhere in this file. The markup, the content type and the CKEditor callback contract are
		// all unchanged, so the editor keeps behaving exactly as it did before.
		private static string BuildCKEditorCallback(int callbackFunctionNumber, string url, string message)
		{
			return @"<html><body><script>window.parent.CKEDITOR.tools.callFunction("
				+ callbackFunctionNumber.ToString(CultureInfo.InvariantCulture)
				+ ", \"" + JavaScriptEncoder.Default.Encode(url ?? string.Empty)
				+ "\", \"" + JavaScriptEncoder.Default.Encode(message ?? string.Empty)
				+ "\");</script></body></html>";
		}

		// THREAT ADDRESSED - insecure direct object reference, OWASP A01 Broken Access Control. MoveFile and
		// DeleteFile took a path straight from the request and acted on whatever it named, with no
		// object-level check at all, so any authenticated caller could rename or destroy another user's file
		// by guessing its path - and DeleteFile is bound to a catch-all route, which puts every stored file
		// within reach. The audit inventory records these two findings under OWASP A01 with NO CWE assigned,
		// so none is attributed here.
		//
		// The check costs nothing extra: both callers had ALREADY retrieved the file and left the result
		// unused, so this is a test on data in hand - no additional query and no added latency. Deny-by-
		// default applies at every uncertain edge, which is the first clause of the authorization standard: an
		// unresolvable principal, a file that does not resolve, and a file whose CreatedBy is null - system-
		// and temp-created files carry no owner - all refuse for a non-administrator. Administrators bypass
		// through ErpUser.IsAdmin, the platform's own role test, rather than a hand-rolled role comparison.
		private bool IsFileMutationAuthorized(DbFile file, string requestedPath, string operation)
		{
			//AuthService.GetUser returns null for a principal this build cannot use, so it is null-guarded
			//before either allow branch rather than trusted
			var currentUser = AuthService.GetUser(User);
			if (currentUser != null)
			{
				if (currentUser.IsAdmin)
				{
					return true;
				}

				if (file != null && file.CreatedBy.HasValue && file.CreatedBy.Value == currentUser.Id)
				{
					return true;
				}
			}

			//"Log authorization failures" is an explicit, separate clause of the authorization standard this
			//audit applies, so a refusal is recorded rather than merely returned. The string-and-details
			//overload is chosen deliberately: LogService's Exception overload sends an outbound SMTP message
			//BEFORE it persists, so routing a refusal through it would let a caller probing object references
			//generate one e-mail per attempt. DoNotNotify is passed explicitly because the parameter's default
			//is NotNotified, which is the mailing path. Only the acting identity, the requested path and the
			//reason are recorded - never a secret - and the path is length-bounded.
			var reason = currentUser == null ? "unresolved principal" : (file == null ? "file not found" : "caller is not the owner");
			var loggedPath = requestedPath ?? string.Empty;
			if (loggedPath.Length > MAX_LOGGED_PATH_LENGTH)
			{
				loggedPath = loggedPath.Substring(0, MAX_LOGGED_PATH_LENGTH);
			}

			new LogService().Create(Diagnostics.LogType.Error, "WebApiController:" + operation,
				"Authorization failure: file modification refused.",
				"user_id=" + (currentUser == null ? "anonymous" : currentUser.Id.ToString())
					+ "; requested_path=" + loggedPath
					+ "; reason=" + reason,
				Diagnostics.LogNotificationStatus.DoNotNotify);

			return false;
		}

		#endregion

		#region << Plugins >>
		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "GET" }, Route = "api/v3/en_US/plugin/list")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult GetPlugins()
		{
			var responseObj = new ResponseModel
			{
				Object = erpService.Plugins,
				Success = true,
				Timestamp = DateTime.UtcNow
			};
			return DoResponse(responseObj);
		}
		#endregion

		#region << Jobs >>

		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "GET" }, Route = "api/v3/en_US/jobs")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult GetJobs(DateTime? startFromDate = null, DateTime? startToDate = null, DateTime? finishedFromDate = null,
			DateTime? finishedToDate = null, string typeName = null, int? status = null, int? priority = null, Guid? schedulePlanId = null, int? page = null, int? pageSize = null)
		{
			ResponseModel response = new ResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };

			try
			{
				int totalCount;
				response.Object = JobManager.Current.GetJobs(out totalCount, startFromDate, startToDate, finishedFromDate, finishedToDate,
					typeName, status, priority, schedulePlanId, page, pageSize);
			}
			catch (Exception e)
			{
				new LogService().Create(Diagnostics.LogType.Error, "ErpApi:GetJobs", e);
				response.Success = false;
				response.Message = e.Message + e.StackTrace;
			}

			return DoResponse(response);
		}



		#endregion

		#region << SchedulePlans >>

		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "PUT" }, Route = "api/v3/en_US/scheduleplan/{planId}")]
		public IActionResult UpdateSchedulePlan(Guid planId, [FromBody] JObject postObject)
		{
			ResponseModel response = new ResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };

			try
			{
				SchedulePlan schedulePlan = ScheduleManager.Current.GetSchedulePlan(planId);

				if (schedulePlan == null)
				{
					response.Errors.Add(new ErrorModel { Message = $"Schedule plan with such id was not found. Id[{planId}]." });
					response.Success = false;
					return DoResponse(response);
				}

				if (postObject.IsNullOrEmpty())
				{
					response.Errors.Add(new ErrorModel { Message = $"Schedule plan with such id was not found. Id[{planId}]." });
					response.Success = false;
					return DoResponse(response);
				}

				#region << Validate >>

				foreach (var prop in postObject.Properties())
				{
					switch (prop.Name)
					{
						case "name":
							{
								if (!string.IsNullOrWhiteSpace((string)postObject["name"]))
								{
									schedulePlan.Name = (string)postObject["name"];
								}
								else
								{
									response.Errors.Add(new ErrorModel("name", (string)postObject["name"], "Name is required field and cannot be empty."));
								}
							}
							break;
						case "type":
							{
								if (!string.IsNullOrWhiteSpace(postObject["type"].ToString()))
								{
									if (int.TryParse(postObject["type"].ToString(), out int type))
									{
										if (type >= 1 && type <= 4)
											schedulePlan.Type = (SchedulePlanType)type;
										else
											response.Errors.Add(new ErrorModel("type", postObject["type"].ToString(), "The value of the type is out of range of valid values."));
									}
									else
										response.Errors.Add(new ErrorModel("type", postObject["type"].ToString(), "Type is invalid integer value."));
								}
								else
								{
									response.Errors.Add(new ErrorModel("type", postObject["type"].ToString(), "Type is required field and cannot be empty."));
								}
							}
							break;
						case "job_type_id":
							{
								if (Guid.TryParse(postObject["job_type_id"].ToString(), out Guid jobTypeId))
								{
									if (JobManager.JobTypes.Any(t => t.Id == jobTypeId))
									{
										schedulePlan.JobTypeId = jobTypeId;
									}
									else
									{
										response.Errors.Add(new ErrorModel("job_type_id", postObject["job_type_id"].ToString(), "There is no job type with such id."));
									}
								}
								else
								{
									response.Errors.Add(new ErrorModel("job_type_id", postObject["job_type_id"].ToString(), "Job type id is not valid."));
								}
							}
							break;
						case "start_date":
							{
								schedulePlan.StartDate = DateTime.UtcNow;

								if (!string.IsNullOrWhiteSpace(postObject["start_date"].ToString()))
								{
									if (DateTime.TryParse(postObject["start_date"].ToString(), out DateTime startDate))
									{
										startDate = (DateTime)postObject["start_date"];
										schedulePlan.StartDate = startDate.ToUniversalTime();
									}
									else
									{
										response.Errors.Add(new ErrorModel("start_date", postObject["start_date"].ToString(), "The value of start date field is not valid."));
									}
								}
							}
							break;
						case "end_date":
							{
								if (!string.IsNullOrWhiteSpace(postObject["end_date"].ToString()))
								{
									if (DateTime.TryParse(postObject["end_date"].ToString(), out DateTime endDate))
									{
										endDate = (DateTime)postObject["end_date"];
										schedulePlan.StartDate = endDate.ToUniversalTime();
									}
									else
									{
										response.Errors.Add(new ErrorModel("end_date", postObject["end_date"].ToString(), "The value of end date field is not valid."));
									}
								}
							}
							break;
						case "schedule_days":
							{
								string days = postObject["schedule_days"].ToString();
								if (!string.IsNullOrWhiteSpace(days))
								{
									schedulePlan.ScheduledDays = JsonConvert.DeserializeObject<SchedulePlanDaysOfWeek>(postObject["schedule_days"].ToString());
								}
								else
								{
									response.Errors.Add(new ErrorModel("schedule_days", postObject["schedule_days"].ToString(), "Schedule days is required field and cannot be empty."));
								}
							}
							break;
						case "interval_in_minutes":
							{
								if (int.TryParse(postObject["interval_in_minutes"].ToString(), out int interval))
								{
									schedulePlan.IntervalInMinutes = interval;
								}
								else
								{
									response.Errors.Add(new ErrorModel("interval_in_minutes", postObject["interval_in_minutes"].ToString(), "The value of Interval in minutes field is not valid."));
								}
							}
							break;
						case "start_timespan":
							{
								if (DateTime.TryParse(postObject["start_timespan"].ToString(), out DateTime startTimespan))
								{
									startTimespan = ((DateTime)postObject["start_timespan"]);
									schedulePlan.StartTimespan = startTimespan.Hour * 60 + startTimespan.Minute;
								}
								else
								{
									response.Errors.Add(new ErrorModel("start_timespan", postObject["start_timespan"].ToString(), "The value of start timespan is not valid."));
								}
							}
							break;
						case "end_timespan":
							{
								if (DateTime.TryParse(postObject["end_timespan"].ToString(), out DateTime endTimespan))
								{
									endTimespan = ((DateTime)postObject["end_timespan"]);
									schedulePlan.EndTimespan = endTimespan.Hour * 60 + endTimespan.Minute;
									if (schedulePlan.EndTimespan == 0) //that's mean 12PM
										schedulePlan.EndTimespan = 1440;
								}
								else
								{
									response.Errors.Add(new ErrorModel("end_timespan", postObject["end_timespan"].ToString(), "The value of end timespan is not valid."));
								}
							}
							break;
						case "enabled":
							{
								schedulePlan.Enabled = (bool)postObject["enabled"];
							}
							break;
					}
				}

				if (schedulePlan.StartDate >= schedulePlan.EndDate)
				{
					if (postObject.Properties().Any(p => p.Name == "start_date"))
						response.Errors.Add(new ErrorModel("start_date", postObject["start_date"].ToString(), "Start date must be before end date."));
					else
						response.Errors.Add(new ErrorModel("end_date", postObject["end_date"].ToString(), "End date must be greater than start date."));
				}

				if ((schedulePlan.Type == SchedulePlanType.Daily || schedulePlan.Type == SchedulePlanType.Interval) && !schedulePlan.ScheduledDays.HasOneSelectedDay())
					response.Errors.Add(new ErrorModel("schedule_days", postObject["schedule_days"].ToString(), "At least one day have to be selected for schedule days field."));

				if (schedulePlan.Type == SchedulePlanType.Interval && schedulePlan.IntervalInMinutes <= 0 || schedulePlan.IntervalInMinutes >= 1440)
					response.Errors.Add(new ErrorModel("interval_in_minutes", postObject["interval_in_minutes"].ToString(), "The value of Interval in minutes field must be greater than 0 and less or  equal than 1440."));

				if (response.Errors.Count > 0)
				{
					response.Success = false;
					return DoResponse(response);
				}

				#endregion

				schedulePlan.NextTriggerTime = ScheduleManager.Current.FindSchedulePlanNextTriggerDate(schedulePlan);
				ScheduleManager.Current.UpdateSchedulePlan(schedulePlan);
			}
			catch (Exception e)
			{
				new LogService().Create(Diagnostics.LogType.Error, "TErpApi:UpdateSchedulePlan", e);
				response.Success = false;
				response.Timestamp = DateTime.UtcNow;
				response.Message = e.Message + e.StackTrace;
			}

			response.Success = true;
			response.Timestamp = DateTime.UtcNow;
			var responseRecord = new EntityRecord();
			var responseList = new List<SchedulePlan> {
				ScheduleManager.Current.GetSchedulePlan(planId)
			};
			responseRecord["data"] = responseList;
			response.Object = responseRecord;
			response.Message = "Schedule plan updated successfully";

			return DoResponse(response);
		}

		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "POST" }, Route = "api/v3/en_US/scheduleplan/{planId}/trigger")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult TriggerNowSchedulePlan(Guid planId)
		{
			BaseResponseModel response = new BaseResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };

			try
			{
				var schedulePlan = ScheduleManager.Current.GetSchedulePlan(planId);

				if (schedulePlan == null)
				{
					response.Errors.Add(new ErrorModel { Message = $"Schedule plan with such id was not found. Id[{planId}]." });
					response.Success = false;
					return DoResponse(response);
				}

				ScheduleManager.Current.TriggerNowSchedulePlan(schedulePlan);
			}
			catch (Exception e)
			{
				new LogService().Create(Diagnostics.LogType.Error, "TErpApi:TriggerNowSchedulePlan", e);
				response.Success = false;
				response.Message = e.Message + e.StackTrace;
			}

			response.Success = true;
			response.Timestamp = DateTime.UtcNow;
			response.Message = "Schedule plan triggered successfully";
			return DoResponse(response);
		}

		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "GET" }, Route = "api/v3/en_US/scheduleplan/list")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult GetSchedulePlansList()
		{
			ResponseModel response = new ResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };

			try
			{
				var responseRecord = new EntityRecord();
				responseRecord["data"] = ScheduleManager.Current.GetSchedulePlans().MapTo<OutputSchedulePlan>();
				response.Object = responseRecord;
			}
			catch (Exception e)
			{
				new LogService().Create(Diagnostics.LogType.Error, "TErpApi:GetSchedulePlansList", e);
				response.Success = false;
				response.Message = e.Message + e.StackTrace;
			}

			return DoResponse(response);
		}

		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "GET" }, Route = "api/v3/en_US/scheduleplan/{planId}")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult GetSchedulePlan(Guid planId)
		{
			ResponseModel response = new ResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };

			try
			{
				var schedulePlan = ScheduleManager.Current.GetSchedulePlan(planId);

				if (schedulePlan == null)
				{
					response.Errors.Add(new ErrorModel { Message = $"Schedule plan with such id was not found. Id[{planId}]." });
					response.Success = false;
					return DoResponse(response);
				}

				var responseRecord = new EntityRecord();
				responseRecord["data"] = schedulePlan.MapTo<OutputSchedulePlan>();
				response.Object = responseRecord;
			}
			catch (Exception e)
			{
				new LogService().Create(Diagnostics.LogType.Error, "TErpApi:GetSchedulePlan", e);
				response.Success = false;
				response.Message = e.Message + e.StackTrace;
			}

			return DoResponse(response);
		}

		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "GET" }, Route = "api/v3/en_US/scheduleplan/test")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult CreateTestSchedulePlan(Guid planId)
		{
			ResponseModel response = new ResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };

			try
			{
				Guid offerSchedulePlanId = Guid.NewGuid();
				SchedulePlan offerSchedulePlan = ScheduleManager.Current.GetSchedulePlan(offerSchedulePlanId);

				if (offerSchedulePlan == null)
				{
					offerSchedulePlan = new SchedulePlan
					{
						Id = offerSchedulePlanId,
						Name = "Offer schedule plan Test",
						Type = SchedulePlanType.Daily,
						StartDate = DateTime.UtcNow,
						EndDate = null,
						ScheduledDays = new SchedulePlanDaysOfWeek()
						{
							ScheduledOnMonday = true,
							ScheduledOnTuesday = true,
							ScheduledOnWednesday = true,
							ScheduledOnThursday = true,
							ScheduledOnFriday = true,
							ScheduledOnSaturday = true,
							ScheduledOnSunday = true
						},
						//IntervalInMinutes = 1,
						//StartTimespan = 0,
						//EndTimespan = 1440,
						JobTypeId = new Guid("70f06b11-2aee-40d5-b8ef-de1a2d8bbb59"),
						JobAttributes = null,
						Enabled = true,
						LastModifiedBy = null
					};

					ScheduleManager.Current.CreateSchedulePlan(offerSchedulePlan);
				}
				response.Object = offerSchedulePlan.MapTo<OutputSchedulePlan>();
			}
			catch (Exception e)
			{
				new LogService().Create(Diagnostics.LogType.Error, "TErpApi:CreateTestSchedulePlan", e);
				response.Success = false;
				response.Message = e.Message + e.StackTrace;
			}

			return DoResponse(response);
		}

		#endregion

		#region << System log >>
		[Authorize(Roles = "administrator")]
		[AcceptVerbs(new[] { "GET" }, Route = "api/v3/en_US/system-log")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult GetSystemLog(DateTime? fromDate = null, DateTime? untilDate = null, string type = "",
			string source = "", string message = "", string notificationStatus = "", int page = 1, int pageSize = 15)
		{
			ResponseModel response = new ResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };
			var recMan = new RecordManager();
			var skipRecords = (page - 1) * pageSize;
			try
			{
				//Filters
				var filterList = new List<QueryObject>();
				if (fromDate != null)
				{
					filterList.Add(EntityQuery.QueryGT("created_on", fromDate));
				}
				if (untilDate != null)
				{
					filterList.Add(EntityQuery.QueryLT("created_on", untilDate));
				}
				if (!String.IsNullOrWhiteSpace(type))
				{
					filterList.Add(EntityQuery.QueryEQ("type", type));
				}
				if (!String.IsNullOrWhiteSpace(source))
				{
					filterList.Add(EntityQuery.QueryContains("source", source));
				}
				if (!String.IsNullOrWhiteSpace(message))
				{
					filterList.Add(EntityQuery.QueryContains("message", message));
				}
				if (!String.IsNullOrWhiteSpace(notificationStatus))
				{
					filterList.Add(EntityQuery.QueryEQ("notificationStatus", notificationStatus));
				}

				var selectFilters = EntityQuery.QueryAND(filterList.ToArray());

				//Sort
				var sortList = new List<QuerySortObject> {
					new QuerySortObject("created_on", QuerySortType.Descending)
				};

				//Fields
				var columns = "*";

				//Query
				var query = new EntityQuery("system_log", columns, selectFilters, sortList.ToArray(), skipRecords, pageSize);
				var queryResponse = recMan.Find(query);
				if (!queryResponse.Success)
				{
					throw new Exception("Error getting the records: " + queryResponse.Message);
				}
				response.Object = queryResponse.Object.Data;
			}
			catch (Exception e)
			{
				new LogService().Create(Diagnostics.LogType.Error, "TErpApi:GetSystemLog", e);
				response.Success = false;
				response.Message = e.Message + e.StackTrace;
			}

			return DoResponse(response);
		}
		#endregion

		#region << UserFile >>

		[AcceptVerbs(new[] { "GET" }, Route = "api/v3/en_US/user_file")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult GetUserFileList(string type = "", string search = "", int sort = 1, int page = 1, int pageSize = 30)
		{
			ResponseModel response = new ResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };

			try
			{
				response.Object = new UserFileService().GetFilesList(type, search, sort, page, pageSize);
			}
			catch (Exception e)
			{
				new LogService().Create(Diagnostics.LogType.Error, "TErpApi:GetUserFileList", e);
				response.Success = false;
				response.Message = e.Message + e.StackTrace;
			}

			return DoResponse(response);
		}

		[AcceptVerbs(new[] { "POST" }, Route = "api/v3/en_US/user_file")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult UploadUserFile([FromBody] JObject submitObj)
		{
			ResponseModel response = new ResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };
			var filePath = "";
			var fileAlt = "";
			var fileCaption = "";
			#region << Init SubmitObj >>
			foreach (var prop in submitObj.Properties())
			{
				switch (prop.Name.ToLower())
				{
					case "path":
						if (!string.IsNullOrWhiteSpace(prop.Value.ToString()))
							filePath = prop.Value.ToString();
						else
						{
							throw new Exception("File path is required");
						}
						break;
					case "alt":
						if (!string.IsNullOrWhiteSpace(prop.Value.ToString()))
							fileAlt = prop.Value.ToString();
						else
						{
							fileAlt = null;
						}
						break;
					case "caption":
						if (!string.IsNullOrWhiteSpace(prop.Value.ToString()))
							fileCaption = prop.Value.ToString();
						else
						{
							fileCaption = null;
						}
						break;
				}
			}

			#endregion
			try
			{
				response.Object = new UserFileService().CreateUserFile(filePath, fileAlt, fileCaption);
			}
			catch (Exception e)
			{
				new LogService().Create(Diagnostics.LogType.Error, "TErpApi:UploadUserFile", e);
				response.Success = false;
				response.Message = e.Message + e.StackTrace;
			}

			return DoResponse(response);
		}


		[AcceptVerbs(new[] { "POST" }, Route = "/ckeditor/drop-upload-url")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult UploadDropCKEditor(IFormFile upload)
		{
			var response = new EntityRecord();
			byte[] fileBytes = null;
			try
			{
				if (upload != null)
				{
					// THREAT ADDRESSED - finding H-08, CWE-434 (unrestricted upload of file with dangerous
					// type), OWASP A04 Insecure Design + A03 Injection. This action accepted any extension,
					// any declared content type and any size, and the stored file is later served from this
					// application's own origin - so an uploaded .html or .svg became stored script. The name
					// was also concatenated raw into the storage path and echoed back in the response. The
					// check runs before the stream is buffered, so an oversized POST is never read into
					// memory, and the sanitised name is used at both of the places the raw one was.
					var rejectionReason = GetUploadRejectionReason(upload.FileName, upload.ContentType, upload.Length, out string safeFileName);
					if (rejectionReason != null)
					{
						//the same failure shape this action's own catch block already returns
						response["uploaded"] = 0;
						var rejectionRecord = new EntityRecord();
						rejectionRecord["message"] = rejectionReason;
						response["error"] = rejectionRecord;
						return Json(response);
					}

					using (var ms = new MemoryStream())
					{
						upload.CopyTo(ms);
						fileBytes = ms.ToArray();
					}
					var tempPath = "tmp/" + Guid.NewGuid() + "/" + safeFileName;
					var tempFile = new DbFileRepository().Create(tempPath, fileBytes, null, null);

					var newFile = new UserFileService().CreateUserFile(tempFile.FilePath, null, null);

					string url = "/fs" + newFile.Path;

					response["uploaded"] = 1;
					response["fileName"] = safeFileName;
					response["url"] = url;
					return Json(response);

				}
				else
				{
					return Json(response);
				}
			}
			catch (Exception ex)
			{
				new LogService().Create(Diagnostics.LogType.Error, "TErpApi:UploadDropCKEditor", ex);
				response["uploaded"] = 0;
				response["error"] = new EntityRecord();
				var message = new EntityRecord();
				message["message"] = ex.Message;
				response["error"] = message;
				return Json(response);
			}

		}


		[AcceptVerbs(new[] { "POST" }, Route = "/ckeditor/image-upload-url")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult UploadFileManagerCKEditor(IFormFile upload)
		{
			byte[] fileBytes = null;
			string CKEditorFuncNum = HttpContext.Request.Query["CKEditorFuncNum"].ToString();

			// THREAT ADDRESSED - finding H-07, CWE-79 (cross-site scripting) + CWE-94 (code injection),
			// OWASP A03 Injection. This value arrives on the query string and was interpolated verbatim into
			// the <script> block returned below as text/html, so any caller could run script on this
			// application's own origin. It is a numeric CKEditor callback index, so parsing it as an integer
			// is both sufficient and lossless, and it removes attacker-controlled text from the bare -
			// therefore unquotable - numeric position entirely. A non-numeric value is refused with an inert
			// page that does NOT echo the offending value back, so the rejection cannot itself become the
			// injection. The two remaining values are encoded in BuildCKEditorCallback.
			if (!int.TryParse(CKEditorFuncNum, NumberStyles.Integer, CultureInfo.InvariantCulture, out int callbackFunctionNumber))
			{
				return Content(CKEDITOR_INVALID_REQUEST_BODY, "text/html");
			}

			try
			{
				// THREAT ADDRESSED - finding H-08, CWE-434, OWASP A04 + A03. This action had no null guard at
				// all - upload.CopyTo below threw straight into the catch, whose text was echoed to the
				// browser - and no type, size or content-type constraint, so any extension was accepted and
				// then served inline from this origin. Validating before the stream is buffered also means an
				// oversized POST is refused without first being read into memory.
				string safeFileName = null;
				var rejectionReason = "No file was supplied.";
				if (upload != null)
				{
					rejectionReason = GetUploadRejectionReason(upload.FileName, upload.ContentType, upload.Length, out safeFileName);
				}

				if (rejectionReason != null)
				{
					return Content(BuildCKEditorCallback(callbackFunctionNumber, string.Empty, rejectionReason), "text/html");
				}

				using (var ms = new MemoryStream())
				{
					upload.CopyTo(ms);
					fileBytes = ms.ToArray();
				}
				var tempPath = "tmp/" + Guid.NewGuid() + "/" + safeFileName;
				var tempFile = new DbFileRepository().Create(tempPath, fileBytes, null, null);

				var newFile = new UserFileService().CreateUserFile(tempFile.FilePath, null, null);

				string url = "/fs" + newFile.Path;
				string vMessage = "";
				var vOutput = BuildCKEditorCallback(callbackFunctionNumber, url, vMessage);

				return Content(vOutput, "text/html");
			}
			catch (Exception ex)
			{
				new LogService().Create(Diagnostics.LogType.Error, "TErpApi:UploadFileManagerCKEditor", ex);
				// THREAT ADDRESSED - finding H-07 (CWE-79 + CWE-94, OWASP A03) compounded by information
				// disclosure: the exception message was interpolated into this same script block, so a
				// provoked fault both leaked internal detail to the browser and carried attacker-influenced
				// text into a script context. It is replaced by the platform's own generic wording. The
				// LogService record written immediately above is retained unchanged, so the detail is still
				// captured server-side and no diagnostic capability is lost.
				var vOutput = BuildCKEditorCallback(callbackFunctionNumber, string.Empty, INTERNAL_ERROR_MESSAGE);
				return Content(vOutput, "text/html");
			}
		}

		[AcceptVerbs(new[] { "POST" }, Route = "/fs/upload-user-file-multiple/")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult UploadUserFileMultiple([FromForm] List<IFormFile> files)
		{

			var resultRecords = new List<EntityRecord>();
			var response = new ResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };

			// THREAT ADDRESSED - finding H-08, CWE-434 (unrestricted upload of file with dangerous type),
			// OWASP A04 Insecure Design + A03 Injection. Every file in the batch is validated for size, type,
			// content-type consistency and name safety HERE, before the connection is opened and before a
			// single byte is read or persisted, so a rejected batch can never leave a partially written set of
			// records behind - rejecting inside the transaction below would have had to unwind it, and that is
			// the easy mistake to make. The sanitised names are carried forward so the value concatenated into
			// the storage path is the validated one.
			var safeFileNames = new Dictionary<IFormFile, string>();
			var batchRejectionReason = GetUploadBatchRejectionReason(files, safeFileNames);
			if (batchRejectionReason != null)
			{
				//the same failure shape this action's own catch block already returns
				response.Success = false;
				response.Message = batchRejectionReason;
				return DoResponse(response);
			}

			using (var connection = DbContext.Current.CreateConnection())
			{
				connection.BeginTransaction();

				try
				{

					var currentUser = AuthService.GetUser(User);

					foreach (var file in files)
					{
						var fileBuffer = ReadFully(file.OpenReadStream());
						var fileName = safeFileNames[file];

						var recMan = new RecordManager();
						DbFileRepository fsRepository = new DbFileRepository();
						string section = Guid.NewGuid().ToString().Replace("-", "").ToLowerInvariant();
						var filePath = "/user_file/" + currentUser.Id + "/" + section + "/" + fileName;
						var createdFile = fsRepository.Create(filePath, fileBuffer, DateTime.Now, currentUser.Id);
						var userFileId = Guid.NewGuid();

						var userFileRecord = new EntityRecord();
						#region << record fill >>
						userFileRecord["id"] = userFileId;
						userFileRecord["created_on"] = DateTime.Now;
						userFileRecord["name"] = fileName;
						userFileRecord["size"] = Math.Round((decimal)(file.Length / 1024), 0);
						userFileRecord["path"] = filePath;

						var mimeType = MimeMapping.MimeUtility.GetMimeMapping(filePath);
						var fileExtension = Path.GetExtension(filePath);
						if (mimeType.StartsWith("image"))
						{
							var dimensionsRecord = Helpers.GetImageDimension(fileBuffer);
							userFileRecord["width"] = (decimal)dimensionsRecord["width"];
							userFileRecord["height"] = (decimal)dimensionsRecord["height"];
							userFileRecord["type"] = "image";
						}
						else if (mimeType.StartsWith("video"))
						{
							userFileRecord["type"] = "video";
						}
						else if (mimeType.StartsWith("audio"))
						{
							userFileRecord["type"] = "audio";
						}
						else if (fileExtension == ".doc" || fileExtension == ".docx" || fileExtension == ".odt" || fileExtension == ".rtf"
						 || fileExtension == ".txt" || fileExtension == ".pdf" || fileExtension == ".html" || fileExtension == ".htm" || fileExtension == ".ppt"
						  || fileExtension == ".pptx" || fileExtension == ".xls" || fileExtension == ".xlsx" || fileExtension == ".ods" || fileExtension == ".odp")
						{
							userFileRecord["type"] = "document";
						}
						else
						{
							userFileRecord["type"] = "other";
						}
						#endregion

						var recordCreateResult = recMan.CreateRecord("user_file", userFileRecord);
						if (!recordCreateResult.Success)
						{
							throw new Exception(recordCreateResult.Message);
						}
						resultRecords.Add(userFileRecord);
					}
					connection.CommitTransaction();
					response.Success = true;
					response.Object = resultRecords;
					return DoResponse(response);
				}
				catch (Exception ex)
				{
					connection.RollbackTransaction();
					response.Success = false;
					response.Message = ex.Message;
					return DoResponse(response);
				}
			}
		}

		[AcceptVerbs(new[] { "POST" }, Route = "/fs/upload-file-multiple/")]
		[ResponseCache(NoStore = true, Duration = 0)]
		public IActionResult UploadFileMultiple([FromForm] List<IFormFile> files)
		{

			var resultRecords = new List<EntityRecord>();
			var response = new ResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };

			// THREAT ADDRESSED - finding H-08, CWE-434, OWASP A04 + A03. Same reasoning as the user-file
			// variant above, and this is the endpoint behind the live PcFieldMultiFileUpload component, so the
			// whole batch is validated before the transaction opens: a refusal must never commit a partial
			// batch, and a legitimate batch must still succeed unchanged.
			var safeFileNames = new Dictionary<IFormFile, string>();
			var batchRejectionReason = GetUploadBatchRejectionReason(files, safeFileNames);
			if (batchRejectionReason != null)
			{
				//the same failure shape this action's own catch block already returns
				response.Success = false;
				response.Message = batchRejectionReason;
				return DoResponse(response);
			}

			using (var connection = DbContext.Current.CreateConnection())
			{
				connection.BeginTransaction();

				try
				{
					foreach (var file in files)
					{
						var fileBuffer = ReadFully(file.OpenReadStream());
						var fileName = safeFileNames[file];

						var recMan = new RecordManager();
						DbFileRepository fsRepository = new DbFileRepository();
						DbFile dbFile = fsRepository.CreateTempFile(fileName, fileBuffer);

						var resultRec = new EntityRecord();

						resultRec["id"] = dbFile.Id;
						resultRec["created_on"] = DateTime.Now;
						resultRec["name"] = fileName;
						resultRec["size"] = Math.Round((decimal)(file.Length / 1024), 0);
						resultRec["path"] = dbFile.FilePath;

						var mimeType = MimeMapping.MimeUtility.GetMimeMapping(dbFile.FilePath);
						var fileExtension = Path.GetExtension(dbFile.FilePath);
						if (mimeType.StartsWith("image"))
						{
							var dimensionsRecord = Helpers.GetImageDimension(fileBuffer);
							resultRec["width"] = (decimal)dimensionsRecord["width"];
							resultRec["height"] = (decimal)dimensionsRecord["height"];
							resultRec["type"] = "image";
						}
						else if (mimeType.StartsWith("video"))
						{
							resultRec["type"] = "video";
						}
						else if (mimeType.StartsWith("audio"))
						{
							resultRec["type"] = "audio";
						}
						else if (fileExtension == ".doc" || fileExtension == ".docx" || fileExtension == ".odt" || fileExtension == ".rtf"
						 || fileExtension == ".txt" || fileExtension == ".pdf" || fileExtension == ".html" || fileExtension == ".htm" || fileExtension == ".ppt"
						  || fileExtension == ".pptx" || fileExtension == ".xls" || fileExtension == ".xlsx" || fileExtension == ".ods" || fileExtension == ".odp")
						{
							resultRec["type"] = "document";
						}
						else
						{
							resultRec["type"] = "other";
						}

						resultRecords.Add(resultRec);
					}

					connection.CommitTransaction();
					response.Success = true;
					response.Object = resultRecords;
					return DoResponse(response);
				}
				catch (Exception ex)
				{
					connection.RollbackTransaction();
					response.Success = false;
					response.Message = ex.Message;
					return DoResponse(response);
				}
			}
		}


		#endregion

		#region << Utils >>

		public static Stream GenerateStreamFromString(string s)
		{
			var stream = new MemoryStream();
			var writer = new StreamWriter(stream);
			writer.Write(s);
			writer.Flush();
			stream.Position = 0;
			return stream;
		}
		#endregion

		#region <== Snippets ===>

		[AcceptVerbs(new[] { "GET" }, Route = "api/v3/en_US/snippets")]
		public IActionResult GetSnippetNames(string search = "", int page = 1, int pageSize = 30)
		{
			var response = new TypeaheadResponse();
			var snippets = SnippetService.Snippets.Keys.OrderBy(x => x).ToList();
			if (string.IsNullOrWhiteSpace(search))
				return new JsonResult(snippets.Skip(page - 1).Take(pageSize).ToList());
			else
				return new JsonResult(snippets.Where(x => x.ToLowerInvariant().Contains(search.ToLowerInvariant())).Skip(page - 1).Take(pageSize).ToList());
		}

		[AcceptVerbs(new[] { "GET" }, Route = "api/v3/en_US/snippet")]
		public IActionResult GetSnippetText([FromQuery] string name)
		{
			ResponseModel response = new ResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };

			try
			{
				var snippet = SnippetService.GetSnippet(name);
				if (snippet == null)
					throw new Exception($"Snippet '{name}' is not found.");
				else
					response.Object = snippet.GetText();
			}
			catch (Exception e)
			{
				new LogService().Create(Diagnostics.LogType.Error, "GetSnippetNames", e);
				response.Success = false;
				response.Message = e.Message + e.StackTrace;
			}

			return DoResponse(response);
		}

		#endregion

		#region <=== JWT Token Auth ===>

		/// <summary>
		/// Returned by both bearer-token routes when no usable signing key is configured.
		/// </summary>
		/// <remarks>
		/// M-2 (CWE-209 information exposure through an error message): states only that the feature is off.
		/// It never names the setting, reports the key's length, or says WHY the value was rejected, because
		/// this is an anonymous route and any of those details would help an attacker profile the deployment.
		/// The actionable detail an operator needs was emitted once, at startup, by
		/// ErpSettings.ValidateRequiredSecurityConfiguration.
		/// </remarks>
		private const string JwtNotConfiguredMessage = "Bearer token authentication is not enabled on this server.";

		[AllowAnonymous]
		[Route("api/v3/en_US/auth/jwt/token")]
		[HttpPost]
		public async Task<IActionResult> GetJwtToken([FromBody] JwtTokenLoginModel model, [FromServices] LoginThrottleService loginThrottle)
		{
			ResponseModel response = new ResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };

			// SECURITY - finding M-2 (CWE-20 improper input validation, CWE-798 hard-coded credentials),
			// OWASP A05 Security Misconfiguration / A07 Authentication Failures.
			// THREAT: this route is [AllowAnonymous] and is declared in WebVella.Erp.Web, so it exists on ALL
			// SEVEN hosts - yet only two of them configure a 'Settings:Jwt' section. On the other five the
			// signing key was null, AuthService reached Encoding.UTF8.GetBytes(null), and the request became a
			// 500 whose body carried a stack trace back to an unauthenticated caller. On a host that kept this
			// repository's published example key the failure was worse than a fault: the route happily issued
			// tokens that anyone reading the public source could forge.
			// ErpSettings.IsJwtConfigured is resolved once at startup by the SAME acceptability rule the host
			// applies when it registers its bearer handler, so the two can never disagree - the route refuses
			// exactly when the handler would refuse to validate.
			//
			// Ordering is deliberate: this is checked BEFORE the throttle reserves an attempt. No credential is
			// verified on this path, so counting it as a failed attempt would let an anonymous caller on a
			// misconfigured host exhaust a real account's lockout budget and deny service to its owner - turning
			// a misconfiguration into a remote denial of service.
			// Nothing is logged per request, also deliberately: the condition is static and was already reported
			// once at startup, so logging every anonymous call would add no diagnostic value while creating a
			// log-flooding and database-write amplification vector (CWE-779).
			if (!ErpSettings.IsJwtConfigured)
			{
				response.Success = false;
				response.Message = JwtNotConfiguredMessage;
				return DoResponse(response);
			}

			// THREAT ADDRESSED - finding H-16, CWE-307 (Improper Restriction of Excessive Authentication
			// Attempts), OWASP A07. This anonymous endpoint verifies a username and password through the very
			// same SecurityManager credential check the login form uses, so it is a second credential-guessing
			// surface, not an ordinary API route. Throttling only the login page would therefore have left the
			// lockout trivially bypassable: an attacker would simply brute-force here instead, unmetered and
			// without needing an antiforgery token. The counters are shared with the login page because the
			// throttle is keyed on the account and the source address, not on the entry point, so attempts
			// spread across both surfaces still add up against one budget.
			var remoteAddress = HttpContext?.Connection?.RemoteIpAddress?.ToString();
			if (!loginThrottle.TryBeginAttempt(model?.Email, remoteAddress))
			{
				// Byte-identical to the rejection this endpoint already returns for a bad credential, so the
				// throttle cannot be used to distinguish a real account from a fabricated one.
				response.Success = false;
				response.Message = AuthService.InvalidCredentialMessage;
				return DoResponse(response);
			}

			// The reserved attempt is finalised on every path out of the credential check. A rejected
			// credential is counted; a server-side fault - an absent signing key, for instance, which is the
			// outcome on hosts that ship no JWT configuration - is NOT, because an attacker cannot provoke it
			// and counting it would let a misconfigured host lock out its own users. The two are told apart by
			// the sentinel message AuthService throws, not by guessing at the exception type.
			var credentialWasRejected = false;
			var authenticated = false;
			try
			{
				response.Object = await AuthService.GetTokenAsync(model.Email, model.Password);
				authenticated = true;
			}
			catch (Exception e)
			{
				credentialWasRejected = string.Equals(e.Message, AuthService.InvalidCredentialMessage, StringComparison.Ordinal);
				new LogService().Create(Diagnostics.LogType.Error, "GetJwtToken", e);
				response.Success = false;

				// THREAT ADDRESSED - finding H-13, CWE-209 (generation of an error message containing
				// sensitive information), OWASP A05 Security Misconfiguration. This route is [AllowAnonymous]
				// and the exception message plus the FULL stack trace were concatenated into the response
				// body, handing framework versions, internal type and namespace names and the call path to
				// any unauthenticated caller able to provoke a fault. The site was guarded by NO
				// development-mode check, so flipping ASPNETCORE_ENVIRONMENT to Production would NOT have
				// closed it - the code had to change. The guard mirrors ApiControllerBase.DoBadRequestResponse
				// (lines 49-58). e.ToString() renders the type, the message, any inner exceptions and the
				// stack trace, so the development-mode detail is a superset of what was emitted before and a
				// developer loses nothing. A rejected credential keeps the platform's own credential wording
				// so this outcome stays byte-identical to the throttle rejection above; diverging here would
				// turn the two different messages into an account-existence oracle. The LogService record
				// written immediately above is retained unchanged, so the detail is still captured
				// server-side and no diagnostic capability is lost.
				if (ErpSettings.DevelopmentMode)
				{
					response.Message = e.ToString();
				}
				else if (credentialWasRejected)
				{
					response.Message = AuthService.InvalidCredentialMessage;
				}
				else
				{
					response.Message = INTERNAL_ERROR_MESSAGE;
				}
			}
			finally
			{
				if (authenticated)
					loginThrottle.RegisterSuccess(model?.Email, remoteAddress);
				else if (credentialWasRejected)
					loginThrottle.RegisterFailedAttempt(model?.Email, remoteAddress);
				else
					loginThrottle.AbandonAttempt(model?.Email, remoteAddress);
			}
			return DoResponse(response);
		}

		[AllowAnonymous]
		[Route("api/v3/en_US/auth/jwt/token/refresh")]
		[HttpPost]
		public async Task<IActionResult> GetNewJwtToken([FromBody] JwtTokenModel model)
		{
			ResponseModel response = new ResponseModel { Timestamp = DateTime.UtcNow, Success = true, Errors = new List<ErrorModel>() };

			// SECURITY - finding M-2 (CWE-20, CWE-798), OWASP A05 / A07. Same reasoning as the issue route
			// above: [AllowAnonymous], present on all seven hosts, and previously faulted on a null signing key
			// with a stack trace in the response body. Refusing here also closes the subtler half of the
			// problem - validating a SUPPLIED token requires the same key, so without this guard the refresh
			// route would attempt to validate an attacker-supplied token against a null or publicly known key.
			if (!ErpSettings.IsJwtConfigured)
			{
				response.Success = false;
				response.Message = JwtNotConfiguredMessage;
				return DoResponse(response);
			}

			try
			{
				response.Object = await AuthService.GetNewTokenAsync(model.Token);
			}
			catch (Exception e)
			{
				new LogService().Create(Diagnostics.LogType.Error, "GetNewJwtToken", e);
				response.Success = false;

				// THREAT ADDRESSED - finding H-13, CWE-209, OWASP A05 Security Misconfiguration. The second
				// of the two unconditional disclosure sites, and the more exposed of the pair: this route has
				// an [AllowAnonymous] exemption and takes an attacker-supplied token, so every failure was a
				// reliable way to pull a stack trace out of the server. Like the issue route above it was
				// guarded by no development-mode check, so an environment change alone would not have fixed
				// it. Every failure here collapses to one generic message on purpose - reporting WHY a token
				// was refused (expired, wrong signature, malformed) would help an attacker tune a forgery,
				// which is the same reasoning behind the token-lifetime validation added in AuthService. The
				// LogService record above is retained unchanged, so the detail is still captured server-side.
				if (ErpSettings.DevelopmentMode)
				{
					response.Message = e.ToString();
				}
				else
				{
					response.Message = INTERNAL_ERROR_MESSAGE;
				}
			}
			return DoResponse(response);
		}

		#endregion
	}
}
