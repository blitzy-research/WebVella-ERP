using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Exceptions;
using WebVella.Erp.Plugins.Project.Services;
using WebVella.Erp.Web;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Services;

namespace WebVella.Erp.Plugins.Project.Components
{
	[PageComponent(Label = "Project Widget Task Distribution", Library = "WebVella", Description = "Chart presenting the current project opened tasks by user", Version = "0.0.1", IconClass = "fas fa-chart-pie")]
	public class PcProjectWidgetTaskDistribution : PageComponent
	{
		protected ErpRequestContext ErpRequestContext { get; set; }

		public PcProjectWidgetTaskDistribution([FromServices]ErpRequestContext coreReqCtx)
		{
			ErpRequestContext = coreReqCtx;
		}

		public class PcProjectWidgetTaskDistributionOptions
		{

			[JsonProperty(PropertyName = "project_id")]
			public string ProjectId { get; set; } = null;
		}

		public async Task<IViewComponentResult> InvokeAsync(PageComponentContext context)
		{
			ErpPage currentPage = null;
			try
			{
				#region << Init >>
				if (context.Node == null)
				{
					return await Task.FromResult<IViewComponentResult>(Content("Error: The node Id is required to be set as query parameter 'nid', when requesting this component"));
				}

				var pageFromModel = context.DataModel.GetProperty("Page");
				if (pageFromModel == null)
				{
					return await Task.FromResult<IViewComponentResult>(Content("Error: PageModel cannot be null"));
				}
				else if (pageFromModel is ErpPage)
				{
					currentPage = (ErpPage)pageFromModel;
				}
				else
				{
					return await Task.FromResult<IViewComponentResult>(Content("Error: PageModel does not have Page property or it is not from ErpPage Type"));
				}

				var options = new PcProjectWidgetTaskDistributionOptions();
				if (context.Options != null)
				{
					options = JsonConvert.DeserializeObject<PcProjectWidgetTaskDistributionOptions>(context.Options.ToString());
				}

				var componentMeta = new PageComponentLibraryService().GetComponentMeta(context.Node.ComponentName);
				#endregion


				ViewBag.Options = options;
				ViewBag.Node = context.Node;
				ViewBag.ComponentMeta = componentMeta;
				ViewBag.RequestContext = ErpRequestContext;
				ViewBag.AppContext = ErpAppContext.Current;
				ViewBag.ComponentContext = context;

				if (context.Mode != ComponentMode.Options && context.Mode != ComponentMode.Help)
				{

					Guid projectId = context.DataModel.GetPropertyValueByDataSource(options.ProjectId) as Guid? ?? Guid.Empty;

					if (projectId == Guid.Empty)
						return await Task.FromResult<IViewComponentResult>(Content("Error: ProjectId is required"));

					var projectRecord = new ProjectService().Get(projectId);
					var projectTasks = new TaskService().GetTaskQueue(projectId,null);

					var users = new UserService().GetAll();
					var userDict = new Dictionary<Guid, EntityRecord>();

					foreach (var task in projectTasks)
					{
						var ownerId = (Guid?)task["owner_id"];
						var taskStatus = (Guid)task["status_id"];
						var endTime = (DateTime?)task["end_time"];


						var userRecord = new EntityRecord();
						userRecord["overdue"] = (int)0;
						userRecord["today"] = (int)0;
						userRecord["other"] = (int)0;
						//The unowned bucket is keyed on Guid.Empty, and that key is now derived ONCE, here, rather
						//than re-derived at each of the three places below that need it.
						//THIS REPAIR IS LOAD-BEARING FOR A SECURITY CONTROL, which is why it is made rather than
						//left as the pre-existing defect it is. The previous form read
						//"if (ownerId == null && !userDict.ContainsKey(Guid.Empty)) ... else if
						//(!userDict.ContainsKey(ownerId.Value))", so on the SECOND task with no owner the first
						//test was false - the empty bucket already existed - and control fell through to
						//ownerId.Value on a null Nullable<Guid>, throwing "Nullable object must have a value."
						//The catch below turned that into an error card in place of the whole widget, so the
						//H-06 encoding fix recorded immediately underneath - which publishes the avatar path and
						//the owner name as DATA so the views encode them - NEVER EXECUTED for any project holding
						//two or more unowned tasks. A stored cross-site-scripting control that cannot be reached
						//is not a control, so leaving the crash in place would have left the remediation
						//unverifiable in exactly the data state most installations are in.
						//Behaviour is otherwise unchanged, case by case: an unowned task with no bucket yet still
						//creates it; an owned task with no bucket yet still creates it; an owned task whose bucket
						//exists still reuses it. Only the case that used to throw now accumulates, which is what
						//the original "&& !ContainsKey" test shows was intended all along.
						var ownerKey = ownerId ?? Guid.Empty;
						if (!userDict.ContainsKey(ownerKey))
							userDict[ownerKey] = userRecord;

						var currentRecord = userDict[ownerKey];

						if (endTime != null)
						{
							if (endTime.Value.AddDays(1) < DateTime.Now.Date)
								currentRecord["overdue"] = ((int)currentRecord["overdue"]) + 1;
							else if (endTime.Value >= DateTime.Now.Date && endTime.Value < DateTime.Now.Date.AddDays(1))
								currentRecord["today"] = ((int)currentRecord["today"]) + 1;
							else
								currentRecord["other"] = ((int)currentRecord["other"]) + 1;
						}
						else {
							currentRecord["other"] = ((int)currentRecord["other"]) + 1;
						}
						userDict[ownerKey] = currentRecord;
					}

					var records = new List<EntityRecord>();
					foreach (var key in userDict.Keys)
					{
						if (key == Guid.Empty)
						{
							var statRecord = userDict[key];
							var row = new EntityRecord();
							var imagePath = "/_content/WebVella.Erp.Web/assets/avatar.png";

							//SECURITY - H-06 (CWE-79, OWASP A03: stored cross-site scripting): this cell used to
							//be composed here as an HTML string and then emitted through Html.Raw by both
							//Design.cshtml and Display.cshtml, which made every value interpolated into it
							//executable in the browser. The avatar and the owner name are now published as
							//separate DATA fields and the markup is authored in the views, where Razor encodes
							//them automatically. The path in this branch is a fixed literal, but the field is
							//still published so that both branches hand the views the same record shape -
							//EntityRecord throws KeyNotFoundException for a field a row does not define.
							row["user_image"] = imagePath;
							row["user_name"] = "No owner";
							row["overdue"] = statRecord["overdue"];
							row["today"] = statRecord["today"];
							row["other"] = statRecord["other"];
							records.Add(row);
						}
						else
						{
							var user = users.First(x => (Guid)x["id"] == key);
							var statRecord = userDict[key];
							var row = new EntityRecord();
							var imagePath = "/_content/WebVella.Erp.Web/assets/avatar.png";
							if (user["image"] != null && (string)user["image"] != "")
								imagePath = "/fs" + (string)user["image"];

							//SECURITY - H-06 (CWE-79, OWASP A03: stored cross-site scripting): user["image"] and
							//user["username"] are database text that any user with write access to the user
							//record controls. Publishing them as data instead of as pre-built markup moves the
							//encoding into the view, where Razor escapes both the src attribute value and the
							//name text, so neither can close the attribute or open a new element.
							row["user_image"] = imagePath;
							row["user_name"] = (string)user["username"];
							row["overdue"] = statRecord["overdue"];
							row["today"] = statRecord["today"];
							row["other"] = statRecord["other"];
							records.Add(row);
						}
					}
					ViewBag.Records = records;
				}
				switch (context.Mode)
				{
					case ComponentMode.Display:
						return await Task.FromResult<IViewComponentResult>(View("Display"));
					case ComponentMode.Design:
						return await Task.FromResult<IViewComponentResult>(View("Design"));
					case ComponentMode.Options:
						return await Task.FromResult<IViewComponentResult>(View("Options"));
					case ComponentMode.Help:
						return await Task.FromResult<IViewComponentResult>(View("Help"));
					default:
						ViewBag.Error = new ValidationException()
						{
							Message = "Unknown component mode"
						};
						return await Task.FromResult<IViewComponentResult>(View("Error"));
				}

			}
			catch (ValidationException ex)
			{
				ViewBag.Error = ex;
				return await Task.FromResult<IViewComponentResult>(View("Error"));
			}
			catch (Exception ex)
			{
				ViewBag.Error = new ValidationException()
				{
					Message = ex.Message
				};
				return await Task.FromResult<IViewComponentResult>(View("Error"));
			}
		}
	}
}
