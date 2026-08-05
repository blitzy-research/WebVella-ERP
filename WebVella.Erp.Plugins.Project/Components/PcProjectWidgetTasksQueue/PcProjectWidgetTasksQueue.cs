using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Exceptions;
using WebVella.Erp.Plugins.Project.Model;
using WebVella.Erp.Plugins.Project.Services;
using WebVella.Erp.Web;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Services;
using WebVella.Erp.Web.Utils;

namespace WebVella.Erp.Plugins.Project.Components
{
	[PageComponent(Label = "Project Widget Tasks Queue", Library = "WebVella", Description = "tasks queue for a project or an user", Version = "0.0.1", IconClass = "fas fa-chart-pie")]
	public class PcProjectWidgetTasksQueue : PageComponent
	{
		protected ErpRequestContext ErpRequestContext { get; set; }

		public PcProjectWidgetTasksQueue([FromServices]ErpRequestContext coreReqCtx)
		{
			ErpRequestContext = coreReqCtx;
		}

		public class PcProjectWidgetTasksQueueOptions
		{

			[JsonProperty(PropertyName = "project_id")]
			public string ProjectId { get; set; } = null;

			[JsonProperty(PropertyName = "user_id")]
			public string UserId { get; set; } = null;

			[JsonProperty(PropertyName = "type")]
			public TasksDueType Type { get; set; } = TasksDueType.All;
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

				var options = new PcProjectWidgetTasksQueueOptions();
				if (context.Options != null)
				{
					options = JsonConvert.DeserializeObject<PcProjectWidgetTasksQueueOptions>(context.Options.ToString());
				}

				var componentMeta = new PageComponentLibraryService().GetComponentMeta(context.Node.ComponentName);
				#endregion


				ViewBag.Options = options;
				ViewBag.Node = context.Node;
				ViewBag.ComponentMeta = componentMeta;
				ViewBag.RequestContext = ErpRequestContext;
				ViewBag.AppContext = ErpAppContext.Current;
				ViewBag.ComponentContext = context;
				ViewBag.TypeOptions = ModelExtensions.GetEnumAsSelectOptions<TasksDueType>();

				if (context.Mode != ComponentMode.Options && context.Mode != ComponentMode.Help)
				{

					Guid? projectId = context.DataModel.GetPropertyValueByDataSource(options.ProjectId) as Guid?;

					Guid? userId = context.DataModel.GetPropertyValueByDataSource(options.UserId) as Guid?;
					var limit = options.Type == TasksDueType.EndTimeNotDue ? 10 : 50;
					var taskQueue = new TaskService().GetTaskQueue(projectId, userId, options.Type, limit);

					var users = new UserService().GetAll();

					var resultRecords = new List<EntityRecord>();

					foreach (var task in taskQueue)
					{
						var imagePath = "/_content/WebVella.Erp.Web/assets/avatar.png";
						var user = new EntityRecord();
						user["username"] = "No Owner";
						if (task["owner_id"] != null)
						{
							user = users.First(x => (Guid)x["id"] == (Guid)task["owner_id"]);
							if (user["image"] != null && (string)user["image"] != "")
								imagePath = "/fs" + (string)user["image"];
						}
						string iconClass = "";
						string color = "";
						new TaskService().GetTaskIconAndColor((string)task["priority"],out iconClass, out color);

						var row = new EntityRecord();
						//SECURITY - H-06 (CWE-79, OWASP A03: stored cross-site scripting): the two cells below
						//used to be composed here as HTML strings and emitted through Html.Raw by Design.cshtml
						//and Display.cshtml, so the task key, the task subject, the owner name, the avatar path
						//and the priority icon class and colour - every one of them database text - reached the
						//browser unencoded. Each value is now published as its own DATA field and the markup is
						//authored in the views, where Razor encodes automatically.
						//The icon class and the colour get an additional allow-list because HTML encoding alone
						//does not fully constrain them: they land in a class attribute and inside a style
						//declaration, where a crafted value still injects extra class names or extra CSS without
						//ever needing to escape the attribute. See SafeStyleValue for the checks themselves.
						//Those two checks used to be private members of this class, which is how three sibling
						//render paths for the same two values came to be left unguarded. They now live in
						//SafeStyleValue so that every consumer shares one implementation. The call below is
						//redundant today because TaskService.GetTaskIconAndColor guards its own output, and it is
						//kept anyway: this component would otherwise depend on a caller-side guarantee for its
						//own safety, and the check is idempotent, so an already-clean value passes unchanged.
						row["task_id"] = (Guid)task["id"];
						row["task_key"] = task["key"];
						row["task_subject"] = task["subject"];
						row["task_icon_class"] = SafeStyleValue.IconClass(iconClass);
						row["task_color"] = SafeStyleValue.CssColor(color);
						row["user_image"] = imagePath;
						row["user_name"] = (string)user["username"];
						row["date"] = ((DateTime?)task["end_time"]).ConvertToAppDate();
						resultRecords.Add(row);
					}
					ViewBag.Records = resultRecords;
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
