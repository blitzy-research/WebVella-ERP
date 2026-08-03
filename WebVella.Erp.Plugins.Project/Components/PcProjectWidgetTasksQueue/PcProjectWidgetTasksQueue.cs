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
						//ever needing to escape the attribute. See SafeIconClass and SafeCssColor below.
						row["task_id"] = (Guid)task["id"];
						row["task_key"] = task["key"];
						row["task_subject"] = task["subject"];
						row["task_icon_class"] = SafeIconClass(iconClass);
						row["task_color"] = SafeCssColor(color);
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

		/// <summary>
		/// Returns the supplied Font Awesome icon class when it is safe to render into a class
		/// attribute, and an empty string when it is not.
		/// </summary>
		/// <remarks>
		/// SECURITY - H-06 (CWE-79, OWASP A03: stored cross-site scripting). The value originates in the
		/// options of the "priority" select field, so it is database configuration rather than a
		/// compile-time constant, and TaskService.GetTaskIconAndColor copies it out verbatim. The views
		/// render it into a class attribute, where Razor already HTML-encodes it - a quote can therefore
		/// no longer terminate the attribute. This allow-list is the layer encoding does not provide: it
		/// stops a value from smuggling additional class names, which would let stored configuration
		/// restyle or reposition an element on every dashboard that shows this widget.
		/// Only what a CSS class list can legitimately contain is accepted - letters, digits, spaces,
		/// hyphens and underscores. A rejected value degrades to an empty string, which is exactly what
		/// GetTaskIconAndColor already yields for a priority option with no icon configured, so the
		/// rejected rendering is an existing state of the product rather than an invented fallback.
		/// </remarks>
		/// <param name="value">The icon class recorded against the priority option.</param>
		/// <returns>The original value, or an empty string when it contains anything unexpected.</returns>
		private static string SafeIconClass(string value)
		{
			if (String.IsNullOrEmpty(value))
				return "";

			foreach (var character in value)
			{
				if (!Char.IsLetterOrDigit(character) && character != ' ' && character != '-' && character != '_')
					return "";
			}

			return value;
		}

		/// <summary>
		/// Returns the supplied colour when it is safe to render inside a style declaration, and an
		/// empty string when it is not.
		/// </summary>
		/// <remarks>
		/// SECURITY - H-06 (CWE-79, OWASP A03: stored cross-site scripting). The value originates in the
		/// options of the "priority" select field and the views interpolate it into a style declaration
		/// of the form "color:{value}". A style attribute is the one attribute where HTML encoding is not
		/// sufficient on its own: the value never has to escape the attribute to do harm, because a
		/// semicolon simply starts another declaration and a url(...) function reaches back out to the
		/// network. Constraining the value is therefore the control, and it is applied here rather than
		/// in the views so that both the Design and the Display twin are covered by one check.
		/// Two shapes are accepted, which together cover every colour this product actually stores: a
		/// hexadecimal literal of 3, 4, 6 or 8 digits, and a bare CSS colour keyword of letters only.
		/// A rejected value degrades to an empty string, so the views emit "color:" - a declaration the
		/// browser discards, leaving the element with its inherited colour. That is the same rendering
		/// the product already produces for a priority option with no colour configured.
		/// </remarks>
		/// <param name="value">The colour recorded against the priority option.</param>
		/// <returns>The original value, or an empty string when it is not a recognised colour shape.</returns>
		private static string SafeCssColor(string value)
		{
			if (String.IsNullOrEmpty(value))
				return "";

			if (value[0] == '#')
			{
				//A leading hash must be followed by exactly 3, 4, 6 or 8 hexadecimal digits.
				if (value.Length != 4 && value.Length != 5 && value.Length != 7 && value.Length != 9)
					return "";

				for (var index = 1; index < value.Length; index++)
				{
					if (!Uri.IsHexDigit(value[index]))
						return "";
				}

				return value;
			}

			//Otherwise only a bare colour keyword is accepted. Letters alone cannot open a new
			//declaration, close the attribute, or form a function call such as url(...) or expression(...).
			foreach (var character in value)
			{
				if (!Char.IsLetter(character))
					return "";
			}

			return value;
		}
	}
}
