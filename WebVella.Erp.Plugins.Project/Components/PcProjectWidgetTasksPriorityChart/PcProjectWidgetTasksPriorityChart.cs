using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Exceptions;
using WebVella.Erp.Plugins.Project.Model;
using WebVella.Erp.Plugins.Project.Services;
using WebVella.Erp.Web;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Services;
//SECURITY - H-06 (CWE-79): SafeStyleValue now lives in WebVella.Erp.Web so the framework's select
//conversion boundary shares this plugin's allow-list rather than duplicating it.
using WebVella.Erp.Web.Utils;
using WebVella.TagHelpers.Models;

namespace WebVella.Erp.Plugins.Project.Components
{
	[PageComponent(Label = "Project Widget Priority Chart", Library = "WebVella", Description = "Chart presenting the current project tasks by priority", Version = "0.0.1", IconClass = "fas fa-chart-pie")]
	public class PcProjectWidgetTasksPriorityChart : PageComponent
	{
		protected ErpRequestContext ErpRequestContext { get; set; }

		public PcProjectWidgetTasksPriorityChart([FromServices]ErpRequestContext coreReqCtx)
		{
			ErpRequestContext = coreReqCtx;
		}

		public class PcProjectWidgetTasksPriorityChartOptions
		{

			[JsonProperty(PropertyName = "project_id")]
			public string ProjectId { get; set; } = null;

			[JsonProperty(PropertyName = "user_id")]
			public string UserId { get; set; } = null;
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

				var options = new PcProjectWidgetTasksPriorityChartOptions();
				if (context.Options != null)
				{
					options = JsonConvert.DeserializeObject<PcProjectWidgetTasksPriorityChartOptions>(context.Options.ToString());
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

					Guid? projectId = context.DataModel.GetPropertyValueByDataSource(options.ProjectId) as Guid?;
					Guid? userId = context.DataModel.GetPropertyValueByDataSource(options.UserId) as Guid?;


					var projectTasks = new TaskService().GetTaskQueue(projectId, userId, TasksDueType.StartTimeDue);
					int lowPriority = 0;
					int normalPriority = 0;
					int highPriority = 0;

					foreach (var task in projectTasks)
					{
						var taskPriority = (string)task["priority"];
						switch (taskPriority) {
							case "1":
								lowPriority++;
								break;
							case "2":
								normalPriority++;
								break;
							case "3":
								highPriority++;
								break;
							default:
								throw new Exception("Unknown task priority: " + taskPriority);
						}
					}


					var theme = new Theme();
					var chartDatasets = new List<WvChartDataset>() {
						new WvChartDataset(){
							Data = new List<decimal>(){ highPriority, normalPriority, lowPriority },
							BackgroundColor = new List<string>{ theme.RedColor, theme.LightBlueColor, theme.GreenColor},
							BorderColor = new List<string>{ theme.RedColor, theme.LightBlueColor, theme.GreenColor }
						}
					};

					//P6-03 (Visual / Data-driven UI): the three arcs above were rendered with an empty
					//`labels` array, so no segment identified itself. Supplied here rather than in the two
					//views so the Design and the Display twin cannot drift apart, and taken as the literal
					//strings both views already print beside the chart rather than from the stored select
					//options - reading them from stored data would add a second instance of the coupling
					//that already makes this widget's legend icon and its arcs disagree by one hue step.
					//Order matches Data above: high, normal, low.
					ViewBag.ChartLabels = new List<string>() { "High", "Normal", "Low" };

					ViewBag.LowPriority = lowPriority;
					ViewBag.NormalPriority = normalPriority;
					ViewBag.HighPriority = highPriority;
					//SECURITY - H-06 (CWE-79, OWASP A03:2021 - stored cross-site scripting): both views bind
					//these options straight into a class attribute and a "color:" style declaration
					//(class="@option.IconClass" style="color: @option.Color"). Razor encodes them, which closes
					//attribute breakout but not the two contexts themselves: a crafted class list still smuggles
					//extra class names, and a semicolon inside the colour simply opens another CSS declaration.
					//The values are therefore allow-listed here rather than in the views, so that the Design and
					//the Display twin are both covered by one check and cannot drift apart.
					//The originals MUST NOT be mutated in place - they belong to the cached entity metadata
					//graph, so writing to them would poison that cache for every other consumer in the process.
					//A sanitised copy is published instead; Value and Label are carried over untouched because
					//the views select options by Value and Razor encodes Label at its own text sink.
					var priorityOptions = ((SelectField)new EntityManager().ReadEntity("task").Object.Fields.First(x => x.Name == "priority")).Options;
					var safePriorityOptions = new List<SelectOption>();
					foreach (var priorityOption in priorityOptions)
					{
						safePriorityOptions.Add(new SelectOption(priorityOption.Value, priorityOption.Label,
							SafeStyleValue.IconClass(priorityOption.IconClass), SafeStyleValue.CssColor(priorityOption.Color)));
					}
					ViewBag.PriorityOptions = safePriorityOptions;
					ViewBag.Datasets = chartDatasets;
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
