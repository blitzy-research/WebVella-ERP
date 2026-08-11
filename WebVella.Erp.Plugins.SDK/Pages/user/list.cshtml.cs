using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Api.Models.AutoMapper;
using WebVella.Erp.Database;
using WebVella.Erp.Diagnostics;
using WebVella.Erp.Eql;
using WebVella.Erp.Exceptions;
using WebVella.Erp.Web;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Services;
using WebVella.Erp.Web.Utils;
using WebVella.TagHelpers.Models;

namespace WebVella.Erp.Plugins.SDK.Pages.User
{
	public class ListModel : BaseErpPageModel
	{
		public ListModel([FromServices]ErpRequestContext reqCtx) { ErpRequestContext = reqCtx; }

		public List<WvGridColumnMeta> Columns { get; set; } = new List<WvGridColumnMeta>();

		public EntityRecordList Records { get; set; } = new EntityRecordList();

		public int PagerSize { get; set; } = 10;

		public int Pager { get; set; } = 1;

		public int TotalCount { get; set; } = 0;

		public string SortBy { get; set; } = "";

		public QuerySortType SortOrder { get; set; } = QuerySortType.Ascending;

		/// <summary>
		/// P6-17: whether the signed-in principal may delete a user record. Resolved from the platform's
		/// own entity permissions rather than from the presence of the button, so that the view can only
		/// ever hide an action the server independently refuses - the delete handler re-reads this value
		/// and does not trust the request that reached it.
		/// Left without an initializer on purpose: bool already defaults to false, so deny-by-default
		/// holds, and writing `= false` is what CA1805 reports as a redundant initialization.
		/// </summary>
		public bool DeleteAccess { get; set; }

		/// <summary>
		/// P6-17: the signed-in principal's own record id, used to withhold the delete action from the
		/// row that would sign the operator out of the interface they are working in.
		/// </summary>
		public Guid CurrentUserId { get; set; } = Guid.Empty;

		public IActionResult OnGet()
		{
			var initResult = Init();
			if (initResult != null)
				return initResult;

			#region << InitPage >>

			int pager = 0;
			string sortBy = "";
			QuerySortType sortOrder = QuerySortType.Ascending;
			PageUtils.GetListQueryParams(PageContext.HttpContext, out pager, out sortBy, out sortOrder);
			Pager = pager;
			SortBy = sortBy;
			SortOrder = sortOrder;

			#endregion

			#region << Create Columns >>

			Columns = new List<WvGridColumnMeta>() {
				new WvGridColumnMeta(){
					Name = "action",
					Width="1%"
				},
				new WvGridColumnMeta(){
					Label = "email",
					Name = "email",
					Sortable = true,
					Width = "120px"
				},
				new WvGridColumnMeta(){
					Label = "username",
					Name = "username",
					Sortable = true
				},
				new WvGridColumnMeta(){
					Label = "role",
					Name = "role",
					Sortable = false
				}
			};

			#endregion

			#region << Records >>
			var eql = " SELECT id,email,username,$user_role.name FROM user ";
			List<EqlParameter> eqlParams = new List<EqlParameter>();

			//Apply sort
			if (!String.IsNullOrWhiteSpace(SortBy) && (new List<string>() { "email", "username" }).Contains(SortBy))
			{
				eqlParams.Add(new EqlParameter("@sortBy", SortBy));
				if (SortOrder == QuerySortType.Descending)
				{
					eqlParams.Add(new EqlParameter("@sortOrder", "Desc"));
				}
				else
				{
					eqlParams.Add(new EqlParameter("@sortOrder", "Asc"));
				}
				eql += " ORDER BY @sortBy @sortOrder ";
			}
			else {
				eql += " ORDER BY email Asc ";
			}
			eql += " PAGE @page ";
			eql += " PAGESIZE @pageSize ";
			eqlParams.Add(new EqlParameter("@page", Pager));
			eqlParams.Add(new EqlParameter("@pageSize", PagerSize));
			
			Records = new EqlCommand(eql, eqlParams).Execute();
			TotalCount = Records.TotalCount;
			#endregion

			#region << P6-17 - delete authorization >>

			//P6-17 (Functional): this list offered no way to delete a user even though the capability
			//already existed and was already authorized on the record API. Authorization is resolved
			//here, from the same EntityPermission check the platform's own record grid uses, and it is
			//resolved again inside OnPost - the button's presence is a convenience, never the control.
			var userEntity = new EntityManager().ReadEntity("user").Object;
			DeleteAccess = userEntity != null && SecurityContext.HasEntityPermission(EntityPermission.Delete, userEntity);
			CurrentUserId = SecurityContext.CurrentUser != null ? SecurityContext.CurrentUser.Id : Guid.Empty;

			#endregion

			BeforeRender();
			return Page();
		}

		/// <summary>
		/// P6-17 (Functional): deletes one user record.
		///
		/// Modelled on the platform's existing guarded delete at
		/// WebVella.Erp.Plugins.SDK/Pages/entity/data.cshtml.cs, deliberately reusing its shape rather
		/// than inventing a second one: the record id arrives as a query key on a POST, is parsed as a
		/// Guid before it is used, and deletion goes through RecordManager.DeleteRecord so that every
		/// hook, relation cascade and validation the platform already runs on a record deletion still
		/// runs here. There is no DeleteUser on SecurityManager to call instead.
		///
		/// Three refusals are added on top of that precedent, all of them server-side, because a
		/// missing UI control is not an access control (OWASP A01:2021, CWE-284 - the interface hiding
		/// an action the server would still perform):
		///   1. the EntityPermission.Delete check is repeated here, so a hand-made POST from a
		///      principal who cannot see the button is refused rather than honoured;
		///   2. the "system" account cannot be deleted - it owns the background job and migration
		///      scopes, and removing it would leave those unattributable;
		///   3. the signed-in principal cannot delete their own record, which would otherwise destroy
		///      the session mid-request and leave the operator staring at a login form with no
		///      explanation.
		/// Each refusal reports through the page's own validation surface rather than a bare NotFound,
		/// so the operator learns why the action was declined.
		/// </summary>
		public IActionResult OnPost()
		{
			var result = OnGet();
			if (result is NotFoundResult)
				return result;

			if (!PageContext.HttpContext.Request.Query.ContainsKey("recordId"))
				return NotFound();

			if (!Guid.TryParse(PageContext.HttpContext.Request.Query["recordId"], out Guid recordId))
				return NotFound();

			var userEntity = new EntityManager().ReadEntity("user").Object;
			if (userEntity == null)
				return NotFound();

			try
			{
				//Guard 1 - deny by default. Re-checked here and not inherited from the rendered page.
				if (!SecurityContext.HasEntityPermission(EntityPermission.Delete, userEntity))
					throw new ValidationException("You are not authorized to delete users.");

				//Guard 3 - self-deletion. Checked before the record is read, because it needs no read.
				if (CurrentUserId != Guid.Empty && recordId == CurrentUserId)
					throw new ValidationException("You cannot delete the user you are signed in as.");

				//Guard 2 - the platform's own account. The username is read back from storage rather
				//than taken from the request, so the check cannot be bypassed by what was posted.
				var targetRecords = new EqlCommand("SELECT id,username FROM user WHERE id = @recordId",
					new EqlParameter("@recordId", recordId)).Execute();

				if (targetRecords == null || targetRecords.Count == 0)
					throw new ValidationException("This user no longer exists.");

				if ((string)targetRecords[0]["username"] == "system")
					throw new ValidationException("The system user cannot be deleted.");

				//DEFECT ADDRESSED - the control this finding asked for has to complete, not merely appear.
				//RecordManager.DeleteRecord delegates to DbRecordRepository.Delete, which issues a bare
				//DELETE and never detaches the record's many-to-many rows, so PostgreSQL refuses it on
				//rel_user_role's user_role_target foreign key (ON DELETE NO ACTION) for every account that
				//holds a role - 15 of the 27 in this installation - and DeleteRecord then replaces the
				//exception with a generic "internal error" that tells the operator nothing actionable.
				//A role assignment is a pure join row with no meaning once one endpoint is gone, so clearing
				//it is part of removing the user rather than a separate act of data destruction.
				//WHY ONE TRANSACTION: without it a failure on the delete would leave a user stripped of every
				//role but still present and able to sign in - a privilege change produced by a delete that
				//did not happen. The platform's Begin/Commit nest as savepoints, so inner calls are safe here.
				//WHY ONLY user_role: it is the one relation the core itself owns (SystemIds.UserRoleRelationId).
				//References from authored content are refused below with an actionable message instead of
				//being cascaded away, because that content is not this handler's to discard.
				var recMan = new RecordManager();
				using (var connection = DbContext.Current.CreateConnection())
				{
					bool committed = false;
					try
					{
						connection.BeginTransaction();

						var detachResponse = recMan.RemoveRelationManyToManyRecord(SystemIds.UserRoleRelationId, null, recordId);
						if (!detachResponse.Success)
						{
							var detachException = new ValidationException(detachResponse.Message);
							detachException.Errors = detachResponse.Errors.MapTo<ValidationError>();
							throw detachException;
						}

						var response = recMan.DeleteRecord(userEntity, recordId);
						if (!response.Success)
						{
							//DeleteRecord has already genericised whatever the database reported, so the only
							//blocker it can still be describing is a row that references this user. Name the
							//remedy rather than repeating "an internal error occurred".
							throw new ValidationException("This user could not be deleted because other records still reference it. Reassign or remove the tasks, time logs, comments, projects and task subscriptions belonging to this user, then try again.");
						}

						connection.CommitTransaction();
						committed = true;
					}
					finally
					{
						if (!committed)
						{
							//A fault while unwinding must not replace the exception that caused it, or the
							//operator is shown a cleanup error instead of the reason the delete was refused.
							try
							{
								connection.RollbackTransaction();
							}
							catch (Exception rollbackException)
							{
								//DoNotNotify: this path is reachable at will, and the notified default is what
								//makes WebVella.Erp.Web/Services/LogService.cs mail a log record off-box.
								//Fully qualified: this page's namespace has a sibling "Log" namespace
								//(Pages/log), which shadows the diagnostics type by simple name.
								new WebVella.Erp.Diagnostics.Log().Create(LogType.Error, "SDK.UserList.Delete",
									"Rolling back a refused user delete failed.", rollbackException.Message,
									LogNotificationStatus.DoNotNotify);
							}
						}
					}
				}

				return Redirect("/sdk/access/user/l/list");
			}
			catch (ValidationException ex)
			{
				Validation.Message = ex.Message;
				Validation.Errors = ex.Errors;
			}

			BeforeRender();
			return Page();
		}
	}
}