using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using Npgsql;
using System;
using System.Data;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Database;

namespace WebVella.Erp.Diagnostics
{
	public class Log
	{

		public EntityRecordList GetLogs(int page, int pageSize, string querySource = null, string queryMessage = null)
		{
			int offset = (page - 1) * pageSize;
			int limit = pageSize;

			using (var connection = DbContext.Current.CreateConnection())
			{
				var sql = $@"SELECT *, COUNT(*) OVER() AS ___total_count___ FROM system_log WHERE (source  ILIKE  @querySource  OR @querySource is null)  AND (message  ILIKE  @queryMessage OR @queryMessage is null ) ORDER BY created_on DESC LIMIT {limit} OFFSET {offset} ";

				var cmd = connection.CreateCommand(sql);
				cmd.Parameters.Add(new NpgsqlParameter("@querySource", string.IsNullOrWhiteSpace(querySource) ? (object)DBNull.Value : $"%{querySource}%"));
				cmd.Parameters.Add(new NpgsqlParameter("@queryMessage", string.IsNullOrWhiteSpace(queryMessage) ? (object)DBNull.Value : $"%{queryMessage}%"));

				DataTable dt = new DataTable();
				new NpgsqlDataAdapter(cmd).Fill(dt);

				EntityRecordList result = new EntityRecordList();
				foreach (DataRow dr in dt.Rows)
				{
					result.TotalCount = (int)((long)dr["___total_count___"]);
					EntityRecord record = new EntityRecord();
					record["id"] = dr["id"];
					record["created_on"] = dr["created_on"];
					record["type"] = dr["type"];
					record["notification_status"] = dr["notification_status"];
					record["source"] = dr["source"];
					record["message"] = dr["message"];
					if (dr["details"] == DBNull.Value)
						record["details"] = null;
					else
						record["details"] = dr["details"];

					result.Add(record);
				}
				return result;

			}
		}

		public void Create(LogType type, string source, string message, string details, LogNotificationStatus notificationStatus = LogNotificationStatus.NotNotified, bool saveDetailsAsJson = false)
		{
			CreateAndGetId(type, source, message, details, notificationStatus, saveDetailsAsJson);
		}

		/// <summary>
		/// Persists a diagnostic record exactly as <see cref="Create(LogType, string, string, string, LogNotificationStatus, bool)"/>
		/// does and returns the identifier of the row that was written.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - review finding M-OPEN-03, CWE-532 (insertion of sensitive information into a
		/// log or transport) with CWE-209 (information exposure through an error message), OWASP A09:2021.
		/// WebVella.Erp.Web.Services.LogService used to hand the full record - the exception message, the
		/// stack trace, the inner exception and the request URL - to an outbound SMTP notification BEFORE
		/// anything was persisted, so the fault detail left the machine ahead of the database and a
		/// delivery failure could lose the diagnostic outright. The notification now carries only the
		/// severity, the source and the identifier RETURNED HERE, which requires the record to exist
		/// first. The identifier is the whole reason this overload exists: without it a content-free
		/// notification could not be correlated with the record it announces, and an operator would have
		/// no way back from the alert to the detail. Callers that do not need the identifier keep using
		/// the void overload above, so no existing call site changes.
		/// </remarks>
		public static Guid CreateAndGetId(LogType type, string source, string message, string details, LogNotificationStatus notificationStatus = LogNotificationStatus.NotNotified, bool saveDetailsAsJson = false)
		{
			Guid id = Guid.NewGuid();
			using (var connection = DbContext.Current.CreateConnection())
			{
				var cmd = connection.CreateCommand("INSERT INTO system_log(id,created_on,type,message,source,details,notification_status) VALUES(@id,@created_on,@type,@message,@source,@details,@notification_status);");
				cmd.Parameters.Add(new NpgsqlParameter("@id", id));
				cmd.Parameters.Add(new NpgsqlParameter("@type", ((int)type)));
				cmd.Parameters.Add(new NpgsqlParameter("@source", source ?? string.Empty));
				cmd.Parameters.Add(new NpgsqlParameter("@message", message ?? string.Empty));
				cmd.Parameters.Add(new NpgsqlParameter("@notification_status", ((int)notificationStatus)));
				cmd.Parameters.Add(new NpgsqlParameter("@details", details ?? string.Empty));
				cmd.Parameters.Add(new NpgsqlParameter("@created_on", DateTime.UtcNow));
				cmd.ExecuteNonQuery();
			}
			return id;
		}

		/// <summary>
		/// Records the outcome of the notification attempt for an already persisted diagnostic record.
		/// </summary>
		/// <remarks>
		/// Part of the finding M-OPEN-03 remediation described on <see cref="CreateAndGetId"/>: because the
		/// record is now written before the notification is attempted, its notification status has to be
		/// settled afterwards rather than being decided up front. <see cref="LogNotificationStatus.Notified"/>
		/// keeps its existing meaning and <see cref="LogNotificationStatus.NotificationFailed"/> - an
		/// existing member that nothing had ever written - now marks a diagnostic whose alert did not
		/// reach the operator, which is itself a condition an operator needs to be able to find.
		/// </remarks>
		public static void SetNotificationStatus(Guid id, LogNotificationStatus notificationStatus)
		{
			using (var connection = DbContext.Current.CreateConnection())
			{
				var cmd = connection.CreateCommand("UPDATE system_log SET notification_status = @notification_status WHERE id = @id;");
				cmd.Parameters.Add(new NpgsqlParameter("@notification_status", ((int)notificationStatus)));
				cmd.Parameters.Add(new NpgsqlParameter("@id", id));
				cmd.ExecuteNonQuery();
			}
		}

		public void Create(LogType type, string source, Exception ex, HttpRequest request = null, LogNotificationStatus notificationStatus = LogNotificationStatus.NotNotified)
		{
			string details = MakeDetailsJson("", ex, request);
			Create(type, source, ex?.Message, details, notificationStatus);
		}

		public void Create(LogType type, string source, string message, Exception ex, HttpRequest request = null, LogNotificationStatus notificationStatus = LogNotificationStatus.NotNotified)
		{
			string details = MakeDetailsJson("", ex, request);
			Create(type, source, message, details, notificationStatus);
		}

		public static string MakeDetailsJson(string details, Exception ex = null, HttpRequest request = null)
		{
			if (string.IsNullOrWhiteSpace(details) && ex == null && request == null)
				return null;

			EntityRecord eRecord = new EntityRecord();
			eRecord["message"] = details;
			eRecord["stack_trace"] = null;
			eRecord["source"] = null;
			eRecord["inner_exception"] = null;
			eRecord["request_url"] = null;

			if (ex != null)
			{
				eRecord["message"] = details + ex.Message;
				eRecord["stack_trace"] = ex.StackTrace;
				eRecord["source"] = ex.Source;
				eRecord["inner_exception"] = null;
				eRecord["request_url"] = null;

				if (ex.InnerException != null)
				{
					EntityRecord ieRecord = new EntityRecord();
					ieRecord["message"] = ex.InnerException.Message;
					ieRecord["stack_trace"] = ex.InnerException.StackTrace;
					eRecord["inner_exception"] = ieRecord;
				}
			}

			//SECURITY - review finding M-OPEN-03, CWE-532 insertion of sensitive information into a log
			//file, OWASP A09:2021. THE QUERY STRING IS DELIBERATELY OMITTED. This value is written to
			//system_log, which every administrator can read through the log screens, and it used to carry
			//request.QueryString verbatim - so a bearer token, a password reset key, a search term or any
			//other secret or personal datum a client happened to place in the URL was copied into durable
			//storage by nothing more than an unrelated exception, and stayed there for the life of the
			//retention window. The scheme, host and path are what identify the failing route and are
			//retained; the parameters are not needed to identify it. Anything genuinely required for
			//diagnosis is already available from the exception itself and the stack trace above.
			if (request != null)
				eRecord["request_url"] = $"{request.Scheme}://{request.Host}{request.Path}";

			return JsonConvert.SerializeObject(eRecord);
		}
	}

	public enum LogType
	{
		Error = 1,
		Info = 2
	}

	public enum LogNotificationStatus
	{
		DoNotNotify = 1,
		NotNotified = 2,
		Notified = 3,
		NotificationFailed = 4
	}
}
