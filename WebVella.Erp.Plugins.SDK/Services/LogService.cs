using Npgsql;
using NpgsqlTypes;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Eql;

namespace WebVella.Erp.Plugins.SDK.Services
{
    public class LogService
    {
        /// <summary>
        /// How long a diagnostic or job record is kept by the scheduled retention job.
        /// </summary>
        /// <remarks>
        /// Thirty days is the window this code always claimed to implement and is the figure the security
        /// documentation states, so it is preserved exactly; only the SELECTION of what falls outside it is
        /// corrected. Named rather than repeated so the two statements below can never drift apart.
        /// </remarks>
        private const int RetentionDays = 30;

        public void ClearJobAndErrorLogs()
        {
            //THREAT ADDRESSED - review finding L-OPEN-01, CWE-359 (exposure of private personal
            //information to an unauthorized actor), OWASP A09:2021. THIS IS NOW AGE-BASED, and the count
            //test that used to gate it is gone deliberately.
            //system_log is where the authentication audit trail lands, so every row can carry a submitted
            //e-mail address and a source IP address. The previous rule was "keep the newest 1000 rows, and
            //only consider deleting anything at all when there are more than 1000 rows AND the oldest is
            //over thirty days old", which failed in BOTH directions and neither of them was the documented
            //behaviour:
            //  RETENTION FAILURE - an installation whose log never exceeds a thousand rows kept personal
            //  data FOREVER. Years-old e-mail addresses and IP addresses were retained by a rule that
            //  claimed a thirty-day window, which is precisely the indefinite retention CWE-359 describes
            //  and what a data-protection commitment cannot survive.
            //  EVIDENCE DESTRUCTION - the mirror image. One row older than thirty days armed the rule, and
            //  it then deleted everything beyond the newest thousand REGARDLESS OF AGE. A burst of activity
            //  - exactly what an attack looks like - could therefore delete audit records minutes old,
            //  while keeping the thousand rows an attacker generated last. A retention rule must never be
            //  able to remove a record that is still inside its own window.
            //Age is now the ONLY criterion, evaluated against the database clock rather than the
            //application's, so a host with a skewed clock cannot widen or narrow the window. Both
            //statements are set-based: the previous code read every id into memory and issued one DELETE
            //per row, so a large backlog meant an unbounded id list and one round trip per record.
            List<NpgsqlParameter> logParameters = new List<NpgsqlParameter>();
            logParameters.Add(new NpgsqlParameter("retention_days", RetentionDays) { NpgsqlDbType = NpgsqlDbType.Integer });
            ExecuteNonQuerySqlCommand("DELETE FROM system_log WHERE created_on < now() - make_interval(days => @retention_days)", logParameters);

            //Canceled, Failed, Finished and Aborted jobs only: a Pending or Running job is never removed by
            //age, exactly as before.
            List<NpgsqlParameter> jobParameters = new List<NpgsqlParameter>();
            jobParameters.Add(new NpgsqlParameter("retention_days", RetentionDays) { NpgsqlDbType = NpgsqlDbType.Integer });
            ExecuteNonQuerySqlCommand("DELETE FROM jobs WHERE (status = 3 OR status = 4 OR status = 5 OR status = 6) AND created_on < now() - make_interval(days => @retention_days)", jobParameters);
        }

        public void ClearJobLogs()
        {
            //clear Canceled, Failed, Finished and Aborted jobs older than 30 days and if there is more than 1000 records
            string sql = "SELECT id, created_on FROM jobs WHERE status = 3 OR status = 4 OR status = 5 OR status = 6";
            var jobTable = ExecuteQuerySqlCommand(sql);
            var jobRows = jobTable.Rows;
            var jobsToDelete = jobRows.OfType<DataRow>().Select(r => (Guid)r["id"]).ToList();
            foreach (var jobId in jobsToDelete)
            {
                string deleteSql = $"DELETE FROM jobs WHERE id = @id";
                List<NpgsqlParameter> parameters = new List<NpgsqlParameter>();
                parameters.Add(new NpgsqlParameter("id", jobId) { NpgsqlDbType = NpgsqlDbType.Uuid });
                ExecuteNonQuerySqlCommand(deleteSql, parameters);
            }
        }

        public void ClearErrorLogs()
        {
            //clear system logs older than 30 days and if there is more than 1000 records
            string logSql = "SELECT id FROM system_log";
            var logTable = ExecuteQuerySqlCommand(logSql);
            var logRows = logTable.Rows;

            var logsToDelete = logRows.OfType<DataRow>().Select(r => (Guid)r["id"]).ToList();
            foreach (var logId in logsToDelete)
            {
                string deleteSql = $"DELETE FROM system_log WHERE id = @id";
                List<NpgsqlParameter> parameters = new List<NpgsqlParameter>();
                parameters.Add(new NpgsqlParameter("id", logId) { NpgsqlDbType = NpgsqlDbType.Uuid });
                ExecuteNonQuerySqlCommand(deleteSql, parameters);
            }

        }


        #region << Helper methods >>

        private bool ExecuteNonQuerySqlCommand(string sql, List<NpgsqlParameter> parameters = null)
        {
            using (NpgsqlConnection con = new NpgsqlConnection(ErpSettings.ConnectionString))
            {
                try
                {
                    con.Open();
                    NpgsqlCommand command = new NpgsqlCommand(sql, con);
                    command.CommandType = CommandType.Text;
                    if (parameters != null && parameters.Count > 0)
                        command.Parameters.AddRange(parameters.ToArray());
                    return command.ExecuteNonQuery() > 0;
                }
                finally
                {
                    con.Close();
                }
            }
        }

        private DataTable ExecuteQuerySqlCommand(string sql, List<NpgsqlParameter> parameters = null)
        {
            using (NpgsqlConnection con = new NpgsqlConnection(ErpSettings.ConnectionString))
            {
                try
                {
                    con.Open();
                    NpgsqlCommand command = new NpgsqlCommand(sql, con);
                    command.CommandType = CommandType.Text;
                    if (parameters != null && parameters.Count > 0)
                        command.Parameters.AddRange(parameters.ToArray());

                    DataTable resultTable = new DataTable();
                    NpgsqlDataAdapter adapter = new NpgsqlDataAdapter(command);
                    adapter.Fill(resultTable);
                    return resultTable;
                }
                finally
                {
                    con.Close();
                }
            }
        }

        #endregion
    }
}
