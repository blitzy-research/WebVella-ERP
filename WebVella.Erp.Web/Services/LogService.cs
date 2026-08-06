using Microsoft.AspNetCore.Http;
using System;
using WebVella.Erp.Diagnostics;

namespace WebVella.Erp.Web.Services
{
    public class LogService : BaseService
	{
        /// <summary>
        /// Creates log of specified type and send email notification.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <param name="source">The source.</param>
        /// <param name="message">The message.</param>
        /// <param name="details">The details.</param>
        /// <param name="notificationStatus">The notification status.</param>
        /// <param name="saveDetailsAsJson">if set to <c>true</c> [save details as json].</param>
        public void Create(LogType type, string source, string message, string details, LogNotificationStatus notificationStatus = LogNotificationStatus.NotNotified, bool saveDetailsAsJson = false)
        {
            //THREAT ADDRESSED - review finding M-OPEN-03, CWE-532 with CWE-209 and CWE-779, OWASP A09:2021.
            //See the PERSIST FIRST, NOTIFY SECOND note on Notify below for the full reasoning; the order of
            //these two statements is the fix and must not be swapped back.
            Guid logId = Log.CreateAndGetId(type, source, message, details, notificationStatus, saveDetailsAsJson);

            if (notificationStatus == LogNotificationStatus.NotNotified)
                Notify(logId, type, source, null);
        }

        /// <summary>
        ///  Creates log of specified type and send email notification.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <param name="source">The source.</param>
        /// <param name="ex">The ex.</param>
        /// <param name="request">The request.</param>
        /// <param name="notificationStatus">The notification status.</param>
        public void Create(LogType type, string source, Exception ex, HttpRequest request = null, LogNotificationStatus notificationStatus = LogNotificationStatus.NotNotified)
        {
            //THREAT ADDRESSED - review finding M-OPEN-03. This overload was the worst of the three: it
            //passed Log.MakeDetailsJson("", ex, request) - the exception message, the stack trace, the inner
            //exception and the request URL - plus ex.Message as the mail SUBJECT, to an off-box relay before
            //the record was written. See Notify below.
            string details = Log.MakeDetailsJson("", ex, request);
            Guid logId = Log.CreateAndGetId(type, source, ex?.Message, details, notificationStatus);

            if (notificationStatus == LogNotificationStatus.NotNotified)
                Notify(logId, type, source, request?.Host.ToString());
        }

        /// <summary>
        ///  Creates log of specified type and send email notification.
        /// </summary>
        /// <param name="type">The type.</param>
        /// <param name="source">The source.</param>
        /// <param name="message">The message.</param>
        /// <param name="ex">The ex.</param>
        /// <param name="request">The request.</param>
        /// <param name="notificationStatus">The notification status.</param>
        public void Create(LogType type, string source, string message, Exception ex, HttpRequest request = null, LogNotificationStatus notificationStatus = LogNotificationStatus.NotNotified)
        {
            //THREAT ADDRESSED - review finding M-OPEN-03. See Notify below.
            string details = Log.MakeDetailsJson("", ex, request);
            Guid logId = Log.CreateAndGetId(type, source, message, details, notificationStatus);

            if (notificationStatus == LogNotificationStatus.NotNotified)
                Notify(logId, type, source, request?.Host.ToString());
        }

        /// <summary>
        /// Announces an ALREADY PERSISTED diagnostic record to the configured operator mailbox and records
        /// the outcome of that attempt on the record itself.
        /// </summary>
        /// <remarks>
        /// <para>
        /// THREAT ADDRESSED - review finding M-OPEN-03, CWE-532 (sensitive information written to a log or
        /// sent over an unprotected transport) with CWE-209 (information exposure through an error message)
        /// and CWE-779 (logging of excessive data), OWASP A09:2021.
        /// </para>
        /// <para>
        /// PERSIST FIRST, NOTIFY SECOND. All three Create overloads used to call
        /// <c>MailService.SendLogMessage</c> BEFORE <c>Log.Create</c> whenever the notification status was
        /// left at its <see cref="LogNotificationStatus.NotNotified"/> default, which is what every caller
        /// that did not think about it did. That ordering had two consequences. The diagnostic left the
        /// machine over SMTP before any durable copy of it existed, so the least trustworthy copy was made
        /// first; and the write waited on a synchronous off-box send that had no timeout of its own, so a
        /// slow or black-holed relay stalled the caller for the client's default of a hundred seconds and a
        /// process or thread that did not survive that window lost the record entirely. The record is now
        /// written first and unconditionally, and this method only announces it.
        /// </para>
        /// <para>
        /// WHAT THE NOTIFICATION MAY CARRY. Severity, source, the originating HTTP host and the identifier
        /// of the stored record - nothing else. It deliberately no longer carries the message, the
        /// exception, the stack trace, the inner exception or the request URL: e-mail is a plaintext,
        /// multi-hop, indefinitely retained transport that the platform does not control past the first
        /// relay, and an operator who needs the detail can read it from <c>system_log</c> using the
        /// identifier. This is what keeps the alert useful without turning every unhandled exception into
        /// an off-box disclosure of internal paths, SQL text and request data.
        /// </para>
        /// <para>
        /// A NOTIFICATION FAILURE NEVER REPLACES THE APPLICATION RESULT. The outcome is recorded on the row
        /// - <see cref="LogNotificationStatus.Notified"/> or <see cref="LogNotificationStatus.NotificationFailed"/>
        /// - and never propagated, because this is called from exception handlers whose own result must
        /// survive. When notification is not configured at all nothing is attempted and the row keeps its
        /// <see cref="LogNotificationStatus.NotNotified"/> status, exactly as before this change, so an
        /// installation with diagnostic mail switched off sees no difference in its data.
        /// </para>
        /// </remarks>
        private static void Notify(Guid logId, LogType type, string source, string host)
        {
            //Not configured is not a failure: attempting a send would throw on every single log write and
            //mark every record NotificationFailed, which would be a change in the stored data of every
            //installation that never enabled diagnostic mail.
            if (!MailService.LogNotificationsEnabled)
                return;

            LogNotificationStatus outcome = new MailService().SendLogNotification(type, source, logId, host)
                ? LogNotificationStatus.Notified
                : LogNotificationStatus.NotificationFailed;

            try
            {
                Log.SetNotificationStatus(logId, outcome);
            }
            catch (Exception ex)
            {
                //The record itself is already safely persisted, which was the point of the reordering. A
                //fault while stamping the notification outcome onto it must not escape into the exception
                //handler that called this, so it is reported on the diagnostic channel of last resort and
                //the row simply keeps its NotNotified status.
                MailService.ReportNotificationFault("status", ex);
            }
        }
    }
}
