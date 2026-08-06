using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Threading;
using WebVella.Erp.Diagnostics;

namespace WebVella.Erp.Web.Services
{
    public class MailService : BaseService
    {
        #region <--- Methods --->

        /// <summary>
        /// True when diagnostic notification is configured completely enough to be attempted.
        /// </summary>
        /// <remarks>
        /// Part of the finding M-OPEN-03 remediation. Callers consult this instead of discovering an
        /// incomplete configuration through a thrown exception on every single log write: an installation
        /// that never set up diagnostic mail must not have every diagnostic record stamped
        /// <c>NotificationFailed</c>, and the operator channel must not be filled with a fault that is a
        /// standing configuration state rather than an event.
        /// </remarks>
        public static bool LogNotificationsEnabled
        {
            get
            {
                return ErpSettings.EmailEnabled
                    && !string.IsNullOrWhiteSpace(ErpSettings.EmailSMTPServerName)
                    && !string.IsNullOrWhiteSpace(ErpSettings.EmailFrom)
                    && !string.IsNullOrWhiteSpace(ErpSettings.EmailTo);
            }
        }

        /// <summary>
        /// Announces an already persisted diagnostic record to the operator mailbox configured in the
        /// application settings. The notification carries the severity, the source, the originating HTTP
        /// host and the identifier of the stored record - never the message, the exception or the request.
        /// </summary>
        /// <param name="type">The severity of the stored record.</param>
        /// <param name="source">The source the stored record was written under.</param>
        /// <param name="logId">The identifier of the row in <c>system_log</c> that carries the detail.</param>
        /// <param name="host">The HTTP host the request arrived on, when the record came from a request.</param>
        /// <returns>True when the notification was handed to the relay, otherwise false.</returns>
        /// <remarks>
        /// <para>
        /// THREAT ADDRESSED - review finding M-OPEN-03, CWE-532 with CWE-209 and CWE-319 (cleartext
        /// transmission of sensitive information), OWASP A02:2021 and A09:2021. This method replaces
        /// <c>SendLogMessage</c>, which mailed the full diagnostic - message, exception detail, stack trace,
        /// inner exception and request URL including its query string - to a relay over an UNENCRYPTED
        /// session, with the exception message as the subject line, and reported nothing when it failed.
        /// The signature changed deliberately rather than the body only: a public method that mails
        /// arbitrary fault detail off-box is the vulnerability, so leaving it in place for a future caller
        /// to find would have left the finding latent. Its only callers were the three
        /// <c>Services/LogService.Create</c> overloads, all updated in the same change.
        /// </para>
        /// <para>
        /// WHY THE PAYLOAD IS AN IDENTIFIER. An alert has to say enough to be acted on and no more.
        /// Severity, source and host tell an operator whether to look now and where; the identifier takes
        /// them to the detail in <c>system_log</c>, which is access controlled, retained on a known
        /// schedule and never leaves the deployment. E-mail is none of those things.
        /// </para>
        /// <para>
        /// TRANSPORT. <see cref="SmtpClient.EnableSsl"/> is set, so the session is upgraded with STARTTLS
        /// and the relay certificate is validated by the platform's default chain policy - this type has no
        /// certificate callback override anywhere in the repository. It is unconditional, with no
        /// development escape hatch, because there is no configuration key that could express the opt-out
        /// and a diagnostic notification is not worth a cleartext session; an installation whose relay
        /// cannot offer STARTTLS should switch diagnostic mail off with <c>Settings:EmailEnabled</c>. The
        /// client is disposed and bounded by an explicit timeout, so a black-holed relay cannot pin the
        /// calling thread - this runs inside exception handlers and on request paths.
        /// </para>
        /// <para>
        /// SUBSTITUTED VALUES ARE ENCODED. The host is taken from the request and the source from the call
        /// site, so both are interpolated into the HTML body through <see cref="WebUtility.HtmlEncode"/>
        /// rather than raw (CWE-79 in an e-mail rendering context).
        /// </para>
        /// </remarks>
        public bool SendLogNotification(LogType type, string source, Guid logId, string host = null)
        {
            if (!LogNotificationsEnabled)
                return false;

            try
            {
                List<KeyValuePair<string, string>> tags = new List<KeyValuePair<string, string>>();
                tags.Add(new KeyValuePair<string, string>(key: "host", value: WebUtility.HtmlEncode(string.IsNullOrWhiteSpace(host) ? "WebVella.Erp.Web" : host)));
                tags.Add(new KeyValuePair<string, string>(key: "type", value: WebUtility.HtmlEncode(type.ToString())));
                tags.Add(new KeyValuePair<string, string>(key: "source", value: WebUtility.HtmlEncode(source ?? string.Empty)));
                tags.Add(new KeyValuePair<string, string>(key: "log_id", value: logId.ToString()));

                string html = ReplaceTagsInHtml(LogTemplate, tags);

                using (SmtpClient client = SmtpClient(ErpSettings.EmailSMTPServerName, ErpSettings.EmailSMTPPort, ErpSettings.EmailSMTPUsername, ErpSettings.EmailSMTPPassword))
                using (MailMessage mailMessage = new MailMessage())
                {
                    mailMessage.From = new MailAddress(ErpSettings.EmailFrom);
                    var emails = ErpSettings.EmailTo.Split(",", StringSplitOptions.RemoveEmptyEntries);
                    foreach (var email in emails)
                    {
                        mailMessage.To.Add(email.Trim());
                    }
                    //The subject is fixed and content-free. It used to be the exception message, which put
                    //fault detail in the one part of a message that intermediate relays log by default.
                    mailMessage.Subject = $"WebVella ERP {type} log entry recorded";
                    mailMessage.IsBodyHtml = true;
                    mailMessage.Body = html;
                    client.Send(mailMessage);
                }
                return true;
            }
            catch (Exception ex)
            {
                //The bare `catch { }` this replaces made a permanently broken notification channel
                //indistinguishable from a working one (CWE-703). The failure is now reported - rate limited,
                //and by exception type only, never by message, because a relay's own response text is
                //untrusted and can carry configuration detail.
                ReportNotificationFault("send", ex);
                return false;
            }
        }

        /// <summary>
        /// Reports a diagnostic-notification fault on the channel of last resort, rate limited.
        /// </summary>
        /// <remarks>
        /// Part of the finding M-OPEN-03 remediation, CWE-703 (improper check or handling of exceptional
        /// conditions). The standard error stream is used rather than the platform log because this is
        /// reached from the platform log's own notification path, and recursing into it would be the defect
        /// this reports. Only the exception TYPE is emitted: the message may quote the relay's response and
        /// is neither trusted nor guaranteed free of configuration detail. The first fault is always
        /// reported so a broken channel cannot go unnoticed; after that one in
        /// <see cref="NotificationFaultReportInterval"/> is, so a relay that is down cannot itself become a
        /// flood.
        /// </remarks>
        internal static void ReportNotificationFault(string stage, Exception failure)
        {
            int occurrence = Interlocked.Increment(ref notificationFaultCount);
            if (occurrence != 1 && (occurrence % NotificationFaultReportInterval) != 0)
                return;

            Console.Error.WriteLine($"WebVella.Erp diagnostic notification fault (stage '{stage}', {failure?.GetType().FullName ?? "unknown"}), occurrence {occurrence}. The diagnostic record itself was persisted to system_log; only the operator notification failed. Check the 'Settings:Email*' configuration and that the relay accepts a STARTTLS session from this host.");
        }

        /// <summary>
        /// How often a repeated notification fault is reported after the first one.
        /// </summary>
        private const int NotificationFaultReportInterval = 100;

        private static int notificationFaultCount;

        #endregion

        #region <--- Common --->

        /// <summary>
        /// Initialize SMTP client.
        /// </summary>
        /// <param name="host">The host.</param>
        /// <param name="port">The port.</param>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        private SmtpClient SmtpClient(string host, int port, string username, string password)
        {
            if (string.IsNullOrWhiteSpace(host))
                throw new InvalidOperationException("No SMTP server is configured for outbound diagnostic mail. Set 'Settings:EmailSMTPServerName' or disable notification with 'Settings:EmailEnabled'.");

            SmtpClient client = new SmtpClient(host, port);
            client.UseDefaultCredentials = false;
            client.Credentials = new NetworkCredential(username, password);
            //SECURITY - review finding M-OPEN-03, CWE-319 cleartext transmission of sensitive information,
            //OWASP A02:2021. THREAT ADDRESSED: the session carried the diagnostic body AND the relay
            //credential set on the line above in the clear, on any network between this host and the relay.
            //EnableSsl upgrades the session with STARTTLS and the certificate is validated by the default
            //chain policy - this type is never given a validation callback anywhere in the repository, and
            //must not be. This mirrors the mandatory-encryption posture finding H-OPEN-03 established for
            //the mail plugin's own MailKit transport; see SmtpService.ResolveConnectionSecurity there.
            client.EnableSsl = true;
            //A black-holed relay must not pin the calling thread: this client is used from exception
            //handlers and from request paths, and the type's own default of a hundred seconds - measured at
            //100.3s against a socket that accepts and never answers - turns an unrelated fault into a
            //request that appears hung (CWE-400).
            client.Timeout = SmtpTimeoutMilliseconds;
            return client;
        }

        /// <summary>
        /// Upper bound on a diagnostic notification send, in milliseconds.
        /// </summary>
        private const int SmtpTimeoutMilliseconds = 15000;

        /// <summary>
        /// Replaces the tags in HTML.
        /// </summary>
        /// <param name="html">The HTML.</param>
        /// <param name="tags">The tags.</param>
        /// <returns></returns>
        private string ReplaceTagsInHtml(string html, List<KeyValuePair<string, string>> tags)
        {

            StringBuilder sb = new StringBuilder(html);
            foreach (var tag in tags)
            {
                sb.Replace("{{" + tag.Key + "}}", tag.Value);
            }
            return sb.ToString();
        }

        private const string LogTemplate = @"<!DOCTYPE html>
                                            <html lang='en'>
	                                            <head>
		                                            <title>Log</title>
	                                            </head>
	                                            <body>
		                                            <table>
			                                            <tr>
				                                            <td>
					                                            <b>host: </b>{{host}}</td>
			                                            </tr>
			                                            <tr>
				                                            <td>
					                                            <b>log type: </b>{{type}}</td>
			                                            </tr>
			                                            <tr>
				                                            <td>
					                                            <b>source: </b>{{source}}</td>
			                                            </tr>
			                                            <tr>
				                                            <td>
					                                            <b>log entry id: </b>{{log_id}}</td>
			                                            </tr>
			                                            <tr>
				                                            <td>
					                                            The message, the exception detail and the request are deliberately excluded from this
					                                            notification (finding M-OPEN-03). Open the log entry above in the ERP administration
					                                            to read them.</td>
			                                            </tr>
		                                            </table>

	                                            </body>
                                            </html>";
        private const string InvoiceTemplate = @"<!DOCTYPE html>
                                            <html lang='en'>
	                                            <head>
		                                            <title>Invoice</title>
	                                            </head>
	                                            <body>
		                                            TODO
	                                            </body>
                                            </html>";
        #endregion //<--- End Common --->
    }
}
