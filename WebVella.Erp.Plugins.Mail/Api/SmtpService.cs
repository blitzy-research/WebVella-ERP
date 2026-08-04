using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using WebVella.Erp.Exceptions;
using WebVella.Erp.Plugins.Mail.Services;
using WebVella.Erp.Utilities;
using HtmlAgilityPack;
using System.IO;
using WebVella.Erp.Database;
using Microsoft.AspNetCore.StaticFiles;

namespace WebVella.Erp.Plugins.Mail.Api
{
	public class SmtpService
	{
		#region <--- Properties --->

		[JsonProperty(PropertyName = "id")]
		public Guid Id { get; internal set; }

		[JsonProperty(PropertyName = "name")]
		public string Name { get; internal set; }

		[JsonProperty(PropertyName = "server")]
		public string Server { get; internal set; }

		[JsonProperty(PropertyName = "port")]
		public int Port { get; internal set; }

		[JsonProperty(PropertyName = "username")]
		public string Username { get; internal set; }

		//SECURITY - finding F31 (High), CWE-200 exposure of sensitive information, CWE-522
		//insufficiently protected credentials, OWASP A01:2021 + A02:2021.
		//THREAT ADDRESSED: the SMTP relay password was an ordinary serializable member, so any object
		//graph that reached a JSON writer - a page data model, an API response envelope, a diagnostic
		//dump of a cached service - carried the plaintext credential out of the process. JsonIgnore
		//REPLACES the property mapping rather than joining it, so there is exactly one serialization
		//instruction on this member and no question of which one wins.
		//NO WRITE PATH LOSES THE VALUE: nothing in the repository serializes or deserializes this type.
		//Its only producer is the record-to-model mapping in Api/AutoMapper/SmtpServiceProfile.cs, which
		//reads the entity record's "password" value directly, and its only consumers are the four send
		//paths below, which pass it to SmtpClient.Authenticate. Neither goes through JSON.
		[JsonIgnore]
		public string Password { get; internal set; }

		[JsonProperty(PropertyName = "default_sender_name")]
		public string DefaultSenderName { get; internal set; }

		[JsonProperty(PropertyName = "default_sender_email")]
		public string DefaultSenderEmail { get; internal set; }

		[JsonProperty(PropertyName = "default_reply_to_email")]
		public string DefaultReplyToEmail { get; internal set; }

		[JsonProperty(PropertyName = "max_retries_count")]
		public int MaxRetriesCount { get; internal set; }

		[JsonProperty(PropertyName = "retry_wait_minutes")]
		public int RetryWaitMinutes { get; internal set; }

		[JsonProperty(PropertyName = "is_default")]
		public bool IsDefault { get; internal set; }

		[JsonProperty(PropertyName = "is_enabled")]
		public bool IsEnabled { get; internal set; }

		[JsonProperty(PropertyName = "connection_security")]
		public SecureSocketOptions ConnectionSecurity { get; internal set; }

		#endregion

		/// <summary>
		/// Whether this installation accepts an SMTP server certificate that fails validation.
		/// Defaults to <c>false</c>, so certificates ARE validated unless an operator opts out.
		/// </summary>
		/// <remarks>
		/// SECURITY - H-11 (High), CWE-295 Improper Certificate Validation, OWASP A02:2021,
		/// remediation class 8 (Transport Security). THREAT: every send path installed a callback
		/// returning true for any certificate, so the TLS session was encrypted but never
		/// authenticated - an active man-in-the-middle could present any certificate, then harvest
		/// the SMTP credentials submitted two lines later and read or rewrite every outbound message.
		/// Controlled by the <c>EmailSMTPAllowInvalidCertificates</c> key of the <c>Settings</c> section,
		/// which operators supply as the environment variable
		/// <c>Settings__EmailSMTPAllowInvalidCertificates</c>; see docs/security/secure-configuration.md.
		/// It is application configuration read from the existing <c>ErpSettings.Configuration</c>, and
		/// <c>static</c> rather than a typed setting or an <c>smtp_service</c> field, so neither the
		/// settings contract nor the database schema changes.
		/// FAIL-SAFE, a deliberate departure from the throwing <c>Boolean.Parse</c> idiom used
		/// throughout <c>ErpSettings</c>: the non-throwing overload resolves a malformed value such as
		/// "yes", "1" or "on" to false - secure - rather than raising <c>FormatException</c> on every
		/// outbound e-mail, which would turn a configuration typo into a mail outage. Absent, blank and
		/// unparseable values, and a settings layer not yet initialised (<c>Configuration</c> is null
		/// until <c>ErpSettings.Initialize</c> runs), all resolve to false. Please do not "correct" this
		/// back to the throwing form for consistency with its neighbours.
		/// <para>
		/// SECURITY - finding F6 (High), CWE-295 Improper Certificate Validation, OWASP A02:2021.
		/// THREAT ADDRESSED: the opt-out was honoured in EVERY posture, so a single environment variable -
		/// <c>Settings__EmailSMTPAllowInvalidCertificates=true</c> - silently restored, in production and on
		/// all five send paths, exactly the accept-any-certificate behaviour that H-11 exists to remove. An
		/// active man-in-the-middle could then present any certificate, harvest the SMTP credentials that
		/// every one of those paths authenticates two lines after connecting, and read or rewrite every
		/// outbound message. A development convenience that is reachable in production is not a
		/// convenience: it is the original vulnerability behind a flag.
		/// </para>
		/// <para>
		/// THE EXACT GATE, stated precisely because it is NOT the hosting environment: the opt-out is
		/// honoured only when <c>ErpSettings.DevelopmentMode</c> is true, and that is an APPLICATION setting
		/// read from <c>Settings:DevelopmentMode</c> (environment variable
		/// <c>Settings__DevelopmentMode</c>). It is independent of <c>ASPNETCORE_ENVIRONMENT</c> and of
		/// <c>IWebHostEnvironment</c>, so a deployment that sets it stays gated open no matter which
		/// environment name the host is running under.
		/// WARNING - ENABLING IT CHANGES POSTURE APPLICATION-WIDE, not just for mail: the same flag widens
		/// internal-detail disclosure in <c>Api/RecordManager.cs</c> and
		/// <c>Web/Controllers/ApiControllerBase.cs</c>. It must never be true on an internet-facing
		/// deployment, and turning it on to make mail work would be the worst possible reason to set it.
		/// When the flag is false this member is false, so no callback is installed at all and MailKit's own
		/// validation applies - which is why the five call sites need no change: each already tests this
		/// member before installing a callback, and the callback yields this member rather than a literal
		/// true. Refusing to START was rejected as the more invasive of the two permitted answers, because
		/// it turns one subsystem's misconfiguration into a total outage of an otherwise healthy
		/// application, and the preservation requirement asks for the least invasive control.
		/// </para>
		/// <para>
		/// WHY <c>ErpSettings.DevelopmentMode</c> IS THE DISCRIMINATOR: it is the platform's single existing
		/// source of truth for posture - already what decides whether internal detail may be disclosed in
		/// <c>Api/RecordManager.cs</c> and <c>Web/Controllers/ApiControllerBase.cs</c> - so this needs no new
		/// configuration key, no new dependency, no new package and no signature change anywhere. It also
		/// FAILS CLOSED by construction: it is <c>false</c> until <c>ErpSettings.Initialize</c> assigns it,
		/// so a host that never initialised the settings layer refuses the opt-out rather than granting it.
		/// The staged shape - honour in development, refuse and report in production - is the same one
		/// <c>ErpSettings</c> itself already uses for a weak encryption key.
		/// </para>
		/// </remarks>
		internal static bool AllowInvalidRemoteCertificates
		{
			get
			{
				//Nothing was asked for. The overwhelmingly common case and the cheapest test, so it comes
				//first: an installation that never requested the opt-out consults no posture and reports
				//nothing. Fail-safe parsing per the remarks above - absent, blank, malformed and
				//not-yet-initialised all resolve here.
				if (!bool.TryParse(ErpSettings.Configuration?["Settings:EmailSMTPAllowInvalidCertificates"], out var allowInvalid) || !allowInvalid)
					return false;

				//Asked for AND development posture: honoured, which is the entire legitimate purpose of the
				//setting - a self-signed or internal-CA relay stays usable on a developer machine.
				if (ErpSettings.DevelopmentMode)
					return true;

				//Asked for in production posture: REFUSED. Reported once, then treated for the rest of the
				//process lifetime exactly as if it had never been set, so certificates are validated.
				ReportProductionCertificateOptOutRefusal();
				return false;
			}
		}

		/// <summary>
		/// Latch for the production refusal notice. Zero until the notice has been emitted.
		/// </summary>
		private static int productionCertificateOptOutRefusalReported;

		/// <summary>
		/// Reports, exactly once per process, that an accept-any-certificate opt-out was refused because
		/// this installation is not in development posture.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding F6. ONCE PER PROCESS, and the reason that matters: the policy above is
		/// evaluated at least twice per outbound message - once to decide whether to install the callback
		/// and once inside the callback - so a notice emitted without this latch would grow with mail volume
		/// and bury the single signal it exists to raise.
		/// <para>
		/// WRITTEN TO STANDARD ERROR rather than through <c>Diagnostics.Log</c>, for two reasons specific to
		/// this subsystem. First, it mirrors the precedent <c>ErpSettings</c> already sets for a refused
		/// security setting and needs no database context, no ambient transaction and no logging stack, so it
		/// reports correctly even when the surrounding transaction is about to roll back. Second and
		/// decisively, the platform log can raise an e-mail notification and the subsystem being reported on
		/// HERE IS THE MAILER: routing this through the log risks a refusal notice about SMTP trying to send
		/// itself by SMTP. Only the setting NAME is named - never a credential, a server or a port.
		/// </para>
		/// </remarks>
		private static void ReportProductionCertificateOptOutRefusal()
		{
			//CompareExchange rather than a plain assignment because send paths overlap - the background
			//queue job and an interactive test send are independent callers - so the notice is emitted once
			//in total rather than once per racing caller.
			if (System.Threading.Interlocked.CompareExchange(ref productionCertificateOptOutRefusalReported, 1, 0) != 0)
				return;

			Console.Error.WriteLine("warn: WebVella.Erp.Plugins.Mail.Api.SmtpService[1] SECURITY - " +
				"'Settings:EmailSMTPAllowInvalidCertificates' is enabled but this installation is not in " +
				"development posture, so it has been REFUSED and SMTP server certificates WILL be validated. " +
				"Remove the setting, or set 'Settings:DevelopmentMode' if this really is a development " +
				"installation; see docs/security/secure-configuration.md.");
		}

		/// <summary>
		/// Whether the SMTP server certificate's revocation status is checked during the TLS handshake.
		/// Defaults to <c>true</c>, so revocation IS checked unless an operator explicitly disables it.
		/// </summary>
		/// <remarks>
		/// SECURITY - H-11 follow-up, CWE-299 Improper Check for Certificate Revocation, CWE-295 Improper
		/// Certificate Validation, OWASP A02:2021, remediation class 8 (Transport Security).
		/// THREAT ADDRESSED, and it runs in both directions - which is why this member exists at all:
		/// <list type="bullet">
		/// <item>Leaving revocation UNCHECKED means a relay certificate whose private key has leaked, and
		/// which its issuer has since revoked, is still accepted - the attacker keeps the ability to
		/// impersonate the relay and harvest the SMTP credentials the send paths authenticate with two
		/// lines after connecting. So the default must be, and is, to check.</item>
		/// <item>Leaving revocation UNCONDITIONALLY checked and unconfigurable makes a relay whose chain
		/// cannot produce a definitive revocation answer permanently unreachable - an availability defect
		/// introduced by a security control. An internal-CA relay publishing no CRL distribution point, or
		/// a host whose egress filtering blocks the CRL or OCSP fetch, fails the handshake on "unable to
		/// get certificate CRL" alone while the certificate is otherwise valid, and the failure reads as
		/// though the certificate were untrusted.</item>
		/// </list>
		/// WHY THIS SETTING IS HONOURED REGARDLESS OF <c>DevelopmentMode</c>, unlike
		/// <see cref="AllowInvalidRemoteCertificates"/> above: the two relaxations are not comparable in
		/// width. Accepting any certificate removes transport authentication entirely, whereas declining to
		/// consult a revocation list removes ONE check and leaves the trust chain, validity dates, key usage
		/// and host name all still enforced - a self-signed, expired, wrong-name or wrong-CA certificate is
		/// still refused. Gating this one behind DevelopmentMode would leave an affected installation
		/// choosing between no mail and the far wider opt-out, which is the trade this member exists to
		/// remove.
		/// <para>
		/// FAIL-SAFE PARSING, WITH THE DEFAULT INVERTED relative to its neighbour. The non-throwing overload
		/// is used for the same reason: a configuration typo must not raise <c>FormatException</c> on every
		/// outbound e-mail and convert a mistyped value into a mail outage. Because the secure state here is
		/// <c>true</c> rather than <c>false</c>, the test is arranged so that ONLY a value that genuinely
		/// parses as <c>false</c> disables the check. Absent, blank, unparseable ("no", "0", "off"), and a
		/// settings layer not yet initialised - <c>Configuration</c> is null until <c>ErpSettings.Initialize</c>
		/// runs - all resolve to <c>true</c>. It is application configuration read from the existing
		/// <c>ErpSettings.Configuration</c> and <c>static</c> rather than a typed setting or an
		/// <c>smtp_service</c> field, so neither the settings contract nor the database schema changes.
		/// Operators supply it as the environment variable
		/// <c>Settings__EmailSMTPCheckCertificateRevocation</c>; see docs/security/secure-configuration.md.
		/// </para>
		/// <para>
		/// The one-shot notice below exists because a deployment running with revocation checking disabled
		/// is in a weakened - though deliberate and supported - posture, and that must be visible in the
		/// host log rather than inferable only from configuration nobody re-reads.
		/// </para>
		/// </remarks>
		internal static bool CheckRemoteCertificateRevocation
		{
			get
			{
				//Only an explicitly parseable false disables the check. Every other outcome - absent,
				//blank, malformed, or a settings layer that has not been initialised - falls through to
				//true, which is the secure state. Note the shape: unlike the sibling policy this cannot be
				//written as "TryParse fails => return false", because here false is the INSECURE answer.
				if (!bool.TryParse(ErpSettings.Configuration?["Settings:EmailSMTPCheckCertificateRevocation"], out var checkRevocation))
					return true;

				if (checkRevocation)
					return true;

				//Disabled on purpose. Honoured in every posture, and reported once so the weakened posture
				//is on the record.
				ReportCertificateRevocationCheckDisabled();
				return false;
			}
		}

		/// <summary>
		/// Latch for the disabled-revocation notice. Zero until the notice has been emitted.
		/// </summary>
		private static int certificateRevocationCheckDisabledReported;

		/// <summary>
		/// Reports, exactly once per process, that SMTP server certificate revocation checking has been
		/// disabled by configuration.
		/// </summary>
		/// <remarks>
		/// SECURITY - H-11 follow-up, CWE-299. ONCE PER PROCESS for the same reason as the refusal notice
		/// above: this policy is evaluated at least once per outbound message, so an unlatched notice would
		/// grow with mail volume and bury the single signal it exists to raise. Written to standard error
		/// rather than through <c>Diagnostics.Log</c> for the same two reasons as well - it needs no
		/// database context or logging stack and therefore reports correctly even when the surrounding
		/// transaction is about to roll back, and decisively, the platform log can raise an e-mail
		/// notification while the subsystem being reported on HERE IS THE MAILER. Only the setting NAME is
		/// named - never a credential, a server or a port.
		/// </remarks>
		private static void ReportCertificateRevocationCheckDisabled()
		{
			if (System.Threading.Interlocked.CompareExchange(ref certificateRevocationCheckDisabledReported, 1, 0) != 0)
				return;

			Console.Error.WriteLine("warn: WebVella.Erp.Plugins.Mail.Api.SmtpService[2] SECURITY - " +
				"'Settings:EmailSMTPCheckCertificateRevocation' is false, so SMTP server certificates are " +
				"accepted WITHOUT a revocation check. The trust chain, validity dates and host name are " +
				"still verified, but a revoked relay certificate will no longer be refused. Remove the " +
				"setting once the relay's chain publishes a reachable CRL or OCSP responder; see " +
				"docs/security/secure-configuration.md.");
		}

		internal SmtpService() { }

		public void SendEmail(EmailAddress recipient, string subject, string textBody, string htmlBody, List<string> attachments)
		{
			ValidationException ex = new ValidationException();

			if (recipient == null)
				ex.AddError("recipientEmail", "Recipient is not specified.");
			else
			{
				if (string.IsNullOrEmpty(recipient.Address))
					ex.AddError("recipientEmail", "Recipient email is not specified.");
				else if (!recipient.Address.IsEmail())
					ex.AddError("recipientEmail", "Recipient email is not valid email address.");
			}

			if (string.IsNullOrEmpty(subject))
				ex.AddError("subject", "Subject is required.");

			ex.CheckAndThrow();

			var message = new MimeMessage();
			if (!string.IsNullOrWhiteSpace(DefaultSenderName))
				message.From.Add(new MailboxAddress(DefaultSenderName, DefaultSenderEmail));
			else
				message.From.Add(new MailboxAddress(DefaultSenderEmail,DefaultSenderEmail));

			if (!string.IsNullOrWhiteSpace(recipient.Name))
				message.To.Add(new MailboxAddress(recipient.Name, recipient.Address));
			else
				message.To.Add(new MailboxAddress(recipient.Address,recipient.Address));

			if (!string.IsNullOrWhiteSpace(DefaultReplyToEmail))
				message.ReplyTo.Add(new MailboxAddress(DefaultReplyToEmail,DefaultReplyToEmail));

			message.Subject = subject;

			var bodyBuilder = new BodyBuilder();
			bodyBuilder.HtmlBody = htmlBody;
			bodyBuilder.TextBody = textBody;

			if (attachments != null && attachments.Count > 0)
			{
				foreach (var att in attachments)
				{
					var filepath = att;

					if (!filepath.StartsWith("/"))
						filepath = "/" + filepath;

					filepath = filepath.ToLowerInvariant();

					if (filepath.StartsWith("/fs"))
						filepath = filepath.Substring(3);

					DbFileRepository fsRepository = new DbFileRepository();
					var file = fsRepository.Find(filepath);
					//SECURITY - companion to finding F24 (High), CWE-269 improper privilege management, CWE-732
					//incorrect permission assignment. Database/DbFileRepository.Find now REFUSES a staged file that
					//belongs to another non-administrative principal, so this lookup has one more legitimate way to
					//answer null than it had before that control existed.
					//FAILING LOUDLY IS THE POINT: before the refusal existed, an attachment path naming somebody
					//else's staged upload was read and mailed to an arbitrary recipient. Skipping silently here
					//would turn that closed exfiltration into a quiet partial success - a message delivered as if
					//complete, with the refused attachment missing and nothing recorded anywhere. The throw
					//surfaces on the caller for an interactive send, and Services/SmtpInternalService records it in
					//the queued email's server_error column, so a refusal is always visible.
					//FileNotFoundException rather than the bare Exception the sibling overloads of this method use:
					//identical behaviour and identical message, but it is the framework type for precisely this
					//condition and it does not add a CA2201 diagnostic. Every existing handler catches Exception, so
					//nothing observes the difference.
					if (file == null)
						throw new FileNotFoundException($"Attachment file '{filepath}' not found.");

					var bytes = file.GetBytes();

					var extension = Path.GetExtension(filepath).ToLowerInvariant();
					new FileExtensionContentTypeProvider().Mappings.TryGetValue(extension, out string mimeType);

					var attachment = new MimePart(mimeType)
					{
						Content = new MimeContent(new MemoryStream(bytes)),
						ContentDisposition = new ContentDisposition(ContentDisposition.Attachment),
						ContentTransferEncoding = ContentEncoding.Base64,
						FileName = Path.GetFileName(filepath)
					};

					bodyBuilder.Attachments.Add(attachment);
				}
			}

			SmtpInternalService.ProcessHtmlContent(bodyBuilder);
			message.Body = bodyBuilder.ToMessageBody();

			using (var client = new SmtpClient())
			{
				// SECURITY H-11 (CWE-295, OWASP A02): validation was unconditionally bypassed here, letting an
				// active man-in-the-middle present any certificate and harvest the credentials authenticated
				// below. Both policy members below are the single source of truth for that decision and carry the
				// full rationale - including the exact gate and its application-wide consequence. Do not inline a
				// literal here: the callback must keep yielding the member so the accept-any-certificate pattern
				// stays visible to analyzer rule CA5359.
				if (AllowInvalidRemoteCertificates)
					client.ServerCertificateValidationCallback = (s, c, h, e) => AllowInvalidRemoteCertificates;

				// SECURITY H-11 follow-up (CWE-299 improper check for certificate revocation, OWASP A02): left
				// implicit, MailKit's default of true made revocation REACHABILITY an unconfigurable delivery
				// prerequisite. Stated explicitly and bound to the policy member, which still defaults to
				// checking; see that member for the asymmetry between this narrow relaxation and the far wider
				// accept-any-certificate opt-out above.
				client.CheckCertificateRevocation = CheckRemoteCertificateRevocation;

				client.Connect(Server, Port, ConnectionSecurity);

				if (!string.IsNullOrWhiteSpace(Username))
					client.Authenticate(Username, Password);

				client.Send(message);
				client.Disconnect(true);
			}

			Email email = new Email();
			email.Id = Guid.NewGuid();
			email.Sender = new EmailAddress { Address = DefaultSenderEmail, Name = DefaultSenderName };
			email.ReplyToEmail = DefaultReplyToEmail;
			email.Recipients = new List<EmailAddress> { recipient };
			email.Subject = subject;
			email.ContentHtml = htmlBody;
			email.ContentText = textBody;
			email.CreatedOn = DateTime.UtcNow;
			email.SentOn = email.CreatedOn;
			email.Priority = EmailPriority.Normal;
			email.Status = EmailStatus.Sent;
			email.ServerError = string.Empty;
			email.ScheduledOn = null;
			email.RetriesCount = 0;
			email.ServiceId = Id;
			if (attachments != null && attachments.Count > 0)
			{
				DbFileRepository fsRepository = new DbFileRepository();
				foreach (var att in attachments)
				{
					var filepath = att;

					if (!filepath.StartsWith("/"))
						filepath = "/" + filepath;

					filepath = filepath.ToLowerInvariant();

					if (filepath.StartsWith("/fs"))
						filepath = filepath.Substring(3);

					var file = fsRepository.Find(filepath);
					if (file == null)
						throw new Exception($"Attachment file '{filepath}' not found.");

					email.Attachments.Add(filepath);
				}
			}
			new SmtpInternalService().SaveEmail(email);
		}

		public void SendEmail(List<EmailAddress> recipients, string subject, string textBody, string htmlBody, List<string> attachments)
		{
			ValidationException ex = new ValidationException();

			if (recipients == null || recipients.Count == 0)
			{
				ex.AddError("recipientEmail", "Recipient is not specified.");
			}
			else
			{
				foreach (var recipient in recipients)
				{
					if (recipient == null)
						ex.AddError("recipientEmail", "Recipient is not specified.");
					else
					{
						if (string.IsNullOrEmpty(recipient.Address))
							ex.AddError("recipientEmail", "Recipient email is not specified.");
						else if (!recipient.Address.IsEmail())
							ex.AddError("recipientEmail", "Recipient email is not valid email address.");
					}
				}
			}

			if (string.IsNullOrEmpty(subject))
				ex.AddError("subject", "Subject is required.");

			ex.CheckAndThrow();

			var message = new MimeMessage();
			if (!string.IsNullOrWhiteSpace(DefaultSenderName))
				message.From.Add(new MailboxAddress(DefaultSenderName, DefaultSenderEmail));
			else
				message.From.Add(new MailboxAddress(DefaultSenderEmail,DefaultSenderEmail));

			foreach (var recipient in recipients)
			{
				if (!string.IsNullOrWhiteSpace(recipient.Name))
					message.To.Add(new MailboxAddress(recipient.Name, recipient.Address));
				else
					message.To.Add(new MailboxAddress(recipient.Address,recipient.Address));
			}

			if (!string.IsNullOrWhiteSpace(DefaultReplyToEmail))
				message.ReplyTo.Add(new MailboxAddress(DefaultReplyToEmail,DefaultReplyToEmail));

			message.Subject = subject;

			var bodyBuilder = new BodyBuilder();
			bodyBuilder.HtmlBody = htmlBody;
			bodyBuilder.TextBody = textBody;

			if (attachments != null && attachments.Count > 0)
			{
				foreach (var att in attachments)
				{
					var filepath = att;

					if (!filepath.StartsWith("/"))
						filepath = "/" + filepath;

					filepath = filepath.ToLowerInvariant();

					if (filepath.StartsWith("/fs"))
						filepath = filepath.Substring(3);

					DbFileRepository fsRepository = new DbFileRepository();
					var file = fsRepository.Find(filepath);
					//SECURITY - companion to finding F24; see the first SendEmail overload in this file for why a
					//refused staged file must fail loudly here instead of being skipped.
					if (file == null)
						throw new FileNotFoundException($"Attachment file '{filepath}' not found.");

					var bytes = file.GetBytes();

					var extension = Path.GetExtension(filepath).ToLowerInvariant();
					new FileExtensionContentTypeProvider().Mappings.TryGetValue(extension, out string mimeType);

					var attachment = new MimePart(mimeType)
					{
						Content = new MimeContent(new MemoryStream(bytes)),
						ContentDisposition = new ContentDisposition(ContentDisposition.Attachment),
						ContentTransferEncoding = ContentEncoding.Base64,
						FileName = Path.GetFileName(filepath)
					};

					bodyBuilder.Attachments.Add(attachment);
				}
			}

			SmtpInternalService.ProcessHtmlContent(bodyBuilder);
			message.Body = bodyBuilder.ToMessageBody();

			using (var client = new SmtpClient())
			{
				// SECURITY H-11 (CWE-295, OWASP A02): validation was unconditionally bypassed here, letting an
				// active man-in-the-middle present any certificate and harvest the credentials authenticated
				// below. Both policy members below are the single source of truth for that decision and carry the
				// full rationale - including the exact gate and its application-wide consequence. Do not inline a
				// literal here: the callback must keep yielding the member so the accept-any-certificate pattern
				// stays visible to analyzer rule CA5359.
				if (AllowInvalidRemoteCertificates)
					client.ServerCertificateValidationCallback = (s, c, h, e) => AllowInvalidRemoteCertificates;

				// SECURITY H-11 follow-up (CWE-299 improper check for certificate revocation, OWASP A02): left
				// implicit, MailKit's default of true made revocation REACHABILITY an unconfigurable delivery
				// prerequisite. Stated explicitly and bound to the policy member, which still defaults to
				// checking; see that member for the asymmetry between this narrow relaxation and the far wider
				// accept-any-certificate opt-out above.
				client.CheckCertificateRevocation = CheckRemoteCertificateRevocation;

				client.Connect(Server, Port, ConnectionSecurity);

				if (!string.IsNullOrWhiteSpace(Username))
					client.Authenticate(Username, Password);

				client.Send(message);
				client.Disconnect(true);
			}

			Email email = new Email();
			email.Id = Guid.NewGuid();
			email.Sender = new EmailAddress { Address = DefaultSenderEmail, Name = DefaultSenderName };
			email.ReplyToEmail = DefaultReplyToEmail;
			email.Recipients = recipients;
			email.Subject = subject;
			email.ContentHtml = htmlBody;
			email.ContentText = textBody;
			email.CreatedOn = DateTime.UtcNow;
			email.SentOn = email.CreatedOn;
			email.Priority = EmailPriority.Normal;
			email.Status = EmailStatus.Sent;
			email.ServerError = string.Empty;
			email.ScheduledOn = null;
			email.RetriesCount = 0;
			email.ServiceId = Id;
			if (attachments != null && attachments.Count > 0)
			{
				DbFileRepository fsRepository = new DbFileRepository();
				foreach (var att in attachments)
				{
					var filepath = att;

					if (!filepath.StartsWith("/"))
						filepath = "/" + filepath;

					filepath = filepath.ToLowerInvariant();

					if (filepath.StartsWith("/fs"))
						filepath = filepath.Substring(3);

					var file = fsRepository.Find(filepath);
					if (file == null)
						throw new Exception($"Attachment file '{filepath}' not found.");

					email.Attachments.Add(filepath);
				}
			}
			new SmtpInternalService().SaveEmail(email);
		}

		public void SendEmail(EmailAddress recipient, EmailAddress sender, string subject, string textBody, string htmlBody, List<string> attachments)
		{
			ValidationException ex = new ValidationException();

			if (recipient == null)
				ex.AddError("recipientEmail", "Recipient is not specified.");
			else
			{
				if (string.IsNullOrEmpty(recipient.Address))
					ex.AddError("recipientEmail", "Recipient email is not specified.");
				else if (!recipient.Address.IsEmail())
					ex.AddError("recipientEmail", "Recipient email is not valid email address.");
			}

			if (string.IsNullOrEmpty(subject))
				ex.AddError("subject", "Subject is required.");

			ex.CheckAndThrow();

			var message = new MimeMessage();
			if (!string.IsNullOrWhiteSpace(sender.Name))
				message.From.Add(new MailboxAddress(sender.Name, sender.Address));
			else
				message.From.Add(new MailboxAddress(sender.Address, sender.Address));

			if (!string.IsNullOrWhiteSpace(recipient.Name))
				message.To.Add(new MailboxAddress(recipient.Name, recipient.Address));
			else
				message.To.Add(new MailboxAddress(recipient.Address, recipient.Address));

			if (!string.IsNullOrWhiteSpace(DefaultReplyToEmail))
				message.ReplyTo.Add(new MailboxAddress(DefaultReplyToEmail, DefaultReplyToEmail));

			message.Subject = subject;

			var bodyBuilder = new BodyBuilder();
			bodyBuilder.HtmlBody = htmlBody;
			bodyBuilder.TextBody = textBody;

			if (attachments != null && attachments.Count > 0)
			{
				foreach (var att in attachments)
				{
					var filepath = att;

					if (!filepath.StartsWith("/"))
						filepath = "/" + filepath;

					filepath = filepath.ToLowerInvariant();

					if (filepath.StartsWith("/fs"))
						filepath = filepath.Substring(3);

					DbFileRepository fsRepository = new DbFileRepository();
					var file = fsRepository.Find(filepath);
					//SECURITY - companion to finding F24; see the first SendEmail overload in this file for why a
					//refused staged file must fail loudly here instead of being skipped.
					if (file == null)
						throw new FileNotFoundException($"Attachment file '{filepath}' not found.");

					var bytes = file.GetBytes();

					var extension = Path.GetExtension(filepath).ToLowerInvariant();
					new FileExtensionContentTypeProvider().Mappings.TryGetValue(extension, out string mimeType);

					var attachment = new MimePart(mimeType)
					{
						Content = new MimeContent(new MemoryStream(bytes)),
						ContentDisposition = new ContentDisposition(ContentDisposition.Attachment),
						ContentTransferEncoding = ContentEncoding.Base64,
						FileName = Path.GetFileName(filepath)
					};

					bodyBuilder.Attachments.Add(attachment);
				}
			}
			SmtpInternalService.ProcessHtmlContent(bodyBuilder);
			message.Body = bodyBuilder.ToMessageBody();

			using (var client = new SmtpClient())
			{
				// SECURITY H-11 (CWE-295, OWASP A02): validation was unconditionally bypassed here, letting an
				// active man-in-the-middle present any certificate and harvest the credentials authenticated
				// below. Both policy members below are the single source of truth for that decision and carry the
				// full rationale - including the exact gate and its application-wide consequence. Do not inline a
				// literal here: the callback must keep yielding the member so the accept-any-certificate pattern
				// stays visible to analyzer rule CA5359.
				if (AllowInvalidRemoteCertificates)
					client.ServerCertificateValidationCallback = (s, c, h, e) => AllowInvalidRemoteCertificates;

				// SECURITY H-11 follow-up (CWE-299 improper check for certificate revocation, OWASP A02): left
				// implicit, MailKit's default of true made revocation REACHABILITY an unconfigurable delivery
				// prerequisite. Stated explicitly and bound to the policy member, which still defaults to
				// checking; see that member for the asymmetry between this narrow relaxation and the far wider
				// accept-any-certificate opt-out above.
				client.CheckCertificateRevocation = CheckRemoteCertificateRevocation;

				client.Connect(Server, Port, ConnectionSecurity);

				if (!string.IsNullOrWhiteSpace(Username))
					client.Authenticate(Username, Password);

				client.Send(message);
				client.Disconnect(true);
			}

			Email email = new Email();
			email.Id = Guid.NewGuid();
			email.Sender = sender;
			email.ReplyToEmail = DefaultReplyToEmail;
			email.Recipients = new List<EmailAddress> { recipient };
			email.Subject = subject;
			email.ContentHtml = htmlBody;
			email.ContentText = textBody;
			email.CreatedOn = DateTime.UtcNow;
			email.SentOn = email.CreatedOn;
			email.Priority = EmailPriority.Normal;
			email.Status = EmailStatus.Sent;
			email.ServerError = string.Empty;
			email.ScheduledOn = null;
			email.RetriesCount = 0;
			email.ServiceId = Id;
			if (attachments != null && attachments.Count > 0)
			{
				DbFileRepository fsRepository = new DbFileRepository();
				foreach (var att in attachments)
				{
					var filepath = att;

					if (!filepath.StartsWith("/"))
						filepath = "/" + filepath;

					filepath = filepath.ToLowerInvariant();

					if (filepath.StartsWith("/fs"))
						filepath = filepath.Substring(3);

					var file = fsRepository.Find(filepath);
					if (file == null)
						throw new Exception($"Attachment file '{filepath}' not found.");

					email.Attachments.Add(filepath);
				}
			}
			new SmtpInternalService().SaveEmail(email);
		}

		public void SendEmail(List<EmailAddress> recipients, EmailAddress sender, string subject, string textBody, string htmlBody, List<string> attachments)
		{
			ValidationException ex = new ValidationException();

			if (recipients == null || recipients.Count == 0)
			{
				ex.AddError("recipientEmail", "Recipient is not specified.");
			}
			else
			{
				foreach (var recipient in recipients)
				{
					if (recipient == null)
						ex.AddError("recipientEmail", "Recipient is not specified.");
					else
					{
						if (string.IsNullOrEmpty(recipient.Address))
							ex.AddError("recipientEmail", "Recipient email is not specified.");
						else if (!recipient.Address.IsEmail())
							ex.AddError("recipientEmail", "Recipient email is not valid email address.");
					}
				}
			}

			if (string.IsNullOrEmpty(subject))
				ex.AddError("subject", "Subject is required.");

			ex.CheckAndThrow();

			var message = new MimeMessage();
			if (!string.IsNullOrWhiteSpace(sender.Name))
				message.From.Add(new MailboxAddress(sender.Name, sender.Address));
			else
				message.From.Add(new MailboxAddress(sender.Address, sender.Address));

			foreach (var recipient in recipients)
			{
				if (!string.IsNullOrWhiteSpace(recipient.Name))
					message.To.Add(new MailboxAddress(recipient.Name, recipient.Address));
				else
					message.To.Add(new MailboxAddress(recipient.Address, recipient.Address));
			}

			if (!string.IsNullOrWhiteSpace(DefaultReplyToEmail))
				message.ReplyTo.Add(new MailboxAddress(DefaultReplyToEmail, DefaultReplyToEmail));

			message.Subject = subject;

			var bodyBuilder = new BodyBuilder();
			bodyBuilder.HtmlBody = htmlBody;
			bodyBuilder.TextBody = textBody;

			if (attachments != null && attachments.Count > 0)
			{
				foreach (var att in attachments)
				{
					var filepath = att;

					if (!filepath.StartsWith("/"))
						filepath = "/" + filepath;

					filepath = filepath.ToLowerInvariant();

					if (filepath.StartsWith("/fs"))
						filepath = filepath.Substring(3);

					DbFileRepository fsRepository = new DbFileRepository();
					var file = fsRepository.Find(filepath);
					//SECURITY - companion to finding F24; see the first SendEmail overload in this file for why a
					//refused staged file must fail loudly here instead of being skipped.
					if (file == null)
						throw new FileNotFoundException($"Attachment file '{filepath}' not found.");

					var bytes = file.GetBytes();

					var extension = Path.GetExtension(filepath).ToLowerInvariant();
					new FileExtensionContentTypeProvider().Mappings.TryGetValue(extension, out string mimeType);

					var attachment = new MimePart(mimeType)
					{
						Content = new MimeContent(new MemoryStream(bytes)),
						ContentDisposition = new ContentDisposition(ContentDisposition.Attachment),
						ContentTransferEncoding = ContentEncoding.Base64,
						FileName = Path.GetFileName(filepath)
					};

					bodyBuilder.Attachments.Add(attachment);
				}
			}
			SmtpInternalService.ProcessHtmlContent(bodyBuilder);
			message.Body = bodyBuilder.ToMessageBody();

			using (var client = new SmtpClient())
			{
				// SECURITY H-11 (CWE-295, OWASP A02): validation was unconditionally bypassed here, letting an
				// active man-in-the-middle present any certificate and harvest the credentials authenticated
				// below. Both policy members below are the single source of truth for that decision and carry the
				// full rationale - including the exact gate and its application-wide consequence. Do not inline a
				// literal here: the callback must keep yielding the member so the accept-any-certificate pattern
				// stays visible to analyzer rule CA5359.
				if (AllowInvalidRemoteCertificates)
					client.ServerCertificateValidationCallback = (s, c, h, e) => AllowInvalidRemoteCertificates;

				// SECURITY H-11 follow-up (CWE-299 improper check for certificate revocation, OWASP A02): left
				// implicit, MailKit's default of true made revocation REACHABILITY an unconfigurable delivery
				// prerequisite. Stated explicitly and bound to the policy member, which still defaults to
				// checking; see that member for the asymmetry between this narrow relaxation and the far wider
				// accept-any-certificate opt-out above.
				client.CheckCertificateRevocation = CheckRemoteCertificateRevocation;

				client.Connect(Server, Port, ConnectionSecurity);

				if (!string.IsNullOrWhiteSpace(Username))
					client.Authenticate(Username, Password);

				client.Send(message);
				client.Disconnect(true);
			}

			Email email = new Email();
			email.Id = Guid.NewGuid();
			email.Sender = sender;
			email.ReplyToEmail = DefaultReplyToEmail;
			email.Recipients = recipients;
			email.Subject = subject;
			email.ContentHtml = htmlBody;
			email.ContentText = textBody;
			email.CreatedOn = DateTime.UtcNow;
			email.SentOn = email.CreatedOn;
			email.Priority = EmailPriority.Normal;
			email.Status = EmailStatus.Sent;
			email.ServerError = string.Empty;
			email.ScheduledOn = null;
			email.RetriesCount = 0;
			email.ServiceId = Id;
			email.Attachments = new List<string>();
			if (attachments != null && attachments.Count > 0)
			{
				DbFileRepository fsRepository = new DbFileRepository();
				foreach (var att in attachments)
				{
					var filepath = att;

					if (!filepath.StartsWith("/"))
						filepath = "/" + filepath;

					filepath = filepath.ToLowerInvariant();

					if (filepath.StartsWith("/fs"))
						filepath = filepath.Substring(3);

					var file = fsRepository.Find(filepath);
					if (file == null)
						throw new Exception($"Attachment file '{filepath}' not found.");

					email.Attachments.Add(filepath);
				}
			}

			

			new SmtpInternalService().SaveEmail(email);
		}

		public void QueueEmail(EmailAddress recipient, string subject, string textBody, string htmlBody, EmailPriority priority = EmailPriority.Normal, List<string> attachments = null)
		{
			ValidationException ex = new ValidationException();

			if (recipient == null)
				ex.AddError("recipientEmail", "Recipient is not specified.");
			else
			{
				var address = recipient.Address;
				if (address.StartsWith("cc:"))
					address = address.Substring(3);

				if (address.StartsWith("bcc:"))
					address = address.Substring(4);

				if (string.IsNullOrEmpty(address))
					ex.AddError("recipientEmail", "Recipient email is not specified.");
				else if (!address.IsEmail())
					ex.AddError("recipientEmail", "Recipient email is not valid email address.");
			}

			if (string.IsNullOrEmpty(subject))
				ex.AddError("subject", "Subject is required.");

			ex.CheckAndThrow();

			Email email = new Email();
			email.Id = Guid.NewGuid();
			email.Sender = new EmailAddress { Address = DefaultSenderEmail, Name = DefaultSenderName };
			email.ReplyToEmail = DefaultReplyToEmail;
			email.Recipients = new List<EmailAddress> { recipient };
			email.Subject = subject;
			email.ContentHtml = htmlBody;
			email.ContentText = textBody;
			email.CreatedOn = DateTime.UtcNow;
			email.SentOn = null;
			email.Priority = priority;
			email.Status = EmailStatus.Pending;
			email.ServerError = string.Empty;
			email.ScheduledOn = email.CreatedOn;
			email.RetriesCount = 0;
			email.ServiceId = Id;

			email.Attachments = new List<string>();
			if (attachments != null && attachments.Count > 0)
			{
				DbFileRepository fsRepository = new DbFileRepository();
				foreach (var att in attachments)
				{
					var filepath = att;

					if (!filepath.StartsWith("/"))
						filepath = "/" + filepath;

					filepath = filepath.ToLowerInvariant();

					if (filepath.StartsWith("/fs"))
						filepath = filepath.Substring(3);

					var file = fsRepository.Find(filepath);
					if (file == null)
						throw new Exception($"Attachment file '{filepath}' not found.");

					email.Attachments.Add(filepath);
				}
			}

			new SmtpInternalService().SaveEmail(email);
		}

		public void QueueEmail(List<EmailAddress> recipients, string subject, string textBody, string htmlBody, EmailPriority priority = EmailPriority.Normal, List<string> attachments = null)
		{
			ValidationException ex = new ValidationException();

			if (recipients == null || recipients.Count == 0)
			{
				ex.AddError("recipientEmail", "Recipient is not specified.");
			}
			else
			{
				foreach (var recipient in recipients)
				{
					if (recipient == null)
						ex.AddError("recipientEmail", "Recipient is not specified.");
					else
					{
						var address = recipient.Address;
						if (address.StartsWith("cc:"))
							address = address.Substring(3);

						if (address.StartsWith("bcc:"))
							address = address.Substring(4);

						if (string.IsNullOrEmpty(address))
							ex.AddError("recipientEmail", "Recipient email is not specified.");
						else if (!address.IsEmail())
							ex.AddError("recipientEmail", "Recipient email is not valid email address.");
					}
				}
			}

			if (string.IsNullOrEmpty(subject))
				ex.AddError("subject", "Subject is required.");

			ex.CheckAndThrow();

			Email email = new Email();
			email.Id = Guid.NewGuid();
			email.Sender = new EmailAddress { Address = DefaultSenderEmail, Name = DefaultSenderName };
			email.ReplyToEmail = DefaultReplyToEmail;
			email.Recipients = recipients;
			email.Subject = subject;
			email.ContentHtml = htmlBody;
			email.ContentText = textBody;
			email.CreatedOn = DateTime.UtcNow;
			email.SentOn = null;
			email.Priority = priority;
			email.Status = EmailStatus.Pending;
			email.ServerError = string.Empty;
			email.ScheduledOn = email.CreatedOn;
			email.RetriesCount = 0;
			email.ServiceId = Id;

			email.Attachments = new List<string>();
			if (attachments != null && attachments.Count > 0)
			{
				DbFileRepository fsRepository = new DbFileRepository();
				foreach (var att in attachments)
				{
					var filepath = att;

					if (!filepath.StartsWith("/"))
						filepath = "/" + filepath;

					filepath = filepath.ToLowerInvariant();

					if (filepath.StartsWith("/fs"))
						filepath = filepath.Substring(3);

					var file = fsRepository.Find(filepath);
					if (file == null)
						throw new Exception($"Attachment file '{filepath}' not found.");

					email.Attachments.Add(filepath);
				}
			}

			new SmtpInternalService().SaveEmail(email);
		}

		public void QueueEmail(EmailAddress recipient, EmailAddress sender, string subject, string textBody, string htmlBody, EmailPriority priority = EmailPriority.Normal, List<string> attachments = null)
		{
			QueueEmail(recipient, sender, null, subject, textBody, htmlBody, priority, attachments);
		}

		public void QueueEmail(List<EmailAddress> recipients, EmailAddress sender, string subject, string textBody, string htmlBody, EmailPriority priority = EmailPriority.Normal, List<string> attachments = null)
		{
			QueueEmail(recipients, sender, null, subject, textBody, htmlBody, priority, attachments);
		}

		public void QueueEmail(EmailAddress recipient, EmailAddress sender, string replyTo, string subject, string textBody, string htmlBody, EmailPriority priority = EmailPriority.Normal, List<string> attachments = null )
		{
			ValidationException ex = new ValidationException();

			if (recipient == null)
				ex.AddError("recipientEmail", "Recipient is not specified.");
			else
			{
				var address = recipient.Address;
				if (address.StartsWith("cc:"))
					address = address.Substring(3);
				if (address.StartsWith("bcc:"))
					address = address.Substring(4);
				if (string.IsNullOrEmpty(address))
					ex.AddError("recipientEmail", "Recipient email is not specified.");
				else if (!address.IsEmail())
					ex.AddError("recipientEmail", "Recipient email is not valid email address.");
			}

			if (!string.IsNullOrWhiteSpace(replyTo))
			{
				string[] replyToEmails = replyTo.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
				foreach (var replyEmail in replyToEmails)
				{
					if (!replyEmail.IsEmail())
						ex.AddError("recipientEmail", "Reply To email is not valid email address.");
				}
			}

			if (string.IsNullOrEmpty(subject))
				ex.AddError("subject", "Subject is required.");

			ex.CheckAndThrow();

			Email email = new Email();
			email.Id = Guid.NewGuid();
			email.Sender = sender ?? new EmailAddress { Address = DefaultSenderEmail, Name = DefaultSenderName };
			if (string.IsNullOrWhiteSpace(replyTo))
				email.ReplyToEmail = DefaultReplyToEmail;
			else
				email.ReplyToEmail = replyTo;
			email.Recipients = new List<EmailAddress> { recipient };
			email.Subject = subject;
			email.ContentHtml = htmlBody;
			email.ContentText = textBody;
			email.CreatedOn = DateTime.UtcNow;
			email.SentOn = null;
			email.Priority = priority;
			email.Status = EmailStatus.Pending;
			email.ServerError = string.Empty;
			email.ScheduledOn = email.CreatedOn;
			email.RetriesCount = 0;
			email.ServiceId = Id;

			email.Attachments = new List<string>();
			if (attachments != null && attachments.Count > 0)
			{
				DbFileRepository fsRepository = new DbFileRepository();
				foreach (var att in attachments)
				{
					var filepath = att;

					if (!filepath.StartsWith("/"))
						filepath = "/" + filepath;

					filepath = filepath.ToLowerInvariant();

					if (filepath.StartsWith("/fs"))
						filepath = filepath.Substring(3);

					var file = fsRepository.Find(filepath);
					if (file == null)
						throw new Exception($"Attachment file '{filepath}' not found.");

					email.Attachments.Add(filepath);
				}
			}

			new SmtpInternalService().SaveEmail(email);
		}

		public void QueueEmail(List<EmailAddress> recipients, EmailAddress sender, string replyTo, string subject, string textBody, string htmlBody, EmailPriority priority = EmailPriority.Normal, List<string> attachments = null)
		{
			ValidationException ex = new ValidationException();

			if (recipients == null || recipients.Count == 0)
			{
				ex.AddError("recipientEmail", "Recipient is not specified.");
			}
			else
			{
				foreach (var recipient in recipients)
				{
					if (recipient == null)
						ex.AddError("recipientEmail", "Recipient is not specified.");
					else
					{
						var address = recipient.Address;
						if (address.StartsWith("cc:"))
							address = address.Substring(3);
						if (address.StartsWith("bcc:"))
							address = address.Substring(4);
						if (string.IsNullOrEmpty(address))
							ex.AddError("recipientEmail", "Recipient email is not specified.");
						else if (!address.IsEmail())
							ex.AddError("recipientEmail", "Recipient email is not valid email address.");
					}
				}
			}

			if (!string.IsNullOrWhiteSpace(replyTo))
			{
				string[] replyToEmails = replyTo.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
				foreach (var replyEmail in replyToEmails)
				{
					if (!replyEmail.IsEmail())
						ex.AddError("recipientEmail", "Reply To email is not valid email address.");
				}
			}

			if (string.IsNullOrEmpty(subject))
				ex.AddError("subject", "Subject is required.");

			ex.CheckAndThrow();

			Email email = new Email();
			email.Id = Guid.NewGuid();
			email.Sender = sender ?? new EmailAddress { Address = DefaultSenderEmail, Name = DefaultSenderName };
			if (string.IsNullOrWhiteSpace(replyTo))
				email.ReplyToEmail = DefaultReplyToEmail;
			else
				email.ReplyToEmail = replyTo;
			email.Recipients = recipients;
			email.Subject = subject;
			email.ContentHtml = htmlBody;
			email.ContentText = textBody;
			email.CreatedOn = DateTime.UtcNow;
			email.SentOn = null;
			email.Priority = priority;
			email.Status = EmailStatus.Pending;
			email.ServerError = string.Empty;
			email.ScheduledOn = email.CreatedOn;
			email.RetriesCount = 0;
			email.ServiceId = Id;

			email.Attachments = new List<string>();
			if (attachments != null && attachments.Count > 0)
			{
				DbFileRepository fsRepository = new DbFileRepository();
				foreach (var att in attachments)
				{
					var filepath = att;

					if (!filepath.StartsWith("/"))
						filepath = "/" + filepath;

					filepath = filepath.ToLowerInvariant();

					if (filepath.StartsWith("/fs"))
						filepath = filepath.Substring(3);

					var file = fsRepository.Find(filepath);
					if (file == null)
						throw new Exception($"Attachment file '{filepath}' not found.");

					email.Attachments.Add(filepath);
				}
			}

			new SmtpInternalService().SaveEmail(email);
		}
	}
}
