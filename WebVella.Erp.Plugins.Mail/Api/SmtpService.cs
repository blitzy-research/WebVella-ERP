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
		/// Content type used for an attachment whose file extension the static-file provider does not map.
		/// </summary>
		/// <remarks>
		/// Review finding INT-12. <c>MimePart(string)</c> throws <c>ArgumentNullException</c> for a null
		/// content type, and <c>FileExtensionContentTypeProvider</c> leaves the value null for any extension it
		/// does not know - which includes extensionless files and the platform's own internal ones - so a single
		/// unmapped attachment aborted delivery of the whole message. This is the exact value MimeKit's own
		/// parameterless <c>MimePart</c> constructor uses, so the fallback is the library's own default rather
		/// than an invention, and it is <c>internal</c> so the queued send path in
		/// <c>Services/SmtpInternalService</c> resolves the same value from the same place.
		/// </remarks>
		internal const string BinaryContentType = "application/octet-stream";

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

			//RESOURCE CLEANUP - review finding INT-09. This message owns every attachment and linked-resource
			//stream added below, and disposing it disposes them; leaving it undisposed held the full byte content
			//of every attachment until a garbage collection, which on a large send is the difference between a
			//bounded and an unbounded working set. The `using` DECLARATION rather than a `using` block is
			//deliberate: it disposes at the end of this method - after Send, which is the last use - without
			//re-indenting the whole body, so the diff stays reviewable and no behaviour moves.
			using var message = new MimeMessage();
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
					//MIME MAPPING - review finding INT-12. TryGetValue leaves mimeType NULL for an unmapped extension
					//and MimePart(string) throws ArgumentNullException for null, so one unmapped attachment aborted
					//the entire message. See BinaryContentType for why that value is the right fallback.
					if (!new FileExtensionContentTypeProvider().Mappings.TryGetValue(extension, out string mimeType) || string.IsNullOrWhiteSpace(mimeType))
						mimeType = BinaryContentType;

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
				// SECURITY H-11 (CWE-295 improper certificate validation, OWASP A02): validation was
				// unconditionally bypassed here, letting an active man-in-the-middle present any certificate and
				// harvest the credentials authenticated below. AllowInvalidRemoteCertificates is the single source
				// of truth for that decision and carries the full rationale - including the exact gate and its
				// application-wide consequence. Do not inline a literal here: the callback must keep yielding the
				// member so the accept-any-certificate pattern stays visible to analyzer rule CA5359.
				// REVOCATION IS LEFT ENTIRELY TO MAILKIT, deliberately and unconfigurably: SmtpClient checks
				// certificate revocation unless told otherwise, so saying nothing here IS the secure state. Do not
				// reintroduce a setting that turns the check off - one existed briefly and was removed, because it
				// weakened the production transport posture beyond the agreed remediation for this finding. A relay
				// whose chain names no reachable CRL or OCSP responder is therefore refused, and the supported
				// remedy is to publish the revocation source; see docs/security/secure-configuration.md.
				if (AllowInvalidRemoteCertificates)
					client.ServerCertificateValidationCallback = (s, c, h, e) => AllowInvalidRemoteCertificates;

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

			//RESOURCE CLEANUP - review finding INT-09. This message owns every attachment and linked-resource
			//stream added below, and disposing it disposes them; leaving it undisposed held the full byte content
			//of every attachment until a garbage collection, which on a large send is the difference between a
			//bounded and an unbounded working set. The `using` DECLARATION rather than a `using` block is
			//deliberate: it disposes at the end of this method - after Send, which is the last use - without
			//re-indenting the whole body, so the diff stays reviewable and no behaviour moves.
			using var message = new MimeMessage();
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
					//MIME MAPPING - review finding INT-12. TryGetValue leaves mimeType NULL for an unmapped extension
					//and MimePart(string) throws ArgumentNullException for null, so one unmapped attachment aborted
					//the entire message. See BinaryContentType for why that value is the right fallback.
					if (!new FileExtensionContentTypeProvider().Mappings.TryGetValue(extension, out string mimeType) || string.IsNullOrWhiteSpace(mimeType))
						mimeType = BinaryContentType;

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
				// SECURITY H-11 (CWE-295 improper certificate validation, OWASP A02): validation was
				// unconditionally bypassed here, letting an active man-in-the-middle present any certificate and
				// harvest the credentials authenticated below. AllowInvalidRemoteCertificates is the single source
				// of truth for that decision and carries the full rationale - including the exact gate and its
				// application-wide consequence. Do not inline a literal here: the callback must keep yielding the
				// member so the accept-any-certificate pattern stays visible to analyzer rule CA5359.
				// REVOCATION IS LEFT ENTIRELY TO MAILKIT, deliberately and unconfigurably: SmtpClient checks
				// certificate revocation unless told otherwise, so saying nothing here IS the secure state. Do not
				// reintroduce a setting that turns the check off - one existed briefly and was removed, because it
				// weakened the production transport posture beyond the agreed remediation for this finding. A relay
				// whose chain names no reachable CRL or OCSP responder is therefore refused, and the supported
				// remedy is to publish the revocation source; see docs/security/secure-configuration.md.
				if (AllowInvalidRemoteCertificates)
					client.ServerCertificateValidationCallback = (s, c, h, e) => AllowInvalidRemoteCertificates;

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

			//API CONTRACT - review finding INT-07. This overload exists precisely to take a caller-supplied
			//sender, and it dereferenced that sender below without ever validating it: a null sender raised
			//NullReferenceException and a malformed address raised MimeKit's ParseException, both from deep inside
			//message construction rather than from the validation block that reports every other bad input on this
			//method. Note the deliberate contrast with the QueueEmail overloads: there a null sender is LEGITIMATE
			//and documented by `sender ?? default`, so no equivalent check belongs in them.
			if (sender == null)
				ex.AddError("senderEmail", "Sender is not specified.");
			else if (string.IsNullOrEmpty(sender.Address))
				ex.AddError("senderEmail", "Sender email is not specified.");
			else if (!sender.Address.IsEmail())
				ex.AddError("senderEmail", "Sender email is not valid email address.");

			if (string.IsNullOrEmpty(subject))
				ex.AddError("subject", "Subject is required.");

			ex.CheckAndThrow();

			//RESOURCE CLEANUP - review finding INT-09. This message owns every attachment and linked-resource
			//stream added below, and disposing it disposes them; leaving it undisposed held the full byte content
			//of every attachment until a garbage collection, which on a large send is the difference between a
			//bounded and an unbounded working set. The `using` DECLARATION rather than a `using` block is
			//deliberate: it disposes at the end of this method - after Send, which is the last use - without
			//re-indenting the whole body, so the diff stays reviewable and no behaviour moves.
			using var message = new MimeMessage();
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
					//MIME MAPPING - review finding INT-12. TryGetValue leaves mimeType NULL for an unmapped extension
					//and MimePart(string) throws ArgumentNullException for null, so one unmapped attachment aborted
					//the entire message. See BinaryContentType for why that value is the right fallback.
					if (!new FileExtensionContentTypeProvider().Mappings.TryGetValue(extension, out string mimeType) || string.IsNullOrWhiteSpace(mimeType))
						mimeType = BinaryContentType;

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
				// SECURITY H-11 (CWE-295 improper certificate validation, OWASP A02): validation was
				// unconditionally bypassed here, letting an active man-in-the-middle present any certificate and
				// harvest the credentials authenticated below. AllowInvalidRemoteCertificates is the single source
				// of truth for that decision and carries the full rationale - including the exact gate and its
				// application-wide consequence. Do not inline a literal here: the callback must keep yielding the
				// member so the accept-any-certificate pattern stays visible to analyzer rule CA5359.
				// REVOCATION IS LEFT ENTIRELY TO MAILKIT, deliberately and unconfigurably: SmtpClient checks
				// certificate revocation unless told otherwise, so saying nothing here IS the secure state. Do not
				// reintroduce a setting that turns the check off - one existed briefly and was removed, because it
				// weakened the production transport posture beyond the agreed remediation for this finding. A relay
				// whose chain names no reachable CRL or OCSP responder is therefore refused, and the supported
				// remedy is to publish the revocation source; see docs/security/secure-configuration.md.
				if (AllowInvalidRemoteCertificates)
					client.ServerCertificateValidationCallback = (s, c, h, e) => AllowInvalidRemoteCertificates;

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

			//API CONTRACT - review finding INT-07. This overload exists precisely to take a caller-supplied
			//sender, and it dereferenced that sender below without ever validating it: a null sender raised
			//NullReferenceException and a malformed address raised MimeKit's ParseException, both from deep inside
			//message construction rather than from the validation block that reports every other bad input on this
			//method. Note the deliberate contrast with the QueueEmail overloads: there a null sender is LEGITIMATE
			//and documented by `sender ?? default`, so no equivalent check belongs in them.
			if (sender == null)
				ex.AddError("senderEmail", "Sender is not specified.");
			else if (string.IsNullOrEmpty(sender.Address))
				ex.AddError("senderEmail", "Sender email is not specified.");
			else if (!sender.Address.IsEmail())
				ex.AddError("senderEmail", "Sender email is not valid email address.");

			if (string.IsNullOrEmpty(subject))
				ex.AddError("subject", "Subject is required.");

			ex.CheckAndThrow();

			//RESOURCE CLEANUP - review finding INT-09. This message owns every attachment and linked-resource
			//stream added below, and disposing it disposes them; leaving it undisposed held the full byte content
			//of every attachment until a garbage collection, which on a large send is the difference between a
			//bounded and an unbounded working set. The `using` DECLARATION rather than a `using` block is
			//deliberate: it disposes at the end of this method - after Send, which is the last use - without
			//re-indenting the whole body, so the diff stays reviewable and no behaviour moves.
			using var message = new MimeMessage();
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
					//MIME MAPPING - review finding INT-12. TryGetValue leaves mimeType NULL for an unmapped extension
					//and MimePart(string) throws ArgumentNullException for null, so one unmapped attachment aborted
					//the entire message. See BinaryContentType for why that value is the right fallback.
					if (!new FileExtensionContentTypeProvider().Mappings.TryGetValue(extension, out string mimeType) || string.IsNullOrWhiteSpace(mimeType))
						mimeType = BinaryContentType;

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
				// SECURITY H-11 (CWE-295 improper certificate validation, OWASP A02): validation was
				// unconditionally bypassed here, letting an active man-in-the-middle present any certificate and
				// harvest the credentials authenticated below. AllowInvalidRemoteCertificates is the single source
				// of truth for that decision and carries the full rationale - including the exact gate and its
				// application-wide consequence. Do not inline a literal here: the callback must keep yielding the
				// member so the accept-any-certificate pattern stays visible to analyzer rule CA5359.
				// REVOCATION IS LEFT ENTIRELY TO MAILKIT, deliberately and unconfigurably: SmtpClient checks
				// certificate revocation unless told otherwise, so saying nothing here IS the secure state. Do not
				// reintroduce a setting that turns the check off - one existed briefly and was removed, because it
				// weakened the production transport posture beyond the agreed remediation for this finding. A relay
				// whose chain names no reachable CRL or OCSP responder is therefore refused, and the supported
				// remedy is to publish the revocation source; see docs/security/secure-configuration.md.
				if (AllowInvalidRemoteCertificates)
					client.ServerCertificateValidationCallback = (s, c, h, e) => AllowInvalidRemoteCertificates;

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
				//API CONTRACT - review finding INT-07. The cc:/bcc: prefix parse below reads the address BEFORE
				//anything established that it exists, so a recipient whose Address was never set raised
				//NullReferenceException from inside a validation block whose entire job is to report bad input as a
				//ValidationException. Hoisting the null-or-empty test is the whole fix; the prefix stripping, the
				//order of the two prefixes and the post-strip empty test are all unchanged, so a caller passing a
				//well-formed address - prefixed or not - sees exactly the behaviour it saw before.
				var address = recipient.Address;
				if (string.IsNullOrEmpty(address))
					ex.AddError("recipientEmail", "Recipient email is not specified.");
				else
				{
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
						//API CONTRACT - review finding INT-07. The cc:/bcc: prefix parse below reads the address BEFORE
						//anything established that it exists, so a recipient whose Address was never set raised
						//NullReferenceException from inside a validation block whose entire job is to report bad input as a
						//ValidationException. Hoisting the null-or-empty test is the whole fix; the prefix stripping, the
						//order of the two prefixes and the post-strip empty test are all unchanged, so a caller passing a
						//well-formed address - prefixed or not - sees exactly the behaviour it saw before.
						var address = recipient.Address;
						if (string.IsNullOrEmpty(address))
							ex.AddError("recipientEmail", "Recipient email is not specified.");
						else
						{
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
				//API CONTRACT - review finding INT-07. The cc:/bcc: prefix parse below reads the address BEFORE
				//anything established that it exists, so a recipient whose Address was never set raised
				//NullReferenceException from inside a validation block whose entire job is to report bad input as a
				//ValidationException. Hoisting the null-or-empty test is the whole fix; the prefix stripping, the
				//order of the two prefixes and the post-strip empty test are all unchanged, so a caller passing a
				//well-formed address - prefixed or not - sees exactly the behaviour it saw before.
				var address = recipient.Address;
				if (string.IsNullOrEmpty(address))
					ex.AddError("recipientEmail", "Recipient email is not specified.");
				else
				{
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
						//API CONTRACT - review finding INT-07. The cc:/bcc: prefix parse below reads the address BEFORE
						//anything established that it exists, so a recipient whose Address was never set raised
						//NullReferenceException from inside a validation block whose entire job is to report bad input as a
						//ValidationException. Hoisting the null-or-empty test is the whole fix; the prefix stripping, the
						//order of the two prefixes and the post-strip empty test are all unchanged, so a caller passing a
						//well-formed address - prefixed or not - sees exactly the behaviour it saw before.
						var address = recipient.Address;
						if (string.IsNullOrEmpty(address))
							ex.AddError("recipientEmail", "Recipient email is not specified.");
						else
						{
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
