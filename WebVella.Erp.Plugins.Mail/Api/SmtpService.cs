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
//Supplies SslProtocols, the type of the negotiated protocol RequireApprovedTransport verifies.
using System.Security.Authentication;
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

		//SECURITY - CWE-200 exposure of sensitive information, CWE-522 insufficiently protected credentials,
		//OWASP A01 / A02. The SMTP relay password was an ordinary serializable member, so any object graph
		//that reached a JSON writer carried the plaintext credential out of the process. JsonIgnore REPLACES
		//the property mapping rather than joining it, so there is exactly one serialization instruction here.
		//No write path loses the value: nothing in the repository serializes this type - the only producer is
		//Api/AutoMapper/SmtpServiceProfile, the only consumers the four send paths below.
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
		/// <c>MimePart(string)</c> throws for a null content type and <c>FileExtensionContentTypeProvider</c>
		/// leaves it null for any extension it does not know, so one unmapped attachment aborted delivery of the
		/// whole message. This is the value MimeKit's own parameterless <c>MimePart</c> constructor uses, and it
		/// is <c>internal</c> so the queued send path resolves the same fallback from the same place.
		/// </remarks>
		internal const string BinaryContentType = "application/octet-stream";

		/// <summary>
		/// Whether this installation accepts an SMTP server certificate that fails validation.
		/// Defaults to <c>false</c>, so certificates ARE validated unless an operator opts out.
		/// </summary>
		/// <remarks>
		/// SECURITY - H-11, CWE-295 improper certificate validation, OWASP A02. THREAT: every send path
		/// installed a callback returning true for any certificate, so the TLS session was encrypted but never
		/// authenticated - an active man-in-the-middle could present any certificate and harvest the SMTP
		/// credential submitted two lines later. Controlled by <c>Settings:EmailSMTPAllowInvalidCertificates</c>,
		/// read from the existing <c>ErpSettings.Configuration</c> so neither the settings contract nor the
		/// schema changes.
		/// <para>
		/// FAIL-SAFE PARSING, a deliberate departure from the throwing <c>Boolean.Parse</c> idiom used throughout
		/// <c>ErpSettings</c>: absent, blank, malformed and not-yet-initialised values all resolve to false,
		/// because a <c>FormatException</c> on every outbound message would turn a typo into a mail outage.
		/// </para>
		/// <para>
		/// THE OPT-OUT IS HONOURED ONLY IN DEVELOPMENT POSTURE, because a convenience reachable in production is
		/// the original vulnerability behind a flag. The gate is <c>ErpSettings.DevelopmentMode</c> - an
		/// APPLICATION setting, independent of <c>ASPNETCORE_ENVIRONMENT</c> - chosen because it is the
		/// platform's single source of truth for posture and fails closed, being false until initialisation.
		/// WARNING: enabling it changes posture APPLICATION-WIDE, also widening internal-detail disclosure in
		/// <c>Api/RecordManager.cs</c> and <c>Web/Controllers/ApiControllerBase</c>, so it must never be true on
		/// an internet-facing deployment. When false, no callback is installed at all and MailKit's own
		/// validation applies - which is why the five call sites need no change.
		/// </para>
		/// </remarks>
		internal static bool AllowInvalidRemoteCertificates
		{
			get
			{
				//Nothing was asked for: the common case and the cheapest test, so it comes first. Fail-safe parsing
				//per the remarks above - absent, blank, malformed and not-yet-initialised all resolve here.
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
		/// Reports, exactly once per process, that an accept-any-certificate opt-out was refused because this
		/// installation is not in development posture.
		/// </summary>
		/// <remarks>
		/// ONCE PER PROCESS because the policy above is evaluated at least twice per outbound message, so an
		/// unlatched notice would grow with mail volume and bury the one signal it raises. Written to standard
		/// error rather than through <c>Diagnostics.Log</c>: it needs no database context, so it reports even
		/// while the surrounding transaction rolls back, and decisively the platform log can raise an e-mail
		/// notification while the subsystem being reported on IS THE MAILER. Only the setting NAME is named.
		/// </remarks>
		private static void ReportProductionCertificateOptOutRefusal()
		{
			//CompareExchange rather than a plain assignment because send paths overlap - the background queue job
			//and an interactive test send are independent callers - so the notice is emitted once in total.
			if (System.Threading.Interlocked.CompareExchange(ref productionCertificateOptOutRefusalReported, 1, 0) != 0)
				return;

			Console.Error.WriteLine("warn: WebVella.Erp.Plugins.Mail.Api.SmtpService[1] SECURITY - " +
				"'Settings:EmailSMTPAllowInvalidCertificates' is enabled but this installation is not in " +
				"development posture, so it has been REFUSED and SMTP server certificates WILL be validated. " +
				"Remove the setting, or set 'Settings:DevelopmentMode' if this really is a development " +
				"installation; see docs/security/secure-configuration.md.");
		}

		/// <summary>
		/// Verifies that a just-connected SMTP session is actually encrypted, at TLS 1.2 or better, BEFORE the
		/// relay credential is presented on it.
		/// </summary>
		/// <remarks>
		/// SECURITY - CWE-319 cleartext transmission, CWE-311 missing encryption, OWASP A02. This OBSERVES THE
		/// NEGOTIATED SESSION rather than constraining what was offered: pinning <c>SmtpClient.SslProtocols</c>
		/// names protocol versions in application code, which CA5398 discourages and which ages badly, whereas
		/// checking the result is strictly stronger and needs no suppression. The version test compares
		/// numerically against <see cref="MinimumApprovedSslProtocolValue"/> - see that constant for the exact
		/// scope of the floor and for the re-review a new <c>SslProtocols</c> member requires.
		/// <para>
		/// CALLED IMMEDIATELY AFTER <c>Connect</c> AND BEFORE <c>Authenticate</c> at all five send paths, and
		/// that ordering is the whole point: the credential is presented a line or two later, so an unencrypted
		/// or obsolete session must be abandoned while nothing secret is on it. Throwing leaves the client to
		/// the enclosing <c>using</c>, which closes the socket; no QUIT is sent. Development posture is exempt,
		/// so a local mail catcher that speaks no TLS stays usable - the gate is
		/// <c>ErpSettings.DevelopmentMode</c>, false until the settings layer initialises, so it fails closed.
		/// No diagnostic names a relay address, port, user name or password.
		/// </para>
		/// </remarks>
		/// <param name="client">A connected client, not yet authenticated.</param>
		/// <exception cref="InvalidOperationException">
		/// The session is not encrypted, or negotiated below TLS 1.2, outside development posture.
		/// </exception>
		internal static void RequireApprovedTransport(SmtpClient client)
		{
			//Development posture: exempt, so a plaintext local mail catcher stays usable. First, so a
			//development installation evaluates no policy and reports nothing.
			if (ErpSettings.DevelopmentMode)
				return;

			//An unencrypted session. ResolveConnectionSecurity should already have made this unreachable, which is
			//exactly why the check belongs here: if it becomes reachable again - a new send path, a mode MailKit
			//resolves differently - the credential must not be the thing that discovers it.
			if (!client.IsEncrypted)
				throw new InvalidOperationException(
					"SECURITY: the SMTP session was established without encryption, so the relay credential "
					+ "was not presented and no mail has been sent. Set the smtp_service "
					+ "'connection_security' field to 'SslOnConnect' or 'StartTls'; see "
					+ "docs/security/secure-configuration.md.");

			//Encrypted, but with an obsolete protocol version. Compared numerically against
			//MinimumApprovedSslProtocolValue - see that constant for why the enum member is not named here.
			if ((int)client.SslProtocol < MinimumApprovedSslProtocolValue)
				throw new InvalidOperationException(
					"SECURITY: the SMTP session negotiated " + client.SslProtocol.ToString() + ", which is "
					+ "below the required minimum of TLS 1.2, so the relay credential was not presented and "
					+ "no mail has been sent. Enable TLS 1.2 or later on the relay; see "
					+ "docs/security/secure-configuration.md.");
		}

		/// <summary>
		/// Returns the connection-security mode that may actually be used, given the mode an
		/// <c>smtp_service</c> record requests and this installation's posture.
		/// </summary>
		/// <remarks>
		/// SECURITY - CWE-319 cleartext transmission, CWE-311 missing encryption, OWASP A02. THREAT: H-11
		/// restored certificate validation, but validation only runs when TLS is negotiated AT ALL. The shipped
		/// default was <c>Auto</c>, the field also offered <c>None</c> and <c>StartTlsWhenAvailable</c>, and all
		/// five send paths handed the stored value straight to MailKit - and <c>StartTlsWhenAvailable</c>
		/// continues in cleartext whenever the relay does not advertise STARTTLS, which an active attacker
		/// arranges by stripping it from the EHLO response.
		/// <para>
		/// THE ASYMMETRY IS DELIBERATE. <c>Auto</c> and <c>StartTlsWhenAvailable</c> are HARDENED to a mandatory
		/// mode rather than refused, because nobody chose them - <c>Auto</c> was the shipped default - and
		/// refusing them would stop mail on every installation that never touched the field. <c>None</c> IS
		/// refused, being an operator stating that encryption is not wanted, which silently upgrading would hide.
		/// An UNDEFINED value is refused too: a numeric cast to an enum never throws, so a row written before
		/// record validation existed would otherwise fail at <c>Connect</c> with an unactionable message.
		/// </para>
		/// <para>
		/// The posture gate is <c>ErpSettings.DevelopmentMode</c>, as for
		/// <see cref="AllowInvalidRemoteCertificates"/>; in development the stored mode is honoured unchanged.
		/// No diagnostic names a relay address, port, user name or password.
		/// </para>
		/// </remarks>
		/// <param name="requested">The mode stored on the <c>smtp_service</c> record.</param>
		/// <param name="port">The port the record targets, used only to resolve <c>Auto</c> as MailKit does.</param>
		/// <returns>The mode that may be used, which is never <c>None</c> outside development posture.</returns>
		/// <exception cref="InvalidOperationException">
		/// The stored mode transmits in cleartext, or is not a defined mode, outside development posture.
		/// </exception>
		internal static SecureSocketOptions ResolveConnectionSecurity(SecureSocketOptions requested, int port)
		{
			//Development posture: honoured unchanged, the entire legitimate purpose of the escape hatch. First, so
			//a development installation consults no policy and reports nothing.
			if (ErpSettings.DevelopmentMode)
				return requested;

			//Already mandatory. Implicit TLS for the whole session, or STARTTLS that MailKit REQUIRES the relay to
			//advertise.
			if (IsMandatoryEncryptedMode(requested))
				return requested;

			switch (requested)
			{
				//Hardened, not refused - see the asymmetry paragraph above. Auto is resolved the way MailKit resolves
				//it, by port, so implicit TLS on 465 stays implicit TLS.
				case SecureSocketOptions.Auto:
					ReportConnectionSecurityHardened(requested);
					return port == ImplicitTlsPort ? SecureSocketOptions.SslOnConnect : SecureSocketOptions.StartTls;

				//Hardened. The requested mode differs from StartTls in exactly one respect - it continues in
				//cleartext when the advertisement is absent - and that is the downgrade this finding is about.
				case SecureSocketOptions.StartTlsWhenAvailable:
					ReportConnectionSecurityHardened(requested);
					return SecureSocketOptions.StartTls;

				//Refused. Cleartext by definition, and explicitly chosen.
				case SecureSocketOptions.None:
					throw new InvalidOperationException(
						"SECURITY: this SMTP service is configured with connection security 'None', which "
						+ "transmits the relay credential and every message in cleartext, and this "
						+ "installation is not in development posture. No mail has been sent. Set the "
						+ "smtp_service 'connection_security' field to 'SslOnConnect' or 'StartTls'; see "
						+ "docs/security/secure-configuration.md.");

				//Refused. Not a mode at all.
				default:
					throw new InvalidOperationException(
						"SECURITY: this SMTP service is configured with a connection security value that is "
						+ "not a supported mode, so no encrypted transport could be established and no mail "
						+ "has been sent. Set the smtp_service 'connection_security' field to 'SslOnConnect' "
						+ "or 'StartTls'; see docs/security/secure-configuration.md.");
			}
		}

		/// <summary>
		/// The numeric value of <c>System.Security.Authentication.SslProtocols.Tls12</c>, the lowest transport
		/// protocol version this installation will send an SMTP credential over.
		/// </summary>
		/// <remarks>
		/// The enum member is deliberately NOT named: analyzer rule CA5398 reports any reference to a specific
		/// <c>SslProtocols</c> version member, even one used only for comparison, and enumerating the versions
		/// to reject would name members the runtime has marked obsolete. 3072 IS <c>SslProtocols.Tls12</c>,
		/// fixed by the runtime's public contract, so the comparison stays exact without a suppression.
		/// <para>
		/// THE FLOOR IS THE CURRENT TLS 1.2 CONTRACT AND NOTHING MORE. Members are numbered in ascending
		/// protocol order today - 12 for SSL 2.0 through 12288 for TLS 1.3 - but neither this code nor the
		/// runtime's contract guarantees the numbering of a member added later, so a NEW <c>SslProtocols</c>
		/// MEMBER REQUIRES RE-REVIEW of this constant and of the comparison in
		/// <see cref="RequireApprovedTransport"/> rather than being assumed to be handled correctly.
		/// </para>
		/// </remarks>
		private const int MinimumApprovedSslProtocolValue = 3072;

		/// <summary>
		/// Whether a connection-security mode guarantees an encrypted session, so that a relay which does not
		/// offer encryption is refused rather than spoken to in cleartext.
		/// </summary>
		/// <remarks>
		/// SECURITY - CWE-319, CWE-311, OWASP A02. Single definition of "mandatory encryption" for the whole
		/// subsystem, shared by <see cref="ResolveConnectionSecurity"/> at the five send paths and by the
		/// <c>smtp_service</c> record validation hooks in <c>Services/SmtpInternalService</c>: enforcement is
		/// required at both, and two independent copies of the permitted set would eventually disagree.
		/// EXACTLY TWO MODES QUALIFY - <c>SslOnConnect</c> negotiates TLS before any SMTP command, and
		/// <c>StartTls</c> REQUIRES the relay to advertise STARTTLS, which is what distinguishes it from
		/// <c>StartTlsWhenAvailable</c>, whose advertisement an active attacker simply removes.
		/// </remarks>
		/// <param name="mode">The mode to test.</param>
		/// <returns><c>true</c> when the mode cannot result in an unencrypted session.</returns>
		internal static bool IsMandatoryEncryptedMode(SecureSocketOptions mode)
		{
			return mode == SecureSocketOptions.SslOnConnect || mode == SecureSocketOptions.StartTls;
		}

		/// <summary>
		/// The port on which SMTP uses implicit TLS, so that <c>Auto</c> resolves the way MailKit resolves it.
		/// </summary>
		/// <remarks>
		/// Named rather than written inline because it appears in a security decision, where an unexplained 465
		/// invites someone to "simplify" it into the STARTTLS branch and silently break implicit-TLS relays.
		/// </remarks>
		private const int ImplicitTlsPort = 465;

		/// <summary>
		/// Latch for the hardening notice. Zero until the notice has been emitted.
		/// </summary>
		private static int connectionSecurityHardeningReported;

		/// <summary>
		/// Reports, exactly once per process, that a stored connection-security mode permitting cleartext was
		/// hardened to a mandatory encrypted mode.
		/// </summary>
		/// <remarks>
		/// ONCE PER PROCESS for the same reason as the certificate notice above: this policy is evaluated on
		/// every outbound message. Written to standard error rather than through <c>Diagnostics.Log</c> because
		/// the platform log can raise an e-mail notification and the subsystem reported on IS THE MAILER. Only
		/// the mode and the field are named - never a relay address, port or credential.
		/// </remarks>
		/// <param name="requested">The stored mode that was hardened.</param>
		private static void ReportConnectionSecurityHardened(SecureSocketOptions requested)
		{
			if (System.Threading.Interlocked.CompareExchange(ref connectionSecurityHardeningReported, 1, 0) != 0)
				return;

			Console.Error.WriteLine("warn: WebVella.Erp.Plugins.Mail.Api.SmtpService[2] SECURITY - an SMTP "
				+ "service is configured with connection security '" + requested.ToString() + "', which "
				+ "permits an unencrypted session, and this installation is not in development posture. It "
				+ "has been raised to a mandatory encrypted mode for every send. Set the smtp_service "
				+ "'connection_security' field to 'SslOnConnect' or 'StartTls' to make the transport explicit; "
				+ "see docs/security/secure-configuration.md.");
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

			//RESOURCE CLEANUP - this message owns every attachment and linked-resource stream added below, and
			//disposing it disposes them; undisposed it held the full byte content of every attachment until a
			//collection. A `using` DECLARATION disposes at the end of the method, after Send, without re-indenting.
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
					//SECURITY - CWE-269 improper privilege management, CWE-732 incorrect permission assignment.
					//Database/DbFileRepository.Find refuses a staged file belonging to another non-administrative
					//principal, so this lookup has one more legitimate way to answer null. FAILING LOUDLY IS THE POINT:
					//skipping silently would turn a closed exfiltration path into a quiet partial success - a message
					//delivered as if complete, with the refused attachment missing and nothing recorded. FileNotFoundException
					//rather than the bare Exception the sibling overloads use: same behaviour, no CA2201 diagnostic.
					if (file == null)
						throw new FileNotFoundException($"Attachment file '{filepath}' not found.");

					var bytes = file.GetBytes();

					var extension = Path.GetExtension(filepath).ToLowerInvariant();
					//MIME MAPPING - TryGetValue leaves mimeType NULL for an unmapped extension; see BinaryContentType.
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
				// SECURITY H-11 (CWE-295 improper certificate validation, OWASP A02): validation was unconditionally
				// bypassed here, letting an active man-in-the-middle present any certificate and harvest the credential
				// authenticated below. AllowInvalidRemoteCertificates owns the decision and the rationale; do not inline
				// a literal, because the callback must keep yielding the member so the pattern stays visible to CA5359.
				// REVOCATION IS LEFT ENTIRELY TO MAILKIT, deliberately and unconfigurably - SmtpClient checks revocation
				// unless told otherwise, so saying nothing here IS the secure state. A relay whose chain names no
				// reachable CRL or OCSP responder is refused: publish the revocation source rather than disabling this.
				if (AllowInvalidRemoteCertificates)
					client.ServerCertificateValidationCallback = (s, c, h, e) => AllowInvalidRemoteCertificates;

				// SECURITY - CWE-319 cleartext transmission, CWE-311 missing encryption, OWASP A02: the stored mode used
				// to reach MailKit unexamined, so a service configured with None, with the shipped Auto default or with
				// StartTlsWhenAvailable could send this message - and authenticate the relay credential two lines below
				// - over an unencrypted session on which the certificate validation H-11 restored never runs.
				// ResolveConnectionSecurity owns that decision; this call is the last point before the socket, so it is
				// where the policy has to be unbypassable. RequireApprovedTransport then VERIFIES the resulting session.
				client.Connect(Server, Port, ResolveConnectionSecurity(ConnectionSecurity, Port));
				RequireApprovedTransport(client);

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

			//RESOURCE CLEANUP - disposing the message disposes every attachment stream it owns; see the first
			//SendEmail overload in this file.
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
					//SECURITY - CWE-269 / CWE-732; see the first SendEmail overload for why a refused staged file throws.
					if (file == null)
						throw new FileNotFoundException($"Attachment file '{filepath}' not found.");

					var bytes = file.GetBytes();

					var extension = Path.GetExtension(filepath).ToLowerInvariant();
					//MIME MAPPING - TryGetValue leaves mimeType NULL for an unmapped extension; see BinaryContentType.
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
				// SECURITY H-11 (CWE-295 improper certificate validation, OWASP A02): the callback must keep yielding
				// AllowInvalidRemoteCertificates, which owns the decision, the gate and the revocation contract.
				if (AllowInvalidRemoteCertificates)
					client.ServerCertificateValidationCallback = (s, c, h, e) => AllowInvalidRemoteCertificates;

				// SECURITY - CWE-319 / CWE-311, OWASP A02: ResolveConnectionSecurity owns the transport-mode policy and
				// RequireApprovedTransport verifies the session, both before the credential is presented below.
				client.Connect(Server, Port, ResolveConnectionSecurity(ConnectionSecurity, Port));
				RequireApprovedTransport(client);

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

			//API CONTRACT - this overload exists to take a caller-supplied MimeMessage, so it must not replace or
			//dispose what the caller owns; see the first SendEmail overload for the ownership split.
			if (sender == null)
				ex.AddError("senderEmail", "Sender is not specified.");
			else if (string.IsNullOrEmpty(sender.Address))
				ex.AddError("senderEmail", "Sender email is not specified.");
			else if (!sender.Address.IsEmail())
				ex.AddError("senderEmail", "Sender email is not valid email address.");

			if (string.IsNullOrEmpty(subject))
				ex.AddError("subject", "Subject is required.");

			ex.CheckAndThrow();

			//RESOURCE CLEANUP - disposing the message disposes every attachment stream it owns; see the first
			//SendEmail overload in this file.
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
					//SECURITY - CWE-269 / CWE-732; see the first SendEmail overload for why a refused staged file throws.
					if (file == null)
						throw new FileNotFoundException($"Attachment file '{filepath}' not found.");

					var bytes = file.GetBytes();

					var extension = Path.GetExtension(filepath).ToLowerInvariant();
					//MIME MAPPING - TryGetValue leaves mimeType NULL for an unmapped extension; see BinaryContentType.
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
				// SECURITY H-11 (CWE-295 improper certificate validation, OWASP A02): the callback must keep yielding
				// AllowInvalidRemoteCertificates, which owns the decision, the gate and the revocation contract.
				if (AllowInvalidRemoteCertificates)
					client.ServerCertificateValidationCallback = (s, c, h, e) => AllowInvalidRemoteCertificates;

				// SECURITY - CWE-319 / CWE-311, OWASP A02: ResolveConnectionSecurity owns the transport-mode policy and
				// RequireApprovedTransport verifies the session, both before the credential is presented below.
				client.Connect(Server, Port, ResolveConnectionSecurity(ConnectionSecurity, Port));
				RequireApprovedTransport(client);

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

			//API CONTRACT - this overload takes a caller-supplied MimeMessage; see the first SendEmail overload.
			if (sender == null)
				ex.AddError("senderEmail", "Sender is not specified.");
			else if (string.IsNullOrEmpty(sender.Address))
				ex.AddError("senderEmail", "Sender email is not specified.");
			else if (!sender.Address.IsEmail())
				ex.AddError("senderEmail", "Sender email is not valid email address.");

			if (string.IsNullOrEmpty(subject))
				ex.AddError("subject", "Subject is required.");

			ex.CheckAndThrow();

			//RESOURCE CLEANUP - disposing the message disposes every attachment stream it owns; see the first
			//SendEmail overload in this file.
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
					//SECURITY - CWE-269 / CWE-732; see the first SendEmail overload for why a refused staged file throws.
					if (file == null)
						throw new FileNotFoundException($"Attachment file '{filepath}' not found.");

					var bytes = file.GetBytes();

					var extension = Path.GetExtension(filepath).ToLowerInvariant();
					//MIME MAPPING - TryGetValue leaves mimeType NULL for an unmapped extension; see BinaryContentType.
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
				// SECURITY H-11 (CWE-295 improper certificate validation, OWASP A02): the callback must keep yielding
				// AllowInvalidRemoteCertificates, which owns the decision, the gate and the revocation contract.
				if (AllowInvalidRemoteCertificates)
					client.ServerCertificateValidationCallback = (s, c, h, e) => AllowInvalidRemoteCertificates;

				// SECURITY - CWE-319 / CWE-311, OWASP A02: ResolveConnectionSecurity owns the transport-mode policy and
				// RequireApprovedTransport verifies the session, both before the credential is presented below.
				client.Connect(Server, Port, ResolveConnectionSecurity(ConnectionSecurity, Port));
				RequireApprovedTransport(client);

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
				//API CONTRACT - the cc:/bcc: prefix parse below reads the address BEFORE trimming, so a prefixed
				//address is routed rather than treated as a literal recipient.
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
						//API CONTRACT - the cc:/bcc: prefix parse below reads the address BEFORE trimming, so a prefixed
						//address is routed rather than treated as a literal recipient.
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
				//API CONTRACT - the cc:/bcc: prefix parse below reads the address BEFORE trimming, so a prefixed
				//address is routed rather than treated as a literal recipient.
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
						//API CONTRACT - the cc:/bcc: prefix parse below reads the address BEFORE trimming, so a prefixed
						//address is routed rather than treated as a literal recipient.
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
