using HtmlAgilityPack;
using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.StaticFiles;
using MimeKit;
using MimeKit.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Api.Models.AutoMapper;
using WebVella.Erp.Database;
using WebVella.Erp.Eql;
using WebVella.Erp.Exceptions;
using WebVella.Erp.Plugins.Mail.Api;
using WebVella.Erp.Utilities;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Pages.Application;
using WebVella.Erp.Web.Utils;

namespace WebVella.Erp.Plugins.Mail.Services
{
	internal class SmtpInternalService
	{
		private static object lockObject = new object();
		private static bool queueProcessingInProgress = false;

		//QUEUE RESILIENCE - CWE-703 / CWE-755. Retry policy applied when the message's OWN smtp_service could
		//not be read, the one failure for which its configured max_retries_count and retry_wait_minutes are by
		//definition unavailable. These are the platform's own seeded defaults for those fields, so the message
		//is treated as the service itself would have treated a momentary send failure.
		private const int ServiceLookupFailureMaxRetriesCount = 3;
		private const int ServiceLookupFailureRetryWaitMinutes = 60;

		#region <--- Hooks Logic --->

		public void ValidatePreCreateRecord(EntityRecord rec, List<ErrorModel> errors)
		{
			foreach (var prop in rec.Properties)
			{
				switch (prop.Key)
				{
					case "name":
						{
							var result = new EqlCommand("SELECT * FROM smtp_service WHERE name = @name", new EqlParameter("name", rec["name"])).Execute();
							if (result.Count > 0)
							{
								errors.Add(new ErrorModel
								{
									Key = "name",
									Value = (string)rec["name"],
									Message = "There is already existing service with that name. Name must be unique"
								});
							}
						}
						break;
					case "port":
						{
							if (!Int32.TryParse(rec["port"]?.ToString(), out int port))
							{
								errors.Add(new ErrorModel
								{
									Key = "port",
									Value = rec["port"]?.ToString(),
									Message = $"Port must be an integer value between 1 and 65025"
								});
							}
							else
							{
								if (port <= 0 || port > 65025)
								{
									errors.Add(new ErrorModel
									{
										Key = "port",
										Value = rec["port"]?.ToString(),
										Message = $"Port must be an integer value between 1 and 65025"
									});
								}
							}

						}
						break;
					//SCHEMA MAPPING - this case label named a field that does not exist. smtp_service carries
					//`default_sender_email`, a REQUIRED InputEmailField, and never carried `default_from_email`, so the
					//switch could not match and this validation never ran: an invalid sender address was accepted on save
					//and failed much later inside MailboxAddress construction, reporting a data-entry mistake as a delivery
					//failure. IsEmail() is null-safe, so a null or blank value reports the same actionable error rather
					//than throwing, which agrees with the field being required.
					case "default_sender_email":
						{
							if (!((string)rec["default_sender_email"]).IsEmail())
							{
								errors.Add(new ErrorModel
								{
									Key = "default_sender_email",
									Value = (string)rec["default_sender_email"],
									Message = $"Default sender email address is invalid"
								});
							}
						}
						break;
					case "default_reply_to_email":
						{
							if (string.IsNullOrWhiteSpace((string)rec["default_reply_to_email"]))
								continue;

							if (!((string)rec["default_reply_to_email"]).IsEmail())
							{
								errors.Add(new ErrorModel
								{
									Key = "default_reply_to_email",
									Value = (string)rec["default_reply_to_email"],
									Message = $"Default reply to email address is invalid"
								});
							}
						}
						break;
					case "max_retries_count":
						{
							if (!Int32.TryParse(rec["max_retries_count"]?.ToString(), out int count))
							{
								errors.Add(new ErrorModel
								{
									Key = "max_retries_count",
									Value = rec["max_retries_count"]?.ToString(),
									Message = $"Number of retries on error must be an integer value between 1 and 10"
								});
							}
							else
							{
								if (count < 1 || count > 10)
								{
									errors.Add(new ErrorModel
									{
										Key = "max_retries_count",
										Value = rec["max_retries_count"]?.ToString(),
										Message = $"Number of retries on error must be an integer value between 1 and 10"
									});
								}
							}
						}
						break;
					case "retry_wait_minutes":
						{
							if (!Int32.TryParse(rec["retry_wait_minutes"]?.ToString(), out int minutes))
							{
								errors.Add(new ErrorModel
								{
									Key = "retry_wait_minutes",
									Value = rec["retry_wait_minutes"]?.ToString(),
									Message = $"Wait period between retries must be an integer value between 1 and 1440 minutes"
								});
							}
							else
							{
								if (minutes < 1 || minutes > 1440)
								{
									errors.Add(new ErrorModel
									{
										Key = "retry_wait_minutes",
										Value = rec["retry_wait_minutes"]?.ToString(),
										Message = $"Wait period between retries must be an integer value between 1 and 1440 minutes"
									});
								}
							}
						}
						break;
					case "connection_security":
						{
							if (!Int32.TryParse(rec["connection_security"] as string, out int connectionSecurityNumber))
							{
								errors.Add(new ErrorModel
								{
									Key = "connection_security",
									Value = (string)rec["connection_security"],
									Message = $"Invalid connection security setting selected."
								});
								continue;
							}

							//INPUT VALIDATION - a numeric cast to an enum NEVER throws, so the try/catch this replaces was
							//unreachable and every integer was accepted, failing much later inside SmtpClient.Connect. The generic
							//Enum.IsDefined overload is the test that rejects it, and avoids boxing and analyzer rule CA2263.
							if (!Enum.IsDefined((MailKit.Security.SecureSocketOptions)connectionSecurityNumber))
							{
								errors.Add(new ErrorModel
								{
									Key = "connection_security",
									Value = (string)rec["connection_security"],
									Message = $"Invalid connection security setting selected."
								});
								continue;
							}

							//SECURITY - CWE-319 cleartext transmission, CWE-311 missing encryption, OWASP A02. This hook accepted
							//every defined mode, so an administrator could reintroduce a cleartext relay through the UI: `None`
							//sends the credential and every message in clear, and `Auto` and `StartTlsWhenAvailable` do so whenever
							//the relay does not advertise STARTTLS. Preservation is honoured without permitting cleartext - the
							//check is POSTURE-GATED on ErpSettings.DevelopmentMode, and it validates only what is being WRITTEN NOW,
							//because SmtpService.ResolveConnectionSecurity hardens an existing row's mode at send time. The message
							//names modes and the posture setting, never the relay or its credential.
							if (!ErpSettings.DevelopmentMode
								&& !SmtpService.IsMandatoryEncryptedMode((MailKit.Security.SecureSocketOptions)connectionSecurityNumber))
							{
								errors.Add(new ErrorModel
								{
									Key = "connection_security",
									Value = (string)rec["connection_security"],
									Message = $"Connection security must be SslOnConnect or StartTls. The selected mode permits an unencrypted session, which is not allowed outside development posture."
								});
							}
						}
						break;
				}
			}
		}

		public void ValidatePreUpdateRecord(EntityRecord rec, List<ErrorModel> errors)
		{
			foreach (var prop in rec.Properties)
			{
				switch (prop.Key)
				{
					case "name":
						{
							var result = new EqlCommand("SELECT * FROM smtp_service WHERE name = @name", new EqlParameter("name", rec["name"])).Execute();
							if (result.Count > 1)
							{
								errors.Add(new ErrorModel
								{
									Key = "name",
									Value = (string)rec["name"],
									Message = "There is already existing service with that name. Name must be unique"
								});
							}
							else if (result.Count == 1 && (Guid)result[0]["id"] != (Guid)rec["id"])
							{
								errors.Add(new ErrorModel
								{
									Key = "name",
									Value = (string)rec["name"],
									Message = "There is already existing service with that name. Name must be unique"
								});
							}
						}
						break;
					case "port":
						{
							if (!Int32.TryParse(rec["port"] as string, out int port))
							{
								errors.Add(new ErrorModel
								{
									Key = "port",
									Value = (string)rec["port"],
									Message = $"Port must be an integer value between 1 and 65025"
								});
							}
							else
							{
								if (port <= 0 || port > 65025)
								{
									errors.Add(new ErrorModel
									{
										Key = "port",
										Value = (string)rec["port"],
										Message = $"Port must be an integer value between 1 and 65025"
									});
								}
							}

						}
						break;
					//SCHEMA MAPPING - this case label named a field that does not exist; see the same correction in the
					//create hook above. smtp_service carries `default_sender_email` and never carried
					//`default_from_email`, so the switch could not match and the sender address went unvalidated on save.
					//IsEmail() is null-safe, so a null or blank value reports the same actionable error.
					case "default_sender_email":
						{
							if (!((string)rec["default_sender_email"]).IsEmail())
							{
								errors.Add(new ErrorModel
								{
									Key = "default_sender_email",
									Value = (string)rec["default_sender_email"],
									Message = $"Default sender email address is invalid"
								});
							}
						}
						break;
					case "default_reply_to_email":
						{
							if (string.IsNullOrWhiteSpace((string)rec["default_reply_to_email"]))
								continue;

							if (!((string)rec["default_reply_to_email"]).IsEmail())
							{
								errors.Add(new ErrorModel
								{
									Key = "default_reply_to_email",
									Value = (string)rec["default_reply_to_email"],
									Message = $"Default reply to email address is invalid"
								});
							}
						}
						break;
					case "max_retries_count":
						{
							if (!Int32.TryParse(rec["max_retries_count"] as string, out int count))
							{
								errors.Add(new ErrorModel
								{
									Key = "max_retries_count",
									Value = (string)rec["max_retries_count"],
									Message = $"Number of retries on error must be an integer value between 1 and 10"
								});
							}
							else
							{
								if (count < 1 || count > 10)
								{
									errors.Add(new ErrorModel
									{
										Key = "max_retries_count",
										Value = (string)rec["max_retries_count"],
										Message = $"Number of retries on error must be an integer value between 1 and 10"
									});
								}
							}
						}
						break;
					case "retry_wait_minutes":
						{
							if (!Int32.TryParse(rec["retry_wait_minutes"] as string, out int minutes))
							{
								errors.Add(new ErrorModel
								{
									Key = "retry_wait_minutes",
									Value = (string)rec["retry_wait_minutes"],
									Message = $"Wait period between retries must be an integer value between 1 and 1440 minutes"
								});
							}
							else
							{
								if (minutes < 1 || minutes > 1440)
								{
									errors.Add(new ErrorModel
									{
										Key = "retry_wait_minutes",
										Value = (string)rec["retry_wait_minutes"],
										Message = $"Wait period between retries must be an integer value between 1 and 1440 minutes"
									});
								}
							}
						}
						break;
					case "connection_security":
						{
							if (!Int32.TryParse(rec["connection_security"] as string, out int connectionSecurityNumber))
							{
								errors.Add(new ErrorModel
								{
									Key = "connection_security",
									Value = (string)rec["connection_security"],
									Message = $"Invalid connection security setting selected."
								});
								continue;
							}

							//INPUT VALIDATION - a numeric cast to an enum NEVER throws, so the try/catch this replaces was
							//unreachable and every integer was accepted. The generic Enum.IsDefined overload rejects an undefined
							//value here rather than leaving it to fail inside SmtpClient.Connect, and avoids CA2263.
							if (!Enum.IsDefined((MailKit.Security.SecureSocketOptions)connectionSecurityNumber))
							{
								errors.Add(new ErrorModel
								{
									Key = "connection_security",
									Value = (string)rec["connection_security"],
									Message = $"Invalid connection security setting selected."
								});
								continue;
							}

							//SECURITY - CWE-319 cleartext transmission, CWE-311 missing encryption, OWASP A02: the same narrowing
							//as the create hook above, for the same reason and under the same posture gate. Only a row being SAVED
							//has to name an already-mandatory mode; an existing row keeps sending because
							//SmtpService.ResolveConnectionSecurity hardens its mode at send time.
							if (!ErpSettings.DevelopmentMode
								&& !SmtpService.IsMandatoryEncryptedMode((MailKit.Security.SecureSocketOptions)connectionSecurityNumber))
							{
								errors.Add(new ErrorModel
								{
									Key = "connection_security",
									Value = (string)rec["connection_security"],
									Message = $"Connection security must be SslOnConnect or StartTls. The selected mode permits an unencrypted session, which is not allowed outside development posture."
								});
							}
						}
						break;
				}
			}
		}

		public void HandleDefaultServiceSetup(EntityRecord rec, List<ErrorModel> errors)
		{
			if (rec.Properties.ContainsKey("is_default") && (bool)rec["is_default"])
			{

				var recMan = new RecordManager(executeHooks: false);
				var records = new EqlCommand("SELECT id,is_default FROM smtp_service").Execute();
				foreach (var record in records)
				{
					if ((bool)record["is_default"])
					{
						record["is_default"] = false;
						recMan.UpdateRecord("smtp_service", record);
					}
				}
			}
			else if (rec.Properties.ContainsKey("is_default") && (bool)rec["is_default"] == false)
			{
				var currentRecord = new EqlCommand("SELECT * FROM smtp_service WHERE id = @id", new EqlParameter("id", rec["id"])).Execute();
				if (currentRecord.Count > 0 && (bool)currentRecord[0]["is_default"])
				{
					errors.Add(new ErrorModel
					{
						Key = "is_default",
						Value = ((bool)rec["is_default"]).ToString(),
						Message = $"Forbidden. There should always be an active default service."
					});
				}
			}
		}

		public IActionResult TestSmtpServiceOnPost(RecordDetailsPageModel pageModel)
		{
			SmtpService smtpService = null;
			string recipientEmail = string.Empty;
			string subject = string.Empty;
			string content = string.Empty;

			ValidationException valEx = new ValidationException();

			if (pageModel.HttpContext.Request.Form == null)
			{
				valEx.AddError("form", "Smtp service test page missing form tag");
				valEx.CheckAndThrow();
			}


			if (!pageModel.HttpContext.Request.Form.ContainsKey("recipient_email"))
				valEx.AddError("recipient_email", "Recipient email is not specified.");
			else
			{
				recipientEmail = pageModel.HttpContext.Request.Form["recipient_email"];
				if (string.IsNullOrWhiteSpace(recipientEmail))
					valEx.AddError("recipient_email", "Recipient email is not specified");
				else if (!recipientEmail.IsEmail())
					valEx.AddError("recipient_email", "Recipient email is not a valid email address");
			}

			if (!pageModel.HttpContext.Request.Form.ContainsKey("subject"))
				valEx.AddError("subject", "Subject is not specified");
			else
			{
				subject = pageModel.HttpContext.Request.Form["subject"];
				if (string.IsNullOrWhiteSpace(subject))
					valEx.AddError("subject", "Subject is required");
			}

			if (!pageModel.HttpContext.Request.Form.ContainsKey("content"))
				valEx.AddError("content", "Content is not specified");
			else
			{
				content = pageModel.HttpContext.Request.Form["content"];
				if (string.IsNullOrWhiteSpace(content))
					valEx.AddError("content", "Content is required");
			}

			var smtpServiceId = pageModel.DataModel.GetProperty("Record.id") as Guid?;

			if (smtpServiceId == null)
				valEx.AddError("serviceId", "Invalid smtp service id");
			else
			{
				smtpService = new EmailServiceManager().GetSmtpService(smtpServiceId.Value);
				if (smtpService == null)
					valEx.AddError("serviceId", "Smtp service with specified id does not exist");
			}

			List<string> attachments = new List<string>();
			if (pageModel.HttpContext.Request.Form.ContainsKey("attachments"))
			{
				var ids = pageModel.HttpContext.Request.Form["attachments"].ToString().Split(",", StringSplitOptions.RemoveEmptyEntries).Select(x => new Guid(x));
				foreach(var id in ids )
				{
					var fileRecord = new EqlCommand("SELECT name,path FROM user_file WHERE id = @id", new EqlParameter("id", id)).Execute().FirstOrDefault();
					if (fileRecord != null)
						attachments.Add((string)fileRecord["path"]);
				}
			}

			//we set current record to store properties which don't exist in current entity
			EntityRecord currentRecord = pageModel.DataModel.GetProperty("Record") as EntityRecord;
			currentRecord["recipient_email"] = recipientEmail;
			currentRecord["subject"] = subject;
			currentRecord["content"] = content;
			pageModel.DataModel.SetRecord(currentRecord);

			valEx.CheckAndThrow();

			try
			{
				EmailAddress recipient = new EmailAddress( recipientEmail );
				smtpService.SendEmail(recipient, subject, string.Empty, content, attachments: attachments );
				pageModel.TempData.Put("ScreenMessage", new ScreenMessage() { Message = "Email was successfully sent", Type = ScreenMessageType.Success, Title = "Success" });
				var returnUrl = pageModel.HttpContext.Request.Query["returnUrl"];
				return new RedirectResult($"/mail/services/smtp/r/{smtpService.Id}/details?returnUrl={returnUrl}");
			}
			catch (Exception ex)
			{
				valEx.AddError("", ex.Message);
				valEx.CheckAndThrow();
				return null;
			}
		}

		public IActionResult EmailSendNowOnPost(RecordDetailsPageModel pageModel)
		{
			var emailId = (Guid)pageModel.DataModel.GetProperty("Record.id");

			var internalSmtpSrv = new SmtpInternalService();
			Email email = internalSmtpSrv.GetEmail(emailId);
			SmtpService smtpService = new EmailServiceManager().GetSmtpService(email.ServiceId);
			internalSmtpSrv.SendEmail(email, smtpService);

			if (email.Status == EmailStatus.Sent)
				pageModel.TempData.Put("ScreenMessage", new ScreenMessage() { Message = "Email was successfully sent", Type = ScreenMessageType.Success, Title = "Success" });
			else
				pageModel.TempData.Put("ScreenMessage", new ScreenMessage() { Message = email.ServerError, Type = ScreenMessageType.Error, Title = "Error" });

			var returnUrl = pageModel.HttpContext.Request.Query["returnUrl"];
			return new RedirectResult($"/mail/emails/all/r/{emailId}/details?returnUrl={returnUrl}");
		}

		#endregion

		internal void SaveEmail(Email email)
		{
			PrepareEmailXSearch(email);
			RecordManager recMan = new RecordManager();
			var response = recMan.Find(new EntityQuery("email", "*", EntityQuery.QueryEQ("id", email.Id)));
			if (response.Object != null && response.Object.Data != null && response.Object.Data.Count != 0)
				response = recMan.UpdateRecord("email", email.MapTo<EntityRecord>());
			else
				response = recMan.CreateRecord("email", email.MapTo<EntityRecord>());

			if (!response.Success)
				throw new Exception(response.Message);

		}


		#region <--- content manipulation --->

		public static void ProcessHtmlContent(BodyBuilder builder)
		{
			if (builder == null)
				return;

			if (string.IsNullOrWhiteSpace(builder.HtmlBody))
				return;

			try
			{
				var htmlDoc = new HtmlDocument();
				htmlDoc.Load(new MemoryStream(Encoding.UTF8.GetBytes(builder.HtmlBody)));

				if (htmlDoc.DocumentNode == null)
					return;

				//CONTENT MAPPING - HtmlAgilityPack returns NULL, not an empty collection, when nothing matches, so
				//every HTML body without an image raised NullReferenceException here; the broad catch below then
				//skipped BOTH the rewritten body and the plain-text alternative. Coalescing to an empty sequence makes
				//"no images" the no-op it should always have been.
				foreach (HtmlNode node in htmlDoc.DocumentNode.SelectNodes("//img[@src]") ?? Enumerable.Empty<HtmlNode>())
				{
					var src = node.Attributes["src"].Value.Split('?', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();


					if (!string.IsNullOrWhiteSpace(src) && src.StartsWith("/fs"))
					{
						try
						{
							Uri uri = new Uri(src);
							src = uri.AbsolutePath;
						}
						catch { }

						if (src.StartsWith("/fs"))
							src = src.Substring(3);

						DbFileRepository fsRepository = new DbFileRepository();
						var file = fsRepository.Find(src);
						if (file == null)
							continue;

						var bytes = file.GetBytes();

						var extension = Path.GetExtension(src).ToLowerInvariant();
						//MIME MAPPING - TryGetValue leaves mimeType NULL for an unmapped extension and MimePart(string) throws
						//for null, so one unmapped inline image aborted the whole method. See SmtpService.BinaryContentType.
						if (!new FileExtensionContentTypeProvider().Mappings.TryGetValue(extension, out string mimeType) || string.IsNullOrWhiteSpace(mimeType))
							mimeType = SmtpService.BinaryContentType;

						var imagePart = new MimePart(mimeType)
						{
							ContentId = MimeUtils.GenerateMessageId(),
							Content = new MimeContent(new MemoryStream(bytes)),
							ContentDisposition = new ContentDisposition(ContentDisposition.Attachment),
							ContentTransferEncoding = ContentEncoding.Base64,
							FileName = Path.GetFileName(src)
						};

						builder.LinkedResources.Add(imagePart);
						node.SetAttributeValue("src", $"cid:{imagePart.ContentId}");
					}
				}
				builder.HtmlBody = htmlDoc.DocumentNode.OuterHtml;
			}
			catch
			{
				//Inline-image embedding is best-effort: a failure leaves the original HtmlBody in place, which is still
				//deliverable, but it must not also cost the plain-text alternative below - hence no return here.
			}

			//Outside the handler above, deliberately: a message with only an HTML body is treated as spam by many
			//relays, so this fallback must run even when image embedding failed.
			if (string.IsNullOrWhiteSpace(builder.TextBody) && !string.IsNullOrWhiteSpace(builder.HtmlBody))
				builder.TextBody = ConvertToPlainText(builder.HtmlBody);
		}


		private static string ConvertToPlainText(string html)
		{
			try
			{
				if (string.IsNullOrWhiteSpace(html))
					return string.Empty;

				HtmlDocument doc = new HtmlDocument();
				doc.LoadHtml(html);

				StringWriter sw = new StringWriter();
				ConvertTo(doc.DocumentNode, sw);
				sw.Flush();
				return sw.ToString();
			}
			catch
			{
				return string.Empty;
			}
		}

		private static void ConvertContentTo(HtmlNode node, TextWriter outText)
		{
			foreach (HtmlNode subnode in node.ChildNodes)
			{
				ConvertTo(subnode, outText);
			}
		}

		private static void ConvertTo(HtmlNode node, TextWriter outText)
		{
			string html;
			switch (node.NodeType)
			{
				case HtmlNodeType.Comment:
					// don't output comments
					break;

				case HtmlNodeType.Document:
					ConvertContentTo(node, outText);
					break;

				case HtmlNodeType.Text:
					// script and style must not be output
					string parentName = node.ParentNode.Name;
					if ((parentName == "script") || (parentName == "style"))
						break;

					// get text
					html = ((HtmlTextNode)node).Text;

					// is it in fact a special closing node output as text?
					if (HtmlNode.IsOverlappedClosingElement(html))
						break;

					// check the text is meaningful and not a bunch of white spaces
					if (html.Trim().Length > 0)
					{
						outText.Write(HtmlEntity.DeEntitize(html));
					}
					break;

				case HtmlNodeType.Element:
					switch (node.Name)
					{
						case "p":
							// treat paragraphs as crlf
							outText.Write(Environment.NewLine);
							break;
						case "br":
							outText.Write(Environment.NewLine);
							break;
						case "a":
							HtmlAttribute att = node.Attributes["href"];
							outText.Write($"<{att.Value}>");
							break;
					}

					if (node.HasChildNodes)
					{
						ConvertContentTo(node, outText);
					}
					break;
			}
		}

		#endregion


		internal Email GetEmail(Guid id)
		{
			var result = new EqlCommand("SELECT * FROM email WHERE id = @id", new EqlParameter("id", id)).Execute();
			if (result.Count == 1)
				return result[0].MapTo<Email>();

			return null;
		}

		internal void PrepareEmailXSearch(Email email)
		{
			var recipientsText = string.Join(" ", email.Recipients.Select(x => $"{x.Name} {x.Address}") );
			email.XSearch = $"{email.Sender?.Name} {email.Sender?.Address} {recipientsText} {email.Subject} {email.ContentText} {email.ContentHtml}";
		}

		internal void SendEmail(Email email, SmtpService service)
		{
			try
			{

				if (service == null)
				{
					email.ServerError = "SMTP service not found";
					email.Status = EmailStatus.Aborted;
					return; //save email in finally block will save changes
				}
				else if (!service.IsEnabled)
				{
					email.ServerError = "SMTP service is not enabled";
					email.Status = EmailStatus.Aborted;
					return; //save email in finally block will save changes
				}

				//RESOURCE CLEANUP - the queued path runs unattended and repeatedly, so an undisposed message retained
				//every attachment's bytes for a whole pass. The `using` declaration disposes at the end of this try
				//block, after Send and before the catch and finally that record the outcome.
				using var message = new MimeMessage();
				if (!string.IsNullOrWhiteSpace(email.Sender?.Name))
					message.From.Add(new MailboxAddress(email.Sender?.Name, email.Sender?.Address));
				else
					message.From.Add(new MailboxAddress(email.Sender?.Address, email.Sender?.Address));

				foreach (var recipient in email.Recipients)
				{
					if (recipient.Address.StartsWith("cc:"))
					{
						if (!string.IsNullOrWhiteSpace(recipient.Name))
							message.Cc.Add(new MailboxAddress(recipient.Name, recipient.Address.Substring(3)));
						else
							message.Cc.Add(new MailboxAddress(recipient.Address.Substring(3), recipient.Address.Substring(3)));
					}
					else if (recipient.Address.StartsWith("bcc:"))
					{
						if (!string.IsNullOrWhiteSpace(recipient.Name))
							message.Bcc.Add(new MailboxAddress(recipient.Name, recipient.Address.Substring(4)));
						else
							message.Bcc.Add(new MailboxAddress(recipient.Address.Substring(4), recipient.Address.Substring(4)));
					}
					else
					{
						if (!string.IsNullOrWhiteSpace(recipient.Name))
							message.To.Add(new MailboxAddress(recipient.Name, recipient.Address));
						else
							message.To.Add(new MailboxAddress(recipient.Address, recipient.Address));
					}
				}

				if (!string.IsNullOrWhiteSpace(email.ReplyToEmail))
				{
					string[] replyToEmails = email.ReplyToEmail.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
					foreach(var replyEmail in replyToEmails)
						message.ReplyTo.Add(new MailboxAddress(replyEmail, replyEmail));
				}
				else
					message.ReplyTo.Add(new MailboxAddress(email.Sender?.Address, email.Sender?.Address));

				message.Subject = email.Subject;

				var bodyBuilder = new BodyBuilder();
				bodyBuilder.HtmlBody = email.ContentHtml;
				bodyBuilder.TextBody = email.ContentText;

				if (email.Attachments != null && email.Attachments.Count > 0)
				{
					foreach (var att in email.Attachments )
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
						//principal, so this lookup has one more legitimate way to answer null. Skipping silently would deliver
						//a queued message as if complete; throwing is caught by this method's own handler, which records the
						//reason in server_error and retries or aborts per policy. Deliberate contrast with the inline-image
						//loop, which does continue: a missing image degrades rendering, a missing attachment loses content.
						if (file == null)
							throw new FileNotFoundException($"Attachment file '{filepath}' not found.");

						var bytes = file.GetBytes();

						var extension = Path.GetExtension(filepath).ToLowerInvariant();
						//MIME MAPPING - an unmapped extension leaves mimeType NULL and MimePart(string) throws for null, which
						//on THIS path counted a retry and eventually aborted the message. See SmtpService.BinaryContentType.
						if (!new FileExtensionContentTypeProvider().Mappings.TryGetValue(extension, out string mimeType) || string.IsNullOrWhiteSpace(mimeType))
							mimeType = SmtpService.BinaryContentType;

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
				ProcessHtmlContent(bodyBuilder);
				message.Body = bodyBuilder.ToMessageBody();

				using (var client = new SmtpClient())
				{
					// SECURITY H-11 (CWE-295 improper certificate validation, OWASP A02): validation was unconditionally
					// bypassed here, so this path - the one the BACKGROUND QUEUE JOB drives - encrypted the session without
					// authenticating it. It shares the single SmtpService policy member, so one configuration key governs
					// all five send paths; do not inline a literal, because the callback must keep yielding the member so
					// the pattern stays visible to CA5359. REVOCATION IS LEFT ENTIRELY TO MAILKIT here too, deliberately
					// and unconfigurably. QUEUE-SPECIFIC CONSEQUENCE, worth knowing before diagnosing a stalled queue: a
					// relay whose chain names no reachable CRL or OCSP responder surfaces as retries ending in an aborted
					// message with the chain detail in server_error, not as an exception an operator sees.
					if (SmtpService.AllowInvalidRemoteCertificates)
						client.ServerCertificateValidationCallback = (s, c, h, e) => SmtpService.AllowInvalidRemoteCertificates;

					// SECURITY - CWE-319 cleartext transmission, CWE-311 missing encryption, OWASP A02: this path handed
					// the stored mode to MailKit unexamined, so a service configured with None, with the shipped Auto
					// default or with StartTlsWhenAvailable sent every queued message - and authenticated the credential
					// two lines below - over an unencrypted session. It shares the single SmtpService policy member, so one
					// posture decision governs all five paths. QUEUE-SPECIFIC CONSEQUENCE: a refusal here surfaces as the
					// message text recorded in server_error rather than as an exception, because the handler below catches
					// it. RequireApprovedTransport then VERIFIES the resulting session before the credential is presented.
					client.Connect(service.Server, service.Port, SmtpService.ResolveConnectionSecurity(service.ConnectionSecurity, service.Port));
					SmtpService.RequireApprovedTransport(client);

					if (!string.IsNullOrWhiteSpace(service.Username))
						client.Authenticate(service.Username, service.Password);

					client.Send(message);
					client.Disconnect(true);
				}
				email.SentOn = DateTime.UtcNow;
				email.Status = EmailStatus.Sent;
				email.ScheduledOn = null;
				email.ServerError = null;
			}
			catch (Exception ex)
			{
				email.SentOn = null;
				//SECURITY - CWE-79 stored cross-site scripting, OWASP A03. TREAT THIS VALUE AS UNTRUSTED EXTERNAL DATA:
				//for a relay failure `ex.Message` is MailKit's report of the SMTP PEER'S OWN RESPONSE TEXT, so a peer
				//can be induced to echo attacker-influenced content into it. It is stored verbatim ON PURPOSE, because
				//the operator guidance for a stalled queue is to read server_error first, and is encoded AT THE SINK
				//where the rendering context is known - the all_emails error-icon node HTML-encodes it into a title
				//attribute. ANY NEW READER OF THIS COLUMN must encode for its own context.
				email.ServerError = ex.Message;
				email.RetriesCount++;
				if (email.RetriesCount >= service.MaxRetriesCount)
				{
					email.ScheduledOn = null;
					email.Status = EmailStatus.Aborted;
				}
				else
				{
					email.ScheduledOn = DateTime.UtcNow.AddMinutes(service.RetryWaitMinutes);
					email.Status = EmailStatus.Pending;
				}

			}
			finally
			{
				new SmtpInternalService().SaveEmail(email);
			}
		}

		public void ProcessSmtpQueue()
		{
			lock (lockObject)
			{
				if (queueProcessingInProgress)
					return;

				queueProcessingInProgress = true;
			}

			try
			{
				List<Email> pendingEmails = new List<Email>();
				do
				{
					EmailServiceManager serviceManager = new EmailServiceManager();

					pendingEmails = new EqlCommand("SELECT * FROM email WHERE status = @status AND scheduled_on <> NULL" +
													" AND scheduled_on < @scheduled_on  ORDER BY priority DESC, scheduled_on ASC PAGE 1 PAGESIZE 10",
                                new EqlParameter("status", ((int)EmailStatus.Pending).ToString()),
								new EqlParameter("scheduled_on", DateTime.UtcNow)).Execute().MapTo<Email>();

					foreach (var email in pendingEmails)
					{
						//QUEUE RESILIENCE - and the reason the abort branch below could never run.
						//Api/EmailServiceManager.GetSmtpService THROWS when no smtp_service row carries the id rather than
						//returning null, so a message whose service row was deleted did not abort: the exception escaped this
						//loop and this method, leaving the row Pending with its scheduled time in the past, and every
						//subsequent pass re-selected it first and threw again. One orphaned row STARVED THE WHOLE QUEUE
						//indefinitely - a denial of service on mail delivery reachable by an ordinary administrative action.
						//Catching PER ROW makes the failure local: the row leaves the pending selection either way, so the
						//loop always makes progress.
						//
						//SECURITY / RESILIENCE - CWE-703 improper handling of exceptional conditions with CWE-755, OWASP A04.
						//THE TWO HANDLERS BELOW ARE THE FIX AND MUST NOT BE MERGED BACK INTO ONE. A single catch (Exception)
						//treated every lookup failure as proof the service was gone, so a momentary datastore, timeout or query
						//fault permanently aborted every message in the page and cleared its schedule, destroying mail
						//silently. The distinction is carried by the exception TYPE: SmtpServiceNotFoundException means the
						//absence is PROVEN, so aborting is right; anything else is presumed transient and keeps its budget.
						SmtpService service;
						try
						{
							service = serviceManager.GetSmtpService(email.ServiceId);
						}
						catch (SmtpServiceNotFoundException ex)
						{
							//PROVEN missing: the lookup ran and returned no row, so this message can never be
							//delivered as addressed. Retrying would only re-prove it. Unchanged behaviour.
							email.Status = EmailStatus.Aborted;
							email.ServerError = ex.Message;
							email.ScheduledOn = null;
							SaveEmail(email);
							continue;
						}
						catch (Exception ex)
						{
							//PRESUMED TRANSIENT: the lookup established nothing about the service, so the message is kept and
							//retried on the budget a send failure spends, using the seeded defaults because the service carrying
							//the configured ones is exactly what could not be read. Only the exception TYPE is recorded, never its
							//message: unlike a relay's response text, a datastore fault message can quote query text and connection
							//detail, and server_error is rendered on the administrative queue screens.
							email.ServerError = $"The SMTP service for this message could not be read ({ex.GetType().FullName}). Delivery will be retried.";
							email.RetriesCount++;
							if (email.RetriesCount >= ServiceLookupFailureMaxRetriesCount)
							{
								email.ScheduledOn = null;
								email.Status = EmailStatus.Aborted;
							}
							else
							{
								email.ScheduledOn = DateTime.UtcNow.AddMinutes(ServiceLookupFailureRetryWaitMinutes);
								email.Status = EmailStatus.Pending;
							}
							SaveEmail(email);
							continue;
						}

						if (service == null)
						{
							email.Status = EmailStatus.Aborted;
							email.ServerError = "SMTP service not found.";
							email.ScheduledOn = null;
							SaveEmail(email);
							continue;
						}
						else
						{
							SendEmail(email, service);
						}
					}
				}
				while (pendingEmails.Count > 0);

			}
			finally
			{
				lock (lockObject)
				{
					queueProcessingInProgress = false;
				}
			}
		}
	}
}
