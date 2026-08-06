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

		//QUEUE RESILIENCE - review finding M-OPEN-06, CWE-703 / CWE-755. Retry policy applied when the
		//message's OWN smtp_service could not be read, which is the one failure for which the service's
		//configured max_retries_count and retry_wait_minutes are by definition unavailable. These are the
		//platform's own seeded defaults for those two fields (MailPlugin.20190215: 3 retries, 60 minutes),
		//so a message whose service is momentarily unreadable is treated exactly as the service itself
		//would have treated a momentary send failure, rather than to a policy invented here.
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
					//SCHEMA MAPPING - review finding INT-11. This case label named a field that does not exist.
					//smtp_service carries `default_sender_email` - provisioned in MailPlugin.20190215 as a REQUIRED
					//InputEmailField and mapped to SmtpService.DefaultSenderEmail - and never carried
					//`default_from_email`, so the switch could not match and this validation never ran. An invalid
					//sender address was therefore accepted on save and failed much later inside MailboxAddress
					//construction, which reports a data-entry mistake as a delivery failure against a relay.
					//The one other place the old name survives is the stale GENERATED SQL text of the AllSmtpSevices
					//data source in MailPlugin.20190215, which also names a mis-spelled `connection_secutity` column
					//and is never executed - DataSourceManager runs the EQL text - so it is evidence of the rename
					//rather than of a second field.
					//IsEmail() is null-safe - it constructs a MailAddress inside a try - so a null or blank value
					//reports the same actionable error instead of throwing, which agrees with the field being required.
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

							//INPUT VALIDATION - review finding INT-06. A numeric cast to an enum NEVER throws, so the
							//try/catch this replaces was unreachable and every integer was accepted: an undefined value
							//passed validation here and failed much later inside SmtpClient.Connect. Enum.IsDefined is the
							//test that actually rejects it, and the generic overload avoids boxing and analyzer rule CA2263.
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

							//SECURITY - review finding H-OPEN-03 (High), CWE-319 cleartext transmission of sensitive
							//information, CWE-311 missing encryption of sensitive data, OWASP A02:2021.
							//THREAT ADDRESSED: this hook used to accept every defined mode, and the comment it replaces said
							//so deliberately - narrowing was declined then on preservation grounds. That decision is
							//SUPERSEDED: `None` sends the relay credential and every message in cleartext, and both `Auto`
							//and `StartTlsWhenAvailable` continue in cleartext whenever the relay does not advertise
							//STARTTLS, which an active man-in-the-middle arranges by stripping the advertisement. Accepting
							//them here meant an administrator could reintroduce a cleartext relay at any time through the UI.
							//THE PRESERVATION CONCERN IS STILL HONOURED, in two ways rather than by permitting cleartext.
							//First, the check is POSTURE-GATED on ErpSettings.DevelopmentMode - the same gate the transport
							//policy uses - so a development installation may still select a plaintext local mail catcher.
							//Second, this validates only what is being WRITTEN NOW: an existing row keeps its stored value
							//and keeps sending, because SmtpService.ResolveConnectionSecurity hardens Auto and
							//StartTlsWhenAvailable to a mandatory mode at send time rather than refusing them. Only a row
							//being saved has to name a mode that is already mandatory.
							//NO SECRET IS NAMED: the message names modes and the posture setting, never the relay or its
							//credential.
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
					//SCHEMA MAPPING - review finding INT-11. This case label named a field that does not exist.
					//smtp_service carries `default_sender_email` - provisioned in MailPlugin.20190215 as a REQUIRED
					//InputEmailField and mapped to SmtpService.DefaultSenderEmail - and never carried
					//`default_from_email`, so the switch could not match and this validation never ran. An invalid
					//sender address was therefore accepted on save and failed much later inside MailboxAddress
					//construction, which reports a data-entry mistake as a delivery failure against a relay.
					//The one other place the old name survives is the stale GENERATED SQL text of the AllSmtpSevices
					//data source in MailPlugin.20190215, which also names a mis-spelled `connection_secutity` column
					//and is never executed - DataSourceManager runs the EQL text - so it is evidence of the rename
					//rather than of a second field.
					//IsEmail() is null-safe - it constructs a MailAddress inside a try - so a null or blank value
					//reports the same actionable error instead of throwing, which agrees with the field being required.
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

							//INPUT VALIDATION - review finding INT-06. A numeric cast to an enum NEVER throws, so the
							//try/catch this replaces was unreachable and every integer was accepted: an undefined value
							//passed validation here and failed much later inside SmtpClient.Connect. Enum.IsDefined is the
							//test that actually rejects it, and the generic overload avoids boxing and analyzer rule CA2263.
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

							//SECURITY - review finding H-OPEN-03 (High), CWE-319 cleartext transmission of sensitive
							//information, CWE-311 missing encryption of sensitive data, OWASP A02:2021.
							//THREAT ADDRESSED: this hook used to accept every defined mode, and the comment it replaces said
							//so deliberately - narrowing was declined then on preservation grounds. That decision is
							//SUPERSEDED: `None` sends the relay credential and every message in cleartext, and both `Auto`
							//and `StartTlsWhenAvailable` continue in cleartext whenever the relay does not advertise
							//STARTTLS, which an active man-in-the-middle arranges by stripping the advertisement. Accepting
							//them here meant an administrator could reintroduce a cleartext relay at any time through the UI.
							//THE PRESERVATION CONCERN IS STILL HONOURED, in two ways rather than by permitting cleartext.
							//First, the check is POSTURE-GATED on ErpSettings.DevelopmentMode - the same gate the transport
							//policy uses - so a development installation may still select a plaintext local mail catcher.
							//Second, this validates only what is being WRITTEN NOW: an existing row keeps its stored value
							//and keeps sending, because SmtpService.ResolveConnectionSecurity hardens Auto and
							//StartTlsWhenAvailable to a mandatory mode at send time rather than refusing them. Only a row
							//being saved has to name a mode that is already mandatory.
							//NO SECRET IS NAMED: the message names modes and the posture setting, never the relay or its
							//credential.
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

				//CONTENT MAPPING - review finding INT-10. HtmlAgilityPack returns NULL, not an empty collection,
				//when nothing matches, so every HTML body without an image raised NullReferenceException here. The
				//broad catch below then swallowed it and skipped BOTH the rewritten body and the plain-text
				//alternative, so the common case - an image-free HTML message - went out with no text/plain part at
				//all. Coalescing to an empty sequence makes "no images" the no-op it always should have been.
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
						//MIME MAPPING - review finding INT-12. TryGetValue leaves mimeType NULL for an extension the
						//provider does not map, and MimePart(string) throws ArgumentNullException for null, so one
						//unmapped inline image aborted the whole method. The binary fallback is what MimeKit's own
						//parameterless constructor uses, so the part stays well formed and delivery continues.
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
				//INT-10: inline-image embedding is best-effort - a failure here leaves the original HtmlBody in
				//place, which is still deliverable - but it must not also cost the plain-text alternative below,
				//which is computed from whatever body survived. That is why this handler no longer returns.
			}

			//INT-10: outside the handler above, deliberately. A message with only an HTML body and no
			//text/plain alternative is treated as spam by many relays, so this fallback is the one part of the
			//method that must run even when image embedding failed.
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

				//RESOURCE CLEANUP - review finding INT-09. The queued path is the one that runs unattended and
				//repeatedly, so an undisposed message here retained every attachment's bytes for one pass of up to
				//ten messages at a time until a garbage collection. Disposing the message disposes the attachment
				//and linked-resource streams it owns. The `using` declaration disposes at the end of this try block,
				//which is after Send and before the catch and finally that record the outcome.
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
						//SECURITY - companion to finding F24 (High), CWE-269 improper privilege management, CWE-732
						//incorrect permission assignment. Database/DbFileRepository.Find now REFUSES a staged file that
						//belongs to another non-administrative principal, so this lookup has one more legitimate way to
						//answer null than it had before that control existed. Skipping silently would deliver a queued
						//message as if complete with the refused attachment missing; throwing instead is caught by this
						//method's own handler, which records the reason in the email's server_error column and retries or
						//aborts per the service policy - so a refusal is auditable rather than invisible. Note the
						//deliberate contrast with the inline-image loop earlier in this method, which does continue on a
						//missing file: a missing inline image degrades rendering, a missing attachment loses content.
						if (file == null)
							throw new FileNotFoundException($"Attachment file '{filepath}' not found.");

						var bytes = file.GetBytes();

						var extension = Path.GetExtension(filepath).ToLowerInvariant();
						//MIME MAPPING - review finding INT-12. TryGetValue leaves mimeType NULL for an extension the
						//provider does not map and MimePart(string) throws ArgumentNullException for null, so on THIS path
						//one unmapped attachment did not merely fail to attach: the throw was caught by this method's own
						//handler, which counted a retry and eventually aborted the message. See SmtpService.BinaryContentType
						//for why that value is the right fallback.
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
					// SECURITY H-11 (CWE-295, OWASP A02): validation was unconditionally bypassed here, so this
					// path - the one the BACKGROUND QUEUE JOB drives - encrypted the session without authenticating
					// it. It shares the single SmtpService policy member, hence one configuration key across all five
					// send paths; see that member for the full rationale and the exact gate. Do not inline a literal:
					// the callback must keep yielding the member so the pattern stays visible to CA5359.
					// REVOCATION IS LEFT ENTIRELY TO MAILKIT here too, deliberately and unconfigurably: SmtpClient
					// checks certificate revocation unless told otherwise, so saying nothing IS the secure state. Do
					// not reintroduce a setting that turns it off - one existed briefly and was removed for weakening
					// the production transport posture beyond this finding's agreed remediation. QUEUE-SPECIFIC
					// CONSEQUENCE, worth knowing before diagnosing a stalled queue: on this path a relay whose chain
					// names no reachable CRL or OCSP responder surfaces not as an exception an operator sees but as
					// retries ending in an aborted message, with the chain detail recorded in server_error. The
					// supported remedy is to publish the revocation source; see docs/security/secure-configuration.md.
					if (SmtpService.AllowInvalidRemoteCertificates)
						client.ServerCertificateValidationCallback = (s, c, h, e) => SmtpService.AllowInvalidRemoteCertificates;

					// SECURITY H-OPEN-03 (CWE-319 cleartext transmission, CWE-311 missing encryption, OWASP A02):
					// this is the path the BACKGROUND QUEUE JOB drives, and it handed the stored mode to MailKit
					// unexamined, so a service configured with None, with the shipped Auto default, or with
					// StartTlsWhenAvailable sent every queued message - and authenticated the relay credential two
					// lines below - over an unencrypted session on which the certificate validation restored by H-11
					// never ran. It shares the single SmtpService policy member with the four interactive paths, so
					// one posture decision governs all five; see ResolveConnectionSecurity for the threat and for why
					// Auto and StartTlsWhenAvailable are hardened while None is refused.
					// QUEUE-SPECIFIC CONSEQUENCE, worth knowing before diagnosing a stalled queue: a refusal here
					// surfaces not as an exception an operator sees but as the message text recorded in
					// server_error, because the handler below catches it. RequireApprovedTransport then VERIFIES the
					// resulting session - encrypted, at TLS 1.2 or better - before the credential below is presented
					// on it, so a downgraded session is abandoned while there is still nothing secret on the wire.
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
				//SECURITY - review finding INT-14 (Major), CWE-79 stored cross-site scripting, OWASP A03:2021.
				//TREAT THIS VALUE AS UNTRUSTED EXTERNAL DATA. For a relay failure `ex.Message` is MailKit's report
				//of the SMTP PEER'S OWN RESPONSE TEXT, so it crosses a trust boundary and a peer can be induced to
				//echo attacker-influenced content back into it - a rejected recipient address, for instance. It is
				//stored verbatim ON PURPOSE, because the operator guidance for a stalled queue is to read
				//server_error first and a sanitised message would defeat that diagnosis; the value is instead
				//encoded AT THE SINK, which is where the rendering context is known. The one sink that renders it
				//as markup is the all_emails error-icon node provisioned by MailPlugin.20190215, whose code variable
				//now HTML-encodes it before interpolating it into a title attribute; Patch20260806 carries that
				//correction to already-provisioned installations. ANY NEW READER OF THIS COLUMN must encode for its
				//own context - do not assume it is safe markup.
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
						//QUEUE RESILIENCE - review finding INT-03, and the reason the abort branch below could never
						//run. Api/EmailServiceManager.GetSmtpService THROWS when no smtp_service row carries the id,
						//rather than returning null, so a message whose service row was deleted did not abort - the
						//exception escaped this loop, the enclosing do/while and this method, leaving the row Pending
						//with its scheduled time in the past. Every subsequent pass then re-selected that same row
						//first, threw again, and delivered nothing: one orphaned row STARVED THE WHOLE QUEUE
						//indefinitely, which is a denial of service on mail delivery reachable by an ordinary
						//administrative action.
						//CATCHING PER ROW is what makes the failure local: the row leaves the pending selection either
						//way - aborted with ScheduledOn cleared, or rescheduled into the future - so the loop always
						//makes progress and no single row can hold the queue.
						//
						//SECURITY / RESILIENCE - review finding M-OPEN-06, CWE-703 improper check or handling of
						//exceptional conditions with CWE-755, OWASP A04:2021. THE TWO HANDLERS BELOW ARE THE FIX AND
						//MUST NOT BE MERGED BACK INTO ONE. A single catch (Exception) here treated EVERY lookup failure
						//as proof that the service was gone, so a momentary datastore, connection, timeout or query
						//fault - a condition that clears by itself - permanently aborted every message in the page
						//being processed and cleared its schedule, which put it beyond the reach of any later pass.
						//Mail was destroyed by a transient fault, silently, and an operator's only trace was a
						//server_error string. The distinction is now carried by the exception TYPE thrown at the four
						//lookup sites in Api/EmailServiceManager: SmtpServiceNotFoundException means the absence is
						//PROVEN, so aborting is right; anything else is presumed transient and the message keeps its
						//retry budget.
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
							//PRESUMED TRANSIENT: the lookup did not get far enough to establish anything about the
							//service. The message is kept and retried on the same budget a send failure spends,
							//using the platform's seeded defaults because the service that carries the configured
							//ones is exactly what could not be read. Only the exception TYPE is recorded, never its
							//message: unlike a relay's response text - which finding INT-14 keeps verbatim on purpose
							//- a datastore fault message can quote query text and connection detail, and server_error
							//is rendered on the administrative queue screens.
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
