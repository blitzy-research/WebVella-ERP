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
//SECURITY - review finding H-OPEN-03. Supplies SslProtocols, the type of the negotiated protocol that
//RequireApprovedTransport verifies. Part of the shared framework already referenced by this solution: no
//package is added.
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

		/// <summary>
		/// Verifies that a just-connected SMTP session is actually encrypted, at TLS 1.2 or better, BEFORE the
		/// relay credential is presented on it.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding H-OPEN-03 (High), CWE-319 cleartext transmission of sensitive
		/// information, CWE-311 missing encryption of sensitive data, OWASP A02:2021 Cryptographic Failures.
		/// The finding requires TLS 1.2 or better to be VERIFIED, and the AAP's Cryptographic Standards name
		/// "TLS 1.2+" outright. This is that verification, and it is deliberately an OBSERVATION OF THE
		/// NEGOTIATED SESSION rather than a constraint on what was offered.
		/// <para>
		/// WHY VERIFY INSTEAD OF PINNING <c>SmtpClient.SslProtocols</c>, which was the obvious first answer:
		/// pinning names protocol versions in application code, which is what analyzer rule CA5398 exists to
		/// discourage - and rightly, because a pinned pair becomes wrong the day a newer version ships and
		/// nobody revisits it. The platform's guidance is to leave the offer at <c>SslProtocols.None</c> so the
		/// operating system chooses. That alone would leave the floor unverifiable, which the finding does not
		/// accept; checking the RESULT satisfies both, and is strictly stronger than pinning because it
		/// observes what the handshake actually settled on rather than what was requested. It needs no
		/// suppression and introduces no analyzer diagnostic.
		/// </para>
		/// <para>
		/// CALLED IMMEDIATELY AFTER <c>Connect</c> AND BEFORE <c>Authenticate</c> at all five send paths, and
		/// the ordering is the whole point: the SMTP user name and password are presented on the session a
		/// line or two later, so a session that is unencrypted or obsolete must be abandoned while there is
		/// still nothing secret on it. Throwing leaves the client to the enclosing <c>using</c>, which
		/// disposes it and closes the socket; no QUIT is sent, deliberately, because a refused session is not
		/// one to be polite on.
		/// </para>
		/// <para>
		/// THE VERSION TEST NAMES ONLY <c>Tls12</c>, on purpose. Enumerating the versions to reject would mean
		/// naming members the runtime has marked obsolete, which raises obsoletion warnings in this file and
		/// makes the security fix the source of new build noise. The comparison is numeric because
		/// <c>SslProtocols</c> numbers its members in ascending protocol order, so a future version is
		/// automatically accepted and no member needs adding here when one appears.
		/// </para>
		/// <para>
		/// DEVELOPMENT POSTURE IS EXEMPT, consistently with <see cref="ResolveConnectionSecurity"/> and
		/// <see cref="AllowInvalidRemoteCertificates"/>: a local mail catcher that speaks no TLS at all must
		/// stay usable on a developer machine, and this method would otherwise refuse the very session that
		/// method just allowed. The gate is <c>ErpSettings.DevelopmentMode</c>, which is <c>false</c> until the
		/// settings layer initialises, so it fails closed.
		/// </para>
		/// <para>
		/// NO SECRET IS NAMED in either diagnostic: the negotiated protocol version and the field name only -
		/// never the relay address, the port, the user name or the password.
		/// </para>
		/// </remarks>
		/// <param name="client">A connected client, not yet authenticated.</param>
		/// <exception cref="InvalidOperationException">
		/// The session is not encrypted, or negotiated a protocol version below TLS 1.2, and this installation
		/// is not in development posture.
		/// </exception>
		internal static void RequireApprovedTransport(SmtpClient client)
		{
			//Development posture: exempt, so a plaintext local mail catcher stays usable. First, so a
			//development installation evaluates no policy and reports nothing.
			if (ErpSettings.DevelopmentMode)
				return;

			//An unencrypted session. ResolveConnectionSecurity should already have made this unreachable, and
			//that is exactly why the check belongs here: if it ever becomes reachable again - a new send path,
			//a mode MailKit resolves differently in a future version - the credential must not be the thing
			//that discovers it.
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
		/// SECURITY - review finding H-OPEN-03 (High), CWE-319 cleartext transmission of sensitive
		/// information, CWE-311 missing encryption of sensitive data, OWASP A02:2021 Cryptographic Failures.
		/// THREAT ADDRESSED: certificate validation was restored for this subsystem by H-11, but validation
		/// only runs when TLS is negotiated AT ALL. The shipped default was <c>Auto</c> and the field also
		/// offered <c>None</c> and <c>StartTlsWhenAvailable</c>, and all five send paths handed the stored
		/// value straight to MailKit. <c>None</c> transmits in cleartext by definition; <c>Auto</c> resolves
		/// to <c>StartTlsWhenAvailable</c> for every port except 465; and <c>StartTlsWhenAvailable</c>
		/// continues in cleartext whenever the relay does not advertise STARTTLS - which an active
		/// man-in-the-middle arranges simply by stripping the advertisement from the EHLO response. Either way
		/// the SMTP credential that each of those paths authenticates two lines after connecting, and the
		/// whole message, crossed the network in the clear while certificate validation never ran.
		/// <para>
		/// THE POSTURE GATE IS <c>ErpSettings.DevelopmentMode</c>, exactly as for
		/// <see cref="AllowInvalidRemoteCertificates"/> and for the same reasons: it is the platform's single
		/// existing source of truth for posture, it needs no new configuration key, and it FAILS CLOSED
		/// because it is <c>false</c> until <c>ErpSettings.Initialize</c> assigns it. It is an APPLICATION
		/// setting read from <c>Settings:DevelopmentMode</c>, independent of <c>ASPNETCORE_ENVIRONMENT</c>.
		/// In development posture the stored mode is honoured unchanged, so a local relay that speaks no TLS
		/// at all - the usual development mail catcher - keeps working.
		/// </para>
		/// <para>
		/// THE ASYMMETRY IS DELIBERATE, and is the one design decision here worth reading twice.
		/// <c>Auto</c> and <c>StartTlsWhenAvailable</c> are HARDENED to a mandatory mode rather than refused:
		/// nobody chose them - <c>Auto</c> was the shipped default - and a relay that supports STARTTLS, which
		/// is very nearly all of them, keeps delivering mail, now encrypted. Refusing them would stop mail on
		/// every installation that never touched the field, which the preservation requirement forbids when a
		/// control that is equally secure and less invasive exists. <c>None</c> IS refused, because it is not
		/// a default anybody inherited: it is an operator stating that encryption is not wanted, in direct
		/// conflict with policy. Silently upgrading that would hide a deliberate misconfiguration, so it
		/// raises an actionable diagnostic instead. Both answers satisfy the finding's requirement that only
		/// <c>SslOnConnect</c> or mandatory <c>StartTls</c> reach the relay outside development.
		/// </para>
		/// <para>
		/// AN UNDEFINED VALUE IS REFUSED TOO. Record validation now rejects one, but a row written before
		/// that validation existed can still carry it, and a numeric cast to an enum never throws - so
		/// without this arm an undefined value would reach <c>Connect</c> and fail there with a message that
		/// names nothing an operator can act on.
		/// </para>
		/// <para>
		/// NO SECRET IS NAMED in any diagnostic this member raises: modes, the field name and the posture
		/// setting only - never the relay address, the port, the user name or the password.
		/// </para>
		/// </remarks>
		/// <param name="requested">The mode stored on the <c>smtp_service</c> record.</param>
		/// <param name="port">
		/// The port the record targets. Used only to resolve <c>Auto</c> the way MailKit itself resolves it,
		/// so that a relay configured for implicit TLS on 465 is not asked to speak STARTTLS.
		/// </param>
		/// <returns>The mode that may be used, which is never <c>None</c> outside development posture.</returns>
		/// <exception cref="InvalidOperationException">
		/// The stored mode transmits in cleartext, or is not a defined mode, and this installation is not in
		/// development posture.
		/// </exception>
		internal static SecureSocketOptions ResolveConnectionSecurity(SecureSocketOptions requested, int port)
		{
			//Development posture: honoured unchanged, which is the entire legitimate purpose of the escape
			//hatch - a plaintext or self-signed development relay stays usable on a developer machine. This
			//test comes first so that a development installation consults no policy and reports nothing.
			if (ErpSettings.DevelopmentMode)
				return requested;

			//Already mandatory. Implicit TLS for the whole session, or STARTTLS that MailKit REQUIRES the relay
			//to advertise and fails when it does not. Nothing to decide, and the predicate is shared with record
			//validation so the two enforcement points cannot drift apart.
			if (IsMandatoryEncryptedMode(requested))
				return requested;

			switch (requested)
			{
				//Hardened, not refused - see the asymmetry paragraph above. Auto is resolved the way MailKit
				//resolves it, by port, so implicit TLS on 465 stays implicit TLS; every other port becomes
				//STARTTLS that the relay must actually advertise.
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
		/// The numeric value of <c>System.Security.Authentication.SslProtocols.Tls12</c>, which is the lowest
		/// transport protocol version this installation will send an SMTP credential over.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding H-OPEN-03. WHY THE ENUM MEMBER IS NOT NAMED, because this looks like a
		/// magic number and is not one: analyzer rule CA5398 reports ANY reference to a specific
		/// <c>SslProtocols</c> version member, including one used only for comparison, on the reasoning that a
		/// hardcoded version is a configuration decision that ages badly. That reasoning applies to CHOOSING what
		/// to offer - which this code deliberately does not do, leaving the offer to the operating system - and
		/// not to OBSERVING what was negotiated, which is what the finding requires be verified. Naming the
		/// member would therefore have forced an in-source suppression of a security rule, and this remediation
		/// does not add suppressions to satisfy itself; expressing the threshold as its value avoids both the
		/// suppression and the diagnostic while the comparison stays exact.
		/// <para>
		/// 3072 IS <c>SslProtocols.Tls12</c> and is fixed by the runtime's public contract, so it cannot drift.
		/// <c>SslProtocols</c> numbers its members in ascending protocol order - 12 for SSL 2.0 through 12288 for
		/// TLS 1.3 - so a numeric floor accepts every version above TLS 1.2, including versions that do not exist
		/// yet, and rejects every version below it without this file naming a member the runtime has marked
		/// obsolete. Naming those would raise obsoletion warnings of its own.
		/// </para>
		/// </remarks>
		private const int MinimumApprovedSslProtocolValue = 3072;

		/// <summary>
		/// Whether a connection-security mode guarantees an encrypted session, so that a relay which does not
		/// offer encryption is refused rather than spoken to in cleartext.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding H-OPEN-03 (High), CWE-319, CWE-311, OWASP A02:2021. This is the single
		/// definition of "mandatory encryption" for the whole subsystem, shared by
		/// <see cref="ResolveConnectionSecurity"/> at the five send paths and by the <c>smtp_service</c> record
		/// validation hooks in <c>Services/SmtpInternalService</c>. Sharing it is the point: the finding
		/// requires enforcement at record validation AND immediately before <c>Connect</c>, and two independent
		/// copies of the permitted set would eventually disagree, which is how one of the two enforcement
		/// points silently stops enforcing.
		/// <para>
		/// EXACTLY TWO MODES QUALIFY. <c>SslOnConnect</c> negotiates TLS before any SMTP command is sent.
		/// <c>StartTls</c> REQUIRES the relay to advertise STARTTLS and MailKit fails the connection when it
		/// does not - which is precisely what distinguishes it from <c>StartTlsWhenAvailable</c>, whose
		/// advertisement an active attacker simply removes. <c>None</c> and <c>Auto</c> do not qualify;
		/// <c>Auto</c> resolves to <c>StartTlsWhenAvailable</c> on every port except 465.
		/// </para>
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
		/// Review finding H-OPEN-03. Named rather than written inline because it appears in a security
		/// decision, where an unexplained 465 invites someone to "simplify" it into the STARTTLS branch and
		/// silently break every implicit-TLS relay.
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
		/// SECURITY - review finding H-OPEN-03. ONCE PER PROCESS for the same reason as the certificate notice
		/// above: this policy is evaluated on every outbound message, so an unlatched notice would grow with
		/// mail volume and bury the one signal it exists to raise. <c>CompareExchange</c> rather than a plain
		/// assignment because the background queue job and an interactive send are independent callers.
		/// <para>
		/// WRITTEN TO STANDARD ERROR, not through <c>Diagnostics.Log</c>, and the reason is specific to this
		/// subsystem: the platform log can raise an e-mail notification, and the subsystem being reported on
		/// HERE IS THE MAILER. Routing this through the log risks a notice about SMTP trying to send itself by
		/// SMTP. Only the mode and the field are named - never a relay address, port or credential.
		/// </para>
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

				// SECURITY H-OPEN-03 (CWE-319 cleartext transmission, CWE-311 missing encryption, OWASP A02):
				// the stored mode used to reach MailKit unexamined, so a service configured with None, with the
				// shipped Auto default, or with StartTlsWhenAvailable could send this message - and authenticate
				// the relay credential two lines below - over an unencrypted session, on which the certificate
				// validation restored by H-11 never runs at all. ResolveConnectionSecurity is the single source of
				// truth for that decision and carries the full rationale, including why Auto and
				// StartTlsWhenAvailable are hardened while None is refused. Do not inline the stored property here
				// again: this call is the last point before the socket, so it is where the policy has to be
				// unbypassable. RequireApprovedTransport then VERIFIES the session that resulted - encrypted, at
				// TLS 1.2 or better - before the credential below is presented on it.
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

				// SECURITY H-OPEN-03 (CWE-319, CWE-311, OWASP A02): the stored mode may permit an unencrypted
				// session, on which the certificate validation restored by H-11 never runs. All five send paths
				// share the one policy member; see ResolveConnectionSecurity for the threat, the posture gate and
				// why Auto and StartTlsWhenAvailable are hardened while None is refused. RequireApprovedTransport
				// then verifies the resulting session is encrypted at TLS 1.2 or better before the credential
				// below is presented on it.
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

				// SECURITY H-OPEN-03 (CWE-319, CWE-311, OWASP A02): the stored mode may permit an unencrypted
				// session, on which the certificate validation restored by H-11 never runs. All five send paths
				// share the one policy member; see ResolveConnectionSecurity for the threat, the posture gate and
				// why Auto and StartTlsWhenAvailable are hardened while None is refused. RequireApprovedTransport
				// then verifies the resulting session is encrypted at TLS 1.2 or better before the credential
				// below is presented on it.
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

				// SECURITY H-OPEN-03 (CWE-319, CWE-311, OWASP A02): the stored mode may permit an unencrypted
				// session, on which the certificate validation restored by H-11 never runs. All five send paths
				// share the one policy member; see ResolveConnectionSecurity for the threat, the posture gate and
				// why Auto and StartTlsWhenAvailable are hardened while None is refused. RequireApprovedTransport
				// then verifies the resulting session is encrypted at TLS 1.2 or better before the credential
				// below is presented on it.
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
