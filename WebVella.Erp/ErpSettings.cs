using Microsoft.Extensions.Configuration;
using System;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text;

namespace WebVella.Erp
{
	public static class ErpSettings
	{
		public static string EncryptionKey { get; private set; }
		public static string ConnectionString { get; private set; }
		public static string Lang { get; private set; }
		public static string Locale { get; private set; }
		public static string CacheKey { get; private set; }
		public static bool EnableBackgroundJobs { get; private set; }
		public static bool EnableFileSystemStorage { get; private set; }
		public static string FileSystemStorageFolder { get; set; }
		public static bool EnableCloudBlobStorage { get; set; }
		/// <summary>
		/// See https://github.com/aloneguid/storage/blob/develop/doc/blobs.md for details
		/// </summary>
		public static string CloudBlobStorageConnectionString { get; set; }
		public static string DevelopmentTestEntityName { get; set; }
		public static Guid DevelopmentTestRecordId { get; set; }
		public static string DevelopmentTestRecordViewName { get; set; }
		public static string DevelopmentTestRecordListName { get; set; }
		public static string TimeZoneName { get; set; }
		public static string JsonDateTimeFormat { get; set; }

		public static bool EmailEnabled { get; private set; }
		public static string EmailSMTPServerName { get; private set; }
		public static int EmailSMTPPort { get; private set; }
		public static string EmailSMTPUsername { get; private set; }
		public static string EmailSMTPPassword { get; private set; }
		public static string EmailFrom { get; private set; }
		public static string EmailTo { get; private set; }

		public static string NavLogoUrl { get; private set; }
		public static string SystemMasterBackgroundImageUrl { get; private set; }
		public static string AppName { get; private set; }

		public static bool ShowAccounting { get; set; }
		public static bool DevelopmentMode { get; private set; }
		public static int DefaultSRID { get; private set; } = 4326;

		public static IConfiguration Configuration { get; private set; }

		public static bool IsInitialized { get; private set; }

		public static string JwtKey { get; private set; }
		public static string JwtIssuer { get; private set; }
		public static string JwtAudience { get; private set; }

		/// <summary>
		/// Whether this process exposes the bearer-token issue and refresh endpoints at all.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding H-04 (High), CWE-798, CWE-321, OWASP A02 Cryptographic Failures.
		/// THREAT: token-issuing capability used to be inferred from the mere presence of a
		/// 'Settings:Jwt' configuration section. That inference is wrong in the dangerous direction. The
		/// token issue and refresh endpoints live in WebVella.Erp.Web and are therefore exposed by every
		/// host that uses the web framework, yet only two of the seven shipped host configurations
		/// declare a Jwt section at all - so section presence exempts five hosts that do expose those
		/// endpoints, and it equally mislabels a process that exposes none of them.
		/// Capability is therefore STATED rather than guessed: either the caller passes it to
		/// <see cref="Initialize(IConfiguration, bool)"/>, or the single-argument overload determines it
		/// from what the deployed application is built from - never from configuration content.
		/// Whether a USABLE signing key was supplied is a separate question, answered once by
		/// <see cref="IsJwtConfigured"/>. The two are combined rather than conflated: an unusable key
		/// disables the token routes instead of aborting startup, which is what keeps the five hosts that
		/// legitimately ship no Jwt section startable - "all existing functionality remains operational" -
		/// while still refusing to issue a forgeable token.
		/// </remarks>
		public static bool JwtEndpointsExposed { get; private set; }

		/// <summary>
		/// True only when a token signing key was supplied AND that key passes
		/// <see cref="IsAcceptableJwtKey"/>. This is the single switch every bearer-token code path
		/// consults, so "is JWT usable here?" has exactly one answer across the platform.
		/// </summary>
		/// <remarks>
		/// SECURITY H-04 (CWE-798 hard-coded credentials, CWE-20 improper input validation): demanding a
		/// signing key only when a 'Settings:Jwt' section already exists, and accepting whatever is there
		/// provided it is not blank, is not sufficient. The token issue and refresh
		/// routes live in WebVella.Erp.Web and are [AllowAnonymous], so they are exposed on ALL seven
		/// hosts - including the five that legitimately ship no Jwt section at all. That combination
		/// meant an anonymous caller could reach a route which then evaluated
		/// Encoding.UTF8.GetBytes(null) and produced a 500 carrying a stack trace, and that a host
		/// configured with the repository's published example key issued forgeable tokens while
		/// passing validation unchallenged.
		/// Rather than demand a key from every host - which would stop five of them starting and
		/// breach "all existing functionality remains operational" - the routes are disabled when the
		/// key is unusable. That is the second branch the finding's own resolution offers: "require
		/// JWT wherever token routes are exposed OR disable those routes".
		/// </remarks>
		public static bool IsJwtConfigured { get; private set; }

		// SECURITY H-04: a signing key for HMAC-SHA-256 must be at least as long as the hash it feeds. RFC 7518
		// section 3.2 requires a key of at least the same size as the hash output for HS256, i.e. 256
		// bits / 32 bytes. Below that the key, not the algorithm, is the weakest link.
		private const int MinimumJwtKeyByteLength = 32;

		// The encryption key protects data at rest, so it is held to the same 256-bit floor.
		private const int MinimumEncryptionKeyCharLength = 32;

		// A cheap entropy floor that costs nothing and catches the padded-placeholder shape - a key
		// that reaches the length requirement by repeating a handful of characters. Deliberately
		// modest: this rejects obviously degenerate material without pretending to measure real
		// entropy, which a static check cannot do.
		private const int MinimumDistinctCharacters = 8;

		// SECURITY C-04 and H-04: the two secrets published in this repository's own
		// example configuration are denied by SHA-256 digest rather than by literal.
		// Storing the digest, not the value, is deliberate and matters twice over: a denylist written
		// as literals would republish the very secrets being retired, and it would make this file a
		// fresh hit for the repository's own hardcoded-secret scan - a validation routine must not
		// become the thing it exists to detect (CWE-798, CWE-540).
		private const string PublishedDefaultJwtKeyDigest = "87184b56659256b8e2d8d29aa5da9fd3b34ec5d5cd41cabe4493eb482b839549";
		private const string PublishedDefaultEncryptionKeyDigest = "7810b2fe1ad52ed53d4fd313052c78a59b15133f1e6e802805fb6e9c32935286";

		//API URLs
		public static string ApiUrlTemplateFieldInlineEdit { get; private set; }

		/// <summary>
		/// Initializes the settings, determining JWT capability from the process itself.
		/// </summary>
		/// <remarks>
		/// This overload's signature is unchanged on purpose: it is the entry point every existing host
		/// and the console application already call, and none of them has to be modified. Callers that
		/// know their own capability should prefer
		/// <see cref="Initialize(IConfiguration, bool)"/> and state it outright.
		/// </remarks>
		public static void Initialize(IConfiguration configuration)
		{
			Initialize(configuration, IsWebFrameworkPresent());
		}

		/// <summary>
		/// Initializes the settings with JWT capability stated explicitly by the caller.
		/// </summary>
		/// <param name="configuration">The configuration root assembled by the host.</param>
		/// <param name="jwtEndpointsExposed">
		/// True when this process serves the bearer-token issue and refresh endpoints, so that
		/// 'Settings:Jwt:Key' is needed for those endpoints to FUNCTION. It is deliberately not needed
		/// for the process to START: an unusable key disables the two routes and is reported on standard
		/// error, and this flag only decides whether that report is worth making - a process that hosts
		/// no token routes is never told that routes it never had are disabled. False for such a
		/// process, the console application being the one the platform ships.
		/// </param>
		public static void Initialize(IConfiguration configuration, bool jwtEndpointsExposed)
		{
			// Recorded before validation runs, because ValidateRequiredSecurityConfiguration consults it.
			JwtEndpointsExposed = jwtEndpointsExposed;

			Configuration = configuration;
			EncryptionKey = configuration["Settings:EncryptionKey"];
			// 628426@gmail.com 27 Jul 2020 backwards compatibility for projects which still have mispelled EncryiptionKey in config
			if (string.IsNullOrWhiteSpace(EncryptionKey))
			{
				EncryptionKey = configuration["Settings:EncriptionKey"];
			}
			ConnectionString = configuration["Settings:ConnectionString"];
			Lang = string.IsNullOrWhiteSpace(configuration["Settings:Lang"]) ? @"en" : configuration["Settings:Lang"];
			// 125	FLE Standard Time	(GMT+02:00) Helsinki, Kiev, Riga, Sofia, Tallinn, Vilnius
			// The hosting server's own time zone is deliberately NOT used as the default. An unset value must
			// resolve to one fixed, documented zone, or the same stored timestamp is interpreted differently on
			// each host. Set 'Settings:TimeZoneName' to override.
			TimeZoneName = string.IsNullOrWhiteSpace(configuration["Settings:TimeZoneName"]) ? @"FLE Standard Time" : configuration["Settings:TimeZoneName"];
			JsonDateTimeFormat = string.IsNullOrWhiteSpace(configuration["Settings:JsonDateTimeFormat"]) ? "yyyy-MM-ddTHH:mm:ss.fff" : configuration["Settings:JsonDateTimeFormat"];

			Locale = string.IsNullOrWhiteSpace(configuration["Settings:Locale"]) ? "en-US" : configuration["Settings:Locale"];
			CacheKey = string.IsNullOrWhiteSpace(configuration["Settings:CacheKey"]) ? $"{DateTime.Now.ToString("yyyyMMdd")}" : configuration["Settings:CacheKey"];

			EnableFileSystemStorage = string.IsNullOrWhiteSpace(configuration["Settings:EnableFileSystemStorage"]) ? false : bool.Parse(configuration["Settings:EnableFileSystemStorage"]);
			FileSystemStorageFolder = string.IsNullOrWhiteSpace(configuration["Settings:FileSystemStorageFolder"]) ? @"c:\erp-files" : configuration["Settings:FileSystemStorageFolder"];

			EnableCloudBlobStorage = string.IsNullOrWhiteSpace(configuration["Settings:EnableCloudBlobStorage"]) ? false : bool.Parse(configuration["Settings:EnableCloudBlobStorage"]);
			CloudBlobStorageConnectionString = string.IsNullOrWhiteSpace(configuration["Settings:CloudBlobStorageConnectionString"]) ? "disk://path=c:\\erp-files" : configuration["Settings:CloudBlobStorageConnectionString"];

			EnableBackgroundJobs = string.IsNullOrWhiteSpace(configuration["Settings:EnableBackgroundJobs"]) ? true : bool.Parse(configuration["Settings:EnableBackgroundJobs"]);
			// 628426@gmail.com 15 Nov 2020 backwards compatibility for projects which still have mispelled EnableBackgroungJobs in config
			if (string.IsNullOrWhiteSpace(configuration["Settings:EnableBackgroundJobs"]))
			{
				EnableBackgroundJobs = string.IsNullOrWhiteSpace(configuration["Settings:EnableBackgroungJobs"]) ? true : bool.Parse(configuration["Settings:EnableBackgroungJobs"]);
			}

			DevelopmentTestEntityName = string.IsNullOrWhiteSpace(configuration["Development:TestEntityName"]) ? @"test" : configuration["Development:TestEntityName"];
			DevelopmentTestRecordId = new Guid("001ea36f-fd2e-4d1b-b8ee-25d32d4e396c");
			DevelopmentTestRecordViewName = "test";
			DevelopmentTestRecordListName = "test";
			var outGuid = Guid.Empty;
			if (!string.IsNullOrWhiteSpace(configuration["Development:TestRecordId"]) && Guid.TryParse(configuration["Development:TestRecordId"], out outGuid))
			{
				DevelopmentTestRecordId = outGuid;
			}

			EmailEnabled = string.IsNullOrWhiteSpace(configuration[$"Settings:EmailEnabled"]) ? false : bool.Parse(configuration[$"Settings:EmailEnabled"]);
			EmailSMTPServerName = configuration[$"Settings:EmailSMTPServerName"];
			EmailSMTPPort = string.IsNullOrWhiteSpace(configuration[$"Settings:EmailSMTPPort"]) ? 25 : int.Parse(configuration[$"Settings:EmailSMTPPort"]);
			EmailSMTPUsername = configuration[$"Settings:EmailSMTPUsername"];
			EmailSMTPPassword = configuration[$"Settings:EmailSMTPPassword"];
			EmailFrom = configuration[$"Settings:EmailFrom"];
			EmailTo = configuration[$"Settings:EmailTo"];

			NavLogoUrl = configuration[$"Settings:NavLogoUrl"];
			SystemMasterBackgroundImageUrl = configuration[$"Settings:SystemMasterBackgroundImageUrl"];
			AppName = configuration[$"Settings:AppName"];

			DevelopmentMode = string.IsNullOrWhiteSpace(configuration[$"Settings:DevelopmentMode"]) ? false : bool.Parse(configuration[$"Settings:DevelopmentMode"]);

			ShowAccounting = string.IsNullOrWhiteSpace(configuration[$"Settings:ShowAccounting"]) ? false : bool.Parse(configuration[$"Settings:ShowAccounting"]);


			ApiUrlTemplateFieldInlineEdit = string.IsNullOrWhiteSpace(configuration[$"ApiUrlTemplates:FieldInlineEdit"]) ? "/api/v3/en_US/record/{entityName}/{recordId}" : configuration[$"ApiUrlTemplates:FieldInlineEdit"];

			// SECURITY - findings C-04 (Critical) and H-04 (High), CWE-798 use of hard-coded credentials,
			// CWE-321 use of a hard-coded cryptographic key, OWASP A02 Cryptographic Failures.
			// THREAT: a compiled-in placeholder signing key ships in the public source tree, so any deployment that
			// does not supply its own key issues bearer tokens an attacker can forge at will - a complete
			// authentication bypass. INVARIANT: this assignment takes the configured value and nothing else; a
			// missing signing key must never acquire a silent default.
			// WHAT ABSENCE COSTS, precisely - an earlier revision of this comment said
			// "ValidateRequiredSecurityConfiguration below turns that absence into an actionable startup
			// failure", and that was WRONG in a way an operator would feel. It does not: JwtKey is never
			// added to the missingSecrets accumulator, so no host is stopped for want of a signing key.
			// Startup PROCEEDS and the capability is withdrawn instead - IsJwtConfigured below goes false,
			// the token issue and refresh routes disable themselves and refuse every request, every
			// presented bearer token fails validation, and cookie login is unaffected. The only thing the
			// presence of a 'Settings:Jwt' section changes is whether that is REPORTED on standard error
			// (see the condition further down). The two settings whose absence really does abort startup
			// are Settings:ConnectionString and Settings:EncryptionKey, and they are the only names that
			// can appear in the abort message. Documented as the two categories in
			// docs/security/secure-configuration.md.
			JwtKey = configuration["Settings:Jwt:Key"];
			JwtIssuer = string.IsNullOrWhiteSpace(configuration["Settings:Jwt:Issuer"]) ? "webvella-erp" : configuration["Settings:Jwt:Issuer"];
			JwtAudience = string.IsNullOrWhiteSpace(configuration["Settings:Jwt:Audience"]) ? "webvella-erp" : configuration["Settings:Jwt:Audience"];

			// SECURITY H-04 (CWE-20, CWE-798): resolved once, here, so that every bearer-token code path asks the
			// same question and gets the same answer. A key that is absent, too short, too repetitive or
			// equal to this repository's published example is not usable, and the token routes disable
			// themselves rather than issue forgeable tokens or fault on a null key.
			IsJwtConfigured = IsAcceptableJwtKey(JwtKey);

			// SECURITY - findings C-04 (Critical), H-04 (High) and H-05 (High), CWE-798, CWE-321, OWASP A02 and A05.
			// THREAT: a settings layer that quietly defaults a secret relocates the defect instead of removing it -
			// the platform starts with a known-bad key and nobody notices. INVARIANT: no required secret may acquire
			// a default here, and its absence must abort startup. This is also the ordering precondition for
			// scrubbing the eight shipped Config.json files, which still carry live connection, encryption and token
			// values: that scrub is only safe once absence fails loudly AND an alternative supply channel has been
			// registered (docs/security/secure-configuration.md). Initialize is the single funnel every host and the
			// console application passes through, and this runs before IsInitialized is set, so a failed validation
			// leaves the settings explicitly un-initialized rather than half-applied.
			ValidateRequiredSecurityConfiguration(configuration);

			IsInitialized = true;
		}

		/// <summary>
		/// Assembly simple name of the web framework. The bearer-token issue and refresh endpoints, and the
		/// token validator that consumes <see cref="JwtKey"/>, both live in it.
		/// </summary>
		private const string WebFrameworkAssemblyName = "WebVella.Erp.Web";

		/// <summary>
		/// Determines whether this process exposes the bearer-token endpoints, for the single-argument
		/// <see cref="Initialize(IConfiguration)"/> overload.
		/// </summary>
		/// <returns>
		/// True when the web framework is part of this application, which is exactly the condition under
		/// which the token endpoints are routable and <see cref="JwtKey"/> is consumed.
		/// </returns>
		/// <remarks>
		/// SECURITY (H-04, CWE-798) - this replaces an inference drawn from configuration CONTENT with one
		/// drawn from what the application actually consists of, which is the thing that determines whether
		/// the endpoints exist. Two independent tests are applied and either is sufficient, which is what
		/// makes the answer reliable in both directions rather than merely likely:
		/// <list type="bullet">
		/// <item><description>
		/// the assembly is already loaded. Every web host reaches
		/// <see cref="Initialize(IConfiguration)"/> through the web framework's own service-registration
		/// extension, so executing that code requires the assembly to be loaded; and
		/// </description></item>
		/// <item><description>
		/// the assembly file sits next to the entry assembly. This second test exists so the answer does not
		/// depend on WHEN initialization happens relative to the first use of a web-framework type - the
		/// runtime loads assemblies lazily, so a caller that initialized settings before touching any
		/// web-framework type would otherwise be misread as a non-web process and silently exempted from the
		/// key requirement, reintroducing the very defect this finding is about.
		/// </description></item>
		/// </list>
		/// The console application is exempt by construction under both tests rather than by luck: it does
		/// not reference the web framework, so the assembly is neither loaded nor present in its output.
		/// Neither test attempts an assembly load - provoking one would be a side effect, and a failure to
		/// find the file would then have to be interpreted, which is exactly the guesswork this replaces.
		/// </remarks>
		private static bool IsWebFrameworkPresent()
		{
			foreach (var loadedAssembly in AppDomain.CurrentDomain.GetAssemblies())
			{
				if (string.Equals(loadedAssembly.GetName().Name, WebFrameworkAssemblyName, StringComparison.Ordinal))
				{
					return true;
				}
			}

			// Probe the application's own directory only. No search path is walked and no load is attempted,
			// so this cannot be influenced by anything outside the deployed application.
			try
			{
				var assemblyPath = System.IO.Path.Combine(AppContext.BaseDirectory, WebFrameworkAssemblyName + ".dll");
				return System.IO.File.Exists(assemblyPath);
			}
			catch (ArgumentException)
			{
				// A malformed base directory cannot be interpreted, so fall back to the loaded-assembly answer
				// above rather than guessing. Deliberately not a silent 'false' for any broader failure: an
				// unexpected error here must surface rather than quietly exempt a host from the key requirement.
				return false;
			}
		}

		/// <summary>
		/// Fails fast when a security setting the platform cannot safely default was not supplied by any
		/// configuration provider. Both callers of Initialize now build a chain of Config.json, then
		/// environment variables, then user secrets in development, so "any provider" means every supply
		/// channel the operator guide documents and the failure message names. Config.json stays first and
		/// non-optional precisely so that an environment variable overrides the blanked shipped value
		/// rather than being shadowed by it.
		/// Part of the OWASP Top 10 remediation for findings C-04, H-04 and H-05 (CWE-798, CWE-321): the
		/// compiled-in default secrets behind those three findings were removed, so a missing value has to
		/// surface as an actionable startup error instead of silently degrading into a known-bad key.
		/// Only configuration key NAMES are reported - never values, prefixes, lengths or digests - so that a
		/// startup failure cannot leak key material into a console, log file or crash report (CWE-532).
		/// </summary>
		private static void ValidateRequiredSecurityConfiguration(IConfiguration configuration)
		{
			// Every missing value is collected before throwing, so a mis-provisioned deployment learns about all of
			// them from a single startup failure instead of one restart per variable.
			var missingSecrets = string.Empty;

			// The connection string is unconditionally required: DbContext, ERPService and every repository consume
			// it immediately after initialization, so no host can function without it (finding H-05, CWE-798).
			if (string.IsNullOrWhiteSpace(ConnectionString))
			{
				missingSecrets += $"{Environment.NewLine}  - 'Settings:ConnectionString'";
			}

			// The encryption key is unconditionally required: CryptoUtility.CryptKey has no compiled-in fallback, so
			// an absent key is caught here at startup rather than at the first encrypt or decrypt of stored data
			// (finding C-04, CWE-798, CWE-321). The legacy misspelled 'EncriptionKey' spelling still satisfies this
			// check, because Initialize resolves that backwards-compatibility path into EncryptionKey first.
			if (string.IsNullOrWhiteSpace(EncryptionKey))
			{
				missingSecrets += $"{Environment.NewLine}  - 'Settings:EncryptionKey'";
			}
			else if (!IsAcceptableSecretShape(EncryptionKey, MinimumEncryptionKeyCharLength) ||
				MatchesKnownPublishedDefault(EncryptionKey, PublishedDefaultEncryptionKeyDigest))
			{
				// THREAT (findings C-04 Critical and H-05 High, CWE-798 use of hard-coded credentials, CWE-321
				// use of a hard-coded cryptographic key, OWASP A02 Cryptographic Failures): a non-blank test
				// alone accepts the example key published in this repository - which is 64 characters long, so no
				// length rule would catch it either - and a publicly known data-at-rest key compromises every
				// encrypted value. It is exactly as public in a development checkout as in production, this
				// repository being open source, so enforcement is UNCONDITIONAL: there is no DevelopmentMode,
				// environment or posture exemption. A development bypass would recreate the defect being removed,
				// because a deployment would inherit the known-bad key merely by leaving one flag set, and a
				// warning that startup deliberately ignores is not a control.
				// Only the setting NAME is reported - never the value, its length or a digest of it - so the
				// startup failure cannot leak key material into a console or crash report (CWE-532).
				missingSecrets += $"{Environment.NewLine}  - 'Settings:EncryptionKey' is weak or is the example key published in this repository" +
					$" (environment variable 'Settings__EncryptionKey')";
			}
			else if (!IsAsciiOnly(EncryptionKey))
			{
				// THREAT ADDRESSED - review finding CR2-F-09 (CWE-331 insufficient entropy, CWE-176 improper
				// handling of Unicode encoding), OWASP A02:2021 Cryptographic Failures. The two checks above
				// measure CHARACTERS, while CryptoUtility.GetValidKey consumes BYTES through an ASCII
				// projection - and that projection SUBSTITUTES rather than fails, mapping every character
				// above U+007F to '?'. Acceptance and derivation could therefore disagree completely, and the
				// gap was measured rather than presumed: a 32-character key of 32 DISTINCT non-ASCII
				// characters satisfies both the 32-character length floor and the 8-distinct-character variety
				// floor, yet derives to the single byte 0x3F repeated 32 times. Two different keys of that
				// shape derive byte-identical AES keys, and the initialisation vector - derived from the same
				// text - collides with them. The variety floor above was, for such a key, measuring entropy
				// that the derivation then discarded in full.
				//
				// Requiring US-ASCII is what closes the gap, and it closes it BY CONSTRUCTION rather than by
				// duplicating the projection here: for US-ASCII input one character is exactly one byte, so
				// the character-based length and variety floors above become byte-exact and the two layers can
				// no longer disagree. Re-implementing the byte projection in this file was rejected as the
				// alternative - the derivation is algorithm-dependent (it sizes itself from
				// SymmetricAlgorithm.LegalKeySizes), so a copy here would be a second thing to keep in step
				// and would recreate this very finding in a new place.
				//
				// This is deliberately scoped to the encryption key and applied to the WHOLE configured value.
				// It is not applied to the connection string, whose password may legitimately be non-ASCII and
				// which Npgsql consumes as a string, never as key bytes. Validating the whole value is
				// marginally stricter than the derivation strictly needs, because a key longer than the
				// algorithm's key size is truncated before projection - but a non-ASCII character sitting in
				// the unused tail is a latent trap that starts destroying entropy the moment a key size or
				// algorithm changes, so refusing it at startup is the fail-safe reading.
				//
				// Only the setting NAME and the rule appear below - never the value, its length, the offending
				// character or its position - so this failure cannot leak key material into a console or a
				// crash report (CWE-532), consistent with every other diagnostic in this method.
				missingSecrets += $"{Environment.NewLine}  - 'Settings:EncryptionKey' contains characters outside US-ASCII, which the key derivation" +
					$" cannot represent and would silently replace, destroying key entropy; supply US-ASCII characters only" +
					$" (environment variable 'Settings__EncryptionKey')";
			}

			// SECURITY H-04 (CWE-798 hard-coded credentials, CWE-321 hard-coded cryptographic key, CWE-20
			// improper input validation). The token signing key is NOT demanded from every host. The token issue
			// and refresh routes are [AllowAnonymous] and are defined in WebVella.Erp.Web, so they exist on ALL
			// seven hosts, yet five of those hosts legitimately ship no 'Settings:Jwt' section at all; demanding
			// a key from them would stop them starting, which the preservation requirement "all existing
			// functionality remains operational" forbids. The routes are DISABLED instead whenever the key is
			// unusable, which is why a non-blank test on an existing section is not sufficient: without this,
			// a keyless host faults inside Encoding.UTF8.GetBytes(null) the moment an anonymous caller reaches
			// the route - a 500 carrying a stack trace rather than a clean refusal - and a host carrying the
			// published example key issues tokens anyone holding that public value can forge.
			// A host that DOES declare a Jwt section plainly intends to serve tokens, and a silently disabled
			// authentication feature is its own kind of defect, so the condition below reports it.
			// JwtEndpointsExposed gates the message so a process that hosts no token routes at all - the console
			// application - is never told that routes it never had are disabled.
			if (JwtEndpointsExposed && !IsJwtConfigured && configuration.GetSection("Settings:Jwt").Exists())
			{
				Console.Error.WriteLine("warn: WebVella.Erp.ErpSettings[2] SECURITY - a 'Settings:Jwt' section is present but " +
					"'Settings:Jwt:Key' is absent, shorter than " +
					MinimumJwtKeyByteLength.ToString(System.Globalization.CultureInfo.InvariantCulture) +
					" bytes, too repetitive, or is the example key published in this repository. The bearer-token issue and " +
					"refresh routes are DISABLED and will refuse every request until an acceptable key is supplied; " +
					"see docs/security/secure-configuration.md.");
			}

			if (string.IsNullOrEmpty(missingSecrets))
			{
				return;
			}

			// A specific exception type rather than the base Exception, so a host that wants to distinguish a
			// configuration fault from any other startup failure can. InvalidOperationException is what the
			// framework itself raises for "this operation cannot proceed in the current state", and because it
			// derives from Exception every existing catch site continues to behave exactly as before.
			throw new InvalidOperationException("WebVella ERP startup aborted - required security configuration is missing:" + missingSecrets +
				$"{Environment.NewLine}Supply every value listed above through an environment variable, user secrets in development, or Config.json, then restart." +
				$"{Environment.NewLine}The compiled-in default encryption key and the default token signing key were removed on purpose by the OWASP Top 10 remediation (findings C-04, H-04, H-05 - CWE-798, CWE-321); no insecure fallback remains by design." +
				$"{Environment.NewLine}See docs/security/secure-configuration.md for the complete list of required settings and how to supply them.");
		}

		/// <summary>
		/// Decides whether a token signing key is fit to sign and validate bearer tokens.
		/// </summary>
		/// <remarks>
		/// SECURITY H-04: this is a pure function on the raw value, deliberately, because the hosts need the same
		/// verdict at a point where <see cref="Initialize"/> has not run yet. Startup.ConfigureServices
		/// configures the JwtBearer handler, but Initialize is called later from UseErp during Configure,
		/// so <see cref="JwtKey"/> is still null while the handler is being registered. A host therefore
		/// asks this method about the value it reads from its own IConfiguration, and
		/// <see cref="IsJwtConfigured"/> answers the same question later for the routes. One rule, two
		/// call times - which is what stops a host trusting a key the routes would reject, or the reverse.
		/// Rejects, in ascending cost so the cheap tests run first:
		///  - absent or whitespace values;
		///  - keys under <see cref="MinimumJwtKeyByteLength"/> bytes once UTF-8 encoded, per RFC 7518
		///    section 3.2 for HS256 - note bytes, not characters, because a non-ASCII key encodes to more
		///    bytes than it has characters and only the byte count reaches the HMAC;
		///  - keys built from fewer than <see cref="MinimumDistinctCharacters"/> distinct characters;
		///  - the example key published in this repository, matched by digest.
		/// </remarks>
		public static bool IsAcceptableJwtKey(string key)
		{
			if (string.IsNullOrWhiteSpace(key))
			{
				return false;
			}

			// The HMAC consumes bytes, so the byte count is what the RFC floor applies to.
			if (Encoding.UTF8.GetByteCount(key) < MinimumJwtKeyByteLength)
			{
				return false;
			}

			if (!HasSufficientCharacterVariety(key))
			{
				return false;
			}

			return !MatchesKnownPublishedDefault(key, PublishedDefaultJwtKeyDigest);
		}

		/// <summary>
		/// Reports whether every character of <paramref name="value"/> is inside US-ASCII.
		/// </summary>
		/// <remarks>
		/// Review finding CR2-F-09: this is the guard that makes the character-based floors below
		/// byte-exact for the encryption key. <c>CryptoUtility</c> derives key and initialisation-vector
		/// bytes through an ASCII projection that SUBSTITUTES unrepresentable characters with '?' instead
		/// of failing, so a key measured in characters could carry far less entropy in bytes - measurably
		/// so: 32 distinct non-ASCII characters collapsed to one distinct byte. For US-ASCII input one
		/// character is exactly one byte, so requiring it removes the discrepancy at its source. The test
		/// is a plain per-character bound rather than a round-trip re-encode, because a substituting
		/// encoder cannot report its own substitutions.
		/// </remarks>
		private static bool IsAsciiOnly(string value)
		{
			for (var index = 0; index < value.Length; index++)
			{
				if (value[index] > 0x7f)
				{
					return false;
				}
			}

			return true;
		}

		/// <summary>
		/// Length and character-variety floor shared by the non-JWT secrets, measured in characters.
		/// </summary>
		/// <remarks>
		/// An earlier revision of this comment justified the character measurement by asserting that
		/// "these values are consumed as strings, not as HMAC input". Review finding CR2-F-09 established
		/// that the assertion was false for the encryption key, which <c>CryptoUtility</c> consumes as
		/// ASCII BYTES - and the correction is recorded here rather than silently overwritten, because
		/// that false premise is what allowed acceptance and derivation to diverge. The measurement is
		/// still in characters, but it is now sound for the encryption key because its caller additionally
		/// requires <see cref="IsAsciiOnly"/>, under which one character is exactly one byte. Any future
		/// caller passing a value that is consumed as bytes must impose the same requirement, or measure
		/// the bytes it actually derives.
		/// </remarks>
		private static bool IsAcceptableSecretShape(string value, int minimumLength)
		{
			if (string.IsNullOrWhiteSpace(value) || value.Length < minimumLength)
			{
				return false;
			}

			return HasSufficientCharacterVariety(value);
		}

		/// <summary>
		/// Counts distinct characters up to <see cref="MinimumDistinctCharacters"/> and no further.
		/// </summary>
		/// <remarks>
		/// SECURITY C-04 and H-04: this is the entropy floor that catches padded placeholders - a key of "aaaa...aaaa" or
		/// "0123012301230123..." clears any length test but carries almost no key material. The buffer is
		/// stack-allocated and can never overflow, because the method returns the moment the floor is
		/// reached, so at most <see cref="MinimumDistinctCharacters"/> characters are ever remembered.
		/// This is a coarse floor, not an entropy measurement; it exists to reject the obvious cases
		/// cheaply, and the digest denylist handles the specific values this repository has published.
		/// </remarks>
		private static bool HasSufficientCharacterVariety(string value)
		{
			Span<char> seen = stackalloc char[MinimumDistinctCharacters];
			var seenCount = 0;

			foreach (var character in value)
			{
				var alreadySeen = false;
				for (var index = 0; index < seenCount; index++)
				{
					if (seen[index] == character)
					{
						alreadySeen = true;
						break;
					}
				}

				if (alreadySeen)
				{
					continue;
				}

				seen[seenCount] = character;
				seenCount++;

				if (seenCount >= MinimumDistinctCharacters)
				{
					// The answer cannot change once the floor is reached.
					return true;
				}
			}

			return false;
		}

		/// <summary>
		/// Compares a supplied secret against a known-bad value held only as a SHA-256 digest.
		/// </summary>
		/// <remarks>
		/// SECURITY C-04 and H-04: the digest, never the literal, is what lives in this source file - see the constants for
		/// why. SHA-256 here is a value-identity comparison against a PUBLIC value, not password storage
		/// and not a confidentiality control, so an unsalted single-pass digest is exactly the right
		/// primitive and carries none of the objections that apply to hashing credentials.
		/// The comparison is fixed-time even so. It compares public data, so a timing signal would leak
		/// nothing useful, but the routine sits on a security decision path and a later reader must not
		/// have to work out whether that was reasoned about.
		/// </remarks>
		private static bool MatchesKnownPublishedDefault(string value, string expectedDigestHex)
		{
			if (string.IsNullOrEmpty(value))
			{
				return false;
			}

			var actualDigest = SHA256.HashData(Encoding.UTF8.GetBytes(value));
			byte[] expectedDigest;
			try
			{
				expectedDigest = Convert.FromHexString(expectedDigestHex);
			}
			catch (FormatException)
			{
				// A malformed constant must not be read as "this secret is fine". Unreachable while the
				// constants above are well formed; present so that a future typo fails closed.
				return true;
			}

			return CryptographicOperations.FixedTimeEquals(actualDigest, expectedDigest);
		}
	}
}
