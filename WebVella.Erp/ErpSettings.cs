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
		/// SECURITY - H-04, CWE-798, CWE-321, OWASP A02. Token-issuing capability used to be inferred from the
		/// mere presence of a 'Settings:Jwt' configuration section, which is wrong in the dangerous direction:
		/// the endpoints live in WebVella.Erp.Web and are therefore exposed by every host using the web
		/// framework, yet only two of the seven shipped configurations declare that section. Capability is
		/// therefore STATED - by the caller, or by what the deployed application is built from - never guessed
		/// from configuration content. Whether a USABLE key was supplied is the separate question
		/// <see cref="IsJwtConfigured"/> answers, and an unusable key disables the token routes instead of
		/// aborting startup, which keeps the five hosts that legitimately ship no Jwt section startable.
		/// </remarks>
		public static bool JwtEndpointsExposed { get; private set; }

		/// <summary>
		/// True only when a token signing key was supplied AND passes <see cref="IsAcceptableJwtKey"/>. The
		/// single switch every bearer-token code path consults, so "is JWT usable here?" has one answer.
		/// </summary>
		/// <remarks>
		/// SECURITY H-04 (CWE-798, CWE-20). Demanding a key only where a 'Settings:Jwt' section already exists,
		/// and accepting whatever is there provided it is not blank, is not sufficient: the token routes are
		/// [AllowAnonymous] and defined in WebVella.Erp.Web, so they exist on ALL seven hosts including the five
		/// that ship no Jwt section. An anonymous caller could therefore reach a route that evaluated
		/// Encoding.UTF8.GetBytes(null) and returned a 500 carrying a stack trace, while a host configured with
		/// this repository's published example key issued forgeable tokens. The routes are disabled instead of
		/// demanding a key from every host, which would stop five of them starting.
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

		// SECURITY C-04 and H-04: the two secrets published in this repository's own example configuration are
		// denied by SHA-256 digest rather than by literal. Storing the digest matters twice over - a denylist
		// written as literals would republish the very secrets being retired, and it would make this file a fresh
		// hit for the repository's own hardcoded-secret scan (CWE-798, CWE-540).
		private const string PublishedDefaultJwtKeyDigest = "87184b56659256b8e2d8d29aa5da9fd3b34ec5d5cd41cabe4493eb482b839549";
		private const string PublishedDefaultEncryptionKeyDigest = "7810b2fe1ad52ed53d4fd313052c78a59b15133f1e6e802805fb6e9c32935286";

		//API URLs
		public static string ApiUrlTemplateFieldInlineEdit { get; private set; }

		/// <summary>
		/// Initializes the settings, determining JWT capability from the process itself.
		/// </summary>
		/// <remarks>
		/// This overload's signature is unchanged on purpose: it is the entry point every existing host and the
		/// console application already call. Callers that know their own capability should prefer
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
		/// True when this process serves the bearer-token endpoints, so that 'Settings:Jwt:Key' is needed for
		/// them to FUNCTION. It is deliberately not needed for the process to START: an unusable key disables
		/// the two routes, and this flag only decides whether that is worth reporting - a process hosting no
		/// token routes is never told that routes it never had are disabled.
		/// </param>
		public static void Initialize(IConfiguration configuration, bool jwtEndpointsExposed)
		{
			// Recorded before validation runs, because ValidateRequiredSecurityConfiguration consults it.
			JwtEndpointsExposed = jwtEndpointsExposed;

			Configuration = configuration;
			EncryptionKey = configuration["Settings:EncryptionKey"];
			// Backwards compatibility: earlier releases published this key under a misspelled name, so a
			// configuration written against them is still honoured.
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
			// Backwards compatibility: earlier releases published this flag under a misspelled name.
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

			// SECURITY - C-04 and H-04, CWE-798 (hard-coded credentials) and CWE-321 (hard-coded cryptographic
			// key), OWASP A02. A compiled-in placeholder signing key shipped in the public source tree, so any
			// deployment that did not supply its own issued bearer tokens an attacker could forge at will.
			// INVARIANT: this assignment takes the configured value and nothing else; a missing signing key must
			// never acquire a silent default.
			// WHAT ABSENCE COSTS, precisely: startup PROCEEDS and the capability is withdrawn. JwtKey is never
			// added to the missingSecrets accumulator, so IsJwtConfigured goes false, the token routes disable
			// themselves, every presented bearer token fails validation, and cookie login is unaffected. The only
			// two settings whose absence aborts startup are Settings:ConnectionString and Settings:EncryptionKey.
			JwtKey = configuration["Settings:Jwt:Key"];
			JwtIssuer = string.IsNullOrWhiteSpace(configuration["Settings:Jwt:Issuer"]) ? "webvella-erp" : configuration["Settings:Jwt:Issuer"];
			JwtAudience = string.IsNullOrWhiteSpace(configuration["Settings:Jwt:Audience"]) ? "webvella-erp" : configuration["Settings:Jwt:Audience"];

			// SECURITY H-04 (CWE-20, CWE-798): resolved once, here, so that every bearer-token code path asks the
			// same question and gets the same answer. A key that is absent, too short, too repetitive or
			// equal to this repository's published example is not usable, and the token routes disable
			// themselves rather than issue forgeable tokens or fault on a null key.
			IsJwtConfigured = IsAcceptableJwtKey(JwtKey);

			// SECURITY - C-04, H-04 and H-05, CWE-798, CWE-321, OWASP A02 and A05.
			// THREAT: a settings layer that quietly defaults a secret relocates the defect instead of removing it -
			// the platform starts with a known-bad key and nobody notices. Compiled-in defaults for the encryption
			// key and the token signing key were removed, and live connection, encryption and token values were
			// scrubbed from the eight shipped Config.json files, which now carry empty placeholders.
			// INVARIANT: no required secret may acquire a default here, and its absence must abort startup. That
			// invariant is the precondition for the scrub being safe, together with the environment-variable and
			// user-secrets providers the hosts now register (docs/security/secure-configuration.md). Initialize is
			// the single funnel every host and the console application passes through, and this runs before
			// IsInitialized is set, so a failed validation leaves the settings explicitly un-initialized.
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
		/// <returns>True when the web framework is part of this application.</returns>
		/// <remarks>
		/// SECURITY (H-04, CWE-798) - this replaces an inference drawn from configuration CONTENT with one drawn
		/// from what the application consists of. Two independent tests are applied and either suffices: the
		/// assembly is already loaded, which every web host guarantees by reaching
		/// <see cref="Initialize(IConfiguration)"/> through the web framework's own registration extension; or
		/// the assembly file sits beside the entry assembly, which is what stops the answer depending on WHEN
		/// initialization happens - the runtime loads lazily, so a caller that initialized before touching any
		/// web-framework type would otherwise be misread as a non-web process and silently exempted. The console
		/// application is exempt under both tests by construction. Neither attempts an assembly load, because
		/// provoking one is a side effect whose failure would then have to be interpreted.
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
		/// configuration provider. Both callers of Initialize build a chain of Config.json, then environment
		/// variables, then user secrets in development, so "any provider" means every channel the operator guide
		/// documents. Config.json stays first and non-optional precisely so an environment variable overrides the
		/// blanked shipped value rather than being shadowed by it. Part of the remediation for C-04, H-04 and
		/// H-05 (CWE-798, CWE-321): with the compiled-in defaults removed, a missing value has to surface as an
		/// actionable startup error rather than degrade into a known-bad key. Only configuration key NAMES are
		/// reported - never values, prefixes, lengths or digests (CWE-532).
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
				// THREAT (C-04 and H-05, CWE-798, CWE-321, OWASP A02): a non-blank test alone accepts the example key
				// published in this repository, which is 64 characters long so no length rule catches it either, and a
				// publicly known data-at-rest key compromises every encrypted value. It is exactly as public in a
				// development checkout as in production, so enforcement is UNCONDITIONAL - no DevelopmentMode,
				// environment or posture exemption, because a deployment would then inherit the known-bad key merely by
				// leaving one flag set. Only the setting NAME is reported (CWE-532).
				missingSecrets += $"{Environment.NewLine}  - 'Settings:EncryptionKey' is weak or is the example key published in this repository" +
					$" (environment variable 'Settings__EncryptionKey')";
			}
			else if (!IsAsciiOnly(EncryptionKey))
			{
				// THREAT ADDRESSED - CWE-331 (insufficient entropy) with CWE-176 (improper handling of Unicode
				// encoding), OWASP A02:2021. The two checks above measure CHARACTERS, while CryptoUtility.GetValidKey
				// consumes BYTES through an ASCII projection that SUBSTITUTES rather than fails, mapping every character
				// above U+007F to '?'. The gap was measured, not presumed: a 32-character key of 32 DISTINCT non-ASCII
				// characters satisfies both the length floor and the variety floor, yet derives to the single byte 0x3F
				// repeated 32 times - and the initialisation vector, derived from the same text, collides with it.
				// Requiring US-ASCII closes the gap BY CONSTRUCTION, because one character is then exactly one byte, so
				// the character-based floors become byte-exact. Re-implementing the byte projection here was rejected:
				// the derivation sizes itself from SymmetricAlgorithm.LegalKeySizes, so a copy would be a second thing
				// to keep in step. Scoped to the encryption key and applied to the WHOLE value - not to the connection
				// string, whose password may legitimately be non-ASCII - because a non-ASCII character in the tail a
				// longer key truncates is a latent trap the moment a key size or algorithm changes.
				missingSecrets += $"{Environment.NewLine}  - 'Settings:EncryptionKey' contains characters outside US-ASCII, which the key derivation" +
					$" cannot represent and would silently replace, destroying key entropy; supply US-ASCII characters only" +
					$" (environment variable 'Settings__EncryptionKey')";
			}

			// SECURITY H-04 (CWE-798, CWE-321, CWE-20). The token signing key is NOT demanded from every host: the
			// routes are [AllowAnonymous] and defined in WebVella.Erp.Web so they exist on all seven, yet five
			// legitimately ship no 'Settings:Jwt' section and demanding a key would stop them starting. The routes
			// are DISABLED instead, which is why a non-blank test on an existing section is not sufficient - without
			// this a keyless host faults inside Encoding.UTF8.GetBytes(null) the moment an anonymous caller arrives,
			// returning a 500 with a stack trace rather than a clean refusal. A host that DOES declare the section
			// plainly intends to serve tokens, and a silently disabled authentication feature is its own defect, so
			// the condition below reports it; JwtEndpointsExposed gates the message so the console application is
			// never told that routes it never had are disabled.
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
		/// SECURITY H-04: a pure function on the raw value, deliberately, because the hosts need the same verdict
		/// before <see cref="Initialize"/> has run - ConfigureServices registers the JwtBearer handler while
		/// <see cref="JwtKey"/> is still null, Initialize being called later from UseErp. One rule, two call
		/// times, which is what stops a host trusting a key the routes would reject or the reverse.
		/// Rejects, in ascending cost: absent or whitespace values; keys under
		/// <see cref="MinimumJwtKeyByteLength"/> bytes once UTF-8 encoded, per RFC 7518 section 3.2 for HS256 -
		/// bytes, not characters, because only the byte count reaches the HMAC; keys built from fewer than
		/// <see cref="MinimumDistinctCharacters"/> distinct characters; and the published example key, by digest.
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
		/// The guard that makes the character-based floors byte-exact for the encryption key.
		/// <c>CryptoUtility</c> derives key and initialisation-vector bytes through an ASCII projection that
		/// SUBSTITUTES unrepresentable characters with '?' instead of failing, so 32 distinct non-ASCII
		/// characters collapse to one distinct byte. A plain per-character bound rather than a round-trip
		/// re-encode, because a substituting encoder cannot report its own substitutions.
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
		/// The character measurement is sound for the encryption key only because its caller additionally
		/// requires <see cref="IsAsciiOnly"/>, under which one character is exactly one byte;
		/// <c>CryptoUtility</c> consumes that key as ASCII BYTES. Any future caller passing a value consumed as
		/// bytes must impose the same requirement, or measure the bytes it actually derives.
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
		/// SECURITY C-04 and H-04: the entropy floor that catches padded placeholders - "aaaa...aaaa" clears any
		/// length test while carrying almost no key material. The buffer is stack-allocated and cannot overflow,
		/// because the method returns the moment the floor is reached. A coarse floor, not an entropy
		/// measurement; the digest denylist handles the specific values this repository has published.
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
		/// SECURITY C-04 and H-04: the digest, never the literal, is what lives in this file - see the constants
		/// for why. SHA-256 here is a value-identity comparison against a PUBLIC value, not password storage, so
		/// an unsalted single-pass digest is the right primitive. The comparison is fixed-time even so: it
		/// compares public data, but it sits on a security decision path and a later reader must not have to work
		/// out whether that was reasoned about.
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
