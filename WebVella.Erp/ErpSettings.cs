using Microsoft.Extensions.Configuration;
using System;
using System.Net.Security;

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

		//API URLs
		public static string ApiUrlTemplateFieldInlineEdit { get; private set; }

		public static void Initialize(IConfiguration configuration)
		{
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
			//TODO - disq about using as default hosting server timezone when not specified in configuration
			// 628426 - I think its better to use the current threads timezone as the default if you don't have one set?
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
			// THREAT: this assignment previously substituted a compiled-in placeholder signing key whenever none was
			// configured. That value shipped in the public source tree, so any deployment which did not supply its own
			// key issued bearer tokens an attacker could forge at will - a complete authentication bypass.
			// The fallback is removed deliberately: a missing signing key must become an error, never a silent default.
			// ValidateRequiredSecurityConfiguration below turns that absence into an actionable startup failure.
			JwtKey = configuration["Settings:Jwt:Key"];
			JwtIssuer = string.IsNullOrWhiteSpace(configuration["Settings:Jwt:Issuer"]) ? "webvella-erp" : configuration["Settings:Jwt:Issuer"];
			JwtAudience = string.IsNullOrWhiteSpace(configuration["Settings:Jwt:Audience"]) ? "webvella-erp" : configuration["Settings:Jwt:Audience"];

			// SECURITY - findings C-04 (Critical), H-04 (High) and H-05 (High), CWE-798, CWE-321, OWASP A02 and A05.
			// THREAT: the shipped Config.json files no longer carry live secrets and CryptoUtility no longer falls back
			// to a compiled-in encryption key, so a settings layer that quietly defaulted would merely relocate the
			// defect - the platform would start with a known-bad key and nobody would notice. Initialize is the single
			// funnel every host and the console application passes through, so the absence of a required secret is
			// asserted here. Invoked before IsInitialized is set, so a failed validation leaves the settings
			// explicitly un-initialized rather than half-applied.
			ValidateRequiredSecurityConfiguration(configuration);

			IsInitialized = true;
		}

		/// <summary>
		/// Fails fast when a security setting the platform cannot safely default was not supplied by any
		/// configuration provider (Config.json, environment variables or user secrets).
		/// Part of the OWASP Top 10 remediation for findings C-04, H-04 and H-05 (CWE-798, CWE-321): every
		/// compiled-in default secret was removed, so a missing value has to surface as an actionable startup
		/// error instead of silently degrading into a known-bad key.
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
				missingSecrets += $"{Environment.NewLine}  - 'Settings:ConnectionString' (environment variable 'Settings__ConnectionString')";
			}

			// The encryption key is unconditionally required: CryptoUtility.CryptKey no longer falls back to a
			// compiled-in constant, so an absent key is caught here at startup rather than at the first
			// encrypt/decrypt of stored data (finding C-04, CWE-798, CWE-321). The legacy mispelled 'EncriptionKey'
			// spelling still satisfies this check, because Initialize resolves that backwards-compatibility path
			// into EncryptionKey before this validation runs.
			if (string.IsNullOrWhiteSpace(EncryptionKey))
			{
				missingSecrets += $"{Environment.NewLine}  - 'Settings:EncryptionKey' (environment variable 'Settings__EncryptionKey')";
			}

			// The token signing key is required only when a 'Settings:Jwt' section is actually configured, which is
			// the case exclusively for the hosts that issue bearer tokens. The remaining hosts and the console
			// application legitimately ship no such section, and demanding a key from them would stop them starting -
			// which the preservation requirement "all existing functionality remains operational" forbids. Where the
			// section IS present the key is mandatory, because the hard-coded fallback that used to cover it was
			// removed above (finding H-04, CWE-798, CWE-321).
			if (configuration.GetSection("Settings:Jwt").Exists() && string.IsNullOrWhiteSpace(JwtKey))
			{
				missingSecrets += $"{Environment.NewLine}  - 'Settings:Jwt:Key' (environment variable 'Settings__Jwt__Key')";
			}

			if (string.IsNullOrEmpty(missingSecrets))
			{
				return;
			}

			throw new Exception("WebVella ERP startup aborted - required security configuration is missing:" + missingSecrets +
				$"{Environment.NewLine}Supply every value listed above through an environment variable, user secrets in development, or Config.json, then restart." +
				$"{Environment.NewLine}The compiled-in default encryption key and the default token signing key were removed on purpose by the OWASP Top 10 remediation (findings C-04, H-04, H-05 - CWE-798, CWE-321); no insecure fallback remains by design." +
				$"{Environment.NewLine}See docs/security/secure-configuration.md for the complete list of required settings and how to supply them.");
		}
	}
}
