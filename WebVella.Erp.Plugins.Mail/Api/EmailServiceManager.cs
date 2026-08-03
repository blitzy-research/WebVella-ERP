using Microsoft.Extensions.Caching.Memory;
using System;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Api.Models.AutoMapper;
using WebVella.Erp.Eql;

namespace WebVella.Erp.Plugins.Mail.Api
{
	public class EmailServiceManager
	{
		static EmailServiceManager()
		{
			InitCache();
		}

		#region <=== General Cache Methods ===>

		private static IMemoryCache cache; 

		private static void InitCache()
		{
			if (cache != null)
				cache.Dispose();

			var cacheOptions = new MemoryCacheOptions();
			//SECURITY - finding F31 (High), CWE-522 insufficiently protected credentials.
			//THREAT ADDRESSED: entries in this cache are SmtpService instances holding the relay credential
			//in plaintext, so this scan frequency is how long an already-expired entry can still be resident
			//in process memory after its last legitimate use. An hour was an hour of needless exposure for a
			//cache that holds a handful of records; one minute bounds it without measurable cost.
			cacheOptions.ExpirationScanFrequency = TimeSpan.FromMinutes(1);
			cache = new MemoryCache(cacheOptions);
		}

		internal static void ClearCache()
		{
			InitCache();
		}

		private static void AddObjectToCache(string key, object obj)
		{
			var options = new MemoryCacheEntryOptions();
			//SECURITY - finding F31 (High), CWE-522. The cached value carries the plaintext SMTP relay
			//credential, so this is the lifetime of that secret in process memory. Narrowed from one hour.
			//SAFE, not merely cheap: a miss is already an ordinary path, because GetSmtpService falls back
			//to a database read and Hooks/Api/SmtpServiceRecordHook clears this cache on every create,
			//update and delete of an smtp_service record. Five minutes therefore changes only how often the
			//value is re-read, never whether it resolves.
			options.SetAbsoluteExpiration(TimeSpan.FromMinutes(5));
			cache.Set(key, obj, options);
		}

		private static object GetObjectFromCache(string key)
		{
			object result = null;
			bool found = cache.TryGetValue(key, out result);
			return result;
		}

		#endregion

		#region <=== SMTP Services ===>
		
		public SmtpService GetSmtpService(Guid id)
		{
			string cacheKey = $"SMTP-{id}";
			SmtpService service = GetObjectFromCache(cacheKey) as SmtpService;
			if (service == null)
			{
				service = GetSmtpServiceInternal(id);
				if (service != null)
					AddObjectToCache(cacheKey, service);
			}
			return service;
		}

		public SmtpService GetSmtpService(string name = null)
		{
			string cacheKey = $"SMTP-{name}";
			SmtpService service = GetObjectFromCache(cacheKey) as SmtpService;
			if (service == null)
			{
				service = GetSmtpServiceInternal(name);
				if (service != null)
					AddObjectToCache(cacheKey, service);
			}
			return service;
		}

		internal SmtpService GetSmtpServiceInternal(string name = null)
		{
			EntityRecord smtpServiceRec = null;
			if (name != null)
			{
				var result = new EqlCommand("SELECT * FROM smtp_service WHERE name = @name", new EqlParameter("name", name)).Execute();
				if (result.Count == 0)
					throw new Exception($"SmtpService with name '{name}' not found.");

				smtpServiceRec = result[0];
			}
			else
			{
				var result = new EqlCommand("SELECT * FROM smtp_service WHERE is_default = @is_default", new EqlParameter("is_default", true)).Execute();
				if (result.Count == 0)
					throw new Exception($"Default SmtpService not found.");
				else if (result.Count > 1)
					throw new Exception($"More than one default SmtpService not found.");

				smtpServiceRec = result[0];
			}
			return smtpServiceRec.MapTo<SmtpService>();
		}

		internal SmtpService GetSmtpServiceInternal(Guid id)
		{
			var result = new EqlCommand("SELECT * FROM smtp_service WHERE id = @id", new EqlParameter("id", id)).Execute();
			if (result.Count == 0)
				throw new Exception($"SmtpService with id = '{id}' not found.");

			return result[0].MapTo<SmtpService>();
		}

		#endregion
	}
}
