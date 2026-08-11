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
					throw new SmtpServiceNotFoundException($"SmtpService with name '{name}' not found.");

				smtpServiceRec = result[0];
			}
			else
			{
				var result = new EqlCommand("SELECT * FROM smtp_service WHERE is_default = @is_default", new EqlParameter("is_default", true)).Execute();
				if (result.Count == 0)
					throw new SmtpServiceNotFoundException($"Default SmtpService not found.");
				else if (result.Count > 1)
					//NOT a not-found condition. Two default services is an administrative ambiguity that a
					//caller cannot resolve but an operator can, and while it stands the correct disposition
					//for a queued message is to keep it and retry, not to abandon it. See the queue loop in
					//Services/SmtpInternalService.ProcessSmtpQueue.
					throw new InvalidOperationException($"More than one default SmtpService found.");

				smtpServiceRec = result[0];
			}
			return smtpServiceRec.MapTo<SmtpService>();
		}

		internal SmtpService GetSmtpServiceInternal(Guid id)
		{
			var result = new EqlCommand("SELECT * FROM smtp_service WHERE id = @id", new EqlParameter("id", id)).Execute();
			if (result.Count == 0)
				throw new SmtpServiceNotFoundException($"SmtpService with id = '{id}' not found.");

			return result[0].MapTo<SmtpService>();
		}

		#endregion
	}

	/// <summary>
	/// Thrown when a lookup PROVES that no matching <c>smtp_service</c> record exists.
	/// </summary>
	/// <remarks>
	/// <para>
	/// THREAT ADDRESSED - review finding M-OPEN-06, CWE-703 (improper check or handling of exceptional
	/// conditions) with CWE-755 (improper handling of exceptional conditions), OWASP A04:2021.
	/// </para>
	/// <para>
	/// WHY A DEDICATED TYPE. The four lookup failures above used to throw the BASE
	/// <see cref="System.Exception"/> type, which left the queue loop in
	/// <c>Services/SmtpInternalService.ProcessSmtpQueue</c> with no way to tell "this message names a
	/// service that does not exist" from "the datastore could not be reached just now". Its per-row handler
	/// - added so that one orphaned row could not starve the whole queue, review finding INT-03 - therefore
	/// had to catch <see cref="System.Exception"/> and treat every failure as the former, so a momentary
	/// database, connection or query fault PERMANENTLY ABORTED every message in the page being processed.
	/// Mail was silently and irrecoverably lost to a condition that would have cleared by itself, and
	/// because the message was moved to Aborted with its schedule cleared, no later pass could recover it.
	/// </para>
	/// <para>
	/// The distinction is now carried by the type: this exception means the absence is proven and the
	/// message cannot ever be delivered as addressed, so aborting it is correct. Anything else is treated
	/// as transient and the message keeps its retry budget. Deriving from <see cref="System.Exception"/>
	/// keeps every existing <c>catch (Exception)</c> in the plugin and in hook code behaving exactly as
	/// before, and the message text of each throw site is unchanged, so nothing that reads the reason
	/// - including the <c>server_error</c> column - sees any difference.
	/// </para>
	/// <para>
	/// Declared here beside the only code that throws it rather than in a file of its own, which is the
	/// smallest change that expresses the distinction. It is public because the members that throw it are
	/// public: an external caller that could not name the type would be forced back to
	/// <c>catch (Exception)</c>, which is the defect itself.
	/// </para>
	/// </remarks>
	public class SmtpServiceNotFoundException : Exception
	{
		public SmtpServiceNotFoundException()
		{
		}

		public SmtpServiceNotFoundException(string message)
			: base(message)
		{
		}

		public SmtpServiceNotFoundException(string message, Exception innerException)
			: base(message, innerException)
		{
		}
	}
}
