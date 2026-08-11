using CSScriptLib;
using Microsoft.Extensions.Caching.Memory;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using WebVella.Erp.Web.Models;

namespace WebVella.Erp.Web.Service
{
	public static class CodeEvalService
	{
		private static object lockObj = new object();

		//private static string CalculateMD5Hash(string input)
		//{
		//	MD5 md5 = MD5.Create();
		//	byte[] inputBytes = Encoding.ASCII.GetBytes(input);
		//	byte[] hash = md5.ComputeHash(inputBytes);

		//	StringBuilder sb = new StringBuilder();
		//	for (int i = 0; i < hash.Length; i++)
		//		sb.Append(hash[i].ToString("X2"));
		//	return sb.ToString();
		//}

		//SECURITY - review finding M-OPEN-04, CWE-362 (concurrent execution using shared resource with
		//improper synchronization) with CWE-770 (allocation without limits), OWASP A04:2021.
		//THREAT ADDRESSED, RACE FIRST because it is the sharper of the two: this was a plain
		//Dictionary<string, object> that was READ on the fast path OUTSIDE the lock that guarded its writes.
		//A read concurrent with the resize a write triggers does not merely return a stale value - it can
		//throw, or spin inside the bucket chain, so a page render could fail or peg a core for reasons no
		//log would explain. A MemoryCache is safe for concurrent readers and writers by contract, which
		//removes the unsynchronised read entirely; the lock below is retained for its ORIGINAL purpose only,
		//serialising COMPILATION so that a burst of first requests for one script cannot compile it many
		//times over.
		//THREAT ADDRESSED, GROWTH SECOND: the dictionary had no bound and no expiry, so every distinct source
		//string ever evaluated was retained for the life of the process. SizeLimit with a size of one per
		//entry bounds it and lets MemoryCache compact under pressure.
		//HONEST LIMIT OF THIS CONTROL, and the reason the retention window is LONG rather than short:
		//evicting an entry releases this cache's reference to the compiled script object, but it CANNOT
		//unload the assembly CSScript emitted for it - .NET cannot unload an assembly outside a collectible
		//load context, and introducing one would be an architectural change well beyond this finding. So a
		//short expiry would make things WORSE, not better: an evicted script that is used again is compiled
		//again and emits ANOTHER assembly, trading a few bytes of dictionary entry for a whole new assembly.
		//The window is therefore generous, the bound is high enough that ordinary authoring never reaches it,
		//and the residual - one loaded assembly per distinct source per process lifetime - is inherent to the
		//evaluator. It is no longer attacker-driven: the route that let a caller submit unlimited distinct
		//source is now authorization-gated (finding CR-01), so distinct sources are bounded by what an
		//administrator authors.
		private const int MaxCachedScripts = 1000;
		private static readonly TimeSpan CachedScriptSlidingExpiration = TimeSpan.FromDays(1);
		private static readonly MemoryCache scriptObjects = new MemoryCache(new MemoryCacheOptions { SizeLimit = MaxCachedScripts });

		private static ICodeVariable GetScriptObject(string sourceCode)
		{
			if (string.IsNullOrWhiteSpace(sourceCode))
				throw new ArgumentException("SourceCode is empty");

			//dublication of MD5 hash, so we stopped using it
			//string md5Key = CalculateMD5Hash(sourceCode);
			//The source text itself remains the key, exactly as before, and that upstream note is why: a cache
			//keyed by a digest of the very input it is protecting returns the WRONG COMPILED CODE on collision.
			if (scriptObjects.TryGetValue(sourceCode, out object cached))
				return cached as ICodeVariable;

			lock (lockObj)
			{
				//Re-checked inside the lock so that concurrent first requests for the same source compile it
				//once between them rather than once each - which also bounds how many assemblies a burst emits.
				if (scriptObjects.TryGetValue(sourceCode, out cached))
					return cached as ICodeVariable;

				CSScript.EvaluatorConfig.ReferenceDomainAssemblies = true;
				ICodeVariable scriptObject = CSScript.Evaluator.LoadCode<ICodeVariable>(sourceCode);
				scriptObjects.Set(sourceCode, scriptObject, new MemoryCacheEntryOptions
				{
					Size = 1,
					SlidingExpiration = CachedScriptSlidingExpiration
				});
				return scriptObject;
			}
		}

		public static object Evaluate(string sourceCode, BaseErpPageModel pageModel)
		{
			ICodeVariable script = GetScriptObject(sourceCode);
			return script.Evaluate(pageModel);
		}

		internal static void Compile(string sourceCode)
		{
			ICodeVariable script = GetScriptObject(sourceCode);
		}
	}
}
