using System;
using Microsoft.Extensions.Caching.Memory;

namespace WebVella.Erp.Web.Services
{
	// Threat addressed - finding F8 (session hijacking; CWE-613 insufficient session expiration,
	// CWE-384 session fixation), OWASP A07 Identification and Authentication Failures.
	//
	// THE THREAT, precisely. The cookie authentication ticket is SELF-CONTAINED: the browser presents an
	// encrypted blob and the server validates it purely by unprotecting it, consulting no server-side
	// state at all. Signing out therefore only deleted the cookie from the ONE browser that asked. Anyone
	// holding a copy - taken from a shared machine, a stolen backup, a proxy log, or a cross-site
	// scripting payload - kept a fully valid credential for the remainder of the eight-hour ticket
	// lifetime, and the legitimate user had no way whatsoever to end that session. "Log out" was a
	// client-side gesture, not a security control.
	//
	// THE CONTROL. Every ticket minted by AuthService.Authenticate carries a random session identifier
	// claim. Logging out records that identifier here, and the cookie authentication pipeline consults
	// this store on EVERY request before accepting a principal, so the first request made with a copied
	// cookie after logout is rejected and the copy is dead. That turns logout into server-validated
	// session termination, which is what the finding asks for.
	//
	// WHY A REVOCATION LIST RATHER THAN A SECURITY STAMP COLUMN. A per-user stamp persisted on the user
	// record would survive a restart and span instances, and is the stronger design - but it requires a
	// schema change, which the change constraints for this remediation exclude, and a database read on
	// every authenticated request, which is a measurable cost on every page. A short-lived in-process
	// list needs neither, and is strictly better than the nothing that exists today.
	//
	// SCOPE LIMITATION, documented rather than hidden. The store is in-process and does not survive a
	// restart, so in a multi-instance deployment a logout revokes the session only on the instance that
	// handled it. This mirrors the same documented limitation as the login throttle and is recorded in the
	// risk register. A restart is not a weakening in itself: the data-protection keys that decrypt the
	// cookie are the same across restarts only when key persistence is configured, and a revoked session
	// surviving a restart is bounded by the ticket lifetime in any case.
	//
	// Sealed deliberately, for the same reason as LoginThrottleService: the invariants below are only
	// sound if no subclass can widen them, and sealing keeps the disposal pattern for the owned cache
	// minimal.
	public sealed class SessionRevocationService : IDisposable
	{
		// Hard ceiling on tracked revocations, which is what keeps CWE-770 (allocation without limits)
		// unreachable: the store evicts rather than grows once this many entries are live. Reaching it
		// requires twenty thousand DISTINCT AUTHENTICATED logouts inside one retention window, because
		// only a successful sign-out can write here - an unauthenticated caller cannot add a single
		// entry. The residual is stated plainly rather than hidden: eviction is fail-OPEN, so an evicted
		// revocation lets a copied cookie work again for the remainder of its own lifetime. That is
		// accepted deliberately, because the alternative - an unbounded store - is a denial-of-service
		// primitive, and a bounded fail-open list is still strictly stronger than today's no list at all.
		private const long MaxRevokedSessions = 20000;

		// Fraction discarded when the ceiling is hit. Matches LoginThrottleService so the two bounded
		// stores in this assembly behave identically under pressure.
		private const double EvictionCompactionPercentage = 0.2;

		// Namespaced so revocation entries cannot collide with any other consumer's cache keys.
		private const string KeyPrefix = "wv_session_revoked_";

		// Ceiling on how long a single revocation is retained, applied to whatever the caller asks for.
		// A revocation only has to outlive the ticket it revokes; retaining it longer pins memory for no
		// benefit, and clamping here means no caller can turn this store into an unbounded one by
		// passing an absurd expiry. Comfortably above the eight-hour authentication ticket lifetime, so
		// a legitimate revocation is never dropped early.
		private static readonly TimeSpan MaxRetention = TimeSpan.FromHours(24);

		// Floor on retention. A revocation written with a near-past expiry would otherwise be discarded
		// by the cache immediately, silently doing nothing; one minute guarantees the entry is actually
		// observable by the requests it exists to reject.
		private static readonly TimeSpan MinRetention = TimeSpan.FromMinutes(1);

		// A dedicated, size-bounded cache rather than the platform's Utils.Cache helper, for exactly the
		// reason recorded on LoginThrottleService: that helper constructs its MemoryCache with default
		// options and exposes no way to set a SizeLimit, so entries written through it are bounded only
		// by their expiration. This instance is private, is never shared, and is owned for the lifetime
		// of this service, which is registered as a singleton so revocations survive across requests. No
		// new package dependency is introduced: MemoryCache is the same type that helper already uses.
		private readonly MemoryCache cache = new MemoryCache(new MemoryCacheOptions
		{
			SizeLimit = MaxRevokedSessions,
			CompactionPercentage = EvictionCompactionPercentage
		});

		// Records that a session identifier must no longer be accepted, until <paramref name="absoluteExpiryUtc"/>.
		//
		// Non-throwing by construction, because it is called from the sign-out path: a failure to record a
		// revocation must never turn logging out into a server error, and Guid.Empty - which is what an
		// absent or malformed claim parses to - is ignored rather than recorded, so it can never revoke
		// every ticket that happens to carry no session claim.
		public void Revoke(Guid sessionId, DateTime absoluteExpiryUtc)
		{
			if (sessionId == Guid.Empty)
				return;

			var retention = absoluteExpiryUtc - DateTime.UtcNow;
			if (retention < MinRetention)
				retention = MinRetention;
			if (retention > MaxRetention)
				retention = MaxRetention;

			// Size is mandatory because the cache above declares a SizeLimit; every revocation counts as
			// one tracked entry. Priority is High so that a burst of new revocations evicts nothing that
			// is still holding a session closed in preference to something else - every entry here is
			// equally load-bearing, and NeverRemove is deliberately NOT used because it would exempt
			// entries from the ceiling and hand back the unbounded growth this store exists to prevent.
			cache.Set(KeyPrefix + sessionId.ToString("N"), true, new MemoryCacheEntryOptions
			{
				AbsoluteExpirationRelativeToNow = retention,
				Size = 1,
				Priority = CacheItemPriority.High
			});
		}

		// Consulted on every authenticated request by the cookie pipeline. Non-throwing and allocation-free
		// on the overwhelmingly common negative path: an empty identifier is not revoked, so a ticket that
		// carries no session claim - notably a bearer principal, which has no cookie session to end - is
		// never rejected by this control.
		public bool IsRevoked(Guid sessionId)
		{
			if (sessionId == Guid.Empty)
				return false;

			return cache.TryGetValue(KeyPrefix + sessionId.ToString("N"), out _);
		}

		public void Dispose()
		{
			cache.Dispose();
			GC.SuppressFinalize(this);
		}
	}
}
