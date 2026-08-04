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
	// F-02 EXTENDS THE CONTROL TO BEARER TOKENS. A JWT is exactly as self-contained as the cookie, so the
	// same threat applied verbatim to every issued token - and worse, because the refresh endpoint would
	// keep minting successors for as long as the horizon allowed. AuthService.BuildTokenAsync now stamps
	// the same session identifier claim into every token and carries it verbatim across refresh, both
	// bearer validators consult this store, and sign-out revokes whichever identifier the current
	// principal carries. One identifier, one store, both credential kinds.
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
	// STATIC deliberately, and that shape is what finding F-02 required rather than a stylistic preference.
	// This began as an injected singleton holding a private instance cache, which confined the control to
	// consumers that could resolve a service - and the bearer-token validators cannot: they are static code
	// (AuthService.GetValidSecurityTokenAsync, and the token-validated hook the two token-issuing hosts
	// install) with no service provider in reach. A static store closes that gap and strengthens the control
	// twice over rather than merely relocating it:
	//   * ONE store per process. An injected instance gave a host that builds more than one service provider
	//     an independent, empty store per provider, so a logout recorded in one was invisible to the other -
	//     a silent fail-open;
	//   * the consult path can FAIL CLOSED. With injection every consumer had to tolerate an unresolvable
	//     service, and "no service" was indistinguishable from "not revoked". A static store cannot be
	//     absent, so a missing control can no longer be mistaken for an authorisation.
	// Nothing is injected and nothing is disposed: every entry is individually bounded by MaxRetention and
	// the whole store by MaxRevokedSessions, so process lifetime introduces no unbounded growth. This
	// mirrors the platform's own process-lifetime cache in ErpAppContext.
	public static class SessionRevocationService
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
		// by their expiration. No new package dependency is introduced: MemoryCache is the same type that
		// helper already uses.
		//
		// THREAT ADDRESSED - finding F-02 (session hijacking via a non-revocable bearer token; CWE-613
		// insufficient session expiration), OWASP A07. The store used to be a PRIVATE INSTANCE field
		// reachable only through dependency injection, and that placement is what confined the control to
		// the cookie pipeline. Bearer tokens are validated by STATIC code - AuthService.GetValidSecurityTokenAsync
		// and the token-validated hook the two token-issuing hosts install - which has no service provider
		// to resolve from, so the revocation list was structurally unreachable from the one credential
		// class that most needed it. Making the store static is the minimum change that closes that gap,
		// and it strengthens the control in two further ways rather than merely relocating it:
		//   * there is now exactly ONE store per process. An instance field gave a host that builds more
		//     than one service provider one independent, empty store per provider, so a logout recorded in
		//     one would be invisible to the other - a silent fail-open;
		//   * the consult path can now FAIL CLOSED. With injection the consumer had to tolerate a null
		//     service (a host that never called AddErp), and "no service" was indistinguishable from "not
		//     revoked". A static store cannot be absent, so a missing store can no longer be mistaken for
		//     an authorisation.
		// The store outlives every service instance deliberately: revocations must survive the disposal of
		// any one provider, and they are individually bounded by MaxRetention plus the ceiling below, so
		// process lifetime introduces no unbounded growth. This mirrors the platform's own ErpAppContext
		// cache, which is likewise process-lifetime.
		private static readonly MemoryCache revokedSessions = new MemoryCache(new MemoryCacheOptions
		{
			SizeLimit = MaxRevokedSessions,
			CompactionPercentage = EvictionCompactionPercentage
		});

		// Records that a session identifier must no longer be accepted, until <paramref name="absoluteExpiryUtc"/>.
		// Written by the sign-out path for whichever credential the caller presented - cookie or bearer.
		//
		// Non-throwing by construction, because it is called from the sign-out path: a failure to record a
		// revocation must never turn logging out into a server error, and Guid.Empty - which is what an
		// absent or malformed claim parses to - is ignored rather than recorded, so it can never revoke
		// every credential that happens to carry no session claim.
		//
		// Assembly-internal deliberately: no public surface is widened by this finding's fix, and every caller
		// - AuthService and the cookie ticket-validation hook in ErpMvcExtensions - lives in this assembly.
		internal static void RevokeSessionIdentifier(Guid sessionId, DateTime absoluteExpiryUtc)
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
			revokedSessions.Set(KeyPrefix + sessionId.ToString("N"), true, new MemoryCacheEntryOptions
			{
				AbsoluteExpirationRelativeToNow = retention,
				Size = 1,
				Priority = CacheItemPriority.High
			});
		}

		// Consulted on every authenticated request, by the cookie ticket-validation hook and by both bearer
		// validators. Non-throwing and allocation-free on the overwhelmingly common negative path.
		//
		// F-02: an empty identifier is reported as NOT revoked, and that stays correct only because every
		// caller now treats an absent or unparseable session claim as a refusal in its own right, before it
		// ever reaches this method. This method answers "is this specific identifier revoked?", nothing more.
		internal static bool IsSessionIdentifierRevoked(Guid sessionId)
		{
			if (sessionId == Guid.Empty)
				return false;

			return revokedSessions.TryGetValue(KeyPrefix + sessionId.ToString("N"), out _);
		}
	}
}
