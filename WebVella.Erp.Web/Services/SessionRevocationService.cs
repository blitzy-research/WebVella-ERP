using System;
using System.Globalization;
using Microsoft.Extensions.Caching.Memory;
using WebVella.Erp.Database;

namespace WebVella.Erp.Web.Services
{
	// Threat addressed - finding F8 (session hijacking; CWE-613 insufficient session expiration,
	// CWE-384 session fixation), OWASP A07 Identification and Authentication Failures; extended by
	// review finding H-OPEN-01 (CWE-613 plus CWE-636 not failing securely).
	//
	// THE THREAT, precisely. The cookie authentication ticket is SELF-CONTAINED: the browser presents an
	// encrypted blob and the server validates it purely by unprotecting it, consulting no server-side
	// state at all. Signing out therefore only deleted the cookie from the ONE browser that asked. Anyone
	// holding a copy - taken from a shared machine, a stolen backup, a proxy log, or a cross-site
	// scripting payload - kept a fully valid credential for the remainder of the ticket lifetime, and the
	// legitimate user had no way whatsoever to end that session. "Log out" was a client-side gesture, not
	// a security control.
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
	// H-OPEN-01: WHY THE STORE IS NOW DURABLE AND SHARED RATHER THAN IN-PROCESS. The revocation list used
	// to be a process-local, size-bounded MemoryCache, and EVERY boundary of that store was a fail-open:
	//   * a process restart discarded every revocation, so a copied cookie or token started working again
	//     after any deployment, recycle or crash - for the remainder of its own lifetime;
	//   * a second instance behind a load balancer never observed the revocation at all, so "log out"
	//     protected exactly one instance and the copy kept working on the others;
	//   * cache compaction at the size ceiling could evict a STILL-LIVE revocation, and the code
	//     acknowledged that eviction was fail-open in its own comment.
	// A revocation that any of those three events can silently undo is not a revocation. State therefore
	// moved to Database/DbSecurityStateRepository, which is durable (it survives restart), shared (every
	// instance against the same database observes the same revocation), atomic, and reclaims entries by
	// EXPIRY ONLY - never by capacity - so no live revocation can ever be displaced by a newer one.
	// Crucially it needs NO SCHEMA CHANGE: it stores under a reserved key prefix in the plugin_data table
	// that every installation already has. See that type for the full rationale.
	//
	// AND IT NOW FAILS CLOSED. When the durable store cannot be consulted at all, this type answers
	// "revoked". That is the direction H-OPEN-01 requires - "fail closed when revocation state cannot be
	// established" - and it costs nothing real: every authenticated request in this platform already
	// re-resolves its user from the same database, so a database this code cannot reach is a database no
	// request could have been served from anyway. The alternative, answering "not revoked" when the answer
	// is unknown, is precisely how an outage would have become an authorisation.
	//
	// THE LOCAL CACHE THAT REMAINS IS POSITIVE-ONLY, and that asymmetry is the whole design. A session
	// once known to be revoked can never become valid again, so caching a POSITIVE answer can only ever
	// make this control stricter and saves a round trip on exactly the requests an attacker generates. A
	// NEGATIVE answer is deliberately NOT cached: caching "not revoked" for any interval would recreate a
	// window in which a revoked credential is still accepted, which is the very defect being closed. The
	// cost is one indexed point lookup per authenticated request, which is accepted and documented in
	// docs/security/secure-configuration.md.
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
	public static class SessionRevocationService
	{
		// Namespace for revocation keys inside the durable store. Every key written by this type begins
		// with it, so reclamation of expired revocations can never reach another control's rows.
		private const string KeyPrefix = DbSecurityStateRepository.ReservedKeyPrefix + "revoked_";

		// Ceiling on how long a single revocation is retained, applied to whatever the caller asks for.
		// A revocation only has to outlive the ticket it revokes; retaining it longer pins storage for no
		// benefit, and clamping here means no caller can turn this store into an unbounded one by
		// passing an absurd expiry.
		//
		// THREAT ADDRESSED - review finding CR3-H-03, CWE-613 (insufficient session expiration), OWASP
		// A07. This ceiling was 24 hours, and the comment justifying it described an eight-hour ticket
		// lifetime that no longer existed: the frozen session contract is 1440 MINUTES, so the ceiling
		// and the credential lifetime were exactly equal. A ceiling equal to the lifetime it is meant to
		// outlive is not a ceiling - it silently truncated the clock-skew allowance
		// AuthService.RevokeCurrentSession must add, because a bearer credential is honoured until its
		// exp PLUS AuthService.JwtClockSkew. The clamp therefore reinstated the very off-by-skew window
		// the caller had just computed away.
		// 25 hours is the smallest round value that leaves the longest legitimate request - 1440 minutes
		// of credential lifetime plus the 1-minute skew, i.e. 1441 minutes - unclamped, while still
		// bounding a caller that asks for something absurd. It is deliberately NOT derived from
		// AuthService's constants: this type is the lower layer of the two and must not take a
		// dependency on its caller. The relationship is asserted in the remarks at both ends instead, and
		// RetentionCeilingMinutes below exposes the number so a test or a caller can check it rather than
		// restate it.
		private static readonly TimeSpan MaxRetention = TimeSpan.FromHours(25);

		// The ceiling above, in minutes, readable by the callers and verifications that have to prove
		// their requested retention is not being clamped. Exposing the value is what makes that provable
		// instead of assumed; it is assembly-internal, so no public surface is widened.
		internal static double RetentionCeilingMinutes
		{
			get { return MaxRetention.TotalMinutes; }
		}

		// Floor on retention. A revocation written with a near-past expiry would otherwise be discarded
		// immediately, silently doing nothing; one minute guarantees the entry is actually observable by
		// the requests it exists to reject.
		private static readonly TimeSpan MinRetention = TimeSpan.FromMinutes(1);

		// H-OPEN-01: the POSITIVE-ONLY local cache described in the header. It holds only identifiers the
		// durable store has already confirmed revoked, so a hit can only refuse a credential that is
		// already refused - it can never authorise one, and it can never mask a revocation recorded by
		// another instance, because a miss always consults the durable store. Entries expire with the
		// revocation they mirror and the store is size-bounded, so eviction here loses nothing: the next
		// request for an evicted identifier simply asks the database again and re-learns the same answer.
		// This is the one place a bounded cache is safe in this type, precisely because its failure mode
		// is a redundant query rather than an accepted credential.
		private static readonly MemoryCache confirmedRevocations = new MemoryCache(new MemoryCacheOptions
		{
			SizeLimit = 20000,
			CompactionPercentage = 0.2
		});

		// Records that a session identifier must no longer be accepted, until <paramref name="absoluteExpiryUtc"/>.
		// Written by the sign-out path for whichever credential the caller presented - cookie or bearer.
		//
		// Non-throwing by construction, because it is called from the sign-out path: a failure to record a
		// revocation must never turn logging out into a server error, and Guid.Empty - which is what an
		// absent or malformed claim parses to - is ignored rather than recorded, so it can never revoke
		// every credential that happens to carry no session claim.
		//
		// H-OPEN-01: returns whether the revocation was DURABLY recorded, so the caller can tell the
		// difference between "this session is now closed everywhere" and "the store could not be written".
		// The local mirror is populated only on success, because a mirror entry written after a failed
		// durable write would make this instance believe a revocation exists that no other instance can
		// see - the single-instance illusion this change exists to remove.
		//
		// Assembly-internal deliberately: no public surface is widened by this finding's fix, and every caller
		// - AuthService and the cookie ticket-validation hook in ErpMvcExtensions - lives in this assembly.
		internal static bool RevokeSessionIdentifier(Guid sessionId, DateTime absoluteExpiryUtc)
		{
			if (sessionId == Guid.Empty)
				return false;

			var retention = absoluteExpiryUtc - DateTime.UtcNow;
			if (retention < MinRetention)
				retention = MinRetention;
			if (retention > MaxRetention)
				retention = MaxRetention;

			DateTime expiresUtc = DateTime.UtcNow.Add(retention);

			// The payload is the expiry restated in round-trip form. It carries no credential material and
			// no user identifier - deliberately: a row in this namespace is readable by anything with
			// database access, so it must not become a session-correlation source (CWE-532). The KEY is the
			// session identifier and is unavoidable, which is why the retention above is bounded.
			if (!DbSecurityStateRepository.TryWrite(BuildKey(sessionId),
				expiresUtc.ToString("O", CultureInfo.InvariantCulture), expiresUtc))
			{
				return false;
			}

			confirmedRevocations.Set(BuildKey(sessionId), true, new MemoryCacheEntryOptions
			{
				AbsoluteExpirationRelativeToNow = retention,
				Size = 1,
				Priority = CacheItemPriority.High
			});

			return true;
		}

		// Consulted on every authenticated request, by the cookie ticket-validation hook and by both bearer
		// validators. Non-throwing.
		//
		// F-02: an empty identifier is reported as NOT revoked, and that stays correct only because every
		// caller now treats an absent or unparseable session claim as a refusal in its own right, before it
		// ever reaches this method. This method answers "is this specific identifier revoked?", nothing more.
		//
		// H-OPEN-01: three outcomes collapse into two, and the collapse is the control.
		//   * the local mirror already knows it is revoked  -> revoked, no query;
		//   * the durable store answers                     -> its answer;
		//   * the durable store CANNOT be consulted         -> REVOKED. Failing closed is what makes this a
		//     control rather than a courtesy: an unreachable store used to be indistinguishable from a
		//     clean one, so an outage granted every copied credential the benefit of the doubt.
		internal static bool IsSessionIdentifierRevoked(Guid sessionId)
		{
			if (sessionId == Guid.Empty)
				return false;

			string key = BuildKey(sessionId);
			if (confirmedRevocations.TryGetValue(key, out _))
				return true;

			if (!DbSecurityStateRepository.TryRead(key, out string payload))
			{
				// Fail closed. Deliberately NOT mirrored locally: a transient outage must not pin a
				// legitimate session as revoked for the rest of the retention window.
				return true;
			}

			if (payload == null)
				return false;

			// Mirrored for exactly as long as the DURABLE entry has left to live, so the mirror can never
			// outlast the fact it mirrors. The payload is the durable expiry in round-trip form; an
			// unparseable one falls back to the floor rather than to the ceiling, because a mirror that
			// guessed high would keep refusing after the durable revocation had gone.
			// RoundtripKind alone, and never combined with AdjustToUniversal or AssumeUniversal: the
			// framework REFUSES that combination with an ArgumentException rather than ignoring it, and a
			// throw from this method would surface as a 500 on the authenticated request path. The "O"
			// format carries its own offset, so RoundtripKind already yields the correct instant; the
			// conversion below then normalises the Kind rather than relying on a style flag to do it.
			TimeSpan mirrorLifetime = MinRetention;
			if (DateTime.TryParse(payload, CultureInfo.InvariantCulture,
				DateTimeStyles.RoundtripKind, out DateTime storedExpiry))
			{
				DateTime storedExpiryUtc = storedExpiry.Kind == DateTimeKind.Utc
					? storedExpiry
					: storedExpiry.ToUniversalTime();
				mirrorLifetime = storedExpiryUtc - DateTime.UtcNow;
				if (mirrorLifetime < MinRetention)
					mirrorLifetime = MinRetention;
				if (mirrorLifetime > MaxRetention)
					mirrorLifetime = MaxRetention;
			}

			confirmedRevocations.Set(key, true, new MemoryCacheEntryOptions
			{
				AbsoluteExpirationRelativeToNow = mirrorLifetime,
				Size = 1,
				Priority = CacheItemPriority.High
			});

			return true;
		}

		private static string BuildKey(Guid sessionId)
		{
			return KeyPrefix + sessionId.ToString("N");
		}
	}
}
