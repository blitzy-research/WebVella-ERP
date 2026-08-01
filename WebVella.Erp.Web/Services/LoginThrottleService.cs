using System;
using Microsoft.Extensions.Caching.Memory;

namespace WebVella.Erp.Web.Services
{
	// Threat addressed - finding H-16, CWE-307 (Improper Restriction of Excessive Authentication
	// Attempts), OWASP A07 Identification and Authentication Failures: no lockout mechanism existed
	// anywhere in the platform, so every credential-verification entry point accepted an unlimited
	// number of authentication attempts and was therefore open to credential stuffing and
	// brute-force password guessing.
	//
	// This service is the application-level account lockout. Transport-level rate limiting is a
	// separate, complementary layer configured in the host pipelines, not here.
	//
	// Also addressed here, because each is a way the lockout could be bypassed rather than a
	// separate feature:
	//   * CWE-367 (time-of-check/time-of-use race). A check-then-authenticate-then-count protocol
	//     lets every request in a concurrent burst observe the same pre-attack counter value and
	//     pass, so the threshold never trips under exactly the concurrent load it exists to stop.
	//     Callers therefore RESERVE an attempt before authenticating and finalise it afterwards;
	//     reservations count towards the threshold while they are outstanding.
	//   * CWE-770 (allocation without limits). The counters are keyed partly by a value the caller
	//     supplies, so an attacker who varies the username can mint unbounded distinct keys. The
	//     backing store is therefore explicitly size-bounded rather than free to grow.
	//   * Source-address rotation. Counting failures against a combined username-and-address key
	//     hands an attacker with a proxy pool a fresh budget per address for the same account, so
	//     the account is never locked. The two dimensions are therefore counted INDEPENDENTLY.
	//
	// Scope limitation, documented rather than hidden: the backing store is in-process, so the
	// protection is per-process only. A multi-instance or load-balanced deployment is NOT protected
	// by this service, because each process counts failures independently. Moving the counters to a
	// distributed backing store is a recorded recommendation and is deliberately not built here.
	//
	// Sealed deliberately. Nothing derives from this type, and the lockout invariants below are only
	// sound if no subclass can override or widen them; sealing also keeps the disposal pattern for
	// the owned cache minimal.
	public sealed class LoginThrottleService : IDisposable
	{
		// "Account lockout after 5 failed attempts" is the literal value mandated by the
		// Authentication Hardening standard: once five failures are recorded against an account the
		// sixth attempt is refused without authentication being attempted at all.
		private const int MaxFailedAttemptsPerAccount = 5;

		// The per-source-address budget is deliberately a multiple of the per-account one rather
		// than equal to it. It exists to bound password spraying - many accounts tried once each
		// from one source, which never trips a per-account counter - and NOT to lock out shared
		// egress. Because a NAT gateway, corporate proxy or VPN concentrator presents one address
		// for many legitimate users, a budget equal to the account threshold would let five people
		// mistyping their passwords lock out the whole site for that address. This value lets five
		// distinct principals each exhaust the mandated five-attempt account budget from one shared
		// address before the address itself is throttled, while still bounding spraying, which needs
		// attempts across hundreds of accounts to be worthwhile.
		private const int MaxFailedAttemptsPerAddress = MaxFailedAttemptsPerAccount * 5;

		// Length of the failure-counting window and of the resulting lockout, in minutes. Both use
		// the same value so a lockout can never outlive the entry that records it. Deliberately not
		// configurable - a configuration surface would exceed the remediation. A bounded window,
		// rather than a lock held until an administrator intervenes, is what keeps the mandated
		// account lockout from becoming a denial-of-service primitive against a known account.
		private const double WindowMinutes = 15;

		// Upper bound applied to each key component. A caller-supplied value can be arbitrarily
		// long, and bounding it keeps the cache key and its memory footprint predictable.
		// Truncation can only merge two principals onto one counter, which throttles more rather
		// than less, so it errs in the safe direction.
		private const int MaxKeyComponentLength = 128;

		// Hard ceiling on the number of tracked principals, which is what makes CWE-770 unreachable:
		// the store evicts rather than grows once this many entries are live. Sized so that ordinary
		// operation never reaches it, while the memory an attacker can pin is bounded to this many
		// small entries no matter how many distinct usernames they submit.
		private const long MaxTrackedPrincipals = 20000;

		// Fraction of entries discarded when the ceiling is hit. Eviction prefers the lowest-priority
		// entries first, which is why in-force lockouts are stored at a higher priority than
		// still-counting entries - see Store.
		private const double EvictionCompactionPercentage = 0.2;

		// Namespaced so throttle entries cannot collide with any other consumer's cache keys, and
		// separated by dimension so an account counter and an address counter can never alias - an
		// account named after an IP address must not share a counter with that address.
		private const string AccountKeyPrefix = "wv_login_throttle_acct_";
		private const string AddressKeyPrefix = "wv_login_throttle_addr_";

		// Substituted for a missing username or address so that a malformed request is still
		// counted against a stable, non-empty key instead of failing.
		private const string MissingValuePlaceholder = "(unspecified)";

		// A dedicated, size-bounded cache rather than the platform's Utils.Cache helper. That helper
		// constructs its MemoryCache with default options and exposes no way to set a SizeLimit, so
		// entries written through it are bounded only by their expiration - which is precisely the
		// CWE-770 exposure above, and is not fixable from the calling side. Raising the limit on the
		// shared instance is not an option either, because it would change eviction behaviour for
		// every other consumer of that cache. This instance is private, is never shared, and is
		// owned for the lifetime of this service, which is registered as a singleton so the counters
		// survive across requests. No new package dependency is introduced: MemoryCache is the same
		// type that helper already uses.
		private readonly MemoryCache cache = new MemoryCache(new MemoryCacheOptions
		{
			SizeLimit = MaxTrackedPrincipals,
			CompactionPercentage = EvictionCompactionPercentage
		});

		// Every state transition below is a read-modify-write of a counter that concurrent login
		// attempts contend for - a brute-force attack is by definition concurrent - so all of them
		// run under this lock. The state object handed back by the cache is the very instance the
		// cache holds, so both the read and the mutation must be inside the same critical section.
		// Contention is irrelevant in practice: the work here is a dictionary lookup and a few field
		// assignments, against a login path that performs a database query and a deliberately slow
		// password hash.
		private readonly object lockObj = new object();

		// Consulted by every credential-verification entry point BEFORE the credential is checked.
		//
		// A false result means the attempt must be refused outright and no authentication attempted.
		// A true result reserves one attempt against both the account and the source address; the
		// caller MUST then finalise that reservation with exactly one of RegisterSuccess,
		// RegisterFailedAttempt or AbandonAttempt, which is why callers wrap the credential check in
		// try/finally. An outstanding reservation counts towards the threshold, so a burst of
		// concurrent requests cannot each slip past the check before any of them has recorded a
		// failure.
		//
		// A leaked reservation - one whose caller died before finalising - can only ever make this
		// service refuse more, never less, and is bounded rather than permanent: the entry holding it
		// expires with the counting window, so the reservation is released within WindowMinutes at
		// worst.
		public bool TryBeginAttempt(string username, string ipAddress)
		{
			var accountKey = BuildAccountKey(username);
			var addressKey = BuildAddressKey(ipAddress);
			var now = DateTime.UtcNow;

			lock (lockObj)
			{
				var account = GetState(accountKey, now);
				var address = GetState(addressKey, now);

				if (IsRefusing(account, MaxFailedAttemptsPerAccount, now))
					return false;

				if (IsRefusing(address, MaxFailedAttemptsPerAddress, now))
					return false;

				Reserve(accountKey, account, now);
				Reserve(addressKey, address, now);
				return true;
			}
		}

		// Finalises a reserved attempt whose credential was rejected. Records one failure against
		// the account and one against the source address, independently, and applies the
		// corresponding lockout as soon as either threshold is reached.
		public void RegisterFailedAttempt(string username, string ipAddress)
		{
			var now = DateTime.UtcNow;

			lock (lockObj)
			{
				RecordOutcome(BuildAccountKey(username), MaxFailedAttemptsPerAccount, failed: true, now: now);
				RecordOutcome(BuildAddressKey(ipAddress), MaxFailedAttemptsPerAddress, failed: true, now: now);
			}
		}

		// Finalises a reserved attempt that authenticated successfully, so a legitimate user is never
		// penalised for earlier mistyped passwords.
		//
		// The account counter is cleared outright, which is the mandated reset-on-success behaviour.
		// The address counter is only released - its failure count is deliberately preserved -
		// because clearing it would turn a single valid credential into a reset oracle: an attacker
		// holding one working account could authenticate every few guesses to wipe the address-level
		// spraying counter and then continue indefinitely. Preserving it costs a legitimate shared
		// address nothing, since that counter has five times the budget and expires with the window.
		public void RegisterSuccess(string username, string ipAddress)
		{
			var now = DateTime.UtcNow;

			lock (lockObj)
			{
				// Removing the entry releases this reservation and discards the account's failures in
				// one step. It also discards any other reservation outstanding against the same
				// account, which yields an attacker nothing: reaching this method at all required a
				// credential that already authenticates.
				cache.Remove(BuildAccountKey(username));

				RecordOutcome(BuildAddressKey(ipAddress), MaxFailedAttemptsPerAddress, failed: false, now: now);
			}
		}

		// Finalises a reserved attempt that could not be completed - the credential was never
		// actually judged, for instance because the datastore was unreachable. The reservation is
		// released without a failure being recorded, so an outage cannot lock out the entire user
		// base, and the reservation cannot leak either.
		public void AbandonAttempt(string username, string ipAddress)
		{
			var now = DateTime.UtcNow;

			lock (lockObj)
			{
				RecordOutcome(BuildAccountKey(username), MaxFailedAttemptsPerAccount, failed: false, now: now);
				RecordOutcome(BuildAddressKey(ipAddress), MaxFailedAttemptsPerAddress, failed: false, now: now);
			}
		}

		// Refusal predicate, evaluated under the caller's lock.
		//
		// Outstanding reservations are added to recorded failures so that concurrent attempts cannot
		// collectively exceed the budget: with a threshold of five, at most five attempts can be in
		// flight or already counted, and the sixth is refused.
		private static bool IsRefusing(LoginAttemptState state, int maxFailedAttempts, DateTime now)
		{
			if (state == null)
				return false;

			if (now < state.LockedOutUntilUtc)
				return true;

			return (state.FailedAttempts + state.AttemptsInFlight) >= maxFailedAttempts;
		}

		// Takes out one reservation against a key, under the caller's lock. The state is passed in
		// already read - and therefore already normalised for a lapsed window by GetState - so that
		// the expiry rule is applied exactly once per operation and cannot diverge between the
		// refusal check and the reservation that follows it.
		private void Reserve(string key, LoginAttemptState state, DateTime now)
		{
			if (state == null)
				state = new LoginAttemptState();

			state.AttemptsInFlight += 1;
			Store(key, state, now);
		}

		// Releases one reservation against a key and, when the credential was rejected, records the
		// failure. Runs under the caller's lock.
		private void RecordOutcome(string key, int maxFailedAttempts, bool failed, DateTime now)
		{
			var state = GetState(key, now) ?? new LoginAttemptState();

			// Floored rather than simply decremented: the entry may have been evicted or expired
			// between the reservation and this call, in which case the count legitimately starts from
			// zero and must not go negative - a negative in-flight count would subtract from recorded
			// failures and silently raise the effective threshold.
			state.AttemptsInFlight = Math.Max(0, state.AttemptsInFlight - 1);

			if (failed)
			{
				if (now < state.LockedOutUntilUtc)
				{
					// A lockout was applied by a concurrent attempt while this one was in flight. The
					// counter is not advanced and the lockout is not extended: the existing entry
					// already carries the protection, and extending it on every further attempt would
					// let an attacker hold a real account locked out indefinitely.
				}
				else
				{
					// No stale-count reset is needed here: GetState has already cleared any window
					// whose lockout deadline has passed, so a lapsed lockout arrives as a zeroed
					// counter and this simply opens a fresh window.
					state.FailedAttempts += 1;
					if (state.FailedAttempts >= maxFailedAttempts)
						state.LockedOutUntilUtc = now.AddMinutes(WindowMinutes);
				}
			}

			Store(key, state, now);
		}

		// Reads the state for a key, normalised for the current time. Returns null when nothing is
		// tracked.
		//
		// This is the ONE place that knows when a counting window has ended, and every operation
		// reads through it. That matters: an earlier revision applied the rule inside the reservation
		// step instead, where it was unreachable, because the refusal check ran first and refused on
		// the stale failure count before the reservation could ever clear it. A principal whose
		// lockout had fully elapsed therefore stayed refused, and was only rescued by the cache entry
		// happening to expire on the same schedule - a coincidence, not a guarantee, since Store
		// deliberately extends an entry's lifetime to outlive the lockout it carries. Applying the
		// rule at the single read path makes recovery a property of the logic rather than of cache
		// timing, and leaves no unreachable safety branch behind.
		private LoginAttemptState GetState(string key, DateTime now)
		{
			LoginAttemptState state;
			if (!cache.TryGetValue(key, out state) || state == null)
				return null;

			// A window whose lockout deadline has passed is spent: its failures must stop refusing
			// anything, or the principal would remain locked out after serving the lockout it earned.
			// Clearing the deadline too is what makes the next failure open a fresh window instead of
			// re-locking the principal on a single attempt.
			if (state.LockedOutUntilUtc != DateTime.MinValue && now >= state.LockedOutUntilUtc)
			{
				state.FailedAttempts = 0;
				state.LockedOutUntilUtc = DateTime.MinValue;
			}

			return state;
		}

		// Writes the state back under the caller's lock.
		private void Store(string key, LoginAttemptState state, DateTime now)
		{
			// Fail-safe invariant. The failure count, the outstanding reservations and the lockout
			// deadline live in ONE cache entry, so nothing can drop the lockout while preserving the
			// counter, nor the reverse. The entry is additionally kept for at least as long as any
			// lockout it carries, so expiry can never release a locked-out principal early.
			var lifetime = TimeSpan.FromMinutes(WindowMinutes);
			var remainingLockout = state.LockedOutUntilUtc - now;
			if (remainingLockout > lifetime)
				lifetime = remainingLockout;

			// An explicit absolute expiration is mandatory: without one the entry would never expire
			// and a user who failed five logins would remain locked out permanently. Re-writing it on
			// every recorded attempt means the window is measured from the most recent attempt, which
			// is stricter than a fixed window - an attacker pacing attempts cannot age the counter out
			// from under itself - while for a legitimate user it only means the counter lives slightly
			// longer before self-clearing.
			//
			// Size is mandatory too, because the cache above declares a SizeLimit; every entry counts
			// as one tracked principal.
			//
			// Priority is what keeps eviction from becoming a bypass. When the ceiling is reached the
			// cache discards the lowest-priority entries first, so an in-force lockout is stored High
			// while a still-counting entry is stored Low: flooding the store with fabricated
			// usernames evicts other attackers' partial counts long before it releases anyone's
			// lockout. NeverRemove is deliberately NOT used - it would exempt lockout entries from the
			// ceiling entirely and hand back the unbounded growth this store exists to prevent. The
			// residual is bounded and accepted: displacing a specific account's partial count costs
			// the attacker a full store turnover, tens of thousands of requests against a transport
			// rate limiter, to buy back at most four guesses.
			var options = new MemoryCacheEntryOptions
			{
				AbsoluteExpirationRelativeToNow = lifetime,
				Size = 1,
				Priority = (state.LockedOutUntilUtc > now) ? CacheItemPriority.High : CacheItemPriority.Low
			};

			cache.Set(key, state, options);
		}

		// The two dimensions are counted independently, under separate keys.
		//
		// A combined username-and-address key - which is what this service originally used - is
		// bypassable from both directions: rotating the source address hands the attacker a fresh
		// budget for the SAME account, so a targeted account is never locked, and rotating the
		// username hands them a fresh budget from the same address. Counting each dimension on its
		// own key closes both, because a failure now advances the account counter regardless of where
		// it came from, and the address counter regardless of which account it named.
		private static string BuildAccountKey(string username)
		{
			return AccountKeyPrefix + Normalize(username);
		}

		private static string BuildAddressKey(string ipAddress)
		{
			return AddressKeyPrefix + Normalize(ipAddress);
		}

		// Malformed input must never turn into a denial of service on the login path, so values are
		// normalised defensively here and every public member is non-throwing by construction: the
		// key is always a non-empty string, the counters are bounded by their thresholds because they
		// stop advancing once a lockout is in force, and the computed expiration is always positive.
		private static string Normalize(string value)
		{
			if (string.IsNullOrWhiteSpace(value))
				return MissingValuePlaceholder;

			// Upper-cased rather than lower-cased because uppercase is the round-trip-safe invariant
			// normalisation form, so two spellings of the same principal cannot end up on separate
			// counters. The value is only ever a cache key and is never displayed.
			var normalized = value.Trim().ToUpperInvariant();
			if (normalized.Length > MaxKeyComponentLength)
				normalized = normalized.Substring(0, MaxKeyComponentLength);

			return normalized;
		}

		// Releases the owned cache. Called by the dependency-injection container when the application
		// shuts down, since this service is registered as a singleton.
		public void Dispose()
		{
			cache.Dispose();
			GC.SuppressFinalize(this);
		}

		// The counter has to be a reference type so that it can be mutated in place while the cache
		// holds it, under the service's lock, rather than being copied in and out.
		private sealed class LoginAttemptState
		{
			// Failures already judged and recorded.
			public int FailedAttempts { get; set; }

			// Attempts reserved but not yet finalised. Counted towards the threshold so that a
			// concurrent burst cannot collectively exceed it.
			public int AttemptsInFlight { get; set; }

			// DateTime.MinValue, the default, means no lockout is in force.
			public DateTime LockedOutUntilUtc { get; set; }
		}
	}
}
