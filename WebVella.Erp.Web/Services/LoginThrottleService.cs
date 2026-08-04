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

		// Number of suppressed refusals after which another audit record is emitted for the same
		// source address - see TryClaimRefusalAudit.
		//
		// Coalescing refusal audits without this would trade one defect for another. The suppressed
		// count is carried into the NEXT audited refusal, so a flood that stops mid-window would have
		// its volume expire with the cache entry and never be recorded at all: the amplification would
		// be gone and so would the evidence. This interval guarantees that a sustained flood keeps
		// producing periodic, dated records, while bounding amplification to one record per hundred
		// refused requests rather than one per request.
		private const int RefusalAuditSuppressionInterval = 100;

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
		// A true result reserves one attempt against both the account and the source address, and the
		// caller MUST then finalise that reservation exactly once - RegisterSuccess or
		// RegisterFailedAttempt on the outcome branch, or AbandonAttempt if the attempt threw before an
		// outcome was reached. An outstanding reservation counts towards the threshold, so a burst of
		// concurrent requests cannot each slip past the check before any of them has recorded a failure.
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

		// Decides whether a REFUSAL should be written to the audit trail, and reports how many
		// refusals from the same source were suppressed since the last one that was.
		//
		// Threat addressed - CWE-778 read in the other direction, plus the audit-amplification half of
		// OWASP A09:2021. The refusal path is reached without authenticating and costs the attacker
		// almost nothing, so auditing every refused request let a caller who had already been locked
		// out keep writing rows into system_log at request rate. Three consequences, all bad: the
		// evidence of the original lockout is buried under thousands of near-identical rows, the log
		// table grows at attacker-chosen speed, and each row is a database write the refusal path did
		// not otherwise need - so the cheap refusal became the expensive operation.
		//
		// COALESCED ON THE SOURCE ADDRESS, deliberately, and this choice is the whole design:
		//   * Not on the username. That is the dimension the attacker varies for free, so a claim per
		//     username would restore amplification in full - one row per fabricated name.
		//   * Not on username-and-address either, for the same reason.
		//   * The address is the dimension that costs something to change. A genuinely new source
		//     deserves its own record, and obtaining one requires a proxy pool rather than a different
		//     string in a form field.
		//
		// Login refusals and token-route refusals share one claim per address, which is also
		// deliberate: an attacker alternating between the two must not be able to double the audit
		// volume. The first record identifies which route tripped, and the suppressed count aggregates
		// everything after it - the actionable datum in every case is the source, not the route.
		//
		// Returns true when the caller should write an audit record, with suppressedRefusals set to the
		// number of refusals suppressed since the previous audited one - report it in that record, then
		// it is cleared. Returns false when the caller should write nothing.
		//
		// Non-throwing by construction, like every other member here: a null or blank address
		// normalises to a stable placeholder key, and no arithmetic below can overflow.
		public bool TryClaimRefusalAudit(string ipAddress, out int suppressedRefusals)
		{
			suppressedRefusals = 0;

			var addressKey = BuildAddressKey(ipAddress);
			var now = DateTime.UtcNow;

			lock (lockObj)
			{
				var state = GetState(addressKey, now) ?? new LoginAttemptState();

				// First refusal of this window from this source: audit it, and carry forward anything
				// suppressed during the previous window so no volume is lost across the boundary.
				if (!state.RefusalAuditClaimed)
				{
					state.RefusalAuditClaimed = true;
					suppressedRefusals = state.SuppressedRefusalAudits;
					state.SuppressedRefusalAudits = 0;
					Store(addressKey, state, now);
					return true;
				}

				// Saturating rather than wrapping. An increment that overflowed would make the reported
				// volume negative, which is worse than a count that stops rising: the interval below
				// means a saturated counter is unreachable in practice anyway.
				if (state.SuppressedRefusalAudits < int.MaxValue)
					state.SuppressedRefusalAudits += 1;

				if (state.SuppressedRefusalAudits >= RefusalAuditSuppressionInterval)
				{
					suppressedRefusals = state.SuppressedRefusalAudits;
					state.SuppressedRefusalAudits = 0;
					Store(addressKey, state, now);
					return true;
				}

				Store(addressKey, state, now);
				return false;
			}
		}

		// Refusal predicate for an entry point that has no account dimension at all - specifically the
		// anonymous bearer-token REFRESH route, which presents a token and no username.
		//
		// Threat addressed - finding H-16, CWE-307, on a path the account-based lockout structurally
		// cannot cover. The refresh route is [AllowAnonymous] and validates a caller-supplied token, so
		// before this it accepted unlimited attempts: a token-forgery or expired-token replay campaign
		// was bounded only by the transport rate limiter. Only the source-address budget applies here,
		// because there is no principal to attribute an attempt to until the token validates.
		//
		// Read-only: this neither reserves nor records. Pair it with RegisterAddressFailure.
		public bool IsAddressRefusing(string ipAddress)
		{
			var addressKey = BuildAddressKey(ipAddress);
			var now = DateTime.UtcNow;

			lock (lockObj)
			{
				return IsRefusing(GetState(addressKey, now), MaxFailedAttemptsPerAddress, now);
			}
		}

		// Records one failure against the source address WITHOUT a prior reservation, for the same
		// account-less entry point IsAddressRefusing serves.
		//
		// WHY THIS IS NOT RegisterFailedAttempt. That method finalises a reservation, so it decrements
		// AttemptsInFlight. Called without a matching TryBeginAttempt it would decrement a reservation
		// belonging to a CONCURRENT login attempt on the same address, and because IsRefusing counts
		// reservations towards the budget, every such decrement would silently raise the effective
		// threshold - a throttle bypass introduced by the throttle itself. The dedicated path below
		// touches only the failure count and the lockout deadline.
		//
		// RESIDUAL, documented rather than hidden: this is a check-then-act protocol, not the
		// reserve-then-finalise one the login path uses, so a concurrent burst can collectively exceed
		// the address budget once by up to the size of the burst before the lockout takes effect. That is
		// bounded and accepted. Reserve-then-finalise is not used because it exists to GATE work that
		// follows the check, whereas this entry point records a failure that has already happened - there
		// is no subsequent work and therefore nothing to finalise. The transport rate limiter already caps
		// how large a burst can be.
		public void RegisterAddressFailure(string ipAddress)
		{
			var now = DateTime.UtcNow;

			lock (lockObj)
			{
				RecordUnreservedFailure(BuildAddressKey(ipAddress), MaxFailedAttemptsPerAddress, now);
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

		// Records a failure against a key that was never reserved. Runs under the caller's lock.
		//
		// Identical to the failure half of RecordOutcome, minus the reservation release - see
		// RegisterAddressFailure for why releasing a reservation this caller never took would be a
		// throttle bypass. The two share no code on purpose: factoring the common half out would leave
		// a helper whose correctness depends on the caller having got the reservation accounting right
		// elsewhere, which is exactly the coupling that produced the hazard.
		private void RecordUnreservedFailure(string key, int maxFailedAttempts, DateTime now)
		{
			var state = GetState(key, now) ?? new LoginAttemptState();

			if (now < state.LockedOutUntilUtc)
			{
				// A lockout is already in force. The counter is not advanced and the deadline is not
				// extended, for the same reason as in RecordOutcome: extending it on every further
				// attempt would let an attacker pin a shared source address in lockout indefinitely.
			}
			else
			{
				// GetState has already cleared any window whose deadline has passed, so a lapsed
				// lockout arrives zeroed and this opens a fresh window.
				state.FailedAttempts += 1;
				if (state.FailedAttempts >= maxFailedAttempts)
					state.LockedOutUntilUtc = now.AddMinutes(WindowMinutes);
			}

			Store(key, state, now);
		}

		// Reads the state for a key, normalised for the current time. Returns null when nothing is
		// tracked.
		//
		// INVARIANT: this is the ONE place that knows when a counting window has ended, and every
		// operation reads through it. Applying the rule here rather than inside any individual operation
		// is what makes recovery from a lockout a property of the LOGIC rather than of cache timing -
		// Store deliberately extends an entry's lifetime to outlive the lockout it carries, so eviction
		// must never be what releases a principal. Do not duplicate this rule into a caller.
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

				// The refusal-audit claim is released with the window that earned it, so a source that
				// is locked out again later is audited again rather than staying permanently silent.
				// The suppressed count is deliberately PRESERVED across this reset: it is reported by
				// the next audited refusal, and clearing it here would discard the very volume the
				// coalescing exists to summarise. When the source simply stops, the entry expires and
				// the residual count goes with it - which is why TryClaimRefusalAudit also reports on a
				// fixed interval rather than only at window boundaries.
				state.RefusalAuditClaimed = false;
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

			// An explicit absolute expiration is mandatory so that tracking state is RECLAIMED rather than
			// retained for the process lifetime. It is not what releases a lockout: GetState normalises a
			// window whose deadline has passed, so a principal recovers on the next read whether or not the
			// entry has been evicted, and the lifetime below is deliberately extended to OUTLIVE the lockout
			// it carries so eviction can never end one early. Re-writing it on every recorded attempt
			// measures the window from the most recent attempt, which is stricter than a fixed window - an
			// attacker pacing attempts cannot age the counter out from under itself.
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
		// normalised defensively here: a null, empty or whitespace value becomes a placeholder rather
		// than a null key, so no public member can fault on the input it was given. Counters stay bounded
		// by their thresholds because they stop advancing once a lockout is in force, and the computed
		// expiration is always positive. This bounds INPUT-driven failure only - it is not a claim that
		// the members cannot throw at all, since the underlying memory cache can still fault (for example
		// ObjectDisposedException during shutdown); callers must not rely on absolute non-throwing.
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

			// True once a refusal from this source has been written to the audit trail for the current
			// window. Lives in the SAME cache entry as the counters above so that a source cannot lose
			// its counters while keeping its claim, or the reverse - the fail-safe invariant Store
			// documents applies to this field too. Only meaningful on address-dimension entries; the
			// account-dimension entries never set it, because coalescing on the username would restore
			// the amplification this exists to bound.
			public bool RefusalAuditClaimed { get; set; }

			// Refusals from this source that were NOT audited because the claim above was already held.
			// Reported by, and cleared on, the next audited refusal, so coalescing bounds the number of
			// records without discarding the volume they would have represented.
			public int SuppressedRefusalAudits { get; set; }
		}
	}
}
