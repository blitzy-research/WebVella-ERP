using System;
using System.Globalization;
using Microsoft.Extensions.Caching.Memory;
using Newtonsoft.Json;
using WebVella.Erp.Database;

namespace WebVella.Erp.Web.Services
{
	// SECURITY H-16, CWE-307 (improper restriction of excessive authentication attempts), OWASP A07: no lockout
	// mechanism existed anywhere in the platform, so every credential-verification entry point accepted an
	// unlimited number of attempts and was open to credential stuffing and brute-force guessing. This service is
	// the application-level account lockout; transport-level rate limiting is a separate, complementary layer
	// configured in the host pipelines.
	//
	// Three bypass routes are closed here, each a way the lockout could be evaded rather than a separate feature:
	//   * CWE-367 (time-of-check/time-of-use). Check-then-authenticate-then-count lets every request in a
	//     concurrent burst observe the same pre-attack counter and pass, so the threshold never trips under
	//     exactly the load it exists to stop. Callers therefore RESERVE an attempt before authenticating and
	//     finalise it afterwards, and outstanding reservations count towards the threshold.
	//   * CWE-770 (allocation without limits). The counters are keyed partly by a caller-supplied value, so an
	//     attacker varying the username can mint unbounded distinct keys. Growth is bounded by EXPIRY rather than
	//     by capacity, which also means a fabricated key cannot displace a real account's counter.
	//   * Source-address rotation. A combined username-and-address key hands an attacker with a proxy pool a
	//     fresh budget per address for the same account, so the two dimensions are counted INDEPENDENTLY.
	//
	// THE COUNTERS ARE DURABLE AND SHARED, AND THAT IS THE FIX. A process-local, size-bounded MemoryCache defeated
	// the mandated five-attempt guarantee three ways: a restart discarded every counter and every in-force
	// lockout; a second instance behind a load balancer counted independently, making the effective budget five
	// failures PER INSTANCE; and capacity eviction of a partial count let fabricated usernames displace a target
	// account's count, repeatable indefinitely. State therefore lives in Database/DbSecurityStateRepository:
	// durable across restarts, shared by every instance against the same database, ATOMIC per key, and reclaimed
	// BY EXPIRY ONLY, so no live counter or lockout can be evicted. No schema change and no new dependency.
	//
	// AND IT FAILS CLOSED. When the durable store cannot be consulted, TryBeginAttempt REFUSES the attempt. That
	// costs nothing real - credential verification reads the user from the same database - and the alternative,
	// allowing an unmetered attempt whenever the counter is unavailable, is how an outage becomes an unlimited
	// guessing window. Sealed deliberately: the lockout invariants below are only sound if no subclass can widen
	// them.
	public sealed class LoginThrottleService : IDisposable
	{
		// "Account lockout after 5 failed attempts" is the literal value mandated by the
		// Authentication Hardening standard: once five failures are recorded against an account the
		// sixth attempt is refused without authentication being attempted at all.
		private const int MaxFailedAttemptsPerAccount = 5;

		// The per-source-address budget is deliberately a MULTIPLE of the per-account one. It bounds password spraying
		// - many accounts tried once each from one source, which never trips a per-account counter - without locking
		// out shared egress: a NAT gateway, proxy or VPN concentrator presents one address for many legitimate users,
		// so a budget equal to the account threshold would let five mistyped passwords lock out the whole site for it.
		private const int MaxFailedAttemptsPerAddress = MaxFailedAttemptsPerAccount * 5;

		// Length of the failure-counting window and of the resulting lockout, in minutes. Both use the same value so a
		// lockout can never outlive the entry that records it. Deliberately not configurable - a configuration surface
		// would exceed the remediation - and bounded rather than held until an administrator intervenes, which is what
		// keeps the mandated lockout from becoming a denial-of-service primitive against a known account.
		private const double WindowMinutes = 15;

		// Upper bound applied to each key component. A caller-supplied value can be arbitrarily long, and bounding it
		// keeps the key and its memory footprint predictable. Truncation can only merge two principals onto one
		// counter, which throttles more rather than less, so it errs in the safe direction.
		private const int MaxKeyComponentLength = 128;

		// Namespaced so throttle entries cannot collide with any other consumer's durable-store keys, and separated by
		// dimension so an account counter and an address counter can never alias - an account named after an IP address
		// must not share a counter with that address. Both sit inside the reserved security namespace, so this
		// control's reclamation sweep can never reach another control's rows or a plugin's own row.
		private const string AccountKeyPrefix = DbSecurityStateRepository.ReservedKeyPrefix + "lthr_acct_";
		private const string AddressKeyPrefix = DbSecurityStateRepository.ReservedKeyPrefix + "lthr_addr_";

		// Substituted for a missing username or address so that a malformed request is still
		// counted against a stable, non-empty key instead of failing.
		private const string MissingValuePlaceholder = "(unspecified)";

		// Number of suppressed refusals after which another audit record is emitted for the same source address - see
		// TryClaimRefusalAudit, whose scope is the anonymous bearer-token refresh route alone. Without an interval the
		// suppressed count, which is carried into the NEXT audited refusal, would expire with the entry when a flood
		// stopped mid-window and never be recorded at all - the amplification gone and the evidence with it.
		private const int RefusalAuditSuppressionInterval = 100;

		// THE COUNTERS HAVE NO IN-PROCESS COPY AND THERE IS NO IN-PROCESS LOCK, and both absences are the control
		// rather than a simplification. Every transition below is a single atomic read-modify-write inside the durable
		// store, which serialises concurrent mutation of one key across every process; a local lock could only
		// serialise the instance that received the request, which is exactly why a process-local counter enforced five
		// failures per instance instead of five in total. A COUNT is never cached, because a count read from a stale
		// local copy permits attempts it should have refused.
		//
		// THE ONE THING MIRRORED LOCALLY IS AN IN-FORCE LOCKOUT, AND ONLY POSITIVELY. Once the store has said "locked
		// out until T", that answer cannot change back before T, so a hit here can only ever REFUSE a key that is
		// already refused: it can never authorise an attempt, never mask a lockout another instance recorded (a miss
		// always consults the store), and never outlive the fact it mirrors, because the entry's absolute expiration
		// IS T. Eviction under the size ceiling is harmless - the next request re-learns the same answer from the
		// database - which is the opposite of a cached partial COUNT, whose eviction would hand the budget back.
		private readonly MemoryCache activeLockouts = new MemoryCache(new MemoryCacheOptions
		{
			SizeLimit = MaxMirroredLockouts,
			CompactionPercentage = EvictionCompactionPercentage
		});

		// Ceiling on mirrored lockouts, and the fraction discarded when it is reached. Both are
		// housekeeping numbers rather than security ones - see the field above for why eviction here
		// cannot weaken the control.
		private const long MaxMirroredLockouts = 20000;
		private const double EvictionCompactionPercentage = 0.2;

		// Consulted by every credential-verification entry point BEFORE the credential is checked.
		//
		// A false result means the attempt must be refused outright and no authentication attempted. A true result
		// reserves one attempt against both the account and the source address, and the caller MUST finalise that
		// reservation exactly once - RegisterSuccess or RegisterFailedAttempt on the outcome branch, or AbandonAttempt
		// if the attempt threw before an outcome was reached. An outstanding reservation counts towards the threshold,
		// so a burst of concurrent requests cannot each slip past the check before any has recorded a failure
		// (CWE-367). A leaked reservation can only make this service refuse MORE, and expires with the window.
		//
		// THE TWO DIMENSIONS ARE RESERVED IN TWO SEPARATE ATOMIC OPERATIONS, because the store's unit of atomicity is
		// one row. Each check-and-reserve is indivisible for its own key - the property that makes the threshold hold
		// under a concurrent burst and across instances - and the composition is made safe by ORDER and COMPENSATION:
		// the account dimension is taken first, and if the address dimension refuses, the account reservation is
		// released before returning. The worst outcome between the two is a released-late reservation, which refuses
		// MORE rather than less. FAILS CLOSED: a store that cannot be consulted refuses the attempt.
		public bool TryBeginAttempt(string username, string ipAddress)
		{
			var accountKey = BuildAccountKey(username);
			var addressKey = BuildAddressKey(ipAddress);

			if (!TryReserve(accountKey, MaxFailedAttemptsPerAccount))
				return false;

			if (!TryReserve(addressKey, MaxFailedAttemptsPerAddress))
			{
				// The account reservation must not outlive a refusal it did not cause. Released with the same non-failure
				// finalisation an abandoned attempt uses, so the account's failure count is untouched: the caller was refused
				// by the ADDRESS budget and must not also be charged a failure against the account it named.
				RecordOutcome(accountKey, MaxFailedAttemptsPerAccount, failed: false);
				return false;
			}

			return true;
		}

		// Finalises a reserved attempt whose credential was rejected. Records one failure against
		// the account and one against the source address, independently, and applies the
		// corresponding lockout as soon as either threshold is reached.
		public void RegisterFailedAttempt(string username, string ipAddress)
		{
			RecordOutcome(BuildAccountKey(username), MaxFailedAttemptsPerAccount, failed: true);
			RecordOutcome(BuildAddressKey(ipAddress), MaxFailedAttemptsPerAddress, failed: true);
		}

		// Finalises a reserved attempt that authenticated successfully, so a legitimate user is never penalised for
		// earlier mistyped passwords. The account counter is cleared outright, the mandated reset-on-success behaviour.
		// The address counter is only RELEASED and its failure count deliberately preserved, because clearing it would
		// let an attacker holding one working account authenticate every few guesses to wipe the spraying counter.
		public void RegisterSuccess(string username, string ipAddress)
		{
			// Deleting the row releases this reservation and discards the account's failures in one step. It also discards
			// any other reservation outstanding against the same account, which yields an attacker nothing: reaching this
			// method at all required a credential that already authenticates.
			DbSecurityStateRepository.TryMutate(BuildAccountKey(username), _ => DbSecurityStateMutation.Delete());

			RecordOutcome(BuildAddressKey(ipAddress), MaxFailedAttemptsPerAddress, failed: false);
		}

		// Finalises a reserved attempt that could not be completed - the credential was never actually judged, for
		// instance because the datastore was unreachable. The reservation is released without a failure being recorded,
		// so an outage cannot lock out the entire user base, and the reservation cannot leak either.
		public void AbandonAttempt(string username, string ipAddress)
		{
			RecordOutcome(BuildAccountKey(username), MaxFailedAttemptsPerAccount, failed: false);
			RecordOutcome(BuildAddressKey(ipAddress), MaxFailedAttemptsPerAddress, failed: false);
		}

		// Decides whether a REFUSAL should be written to the audit trail, and reports how many refusals from the same
		// source were suppressed since the last one that was.
		//
		// THREAT ADDRESSED - CWE-778 read in the other direction, plus the audit-amplification half of OWASP A09. The
		// refusal path is reached without authenticating and costs the attacker almost nothing, so auditing every
		// refused request let an already-locked-out caller write rows into system_log at request rate: the evidence of
		// the original lockout is buried, the table grows at attacker-chosen speed, and the cheap refusal becomes the
		// expensive operation.
		//
		// COALESCED ON THE SOURCE ADDRESS, deliberately. Not on the username, which is the dimension an attacker
		// varies for free and would restore amplification in full, nor on username-and-address for the same reason.
		// The address is the dimension that costs something to change.
		//
		// SCOPE: this serves ONLY the anonymous bearer-token refresh route, where the refused request names no
		// principal, so a refusal is aggregate telemetry about a source rather than an authentication outcome about an
		// account. It is deliberately NOT used by the interactive login page, where a refusal IS an outcome against a
		// named principal: sampling those would break the property the trail is read for, because its cardinality
		// would no longer match the attempt cardinality. That page writes one bounded record per refusal, with volume
		// bounded at the transport by the framework's global fixed-window limiter. Do NOT reintroduce this claim on a
		// path that has a principal to attribute. Non-throwing by construction, like every member here.
		public bool TryClaimRefusalAudit(string ipAddress, out int suppressedRefusals)
		{
			suppressedRefusals = 0;

			var addressKey = BuildAddressKey(ipAddress);
			int claimed = 0;
			bool audit = false;
			DateTime observedLockout = DateTime.MinValue;

			// One atomic mutation, so two concurrent refusals from the same source cannot both claim the same audit slot,
			// which two instances under an in-process lock could, producing the amplification the coalescing exists to
			// prevent. A store fault means the claim CANNOT be recorded and the caller is told not to write: an unrecorded
			// claim would let every subsequent refusal claim again, so failing towards silence is what bounds the log.
			bool recorded = MutateState(addressKey, (state, now) =>
			{
				// This method is only ever reached after a refusal, so the record it reads is the one most likely to carry a
				// live lockout. Noting the deadline here keeps the positive-only mirror warm on exactly the hot path - a source
				// hammering while already locked out - so those requests stop costing a row-locked transaction each.
				observedLockout = state.LockedOutUntilUtc;

				// First refusal of this window from this source: audit it, and carry forward anything
				// suppressed during the previous window so no volume is lost across the boundary.
				if (!state.RefusalAuditClaimed)
				{
					state.RefusalAuditClaimed = true;
					claimed = state.SuppressedRefusalAudits;
					state.SuppressedRefusalAudits = 0;
					audit = true;
					return true;
				}

				// Saturating rather than wrapping. An increment that overflowed would make the reported
				// volume negative, which is worse than a count that stops rising: the interval below
				// means a saturated counter is unreachable in practice anyway.
				if (state.SuppressedRefusalAudits < int.MaxValue)
					state.SuppressedRefusalAudits += 1;

				if (state.SuppressedRefusalAudits >= RefusalAuditSuppressionInterval)
				{
					claimed = state.SuppressedRefusalAudits;
					state.SuppressedRefusalAudits = 0;
					audit = true;
				}

				return true;
			});

			MirrorLockout(addressKey, observedLockout);

			if (!recorded)
				return false;

			suppressedRefusals = claimed;
			return audit;
		}

		// Refusal predicate for an entry point that has no account dimension at all - specifically the anonymous
		// bearer-token REFRESH route, which presents a token and no username.
		//
		// SECURITY H-16, CWE-307, on a path the account-based lockout structurally cannot cover: the refresh route is
		// [AllowAnonymous] and validates a caller-supplied token, so before this it accepted unlimited attempts and a
		// token-forgery or expired-token replay campaign was bounded only by the transport rate limiter. Only the
		// source-address budget applies, because there is no principal to attribute an attempt to until the token
		// validates. Read-only - it neither reserves nor records - and it FAILS CLOSED, because an unreadable counter
		// must not read as an empty one. The route now reserves through TryBeginAddressAttempt instead; this member
		// and RegisterAddressFailure remain because both are public members of a public type.
		public bool IsAddressRefusing(string ipAddress)
		{
			var addressKey = BuildAddressKey(ipAddress);
			var now = DateTime.UtcNow;

			if (activeLockouts.TryGetValue(addressKey, out _))
				return true;

			if (!TryReadState(addressKey, out LoginAttemptState state))
				return true;

			if (IsRefusing(state, MaxFailedAttemptsPerAddress, now))
			{
				MirrorLockout(addressKey, state.LockedOutUntilUtc);
				return true;
			}

			return false;
		}

		// Reserves one attempt against the source address alone, for an entry point that has no account dimension -
		// the anonymous bearer-token REFRESH route.
		//
		// SECURITY H-16, CWE-307 read together with CWE-367 (time-of-check/time-of-use). The refresh route used the
		// check-then-act pair above, so a concurrent burst could collectively overshoot the address budget by the size
		// of the burst before any member of it had recorded a failure; a reservation must be taken BEFORE the
		// validation work an attempt causes. One atomic check-and-reserve, exactly like the account dimension of
		// TryBeginAttempt. A true result MUST be finalised exactly once with FinishAddressAttempt. FAILS CLOSED.
		public bool TryBeginAddressAttempt(string ipAddress)
		{
			return TryReserve(BuildAddressKey(ipAddress), MaxFailedAttemptsPerAddress);
		}

		// Finalises a reservation taken by TryBeginAddressAttempt: records the failure when
		// <paramref name="failed"/> is true, and releases the reservation either way.
		public void FinishAddressAttempt(string ipAddress, bool failed)
		{
			RecordOutcome(BuildAddressKey(ipAddress), MaxFailedAttemptsPerAddress, failed);
		}

		// Records one failure against the source address WITHOUT a prior reservation, for the same account-less entry
		// point IsAddressRefusing serves.
		//
		// WHY THIS IS NOT RegisterFailedAttempt: that method finalises a reservation, so it decrements
		// AttemptsInFlight. Called without a matching TryBeginAttempt it would decrement a reservation belonging to a
		// CONCURRENT login attempt on the same address, and because IsRefusing counts reservations towards the budget,
		// every such decrement would silently raise the effective threshold - a throttle bypass introduced by the
		// throttle itself. This path touches only the failure count and the lockout deadline.
		//
		// RESIDUAL, documented rather than hidden: this is check-then-act rather than reserve-then-finalise, so a
		// concurrent burst can collectively exceed the address budget once by up to its own size before the lockout
		// takes effect. Accepted: reserve-then-finalise exists to GATE work that FOLLOWS the check, whereas this
		// records a failure that has already happened, and the transport limiter caps how large a burst can be.
		public void RegisterAddressFailure(string ipAddress)
		{
			RecordUnreservedFailure(BuildAddressKey(ipAddress), MaxFailedAttemptsPerAddress);
		}

		// Refusal predicate, evaluated under the caller's lock. Outstanding reservations are added to recorded failures
		// so that concurrent attempts cannot collectively exceed the budget: with a threshold of five, at most five
		// attempts can be in flight or already counted, and the sixth is refused.
		private static bool IsRefusing(LoginAttemptState state, int maxFailedAttempts, DateTime now)
		{
			if (state == null)
				return false;

			if (now < state.LockedOutUntilUtc)
				return true;

			return (state.FailedAttempts + state.AttemptsInFlight) >= maxFailedAttempts;
		}

		// Atomically tests the refusal predicate and, if it passes, takes out one reservation against a key. ONE durable
		// mutation, so the test and the reservation cannot be separated by a concurrent attempt on any instance - the
		// property that makes the mandated threshold hold rather than merely be written down. Returns false both when
		// the key is refusing and when the store could not be reached: both mean "do not verify a credential now".
		private bool TryReserve(string key, int maxFailedAttempts)
		{
			// Short-circuit on a lockout this process has already been told about. Positive-only, so this
			// can only refuse an attempt the durable store would also refuse.
			if (activeLockouts.TryGetValue(key, out _))
				return false;

			bool reserved = false;
			DateTime observedLockout = DateTime.MinValue;

			bool recorded = MutateState(key, (state, now) =>
			{
				if (IsRefusing(state, maxFailedAttempts, now))
				{
					observedLockout = state.LockedOutUntilUtc;
					return true;
				}

				state.AttemptsInFlight += 1;
				reserved = true;
				return true;
			});

			if (!reserved)
				MirrorLockout(key, observedLockout);

			return recorded && reserved;
		}

		// Releases one reservation against a key and, when the credential was rejected, records the
		// failure. One atomic durable mutation.
		private void RecordOutcome(string key, int maxFailedAttempts, bool failed)
		{
			DateTime appliedLockout = DateTime.MinValue;

			MutateState(key, (state, now) =>
			{
				// Floored rather than simply decremented: the entry may have expired between the reservation and this call, in
				// which case the count legitimately starts from zero and must not go negative - a negative in-flight count
				// would subtract from recorded failures and silently raise the effective threshold.
				state.AttemptsInFlight = Math.Max(0, state.AttemptsInFlight - 1);

				if (failed)
				{
					if (now < state.LockedOutUntilUtc)
					{
						// A lockout was applied by a concurrent attempt while this one was in flight. The counter is not advanced and
						// the lockout is not extended: the existing entry already carries the protection, and extending it on every
						// further attempt would let an attacker hold a real account locked out indefinitely.
					}
					else
					{
						// No stale-count reset is needed here: Normalize has already cleared any window
						// whose lockout deadline has passed, so a lapsed lockout arrives as a zeroed
						// counter and this simply opens a fresh window.
						state.FailedAttempts += 1;
						if (state.FailedAttempts >= maxFailedAttempts)
						{
							state.LockedOutUntilUtc = now.AddMinutes(WindowMinutes);
							appliedLockout = state.LockedOutUntilUtc;
						}
					}
				}

				return true;
			});

			MirrorLockout(key, appliedLockout);
		}

		// Records a failure against a key that was never reserved. Identical to the failure half of RecordOutcome minus
		// the reservation release - see RegisterAddressFailure for why releasing a reservation this caller never took
		// would be a throttle bypass. The two share no code on purpose: factoring the common half out would leave a
		// helper whose correctness depends on the caller having got the reservation accounting right elsewhere, which
		// is exactly the coupling that produced the hazard.
		private void RecordUnreservedFailure(string key, int maxFailedAttempts)
		{
			DateTime appliedLockout = DateTime.MinValue;

			MutateState(key, (state, now) =>
			{
				if (now < state.LockedOutUntilUtc)
				{
					// A lockout is already in force. The counter is not advanced and the deadline is not
					// extended, for the same reason as in RecordOutcome: extending it on every further
					// attempt would let an attacker pin a shared source address in lockout indefinitely.
				}
				else
				{
					// Normalize has already cleared any window whose deadline has passed, so a lapsed
					// lockout arrives zeroed and this opens a fresh window.
					state.FailedAttempts += 1;
					if (state.FailedAttempts >= maxFailedAttempts)
					{
						state.LockedOutUntilUtc = now.AddMinutes(WindowMinutes);
						appliedLockout = state.LockedOutUntilUtc;
					}
				}

				return true;
			});

			MirrorLockout(key, appliedLockout);
		}

		// Records an in-force lockout in the positive-only local mirror. A deadline that is absent or
		// already past is not mirrored, so the mirror can never hold an entry that outlives the lockout it
		// represents - its absolute expiration is that deadline exactly.
		private void MirrorLockout(string key, DateTime lockedOutUntilUtc)
		{
			if (lockedOutUntilUtc <= DateTime.UtcNow)
				return;

			activeLockouts.Set(key, true, new MemoryCacheEntryOptions
			{
				AbsoluteExpiration = new DateTimeOffset(lockedOutUntilUtc, TimeSpan.Zero),
				Size = 1,
				Priority = CacheItemPriority.High
			});
		}

		// Reads the state for a key from the durable store, normalised for the current time. Returns false when the
		// store could not be consulted at all, which every caller treats as a refusal. A true result with a default
		// state means "nothing is tracked", a different answer that must stay distinguishable from the first.
		private static bool TryReadState(string key, out LoginAttemptState state)
		{
			state = new LoginAttemptState();

			if (!DbSecurityStateRepository.TryRead(key, out string payload))
				return false;

			state = Normalize(Deserialize(payload), DateTime.UtcNow);
			return true;
		}

		// Applies an atomic read-modify-write to the state for a key, and stores the result with an expiry guaranteed
		// to outlive any lockout it carries. INVARIANT: the failure count, the outstanding reservations and the lockout
		// deadline live in ONE record, so nothing can drop the lockout while preserving the counter, nor the reverse.
		// The window-lapse rule is applied in exactly one place - Normalize, called here - so recovery from a lockout
		// is a property of the LOGIC rather than of storage timing, and expiry can never release a principal early.
		private static bool MutateState(string key, Func<LoginAttemptState, DateTime, bool> mutate)
		{
			return DbSecurityStateRepository.TryMutate(key, payload =>
			{
				DateTime now = DateTime.UtcNow;
				LoginAttemptState state = Normalize(Deserialize(payload), now);

				if (!mutate(state, now))
					return DbSecurityStateMutation.Delete();

				// Re-measured from the most recent attempt, which is stricter than a fixed window: an
				// attacker pacing attempts cannot age the counter out from under itself. Extended to
				// outlive an in-force lockout so expiry can never end one early.
				TimeSpan lifetime = TimeSpan.FromMinutes(WindowMinutes);
				TimeSpan remainingLockout = state.LockedOutUntilUtc - now;
				if (remainingLockout > lifetime)
					lifetime = remainingLockout;

				return DbSecurityStateMutation.Store(JsonConvert.SerializeObject(state, StorageSerializerSettings), now.Add(lifetime));
			});
		}

		// Serialisation settings for the stored record: invariant culture and unambiguous UTC handling, supplied
		// explicitly rather than inherited.
		//
		// AND THE RECORD ITSELF CARRIES NO DateTime, WHICH IS THE REAL DEFENCE. Explicit settings are not sufficient
		// alone, because JsonConvert.SerializeObject with a settings argument resolves through
		// JsonSerializer.CreateDefault, so the CONVERTERS in JsonConvert.DefaultSettings still apply - and all seven
		// hosts register ErpDateTimeJsonConverter globally, which renders a DateTime in the installation's configured
		// display time zone and drops the UTC marker. A deadline computed in UTC would be written as an unmarked LOCAL
		// timestamp: self-consistent on ONE host, which is what makes it dangerous, but ambiguous in the stored text,
		// so two instances in different zones would disagree about when a lockout ends. The deadline is therefore
		// stored as UTC TICKS, a plain integer no converter can reinterpret, and these settings remain a second line
		// of defence over the record's remaining numeric fields.
		private static readonly JsonSerializerSettings StorageSerializerSettings = new JsonSerializerSettings
		{
			DateTimeZoneHandling = DateTimeZoneHandling.Utc,
			DateFormatHandling = DateFormatHandling.IsoDateFormat,
			DateParseHandling = DateParseHandling.DateTime,
			Culture = CultureInfo.InvariantCulture,
			Formatting = Formatting.None
		};

		// Reads a stored record, or a fresh one when nothing is stored. A payload this build cannot deserialise yields
		// a FRESH state rather than a fault or a lockout, deliberately: an unreadable counter must not lock an account
		// out on state nobody can interpret, and the cost of the other direction - restarting one principal's count -
		// is bounded by the window, whereas an uninterpretable permanent lockout is not.
		private static LoginAttemptState Deserialize(string payload)
		{
			if (string.IsNullOrWhiteSpace(payload))
				return new LoginAttemptState();

			try
			{
				return JsonConvert.DeserializeObject<LoginAttemptState>(payload, StorageSerializerSettings) ?? new LoginAttemptState();
			}
			catch (JsonException)
			{
				return new LoginAttemptState();
			}
		}

		// Applies the end-of-window rule. See MutateState for why this lives in exactly one place.
		private static LoginAttemptState Normalize(LoginAttemptState state, DateTime now)
		{
			if (state == null)
				return new LoginAttemptState();

			// A window whose lockout deadline has passed is spent: its failures must stop refusing anything, or the
			// principal would remain locked out after serving the lockout it earned. Clearing the deadline too is what
			// makes the next failure open a fresh window instead of re-locking the principal on a single attempt.
			if (state.LockedOutUntilUtc != DateTime.MinValue && now >= state.LockedOutUntilUtc)
			{
				state.FailedAttempts = 0;
				state.LockedOutUntilUtc = DateTime.MinValue;

				// The refusal-audit claim is released with the window that earned it, so a source that is locked out again
				// later is audited again rather than staying permanently silent. The suppressed count is deliberately PRESERVED
				// across this reset: it is reported by the next audited refusal, and clearing it here would discard the very
				// volume the coalescing exists to summarise. When the source simply stops, the record expires and the residual
				// count goes with it - which is why TryClaimRefusalAudit also reports on a fixed interval.
				state.RefusalAuditClaimed = false;
			}

			return state;
		}

		// The two dimensions are counted independently, under separate keys. A combined username-and-address key is
		// bypassable from both directions: rotating the source address hands the attacker a fresh budget for the SAME
		// account, so a targeted account is never locked, and rotating the username gives a fresh budget from one address.
		private static string BuildAccountKey(string username)
		{
			return AccountKeyPrefix + Normalize(username);
		}

		private static string BuildAddressKey(string ipAddress)
		{
			return AddressKeyPrefix + Normalize(ipAddress);
		}

		// Malformed input must never turn into a denial of service on the login path, so a null, empty or whitespace
		// value becomes a placeholder rather than a null key and no public member can fault on its input. This bounds
		// INPUT-driven failure only: storage faults never propagate, because every member treats them as a refusal.
		private static string Normalize(string value)
		{
			if (string.IsNullOrWhiteSpace(value))
				return MissingValuePlaceholder;

			// Upper-cased rather than lower-cased because uppercase is the round-trip-safe invariant
			// normalisation form, so two spellings of the same principal cannot end up on separate
			// counters. The value is only ever a storage key and is never displayed.
			var normalized = value.Trim().ToUpperInvariant();
			if (normalized.Length > MaxKeyComponentLength)
				normalized = normalized.Substring(0, MaxKeyComponentLength);

			return normalized;
		}

		// Releases the owned lockout mirror. Called by the dependency-injection container at shutdown, since this
		// service is a singleton. The COUNTERS need no release - they live in the durable store, which opens its
		// connections per operation - so what is disposed here is only the positive-only mirror described above.
		public void Dispose()
		{
			activeLockouts.Dispose();
			GC.SuppressFinalize(this);
		}

		// The record persisted for one counted principal, serialised as JSON into the durable store. A class rather
		// than a struct because the mutation callbacks above amend it in place. Property names are serialised as
		// written and never exposed, so no wire contract depends on them - but a rename is still a storage-format
		// change, and an unreadable record deliberately reads as a FRESH counter (see Deserialize).
		private sealed class LoginAttemptState
		{
			// Failures already judged and recorded.
			public int FailedAttempts { get; set; }

			// Attempts reserved but not yet finalised. Counted towards the threshold so that a
			// concurrent burst cannot collectively exceed it.
			public int AttemptsInFlight { get; set; }

			// The lockout deadline, stored as UTC ticks. Zero - the default - means no lockout is in force. AN INTEGER
			// RATHER THAN A DateTime, deliberately: see StorageSerializerSettings. A DateTime here was rewritten by the
			// platform's global JSON date converter into the host's display time zone with no marker, making the stored
			// deadline ambiguous between instances. Ticks cannot be reinterpreted by a converter, culture or time zone.
			public long LockedOutUntilUtcTicks { get; set; }

			// The deadline as an instant, for the logic above. Not serialised - LockedOutUntilUtcTicks is the stored form -
			// and always UTC, so every comparison in this file is against the same clock. A value whose ticks are zero
			// round-trips as DateTime.MinValue rather than being shifted, which is what the ticks test in the setter protects.
			[JsonIgnore]
			public DateTime LockedOutUntilUtc
			{
				get { return new DateTime(LockedOutUntilUtcTicks, DateTimeKind.Utc); }
				set
				{
					if (value.Ticks == 0)
						LockedOutUntilUtcTicks = 0;
					else if (value.Kind == DateTimeKind.Utc)
						LockedOutUntilUtcTicks = value.Ticks;
					else
						LockedOutUntilUtcTicks = value.ToUniversalTime().Ticks;
				}
			}

			// True once a refusal from this source has been written to the audit trail for the current window. Lives in the
			// SAME record as the counters above so a source cannot lose its counters while keeping its claim, or the
			// reverse. Only meaningful on address-dimension entries; the account-dimension entries never set it, because
			// coalescing on the username would restore the amplification this exists to bound.
			public bool RefusalAuditClaimed { get; set; }

			// Refusals from this source that were NOT audited because the claim above was already held.
			// Reported by, and cleared on, the next audited refusal, so coalescing bounds the number of
			// records without discarding the volume they would have represented.
			public int SuppressedRefusalAudits { get; set; }
		}
	}
}
