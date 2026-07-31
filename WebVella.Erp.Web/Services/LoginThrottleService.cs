using System;
using Microsoft.Extensions.Caching.Memory;
using WebVella.Erp.Web.Utils;

namespace WebVella.Erp.Web.Services
{
	// Threat addressed - finding H-16, CWE-307 (Improper Restriction of Excessive Authentication
	// Attempts), OWASP A07 Identification and Authentication Failures: no lockout mechanism existed
	// anywhere in the platform, so the login page accepted an unlimited number of authentication
	// attempts and was therefore open to credential stuffing and brute-force password guessing.
	// This service is the application-level account lockout. Transport-level rate limiting is a
	// separate, complementary layer configured in the host pipelines, not here.
	//
	// Scope limitation, documented rather than hidden: the backing store is an in-process cache, so
	// the protection is per-process only. A multi-instance or load-balanced deployment is NOT
	// protected by this service, because each process counts failures independently. Moving the
	// counters to a distributed backing store is a recorded recommendation and is deliberately not
	// built here.
	public class LoginThrottleService
	{
		// "Account lockout after 5 failed attempts" is the literal value mandated by the
		// Authentication Hardening standard: once five consecutive failures are recorded the sixth
		// attempt is refused without authentication being attempted at all.
		private const int MaxFailedAttempts = 5;

		// Length of the failure-counting window and of the resulting lockout, in minutes. Both use
		// the same value so a lockout can never outlive the entry that records it. Deliberately not
		// configurable - a configuration surface would exceed the remediation.
		private const double WindowMinutes = 15;

		// Upper bound applied to each key component. A caller-supplied value can be arbitrarily
		// long, and bounding it keeps the cache key and its memory footprint predictable.
		// Truncation can only merge two principals onto one counter, which throttles more rather
		// than less, so it errs in the safe direction.
		private const int MaxKeyComponentLength = 128;

		// Namespaced so throttle entries cannot collide with any other consumer's cache keys.
		private const string KeyPrefix = "wv_login_throttle_";

		// Substituted for a missing username or address so that a malformed request is still
		// counted against a stable, non-empty key instead of failing.
		private const string MissingValuePlaceholder = "(unspecified)";

		// The platform's existing in-process cache is the backing store because it is the least
		// invasive control available: it avoids both a database schema change and a new package
		// dependency. The instance is owned for the lifetime of this service, which is registered as
		// a singleton, so the counters survive across requests. It is never shared with, and never
		// mutates the behaviour of, any other cache in the application.
		private readonly Cache cache = new Cache();

		// Concurrent login attempts are the expected case - a brute-force attack is by definition
		// concurrent - and an unsynchronised read-modify-write of the counter would lose increments,
		// so the lockout would fail to trigger under exactly the load it exists to defend against.
		// The state object returned by the cache is the very instance the cache holds, so every read
		// and every mutation of it happens inside this lock.
		private readonly object lockObj = new object();

		// Consulted by Pages/login.cshtml.cs before authenticating. A true result means the attempt
		// must be refused without any authentication being attempted.
		public bool IsLockedOut(string username, string ipAddress)
		{
			var key = BuildKey(username, ipAddress);

			lock (lockObj)
			{
				var state = cache.Get<LoginAttemptState>(key);
				if (state == null)
				{
					return false;
				}

				return (state.FailedAttempts >= MaxFailedAttempts) && (DateTime.UtcNow < state.LockedOutUntilUtc);
			}
		}

		// Called by Pages/login.cshtml.cs when authentication fails. Records one failure against the
		// username and address pair and applies the lockout as soon as the threshold is reached.
		public void RegisterFailedAttempt(string username, string ipAddress)
		{
			var key = BuildKey(username, ipAddress);
			var now = DateTime.UtcNow;

			lock (lockObj)
			{
				var state = cache.Get<LoginAttemptState>(key);
				if (state == null)
				{
					state = new LoginAttemptState();
				}
				else if (now < state.LockedOutUntilUtc)
				{
					// Already locked out. The counter is not advanced and the lockout is not
					// extended: the existing entry already carries the protection, and extending it
					// on every further attempt would let an attacker keep a real account locked out
					// indefinitely.
					return;
				}
				else if (state.FailedAttempts >= MaxFailedAttempts)
				{
					// A previous lockout has run its full term, so the principal begins a fresh
					// counting window rather than being locked again by a single attempt.
					state = new LoginAttemptState();
				}

				state.FailedAttempts += 1;
				if (state.FailedAttempts >= MaxFailedAttempts)
				{
					state.LockedOutUntilUtc = now.AddMinutes(WindowMinutes);
				}

				Store(key, state, now);
			}
		}

		// Called by Pages/login.cshtml.cs after a successful authentication, so that a legitimate
		// user is never penalised for earlier mistyped passwords.
		public void Reset(string username, string ipAddress)
		{
			var key = BuildKey(username, ipAddress);

			lock (lockObj)
			{
				// Removal is by key: the cache exposes no public flush operation.
				cache.Remove(key);
			}
		}

		// Writes the state back under the caller's lock.
		private void Store(string key, LoginAttemptState state, DateTime now)
		{
			// Fail-closed invariant. The failure count and the lockout deadline live in one single
			// cache entry, so eviction can never drop the lockout while preserving the counter, nor
			// the reverse. The entry is additionally kept for at least as long as any lockout it
			// carries, so expiry can never release a locked-out principal early. Missing state is
			// consequently never interpretable as "no failures recorded, proceed indefinitely":
			// there is no path by which a caller can shorten or discard an in-force lockout.
			var lifetime = TimeSpan.FromMinutes(WindowMinutes);
			var remainingLockout = state.LockedOutUntilUtc - now;
			if (remainingLockout > lifetime)
			{
				lifetime = remainingLockout;
			}

			// An explicit absoluteExpiration is mandatory. The cache's own default entry options use
			// CacheItemPriority.NeverRemove, so an entry written without one would never expire and a
			// user who failed five logins would remain locked out permanently.
			//
			// A private MemoryCacheEntryOptions instance is passed rather than letting the argument
			// default to null, because Cache.Put adopts and then mutates its shared default options
			// object when null is supplied. That would leak this service's expiration onto every
			// other consumer of that cache. Do not simplify this argument away.
			cache.Put(key, state, options: new MemoryCacheEntryOptions(), absoluteExpiration: lifetime);
		}

		// The counter is keyed by username AND address together, so failures recorded for one
		// account from one address can never lock out a different account or a different address.
		private static string BuildKey(string username, string ipAddress)
		{
			return $"{KeyPrefix}{Normalize(username)}|{Normalize(ipAddress)}";
		}

		// Malformed input must never turn into a denial of service on the login path, so values are
		// normalised defensively here and every public member is non-throwing by construction: the
		// key is always a non-empty string, the counter is bounded by the threshold because it stops
		// advancing once a lockout is in force, and the computed expiration is always positive.
		private static string Normalize(string value)
		{
			if (string.IsNullOrWhiteSpace(value))
			{
				return MissingValuePlaceholder;
			}

			// Upper-cased rather than lower-cased because uppercase is the round-trip-safe invariant
			// normalisation form, so two spellings of the same principal cannot end up on separate
			// counters. The value is only ever a cache key and is never displayed.
			var normalized = value.Trim().ToUpperInvariant();
			if (normalized.Length > MaxKeyComponentLength)
			{
				normalized = normalized.Substring(0, MaxKeyComponentLength);
			}

			return normalized;
		}

		// The counter has to be a reference type: Cache.Get<T> is constrained to "where T : class",
		// so a bare integer cannot be retrieved through it.
		private sealed class LoginAttemptState
		{
			public int FailedAttempts { get; set; }

			// DateTime.MinValue, the default, means no lockout is in force.
			public DateTime LockedOutUntilUtc { get; set; }
		}
	}
}
