// SECURITY - review findings H-OPEN-01 (CWE-613 insufficient session expiration, CWE-636 not failing
// securely) and H-OPEN-02 (CWE-307 improper restriction of excessive authentication attempts, CWE-770
// allocation without limits, CWE-636), OWASP A07:2021 Identification and Authentication Failures.
//
// WHAT THIS TYPE EXISTS FOR. Two authentication controls - the session revocation list that makes
// logging out mean something, and the login lockout that bounds credential stuffing - were held in a
// process-local, capacity-bounded MemoryCache. Every one of that store's boundaries was a FAIL-OPEN:
//   * a process restart discarded every revocation and every partial failure counter;
//   * a second instance behind a load balancer never observed either, so a logout revoked the session
//     on one instance while the copied credential kept working on the others, and five failures per
//     instance multiplied the mandated five-attempt budget by the instance count;
//   * cache compaction could evict a still-live revocation, or a target account's partial counter, so an
//     attacker able to churn distinct keys could buy the budget back.
// A control whose guarantee ends at the process boundary is not the guarantee that was specified. This
// type is the shared, durable, atomic state those two controls now sit on.
//
// WHY THE plugin_data TABLE AND NOT A NEW ONE. The engagement forbids schema definition statements
// (Agent Action Plan 0.9.2: "No schema definition change ... no data definition statement is emitted at
// any point"), and that constraint is honoured literally here: NOT ONE DDL STATEMENT IS ISSUED BY THIS
// FILE. public.plugin_data already exists in every installation - ERPService.CheckCreateSystemTables
// creates it unconditionally when absent, outside every version gate, so it is present on a database
// provisioned by any release - and it is exactly a durable key/value store: `name TEXT` carries a UNIQUE
// constraint, hence a unique index, hence a point lookup, and `data TEXT` is free-form. The platform's
// own accessors (ErpPlugin.GetPluginData / SavePluginData) address it BY NAME ONLY and nothing anywhere
// enumerates it, so a reserved key prefix cannot collide with a plugin's row or be mistaken for one.
//
// KEY PREFIX RESERVATION. Every key this type writes begins with <see cref="ReservedKeyPrefix"/>. No
// plugin may take a name in that space; the platform's plugin names are short lower-case words ("sdk",
// "mail", "project", "crm", "cdm", "next") and none can reach it.
//
// WHY ITS OWN CONNECTION RATHER THAN DbContext.Current. Two independent reasons, and both are
// correctness rather than preference:
//   * AVAILABILITY. DbContext.Current is an AsyncLocal established by ErpMiddleware, which runs AFTER
//     authentication. The cookie ticket-validation hook and both bearer validators - the consumers that
//     matter most - run with no ambient context at all, so a store that required one would be
//     unreachable from the exact place the control has to be enforced.
//   * ISOLATION. A revocation and a failed-attempt counter must be durable independently of whatever
//     business transaction happens to be open on the calling thread. Enlisting in an ambient transaction
//     would mean a rollback silently discarding a security fact that had already been decided - a
//     failure counter that unwinds is not a counter.
//
// FAILURE IS REPORTED, NEVER SWALLOWED, AND NEVER DECIDED HERE. Every member returns false when the
// store could not be consulted and leaves the security decision to the caller, because "absent" and
// "unknown" are different answers and only the caller knows which way its control must fail. Both
// current callers fail CLOSED. Nothing here throws into an authentication path.

using System;
using System.Collections.Concurrent;
using System.Data;
using System.Globalization;
using System.Threading;
using Npgsql;
using NpgsqlTypes;

namespace WebVella.Erp.Database
{
	/// <summary>
	/// The outcome a <see cref="DbSecurityStateRepository.TryMutate"/> callback asks for.
	/// </summary>
	/// <remarks>
	/// A struct rather than a tuple so the three fields are named at every call site: a mutation that
	/// meant to delete a row and instead wrote one with a default expiry would be a silent security
	/// regression, and positional tuples are how that mistake gets made.
	/// </remarks>
	public struct DbSecurityStateMutation
	{
		/// <summary>The payload to store. Ignored when <see cref="Remove"/> is true.</summary>
		public string Payload { get; set; }

		/// <summary>
		/// The instant after which the payload must read as absent. Ignored when <see cref="Remove"/>
		/// is true.
		/// </summary>
		public DateTime ExpiresUtc { get; set; }

		/// <summary>True to delete the row outright rather than store a payload.</summary>
		public bool Remove { get; set; }

		/// <summary>Stores <paramref name="payload"/> until <paramref name="expiresUtc"/>.</summary>
		public static DbSecurityStateMutation Store(string payload, DateTime expiresUtc)
		{
			return new DbSecurityStateMutation { Payload = payload, ExpiresUtc = expiresUtc, Remove = false };
		}

		/// <summary>Deletes the row.</summary>
		public static DbSecurityStateMutation Delete()
		{
			return new DbSecurityStateMutation { Payload = null, ExpiresUtc = DateTime.MinValue, Remove = true };
		}
	}

	/// <summary>
	/// Durable, shared, atomic key/value state for the platform's authentication controls, stored in the
	/// pre-existing <c>plugin_data</c> table under a reserved key prefix.
	/// </summary>
	/// <remarks>
	/// Public because its consumers - <c>WebVella.Erp.Web.Services.SessionRevocationService</c> and
	/// <c>WebVella.Erp.Web.Services.LoginThrottleService</c> - live in a different assembly that project
	/// references this one, which is the same reason <see cref="DbIdentifier"/> is public while
	/// <c>Utilities/PasswordUtil</c> is not.
	/// <para>
	/// Static and stateless apart from two diagnostic latches, matching the other helpers in this folder.
	/// No dependency-injection registration, no interface and no configuration surface: a control that
	/// could be left unregistered is a control that can be absent, and an absent store was one of the
	/// fail-open shapes H-OPEN-01 identified.
	/// </para>
	/// </remarks>
	public static class DbSecurityStateRepository
	{
		/// <summary>
		/// Key namespace reserved for security state. No plugin may use a <c>plugin_data.name</c> that
		/// begins with this.
		/// </summary>
		public const string ReservedKeyPrefix = "wv_sec_";

		/// <summary>
		/// Fixed-width, sortable, UTC expiry stamp written as the first field of every payload envelope.
		/// </summary>
		/// <remarks>
		/// The format matters and is not cosmetic. <c>plugin_data</c> has no expiry column and none may be
		/// added, so the expiry travels inside <c>data</c>. Writing it as a fixed-width UTC stamp in this
		/// order makes lexicographic comparison identical to chronological comparison, which is what lets
		/// <see cref="TryPurgeExpired"/> reclaim expired rows with a plain indexed predicate
		/// (<c>left(data, 20) &lt; @now</c>) instead of parsing every row in the application.
		/// </remarks>
		private const string ExpiryStampFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'";

		/// <summary>Length of <see cref="ExpiryStampFormat"/> rendered, i.e. of the envelope prefix.</summary>
		private const int ExpiryStampLength = 20;

		/// <summary>Separator between the expiry stamp and the payload.</summary>
		private const char EnvelopeSeparator = '|';

		/// <summary>
		/// Command timeout, in seconds, for every statement this type issues.
		/// </summary>
		/// <remarks>
		/// Set explicitly rather than inherited, because the platform connection string carries
		/// <c>CommandTimeout=300</c> and these statements sit on the authentication path of every
		/// request. A five-minute hang while a caller waits to learn whether a session is revoked is a
		/// denial of service in its own right; ten seconds is far longer than an indexed point lookup can
		/// legitimately take and still bounds the wait.
		/// </remarks>
		private const int CommandTimeoutSeconds = 10;

		/// <summary>
		/// Minimum interval between reclamation sweeps for one key prefix.
		/// </summary>
		/// <remarks>
		/// Expired rows are logically absent the moment their stamp passes, so a sweep is housekeeping and
		/// never a correctness requirement. Throttling it here rather than at the call sites means no
		/// caller can turn a security write into a table scan per request.
		/// </remarks>
		private static readonly TimeSpan PurgeInterval = TimeSpan.FromMinutes(10);

		/// <summary>Last sweep per key prefix, in UTC.</summary>
		private static readonly ConcurrentDictionary<string, DateTime> lastPurgeUtc = new ConcurrentDictionary<string, DateTime>(StringComparer.Ordinal);

		/// <summary>
		/// Rate limit for the fault notice below, expressed as UTC ticks and updated with
		/// <see cref="Interlocked"/> so concurrent callers cannot both pass the gate.
		/// </summary>
		private static long lastFaultReportTicks;

		/// <summary>Minimum interval between fault notices.</summary>
		private static readonly TimeSpan FaultReportInterval = TimeSpan.FromMinutes(1);

		/// <summary>
		/// Reads the live payload stored under <paramref name="key"/>.
		/// </summary>
		/// <param name="key">Key, which must begin with <see cref="ReservedKeyPrefix"/>.</param>
		/// <param name="payload">
		/// The stored payload, or <c>null</c> when no row exists or the row has expired. Meaningful only
		/// when this method returns <c>true</c>.
		/// </param>
		/// <returns>
		/// <c>true</c> when the store was consulted successfully - whether or not a live payload was
		/// found; <c>false</c> when it could not be consulted at all.
		/// </returns>
		/// <remarks>
		/// The distinction in the return value is the whole point: "there is no revocation" and "I could
		/// not find out whether there is a revocation" must not be the same answer, because treating the
		/// second as the first is exactly the fail-open H-OPEN-01 describes.
		/// </remarks>
		public static bool TryRead(string key, out string payload)
		{
			payload = null;
			if (!IsUsableKey(key))
				return false;

			try
			{
				using (var connection = OpenConnection())
				{
					if (connection == null)
						return false;

					using (var command = Prepare(new NpgsqlCommand("SELECT data FROM plugin_data WHERE name = @name;", connection)))
					{
						AddTextParameter(command, "name", key);
						object stored = command.ExecuteScalar();
						if (stored == null || stored == DBNull.Value)
							return true;

						payload = ReadLivePayload((string)stored, DateTime.UtcNow);
						return true;
					}
				}
			}
			catch (Exception exception)
			{
				ReportFault("read", exception);
				return false;
			}
		}

		/// <summary>
		/// Stores <paramref name="payload"/> under <paramref name="key"/> until
		/// <paramref name="expiresUtc"/>, replacing any existing value.
		/// </summary>
		/// <returns><c>true</c> when the value is durably stored; <c>false</c> on any failure.</returns>
		/// <remarks>
		/// A single upsert statement, so two instances writing the same key concurrently cannot produce a
		/// duplicate-key fault and neither loses to the other's insert. Last write wins, which is correct
		/// for both current callers: a revocation is idempotent, and its expiry is recomputed from the
		/// same credential lifetime every time.
		/// </remarks>
		public static bool TryWrite(string key, string payload, DateTime expiresUtc)
		{
			if (!IsUsableKey(key))
				return false;

			try
			{
				using (var connection = OpenConnection())
				{
					if (connection == null)
						return false;

					using (var command = Prepare(new NpgsqlCommand(
						@"INSERT INTO plugin_data (id, name, data) VALUES (@id, @name, @data)
						  ON CONFLICT (name) DO UPDATE SET data = EXCLUDED.data;", connection)))
					{
						AddUuidParameter(command, "id", Guid.NewGuid());
						AddTextParameter(command, "name", key);
						AddTextParameter(command, "data", BuildEnvelope(payload, expiresUtc));
						command.ExecuteNonQuery();
					}
				}

				TryPurgeExpired(KeyNamespaceOf(key));
				return true;
			}
			catch (Exception exception)
			{
				ReportFault("write", exception);
				return false;
			}
		}

		/// <summary>
		/// Applies an atomic read-modify-write to the value under <paramref name="key"/>.
		/// </summary>
		/// <param name="key">Key, which must begin with <see cref="ReservedKeyPrefix"/>.</param>
		/// <param name="mutate">
		/// Receives the live payload, or <c>null</c> when none exists, and returns what to store. Called
		/// exactly once, while the row is locked. It must not throw, must not block and must not perform
		/// database work of its own.
		/// </param>
		/// <returns><c>true</c> when the mutation is durably committed; <c>false</c> on any failure.</returns>
		/// <remarks>
		/// ATOMICITY ACROSS INSTANCES, which is what H-OPEN-02 requires and an in-process lock cannot
		/// provide. The row is created if absent with an already-expired envelope - so it reads as absent
		/// to the callback while still being a lockable row - and is then taken with
		/// <c>SELECT ... FOR UPDATE</c>, which serialises every concurrent mutation of the same key
		/// across every process against this database for the remainder of the transaction. The insert is
		/// <c>ON CONFLICT DO NOTHING</c> so two instances racing to create the same key cannot fault, and
		/// the loser simply proceeds to lock the row the winner inserted.
		/// </remarks>
		public static bool TryMutate(string key, Func<string, DbSecurityStateMutation> mutate)
		{
			if (!IsUsableKey(key) || mutate == null)
				return false;

			try
			{
				using (var connection = OpenConnection())
				{
					if (connection == null)
						return false;

					using (var transaction = connection.BeginTransaction())
					{
						using (var seed = Prepare(new NpgsqlCommand(
							@"INSERT INTO plugin_data (id, name, data) VALUES (@id, @name, @data)
							  ON CONFLICT (name) DO NOTHING;", connection, transaction)))
						{
							AddUuidParameter(seed, "id", Guid.NewGuid());
							AddTextParameter(seed, "name", key);
							// Seeded already expired, so a callback that sees this row sees "absent".
							AddTextParameter(seed, "data", BuildEnvelope(string.Empty, DateTime.MinValue.ToUniversalTime()));
							seed.ExecuteNonQuery();
						}

						string stored = null;
						using (var select = Prepare(new NpgsqlCommand(
							"SELECT data FROM plugin_data WHERE name = @name FOR UPDATE;", connection, transaction)))
						{
							AddTextParameter(select, "name", key);
							object result = select.ExecuteScalar();
							if (result != null && result != DBNull.Value)
								stored = (string)result;
						}

						DbSecurityStateMutation mutation = mutate(ReadLivePayload(stored, DateTime.UtcNow));

						if (mutation.Remove)
						{
							using (var delete = Prepare(new NpgsqlCommand(
								"DELETE FROM plugin_data WHERE name = @name;", connection, transaction)))
							{
								AddTextParameter(delete, "name", key);
								delete.ExecuteNonQuery();
							}
						}
						else
						{
							using (var update = Prepare(new NpgsqlCommand(
								"UPDATE plugin_data SET data = @data WHERE name = @name;", connection, transaction)))
							{
								AddTextParameter(update, "name", key);
								AddTextParameter(update, "data", BuildEnvelope(mutation.Payload, mutation.ExpiresUtc));
								update.ExecuteNonQuery();
							}
						}

						transaction.Commit();
					}
				}

				TryPurgeExpired(KeyNamespaceOf(key));
				return true;
			}
			catch (Exception exception)
			{
				ReportFault("mutate", exception);
				return false;
			}
		}

		/// <summary>
		/// Deletes the rows in a key namespace whose expiry has passed, at most once per
		/// <see cref="PurgeInterval"/> per namespace and per process.
		/// </summary>
		/// <remarks>
		/// Reclamation only. An expired row is already logically absent, so failing to sweep costs storage
		/// and nothing else - which is why every failure here is swallowed after being reported rather
		/// than propagated to an authentication caller.
		/// </remarks>
		public static void TryPurgeExpired(string keyNamespace)
		{
			if (string.IsNullOrEmpty(keyNamespace) || !keyNamespace.StartsWith(ReservedKeyPrefix, StringComparison.Ordinal))
				return;

			DateTime now = DateTime.UtcNow;
			DateTime previous = lastPurgeUtc.GetOrAdd(keyNamespace, DateTime.MinValue);
			if (previous != DateTime.MinValue && now - previous < PurgeInterval)
				return;

			// Claimed before the work is done, so a burst of concurrent writers issues one sweep rather
			// than one each.
			if (!lastPurgeUtc.TryUpdate(keyNamespace, now, previous))
				return;

			try
			{
				using (var connection = OpenConnection())
				{
					if (connection == null)
						return;

					using (var command = Prepare(new NpgsqlCommand(
						@"DELETE FROM plugin_data
						  WHERE name LIKE @pattern AND left(data, @stamp_length) < @now;", connection)))
					{
						// The pattern is a bound parameter, and the only wildcard in it is the one added
						// here - a namespace that reached this point has already been proved to start with
						// the reserved prefix, so no caller-influenced text can widen the predicate beyond
						// this type's own keys.
						AddTextParameter(command, "pattern", keyNamespace + "%");
						var lengthParameter = command.CreateParameter();
						lengthParameter.ParameterName = "stamp_length";
						lengthParameter.NpgsqlDbType = NpgsqlDbType.Integer;
						lengthParameter.Value = ExpiryStampLength;
						command.Parameters.Add(lengthParameter);
						AddTextParameter(command, "now", FormatExpiry(now));
						command.ExecuteNonQuery();
					}
				}
			}
			catch (Exception exception)
			{
				ReportFault("purge", exception);
			}
		}

		/// <summary>
		/// The namespace of a key: everything up to and including the segment that follows the reserved
		/// prefix, so a sweep of one control's keys never touches another's.
		/// </summary>
		private static string KeyNamespaceOf(string key)
		{
			int separator = key.IndexOf('_', ReservedKeyPrefix.Length);
			if (separator < 0)
				return ReservedKeyPrefix;

			return key.Substring(0, separator + 1);
		}

		/// <summary>
		/// Whether a key is one this type may act on. A key outside the reserved namespace is refused
		/// rather than accepted, so this type can never read or overwrite a plugin's own row.
		/// </summary>
		private static bool IsUsableKey(string key)
		{
			return !string.IsNullOrEmpty(key)
				&& key.StartsWith(ReservedKeyPrefix, StringComparison.Ordinal)
				&& !string.IsNullOrWhiteSpace(ErpSettings.ConnectionString);
		}

		private static NpgsqlConnection OpenConnection()
		{
			string connectionString = ErpSettings.ConnectionString;
			if (string.IsNullOrWhiteSpace(connectionString))
				return null;

			var connection = new NpgsqlConnection(connectionString);
			connection.Open();
			return connection;
		}

		/// <summary>
		/// Applies this type's command settings to an already-constructed command.
		/// </summary>
		/// <remarks>
		/// It takes the COMMAND rather than the command text, and that shape is deliberate. A helper that
		/// accepted a string would put every statement in this file behind a variable, which is exactly the
		/// pattern analyzer rule CA2100 exists to flag at a SQL construction site - and suppressing that
		/// rule here, of all places, would be indefensible. Every statement this type issues is therefore
		/// written as a compile-time literal at its own call site, so the rule can see that no value is
		/// concatenated into any of them; every value travels as a bound parameter.
		/// </remarks>
		private static NpgsqlCommand Prepare(NpgsqlCommand command)
		{
			command.CommandType = CommandType.Text;
			command.CommandTimeout = CommandTimeoutSeconds;
			return command;
		}

		private static void AddTextParameter(NpgsqlCommand command, string name, string value)
		{
			var parameter = command.CreateParameter();
			parameter.ParameterName = name;
			parameter.NpgsqlDbType = NpgsqlDbType.Text;
			parameter.Value = value ?? string.Empty;
			command.Parameters.Add(parameter);
		}

		private static void AddUuidParameter(NpgsqlCommand command, string name, Guid value)
		{
			var parameter = command.CreateParameter();
			parameter.ParameterName = name;
			parameter.NpgsqlDbType = NpgsqlDbType.Uuid;
			parameter.Value = value;
			command.Parameters.Add(parameter);
		}

		private static string FormatExpiry(DateTime instantUtc)
		{
			DateTime utc = instantUtc.Kind == DateTimeKind.Utc ? instantUtc : instantUtc.ToUniversalTime();
			return utc.ToString(ExpiryStampFormat, CultureInfo.InvariantCulture);
		}

		private static string BuildEnvelope(string payload, DateTime expiresUtc)
		{
			return FormatExpiry(expiresUtc) + EnvelopeSeparator + (payload ?? string.Empty);
		}

		/// <summary>
		/// Splits an envelope and returns its payload, or <c>null</c> when the envelope is absent,
		/// malformed or expired.
		/// </summary>
		/// <remarks>
		/// A malformed envelope reads as ABSENT rather than as live, and that direction is deliberate for
		/// both callers: a revocation entry that cannot be parsed is not evidence that a session is still
		/// valid - the caller treats a failed READ as revoked - while a failure counter that cannot be
		/// parsed must restart from zero rather than lock an account out on unreadable state.
		/// </remarks>
		private static string ReadLivePayload(string envelope, DateTime nowUtc)
		{
			if (string.IsNullOrEmpty(envelope) || envelope.Length < ExpiryStampLength + 1)
				return null;

			if (envelope[ExpiryStampLength] != EnvelopeSeparator)
				return null;

			if (!DateTime.TryParseExact(envelope.Substring(0, ExpiryStampLength), ExpiryStampFormat,
				CultureInfo.InvariantCulture,
				DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
				out DateTime expiresUtc))
			{
				return null;
			}

			if (nowUtc >= expiresUtc)
				return null;

			return envelope.Substring(ExpiryStampLength + 1);
		}

		/// <summary>
		/// Reports, at most once per <see cref="FaultReportInterval"/>, that the durable security store
		/// could not be reached.
		/// </summary>
		/// <remarks>
		/// STANDARD ERROR RATHER THAN THE PLATFORM LOG, and the reason is structural rather than
		/// stylistic: <c>Diagnostics.Log</c> persists through this same database, so the one condition
		/// this notice exists to announce is the condition under which the log cannot record it. It
		/// mirrors the precedent <c>ErpSettings</c> and <c>SmtpService</c> already set for a refused or
		/// unavailable security setting. RATE LIMITED because a database outage would otherwise emit one
		/// line per authenticated request, burying the signal in its own volume (CWE-779). Only the
		/// operation name and the exception type are named - never a key, never a connection string and
		/// never a session identifier, because a key in this namespace is a lookup value for the
		/// revocation store (CWE-532).
		/// </remarks>
		private static void ReportFault(string operation, Exception exception)
		{
			long now = DateTime.UtcNow.Ticks;
			long previous = Interlocked.Read(ref lastFaultReportTicks);
			if (previous != 0 && now - previous < FaultReportInterval.Ticks)
				return;

			if (Interlocked.CompareExchange(ref lastFaultReportTicks, now, previous) != previous)
				return;

			Console.Error.WriteLine(
				"SECURITY: the durable security-state store could not be reached (operation '"
				+ operation + "', " + (exception == null ? "unknown fault" : exception.GetType().FullName)
				+ "). Session revocation and login lockout FAIL CLOSED while this persists: authenticated "
				+ "requests and login attempts are refused rather than allowed. Check the database "
				+ "connection named by 'Settings:ConnectionString'.");
		}
	}
}
