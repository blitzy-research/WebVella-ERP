using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using WebVella.Erp.Diagnostics;

namespace WebVella.Erp.Web.Utils
{
	/// <summary>
	/// The single writing and neutralisation boundary for security audit records - authentication outcomes,
	/// authorization denials and rejected anonymous token requests.
	/// </summary>
	/// <remarks>
	/// SECURITY - the shared implementation of three related defects that had been fixed, or left unfixed,
	/// independently at each call site:
	/// <list type="bullet">
	/// <item><description>
	/// CWE-117 improper output neutralisation for logs. Audit details are assembled as
	/// <c>name: value; name: value</c> text and persisted verbatim, so a caller-controlled value containing
	/// a carriage return, a line feed, a semicolon or a colon could forge additional fields or additional
	/// apparent records. Since the attacker chooses the username and can influence the forwarded address,
	/// the party the audit trail exists to incriminate is the party who writes half of it. See
	/// <see cref="Field(string, int)"/>.
	/// </description></item>
	/// <item><description>
	/// CWE-778 insufficient logging. Persisting an audit record needs the database, so a database outage
	/// silently erased authentication and authorization audit entries with no trace beyond their absence -
	/// the failure mode indistinguishable from "nothing happened". See <see cref="Write"/>, which counts
	/// every lost write and carries the count into the next record that does succeed.
	/// </description></item>
	/// <item><description>
	/// The audit write must never change the outcome of the operation it audits. A caller that denies a
	/// request must still deny it when the log is unavailable, and a caller that refuses a credential must
	/// still refuse it - never convert either into a server error. See <see cref="Write"/>, which cannot
	/// throw for any storage failure.
	/// </description></item>
	/// </list>
	/// <para>
	/// WHY THIS IS SHARED RATHER THAN REPEATED. The same three properties are required at the login page,
	/// at the file-mutation authorization check and at both anonymous token routes. Four independent
	/// implementations would be four independent opportunities to get the escaping, the narrow catch list
	/// or the loss accounting subtly wrong, and a reviewer would have to verify each separately. One
	/// audited helper is the pattern this remediation already applied to
	/// <c>WebVella.Erp/Database/DbIdentifier.cs</c> and
	/// <c>WebVella.Erp/Api/Models/ErpSerializationBinder.cs</c> for exactly the same reason.
	/// </para>
	/// <para>
	/// WHY THE CORE <see cref="Log"/> AND NOT <c>Services/LogService</c>. <c>LogService.Create</c> sends an
	/// operator notification whenever the notification status is <c>NotNotified</c> - which is its default.
	/// Every route audited through this helper is reachable without credentials, so that default turns a
	/// request flood into an outbound mail flood. It was worse before the finding M-OPEN-03 remediation,
	/// which mailed the full record BEFORE persisting it and so also put audit detail on an off-box
	/// transport ahead of the database; that ordering is now reversed and the notification carries only the
	/// severity, the source and the identifier of the stored record. The VOLUME argument stands unchanged,
	/// which is why this helper still does not use that wrapper. Passing
	/// <see cref="LogNotificationStatus.DoNotNotify"/> to <c>LogService</c> would also avoid it, but relies
	/// on every present and future call site remembering to. The core <see cref="Log"/> has no mail branch
	/// at all: it opens a connection, executes one parameterised INSERT into <c>system_log</c> and returns.
	/// The guarantee is structural here rather than a convention, and the explicit
	/// <see cref="LogNotificationStatus.DoNotNotify"/> below is belt and braces.
	/// </para>
	/// <para>
	/// THREAD SAFETY. The aggregate loss count is a single <see cref="int"/> mutated only through
	/// <see cref="Interlocked"/>/<see cref="Volatile"/>, and the per-source ledger is a bounded
	/// <see cref="ConcurrentDictionary{TKey, TValue}"/> whose entries guard their own counters, so
	/// concurrent requests cannot corrupt either ledger and recording a loss can never itself throw.
	/// </para>
	/// </remarks>
	internal static class SecurityAuditLog
	{
		/// <summary>
		/// Upper bound applied to an assembled details string before it is persisted.
		/// </summary>
		/// <remarks>
		/// A last-resort bound. Callers already bound each field individually through
		/// <see cref="Field(string, int)"/>; this exists so that a future caller which forgets to, or which
		/// composes many fields, still cannot write an unbounded row. Generous enough that no legitimate
		/// audit detail is truncated in practice.
		/// </remarks>
		private const int MaxDetailsLength = 1024;

		/// <summary>
		/// Ceiling on the reported lost-write count.
		/// </summary>
		/// <remarks>
		/// A sustained outage under load could otherwise let the counter grow without limit. Clamping the
		/// REPORTED value keeps the appended sentence a fixed width; the counter itself is bounded by
		/// <see cref="int"/> and is only ever incremented once per failed write, so it cannot overflow
		/// within any plausible outage.
		/// </remarks>
		private const int MaxReportedLostWrites = 1000000;

		/// <summary>
		/// Bound applied to an exception type name recorded when its detail could not be serialised.
		/// </summary>
		/// <remarks>
		/// Generously above any real fully-qualified type name, including a deeply generic one. Bounded at all
		/// because a type name can originate in a dynamically generated or plugin-supplied assembly, so it is
		/// not treated as unconditionally trustworthy text.
		/// </remarks>
		private const int MaxDiagnosticTypeNameLength = 256;

		/// <summary>
		/// Number of audit records that could not be persisted and have not yet been reported.
		/// </summary>
		/// <remarks>
		/// SECURITY (CWE-778). This is what makes a gap in the audit trail visible IN the trail rather than
		/// only as an absence of rows. Read before a write and decremented only after it succeeds, so a
		/// loss recorded concurrently by another request is carried forward instead of being discarded.
		/// </remarks>
		private static int unreportedWriteFailures;

		/// <summary>
		/// Bounds a value destined for a persisted log record and replaces control characters with spaces.
		/// </summary>
		/// <param name="value">The value to neutralise. A null or empty value yields an empty string.</param>
		/// <param name="maxLength">
		/// Maximum number of characters retained. Values of zero or less yield an empty string.
		/// </param>
		/// <remarks>
		/// CWE-117. Bounding happens BEFORE the scan so a hostile length cannot buy work here, and control
		/// characters are REPLACED rather than stripped: replacement removes the injection primitive -
		/// carriage return and line feed are what let a crafted value forge additional entries in a
		/// line-oriented log - while keeping the surrounding text legible and the same length, so a reader
		/// can still see that something odd was submitted.
		/// <para>
		/// Use this for text the platform itself composed - a fixed description, a diagnostic code, an
		/// exception type name. For anything a caller supplied, use <see cref="Field(string, int)"/>
		/// instead, which additionally prevents the value from impersonating a field boundary.
		/// </para>
		/// </remarks>
		internal static string Normalize(string value, int maxLength)
		{
			if (string.IsNullOrEmpty(value) || maxLength <= 0)
			{
				return string.Empty;
			}

			var bounded = value.Length <= maxLength ? value : value.Substring(0, maxLength);
			var builder = new StringBuilder(bounded.Length);
			foreach (var character in bounded)
			{
				builder.Append(char.IsControl(character) ? ' ' : character);
			}

			return builder.ToString();
		}

		/// <summary>
		/// Renders a caller-supplied value as a single, unambiguous, quoted audit field.
		/// </summary>
		/// <param name="value">
		/// The caller-supplied value. A null or empty value yields <c>""</c> - an explicitly empty field
		/// rather than nothing at all, so "absent" and "blank" remain distinguishable from a missing field.
		/// </param>
		/// <param name="maxLength">Maximum number of characters retained from <paramref name="value"/>.</param>
		/// <remarks>
		/// SECURITY - CWE-117 improper output neutralisation for logs, OWASP A09:2021.
		/// THREAT: audit details in this platform are <c>name: value; name: value</c> text. Neutralising
		/// control characters alone is NOT sufficient there, because the delimiters are printable: a
		/// username of <c>alice; ip: 10.0.0.1</c> reads back as two well-formed fields and lets an attacker
		/// write whatever address, outcome or username they please into the record that is supposed to
		/// incriminate them. Quoting is what removes the ambiguity - a delimiter inside quotes is
		/// unmistakably part of the value - and escaping the quote and the escape character is what stops
		/// the quoting itself from being escaped out of.
		/// <para>
		/// Escaping is deliberately done in ONE pass that inspects each source character and emits its
		/// escape immediately. That structure is what makes the classic failure here impossible rather than
		/// merely avoided: written as two sequential replacements, the passes must run backslash-first,
		/// because a quote-first pass introduces a backslash that the later backslash pass then doubles -
		/// turning <c>\"</c> into <c>\\"</c> and handing the closing quote straight back to the attacker. A
		/// single pass never revisits a character it has already escaped, so no ordering can be got wrong.
		/// Anyone refactoring this into sequential replacements reintroduces that ordering obligation.
		/// </para>
		/// <para>
		/// Bounding is applied to the RAW value before escaping, so the retained amount of caller data is
		/// exactly the documented bound and does not shrink as a function of how many characters needed
		/// escaping. Escaping can therefore expand the result past <paramref name="maxLength"/>, which is
		/// intended: the bound governs attacker-supplied content, not the delimiters this method adds.
		/// </para>
		/// </remarks>
		internal static string Field(string value, int maxLength)
		{
			if (string.IsNullOrEmpty(value) || maxLength <= 0)
			{
				return "\"\"";
			}

			var bounded = value.Length <= maxLength ? value : value.Substring(0, maxLength);

			// Sized for the common case where nothing needs escaping: the value plus its two quotes.
			var builder = new StringBuilder(bounded.Length + 2);
			builder.Append('"');
			foreach (var character in bounded)
			{
				if (char.IsControl(character))
				{
					// Same rationale as Normalize: replaced, not stripped, so length and legibility survive
					// while the record-forging primitive does not.
					builder.Append(' ');
				}
				else if (character == '\\' || character == '"')
				{
					// Both the escape character and the quote are escaped, in the same pass that reads them,
					// so an escape this method emits is never itself re-escaped. See the remarks.
					builder.Append('\\');
					builder.Append(character);
				}
				else
				{
					builder.Append(character);
				}
			}

			builder.Append('"');
			return builder.ToString();
		}

		/// <summary>
		/// Persists a security audit record, and cannot throw.
		/// </summary>
		/// <param name="type">Record type. <see cref="LogType.Error"/> for a refusal, <see cref="LogType.Info"/> for a success.</param>
		/// <param name="source">Origin of the record, in the platform's existing <c>Class.Method</c> form.</param>
		/// <param name="message">Fixed, platform-composed summary. Never caller-supplied text.</param>
		/// <param name="details">
		/// Assembled detail text. Caller-supplied components must already have been passed through
		/// <see cref="Field(string, int)"/>.
		/// </param>
		/// <returns>
		/// <c>true</c> when the record was persisted; <c>false</c> when it was lost to a storage failure and
		/// counted for later reporting. Callers are free to ignore the result - and the security-relevant
		/// ones do, because the outcome they are auditing must not depend on the audit succeeding.
		/// </returns>
		/// <remarks>
		/// SECURITY - CWE-778 insufficient logging, and the availability requirement that an audit write
		/// must not be able to change what it audits.
		/// <para>
		/// WHY THE RETURN VALUE IS NOT AN EXCEPTION. Every caller of this method has already decided what
		/// the security outcome is - denied, refused, locked out - before the record is written. Propagating
		/// a storage failure would convert a correct denial into an HTTP 500, which is strictly worse than a
		/// missing log line: it changes the response an attacker sees, tells them the denial path is
		/// fragile, and on the file-authorization path would turn "you may not do this" into "the server
		/// broke", which some clients treat as retryable.
		/// </para>
		/// <para>
		/// WHY THE CATCH LIST IS NARROW AND NOT <c>catch (Exception)</c>. A bare catch here is what let the
		/// original defect hide: it swallowed genuine coding errors alongside the transient storage faults
		/// this write can actually produce. Only the latter are caught, and each is counted rather than
		/// discarded. <see cref="OutOfMemoryException"/>, <c>StackOverflowException</c>,
		/// <see cref="OperationCanceledException"/> and security exceptions propagate untouched, because a
		/// process in that state must not be kept running by an audit helper. The list mirrors
		/// <c>Services/AuthService.cs</c> so the two audit paths cannot diverge on which faults are
		/// survivable.
		/// </para>
		/// <para>
		/// The write reaches <c>Diagnostics/Log.cs</c>, which opens an Npgsql connection, executes one
		/// parameterised INSERT and releases it. Because <see cref="LogNotificationStatus.DoNotNotify"/> is
		/// passed, no mail transport is involved and no mail failure is possible; because no transaction is
		/// begun, the plain-<see cref="Exception"/> throws in the platform's connection code are
		/// unreachable from here.
		/// </para>
		/// </remarks>
		internal static bool Write(LogType type, string source, string message, string details)
		{
			return Write(type, source, message, details, null);
		}

		/// <summary>
		/// Persists a security audit record together with an exception's server-side diagnostic detail, and
		/// cannot throw.
		/// </summary>
		/// <param name="type">Record type, as for the four-argument overload.</param>
		/// <param name="source">Origin of the record, as for the four-argument overload.</param>
		/// <param name="message">Fixed, platform-composed summary. Never caller-supplied text.</param>
		/// <param name="details">
		/// Assembled detail text. Caller-supplied components must already have been passed through
		/// <see cref="Field(string, int)"/>.
		/// </param>
		/// <param name="exception">
		/// The fault to capture, or <c>null</c> to write <paramref name="details"/> alone. When supplied,
		/// its message, source, stack trace and inner exception are recorded through the platform's own
		/// <c>Log.MakeDetailsJson</c>, exactly as the untrusted-free error paths elsewhere record them.
		/// </param>
		/// <returns>
		/// <c>true</c> when the record was persisted; <c>false</c> when it was lost and counted.
		/// </returns>
		/// <remarks>
		/// SECURITY - this overload exists so that a route needing a stack trace for an operator does not
		/// have to fall back to an UNGUARDED write or to <c>LogService</c> to get one. Both alternatives
		/// reintroduce a defect: the first can throw out of an error handler, and the second mails the
		/// detail off-box before persisting it whenever the status is left at its default.
		/// <para>
		/// THE EXCEPTION DETAIL IS DELIBERATELY NOT LENGTH-BOUNDED, while
		/// <paramref name="details"/> still is. A stack trace truncated to the details bound loses the
		/// frames that make it worth recording, and the text is composed by the runtime rather than by the
		/// caller. The obligation this places on the caller is explicit: pass an exception only on a path
		/// whose faults are genuine server faults, and pass <c>null</c> on any path an attacker can drive
		/// at will - a rejected credential, a malformed body - where the fault carries no diagnostic value
		/// and the volume would be attacker-chosen. Every caller in this repository states which of the two
		/// it is at the call site.
		/// </para>
		/// <para>
		/// The no-throw guarantee is unconditional here as well, but it is reached in two different ways and
		/// the distinction matters to anyone editing this method. The INSERT is protected by the narrow
		/// storage catch list below. Rendering the exception is not a storage operation and so is not covered
		/// by that list; it is guarded separately and degrades to the assembled fields instead of
		/// propagating. Any new step added to this method must be placed under one of the two, because a
		/// caller invokes this from inside its own catch block, where an escaping exception becomes an
		/// unhandled 500.
		/// </para>
		/// </remarks>
		internal static bool Write(LogType type, string source, string message, string details, Exception exception)
		{
			// Read BEFORE the write and subtracted only after it succeeds. A loss recorded concurrently by
			// another request is therefore carried forward to the next successful record rather than being
			// silently dropped by this one's subtraction.
			var carriedFailures = Volatile.Read(ref unreportedWriteFailures);
			var reportedFailures = carriedFailures > MaxReportedLostWrites ? MaxReportedLostWrites : carriedFailures;

			var auditDetails = Normalize(details, MaxDetailsLength);
			if (reportedFailures > 0)
			{
				auditDetails = auditDetails + " | audit_writes_lost: "
					+ reportedFailures.ToString(CultureInfo.InvariantCulture)
					+ " (earlier security audit record(s) could not be persisted and are unrecorded)";
			}

			// MakeDetailsJson is the platform's own exception serialiser, already used by every error path in
			// the codebase, so an operator reading system_log sees the shape they already know. It records
			// the message, source, stack trace and one level of inner exception - and NOT the request, which
			// is why no headers, cookies or body can reach the row through this helper (finding M-17).
			//
			// Serialisation is guarded separately from the write below, and degrades rather than propagates.
			// It runs before the try that protects the INSERT, and it is the one step here that is not a
			// storage operation, so an exception escaping it would break this method's no-throw contract from
			// outside the storage catch list - and it would do so inside a caller's own catch block, turning a
			// handled failure into an unhandled 500. Falling back to the already-assembled fields keeps the
			// audit record itself, which matters more than the stack trace attached to it.
			if (exception != null)
			{
				try
				{
					auditDetails = Log.MakeDetailsJson(auditDetails + " | ", exception);
				}
				catch (Newtonsoft.Json.JsonException)
				{
					// Fully qualified so no using directive is needed for a type referenced once. The audit
					// record is NOT lost here - only the serialised detail is - so the lost-write counter is
					// deliberately left alone; inflating it would report a phantom missing record. The reader
					// is told what is absent and why, using the exception's type name rather than its message
					// so that nothing from an inner fault is copied in unbounded.
					auditDetails = auditDetails + " | audit_detail_unavailable: "
						+ Normalize(exception.GetType().FullName, MaxDiagnosticTypeNameLength)
						+ " could not be serialised";
				}
			}

			try
			{
				new Log().Create(type, source, message, auditDetails, LogNotificationStatus.DoNotNotify);
			}
			catch (System.Data.Common.DbException)
			{
				// Npgsql surfaces every server-side and connection-level fault as NpgsqlException : DbException.
				// FULLY QUALIFIED on purpose, matching Services/AuthService.cs: the platform declares an
				// unrelated WebVella.Erp.Database.DbException of the same simple name, caught separately below.
				// Written unqualified, a later `using WebVella.Erp.Database;` added to this file for any reason
				// would silently repoint this clause at that type - the code would still compile, the catch
				// would still look right, and Npgsql faults would stop being counted. Qualifying removes that
				// failure mode rather than relying on nobody adding the directive.
				Interlocked.Increment(ref unreportedWriteFailures);
				return false;
			}
			catch (WebVella.Erp.Database.DbException)
			{
				// The platform's own data-layer exception, raised when a connection is released out of order -
				// which an audit write can encounter while the request already holds one.
				Interlocked.Increment(ref unreportedWriteFailures);
				return false;
			}
			catch (TimeoutException)
			{
				// Connection-pool exhaustion or command timeout while the database is saturated. Exactly the
				// condition a credential-stuffing flood creates, which is when the audit matters most.
				Interlocked.Increment(ref unreportedWriteFailures);
				return false;
			}
			catch (IOException)
			{
				// Transport failure writing to or reading from the database socket.
				Interlocked.Increment(ref unreportedWriteFailures);
				return false;
			}
			catch (InvalidOperationException)
			{
				// Connection or transaction in an unusable state. Also covers ObjectDisposedException, which
				// derives from it, when the request's database scope has already been torn down.
				Interlocked.Increment(ref unreportedWriteFailures);
				return false;
			}
			catch (NullReferenceException)
			{
				// Narrowly justified: Diagnostics/Log.cs dereferences the ambient DbContext.Current without a
				// null guard, and these audit records are written from paths that can run before or after the
				// ERP database scope exists. That is an expected environmental condition on this path, not a
				// defect in the code being audited.
				Interlocked.Increment(ref unreportedWriteFailures);
				return false;
			}

			// Only now, and only by the amount actually reported, so a concurrent loss is not cancelled by a
			// success that never mentioned it.
			if (reportedFailures > 0)
			{
				Interlocked.Add(ref unreportedWriteFailures, -reportedFailures);
			}

			return true;
		}

		/// <summary>
		/// Source name under which the per-source accounting record is written.
		/// </summary>
		internal const string AccountingSource = "SecurityAuditLog";

		/// <summary>
		/// Minimum interval between two persisted fault records for the same source.
		/// </summary>
		/// <remarks>
		/// SECURITY (CWE-779, CWE-400). An unhandled fault reachable from a request is reachable
		/// repeatedly, so recording every occurrence lets a caller flood the log table - burying the
		/// authentication and authorization records this class exists to preserve, and turning an audit
		/// control into an availability defect. One record per source per interval keeps the first
		/// occurrence, which is the diagnostically useful one, and counts the rest.
		/// </remarks>
		private const double FaultIntervalMinutes = 1;

		/// <summary>
		/// Upper bound on the number of distinct sources tracked in the per-source ledger.
		/// </summary>
		/// <remarks>
		/// SECURITY (CWE-770). Source names originate in the platform's own call sites, but bounding the
		/// dictionary means even a future caller deriving a source name from request data cannot grow it
		/// without limit. Beyond the bound every further source shares one overflow entry, so rate
		/// limiting degrades to coarser attribution rather than failing open.
		/// </remarks>
		private const int MaxTrackedSources = 64;

		/// <summary>
		/// Bound applied to a source name and to a fault or audit message.
		/// </summary>
		private const int MaxLoggedValueLength = 400;

		/// <summary>
		/// Ledger key used when a caller supplies no usable source name.
		/// </summary>
		private const string UnknownSourceKey = "unknown";

		/// <summary>
		/// Ledger key shared by every source beyond <see cref="MaxTrackedSources"/>.
		/// </summary>
		private const string OverflowSourceKey = "(source overflow)";

		/// <summary>
		/// Per-source rate-limit and loss ledger.
		/// </summary>
		private static readonly ConcurrentDictionary<string, SourceState> sourceStates =
			new ConcurrentDictionary<string, SourceState>(StringComparer.Ordinal);

		/// <summary>
		/// Rate-limit window and outstanding counts for one source.
		/// </summary>
		private sealed class SourceState
		{
			private readonly object gate = new object();
			private DateTime lastWrittenUtc = DateTime.MinValue;
			private int suppressedSinceLastWrite;
			private int unpersistedRecords;

			/// <summary>
			/// Attempts to claim the current window, returning false when one was already claimed.
			/// </summary>
			/// <remarks>
			/// The read and the update are taken under one lock so two concurrent faults cannot both
			/// observe an expired window and both write - which would defeat the rate limit exactly when
			/// it matters, under a fault storm.
			/// </remarks>
			internal bool TryClaimWindow(double intervalMinutes)
			{
				lock (gate)
				{
					var now = DateTime.UtcNow;
					if (now < lastWrittenUtc.AddMinutes(intervalMinutes))
					{
						return false;
					}

					lastWrittenUtc = now;
					return true;
				}
			}

			/// <summary>
			/// Counts one record withheld by the rate limit.
			/// </summary>
			internal void CountSuppressed()
			{
				Interlocked.Increment(ref suppressedSinceLastWrite);
			}

			/// <summary>
			/// Counts one record this source could not persist.
			/// </summary>
			internal void CountUnpersisted()
			{
				Interlocked.Increment(ref unpersistedRecords);
			}

			/// <summary>
			/// Reads the outstanding counts without clearing them.
			/// </summary>
			internal void ReadOutstanding(out int suppressed, out int unpersisted)
			{
				suppressed = Volatile.Read(ref suppressedSinceLastWrite);
				unpersisted = Volatile.Read(ref unpersistedRecords);
			}

			/// <summary>
			/// Subtracts the counts that have now been reported, keeping anything accrued concurrently.
			/// </summary>
			internal void ClearReported(int suppressed, int unpersisted)
			{
				if (suppressed > 0)
				{
					Interlocked.Add(ref suppressedSinceLastWrite, -suppressed);
				}

				if (unpersisted > 0)
				{
					Interlocked.Add(ref unpersistedRecords, -unpersisted);
				}
			}
		}

		/// <summary>
		/// Records an unhandled fault raised while serving a request, at most once per source per
		/// <see cref="FaultIntervalMinutes"/>.
		/// </summary>
		/// <param name="source">Call site the fault escaped from.</param>
		/// <param name="ex">The fault. A null value is recorded as an absent exception rather than thrown on.</param>
		/// <remarks>
		/// SECURITY (CWE-390, CWE-778). This replaces catch blocks that discarded the exception entirely,
		/// which left an attacker probing an endpoint no trace at all. It never throws and never returns a
		/// fault to the caller: the exception detail is persisted server-side only, so remediating the
		/// silent-catch defect cannot reintroduce the information disclosure of CWE-209.
		/// <para>
		/// The exception is handed to <see cref="Write(LogType, string, string, string, Exception)"/> rather
		/// than serialised here, so serialisation of a hostile or non-serialisable payload is caught by that
		/// method instead of escaping into the caller's catch block and replacing the original fault.
		/// </para>
		/// </remarks>
		internal static void RecordApiFault(string source, Exception ex)
		{
			var key = NormalizeSource(source);
			var state = GetState(key);

			if (!state.TryClaimWindow(FaultIntervalMinutes))
			{
				state.CountSuppressed();
				return;
			}

			var category = "Unhandled fault: " + (ex == null ? "none" : Normalize(ex.GetType().Name, MaxLoggedValueLength));

			if (!Write(LogType.Error, key, category, "api_fault source=" + key + "; ", ex))
			{
				state.CountUnpersisted();
				EmitFallbackSignal(key, category);
				return;
			}

			ReportOutstanding(key, state);
		}

		/// <summary>
		/// Records a security audit record for an event an unauthenticated caller can repeat for free, at
		/// most once per source per <see cref="FaultIntervalMinutes"/>, with everything it withheld counted
		/// and reported by the per-source ledger.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding OBS-06, CWE-778 (insufficient logging) held in tension with CWE-779
		/// (logging of excessive data), OWASP A09:2021. Some security-relevant refusals sit on paths an
		/// anonymous caller can drive in a loop at no cost - replaying one revoked bearer token is the case
		/// this was added for. Not recording them at all leaves no forensic evidence that a stolen credential
		/// was being reused after its session ended; recording every one hands the caller an unbounded write
		/// amplifier aimed at the audit trail. Neither is acceptable, so the event is recorded at a bounded
		/// rate and the volume it hid is reported by <see cref="ReportOutstanding"/> as
		/// <c>suppressed_by_rate_limit</c> - so a flood is visible AS a flood rather than as either silence or
		/// a flood of rows.
		/// <para>
		/// This is deliberately NOT <see cref="RecordAudit(string, LogType, string, string)"/>: that method is
		/// unbounded because an evaluated authentication outcome must never be withheld. The distinction is
		/// which side of the credential check the event sits on. Use this one only where the caller needs no
		/// credential to repeat the event.
		/// </para>
		/// <para>
		/// It never throws, for the same reason <see cref="RecordApiFault(string, Exception)"/> never does:
		/// its callers are refusal paths, and an audit write that could fail one of them would convert an
		/// audit-store hiccup into an authorization change.
		/// </para>
		/// </remarks>
		/// <param name="source">Stable call-site identifier; also the ledger partition.</param>
		/// <param name="type">Record severity.</param>
		/// <param name="message">Fixed literal describing the event. Never composed from caller data.</param>
		/// <param name="details">Already-neutralised detail text, assembled with <see cref="Field"/>.</param>
		internal static void RecordRateLimitedAudit(string source, LogType type, string message, string details)
		{
			var key = NormalizeSource(source);
			var state = GetState(key);

			if (!state.TryClaimWindow(FaultIntervalMinutes))
			{
				state.CountSuppressed();
				return;
			}

			var boundedMessage = Sanitize(message);

			if (!Write(type, key, boundedMessage, details))
			{
				state.CountUnpersisted();
				EmitFallbackSignal(key, boundedMessage);
				return;
			}

			ReportOutstanding(key, state);
		}

		/// <summary>
		/// Records a security audit record for a source that participates in the per-source ledger.
		/// </summary>
		/// <returns>True when the record was persisted.</returns>
		/// <remarks>
		/// Unlike <see cref="RecordApiFault(string, Exception)"/> and
		/// <see cref="RecordRateLimitedAudit(string, LogType, string, string)"/> this is NOT rate limited:
		/// authentication and authorization outcomes are the records the audit trail exists for, and
		/// withholding them to save log rows would let an attacker hide a credential-stuffing run behind its
		/// own volume. The throttle in front of the login path is what bounds the volume instead.
		/// </remarks>
		internal static bool RecordAudit(string source, LogType type, string message, string details)
		{
			var key = NormalizeSource(source);
			var state = GetState(key);
			var boundedMessage = Sanitize(message);

			if (!Write(type, key, boundedMessage, details))
			{
				state.CountUnpersisted();
				EmitFallbackSignal(key, boundedMessage);
				return false;
			}

			ReportOutstanding(key, state);
			return true;
		}

		/// <summary>
		/// Writes the per-source accounting record when a source has withheld or lost records.
		/// </summary>
		/// <remarks>
		/// SECURITY (CWE-778). Makes a gap in the trail visible IN the trail. The counts are read, then
		/// cleared only on a successful write, so a concurrent suppression is carried to the next report
		/// rather than lost.
		/// <para>
		/// ACCOUNTING. <c>not_persisted</c> is the per-source attribution of the same failures the
		/// aggregate <c>audit_writes_lost</c> field counts across all sources - the two are different views
		/// of one loss, not two losses. <c>suppressed_by_rate_limit</c> has no aggregate counterpart and is
		/// reported only here.
		/// </para>
		/// </remarks>
		private static void ReportOutstanding(string source, SourceState state)
		{
			state.ReadOutstanding(out var suppressed, out var unpersisted);
			if (suppressed == 0 && unpersisted == 0)
			{
				return;
			}

			var detail = "source=" + Field(source, MaxLoggedValueLength)
				+ "; suppressed_by_rate_limit=" + suppressed.ToString(CultureInfo.InvariantCulture)
				+ "; not_persisted=" + unpersisted.ToString(CultureInfo.InvariantCulture);

			if (Write(LogType.Info, AccountingSource, "Audit records suppressed or lost", detail))
			{
				state.ClearReported(suppressed, unpersisted);
			}
		}

		/// <summary>
		/// Emits an out-of-band signal when the log table itself could not be written.
		/// </summary>
		/// <remarks>
		/// The persistent store is exactly what is unavailable at this point, so the signal has to leave
		/// the process by another channel or the loss is invisible until the next successful write.
		/// </remarks>
		private static void EmitFallbackSignal(string source, string category)
		{
			System.Diagnostics.Trace.TraceError(
				"WebVella security audit record could not be persisted. source=" + source + "; category=" + category);
		}

		/// <summary>
		/// Resolves the ledger entry for a source, collapsing into a shared entry past the bound.
		/// </summary>
		private static SourceState GetState(string source)
		{
			if (sourceStates.TryGetValue(source, out var existing))
			{
				return existing;
			}

			var key = sourceStates.Count >= MaxTrackedSources ? OverflowSourceKey : source;
			return sourceStates.GetOrAdd(key, static _ => new SourceState());
		}

		/// <summary>
		/// Bounds and neutralises a source name, substituting a placeholder when none was supplied.
		/// </summary>
		private static string NormalizeSource(string source)
		{
			return string.IsNullOrWhiteSpace(source) ? UnknownSourceKey : Sanitize(source);
		}

		/// <summary>
		/// Bounds and neutralises a message destined for a persisted log record.
		/// </summary>
		/// <remarks>
		/// CWE-117. Delegates to <see cref="Normalize(string, int)"/> so this class has exactly one
		/// control-character neutralisation implementation to audit.
		/// </remarks>
		private static string Sanitize(string value)
		{
			return Normalize(value, MaxLoggedValueLength);
		}
	}
}
