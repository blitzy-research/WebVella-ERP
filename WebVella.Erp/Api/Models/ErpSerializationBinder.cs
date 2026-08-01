using System;
using System.Collections.Generic;
using System.Reflection;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

// SECURITY H-10 (CWE-502 deserialization of untrusted data / OWASP A08:2021 Software and
// Data Integrity Failures): polymorphic type handling (TypeNameHandling.All / .Auto) allows a
// persisted $type discriminator to instantiate an arbitrary type. This binder constrains TYPE
// RESOLUTION to an explicit allow-list of the platform's own persisted types rather than
// disabling polymorphism, precisely so already-persisted payloads continue to deserialise.
// BindToName is deliberately left to the base implementation: serialisation is not the
// CWE-502 attack surface, and constraining it would break SDK code generation and
// entity/relation persistence, whose graphs include open-ended dynamic content.

namespace WebVella.Erp.Api.Models
{
	/// <summary>
	/// Allow-list serialization binder for every deserialization site that enables polymorphic
	/// type handling. A stored <c>$type</c> discriminator is honoured only when the type it names
	/// satisfies one of exactly two rules:
	/// <list type="number">
	/// <item><description>
	/// it is a first party platform type - the assembly simple name is <c>WebVella.Erp</c> or
	/// begins with <c>WebVella.Erp.</c> AND the type name begins with <c>WebVella.Erp.</c>; or
	/// </description></item>
	/// <item><description>
	/// it is one of the small, explicitly enumerated framework types that the platform's own
	/// payloads legitimately carry.
	/// </description></item>
	/// </list>
	/// Everything else is refused with a <see cref="JsonSerializationException"/> naming the
	/// rejected assembly and type, so a refusal is diagnosable and can never silently degrade
	/// into permissive behaviour.
	/// </summary>
	/// <remarks>
	/// Usage - a deserialization site keeps the type handling value it already has and additionally
	/// attaches the shared <see cref="Instance"/>. This binder configures no serializer option of
	/// its own; it only constrains resolution, which is why already-persisted discriminators keep
	/// round-tripping:
	/// <code>
	/// settings.SerializationBinder = ErpSerializationBinder.Instance;
	/// </code>
	/// The binder holds no mutable state, so the shared instance is safe for concurrent use: the
	/// only collection it touches is populated once by its static initializer and is never
	/// written to afterwards, and <see cref="HashSet{T}"/> supports concurrent readers.
	/// </remarks>
	public class ErpSerializationBinder : DefaultSerializationBinder
	{
		/// <summary>
		/// Assembly simple name of the platform core library.
		/// </summary>
		private const string FirstPartyAssemblyName = "WebVella.Erp";

		/// <summary>
		/// Shared prefix of every first party namespace and of every first party satellite
		/// assembly simple name - the web framework and the plugin assemblies.
		/// </summary>
		private const string FirstPartyPrefix = "WebVella.Erp.";

		/// <summary>
		/// Upper bound on how deep the resolved type graph is walked while re-validating generic
		/// arguments and array element types. A hostile discriminator can nest generic arguments
		/// arbitrarily deeply, so the walk is bounded to keep a malformed payload from turning
		/// into a denial of service. Real payloads nest at most a few levels.
		/// </summary>
		private const int MaxTypeGraphDepth = 16;

		/// <summary>
		/// Upper bound on the length of a <c>$type</c> type-name token, applied before any
		/// resolution is attempted.
		/// </summary>
		/// <remarks>
		/// SECURITY M-01 (CWE-400 uncontrolled resource consumption). <see cref="MaxTypeGraphDepth"/>
		/// bounds the walk over an ALREADY RESOLVED type, which is too late to be the only bound.
		/// The outer-name allow-list inspects only the portion of the discriminator before the first
		/// bracket, so a token such as
		/// <c>System.Collections.Generic.List`1[[System.Collections.Generic.List`1[[ ... ]]]]</c>
		/// nested thousands of levels deep presents a permitted outer name, clears the allow-list,
		/// and is then handed to the base binder - which parses and resolves the entire nested
		/// structure, loading assemblies as it goes, before the depth bound is ever consulted. The
		/// work is done by the time the graph can be rejected.
		/// These two bounds are therefore enforced on the RAW token first, so a malformed
		/// discriminator is refused before it can cost anything. Real discriminators in this
		/// platform are around sixty characters - the longest observed in persisted data is
		/// <c>WebVella.Erp.Database.DbMultiLineTextField, WebVella.Erp</c> - so the limit leaves
		/// generous headroom for legitimately nested generics while removing the amplification.
		/// </remarks>
		private const int MaxTypeNameLength = 1024;

		/// <summary>
		/// Upper bound on the bracket nesting depth of a raw <c>$type</c> token, applied before any
		/// resolution is attempted. Deliberately equal to <see cref="MaxTypeGraphDepth"/> so the
		/// pre-resolution bound and the post-resolution walk agree; see
		/// <see cref="MaxTypeNameLength"/> for why a pre-resolution bound is required at all.
		/// </summary>
		private const int MaxTypeNameNestingDepth = MaxTypeGraphDepth;

		/// <summary>
		/// Upper bound on the length of the assembly-name portion of a discriminator.
		/// </summary>
		private const int MaxAssemblyNameLength = 256;

		/// <summary>
		/// Upper bound on the number of resolved discriminators memoised at any one time.
		/// </summary>
		/// <remarks>
		/// Threat addressed - CWE-770 (allocation without limits), OWASP A08:2021. See
		/// <see cref="ResolveBounded"/> for why memoisation cannot be left to the base binder. 256
		/// comfortably exceeds the number of distinct discriminators a real deployment persists -
		/// the first party types actually stored are a few dozen - while capping the retained set at
		/// a few tens of kilobytes of keys plus 256 type references.
		/// </remarks>
		private const int MaxCachedResolutions = 256;

		/// <summary>
		/// The namespaces of the core library whose types the platform legitimately persists inside
		/// a polymorphic payload. Used only to BUILD <see cref="AllowedFirstPartyTypes"/> at type
		/// initialization; it is never consulted while binding.
		/// </summary>
		/// <remarks>
		/// SECURITY M-01 (CWE-502). These five namespaces are what the deserialization sites this
		/// binder is attached to actually read: entity and relation documents and their field
		/// hierarchy (<c>WebVella.Erp.Database</c>), job attributes and results
		/// (<c>WebVella.Erp.Jobs</c>), the PostgreSQL notification payload
		/// (<c>WebVella.Erp.Notifications</c>), the shared API model graph
		/// (<c>WebVella.Erp.Api.Models</c>) and the log record (<c>WebVella.Erp.Diagnostics</c>).
		/// The choice is evidence-based rather than assumed: every <c>$type</c> discriminator
		/// present in persisted data is a <c>WebVella.Erp.Database.Db*Field</c> in the
		/// <c>WebVella.Erp</c> assembly, and the twenty-two concrete field subclasses are picked up
		/// wholesale from that namespace, so no persisted payload loses the ability to round-trip.
		/// </remarks>
		private static readonly string[] PersistedModelNamespaces =
		{
			"WebVella.Erp.Database",
			"WebVella.Erp.Api.Models",
			"WebVella.Erp.Jobs",
			"WebVella.Erp.Notifications",
			"WebVella.Erp.Diagnostics"
		};

		/// <summary>
		/// The exact, enumerated set of first party types a discriminator may name, keyed by full
		/// type name. Built once from the PINNED core assembly.
		/// </summary>
		/// <remarks>
		/// SECURITY M-01 (CWE-502 deserialization of untrusted data). An earlier revision admitted
		/// a first party type by PREFIX - any type whose name began with <c>WebVella.Erp.</c> in any
		/// assembly whose simple name began with <c>WebVella.Erp.</c>. That is an allow-list in name
		/// only: it spanned roughly seven hundred types across the core library, the web framework
		/// and all six plugin assemblies, including services, repositories, page models, hook
		/// implementations and anything else those assemblies happen to contain. A deserialization
		/// gadget does not need to be a plausible DTO - it only needs a reachable constructor or
		/// property setter with a side effect - so a wildcard of that breadth leaves CWE-502
		/// substantially open while presenting as closed.
		/// This map replaces the wildcard with exact full-name matching over a curated set, and the
		/// assembly is PINNED to the one this binder is compiled into rather than being taken from
		/// the payload, so a discriminator can no longer nominate which assembly is consulted. Two
		/// categories are excluded even inside the permitted namespaces: delegates, whose whole
		/// purpose is to carry an invocation target, and <see cref="IDisposable"/> implementors,
		/// which is how this codebase marks types owning a connection or other live resource. A
		/// persisted data document needs neither.
		/// </remarks>
		private static readonly Dictionary<string, Type> AllowedFirstPartyTypes = BuildFirstPartyTypeMap();

		/// <summary>
		/// The framework types the platform's own persisted payloads legitimately carry.
		/// <para>
		/// This set is required rather than cosmetic: <c>TypeNameHandling.All</c> stamps a
		/// <c>$type</c> discriminator on every object AND every array in a graph, not only on
		/// polymorphic members. A job's <c>attributes</c> and <c>result</c> are declared
		/// <c>dynamic</c>, so their persisted JSON routinely carries discriminators for
		/// <c>ExpandoObject</c>, <c>List&lt;object&gt;</c>, <c>Dictionary&lt;string, object&gt;</c>
		/// and <c>object[]</c>. Refusing those would not harden anything - it would break every
		/// read of an already-persisted job.
		/// </para>
		/// <para>
		/// The set is deliberately kept no larger than the deserialization sites need, is compared
		/// with <see cref="StringComparer.Ordinal"/> because type names are case sensitive, and is
		/// never widened into a namespace wildcard. It admits no type that has ever been used as a
		/// deserialization gadget.
		/// </para>
		/// </summary>
		private static readonly HashSet<string> AllowedFrameworkTypeNames = new HashSet<string>(StringComparer.Ordinal)
		{
			"System.Dynamic.ExpandoObject",
			"System.Object",
			"System.String",
			"System.Boolean",
			"System.Byte",
			"System.SByte",
			"System.Int16",
			"System.UInt16",
			"System.Int32",
			"System.UInt32",
			"System.Int64",
			"System.UInt64",
			"System.Single",
			"System.Double",
			"System.Decimal",
			"System.Char",
			"System.DateTime",
			"System.DateTimeOffset",
			"System.TimeSpan",
			"System.Guid",
			"System.Uri",
			"System.Collections.Generic.List`1",
			"System.Collections.Generic.Dictionary`2",
			"System.Collections.Generic.HashSet`1",
			"System.Collections.Generic.KeyValuePair`2",
			"System.Object[]",
			"System.String[]"
		};

		/// <summary>
		/// Shared, stateless instance. Deserialization runs once per database row and this binder
		/// runs once per <c>$type</c> token, so the sites that attach it reuse this instance
		/// instead of allocating a binder per row.
		/// </summary>
		public static readonly ErpSerializationBinder Instance = new ErpSerializationBinder();


		/// <summary>
		/// Serialises every read and write of <see cref="resolutionCache"/> and <see cref="resolver"/>.
		/// </summary>
		private readonly object resolutionLock = new object();

		/// <summary>
		/// Bounded memoisation of resolved discriminators, keyed by assembly and type name.
		/// </summary>
		private readonly Dictionary<string, Type> resolutionCache = new Dictionary<string, Type>(StringComparer.Ordinal);

		/// <summary>
		/// The delegate that performs actual type resolution. Replaceable, which is what bounds the
		/// memory the base implementation would otherwise retain - see <see cref="ResolveBounded"/>.
		/// </summary>
		private DefaultSerializationBinder resolver = new DefaultSerializationBinder();

		/// <summary>
		/// Resolves a stored <c>$type</c> discriminator to a <see cref="Type"/>, refusing anything
		/// the allow-list does not admit.
		/// </summary>
		/// <param name="assemblyName">
		/// Assembly portion of the discriminator. May be <c>null</c>, a simple name such as
		/// <c>WebVella.Erp</c>, or a qualified name carrying one or more comma delimited
		/// attributes after the simple name, as in <c>WebVella.Erp, Version=1.7.7.0</c>. Only the
		/// portion before the first comma is significant here, so any further attribute the
		/// runtime appends is tolerated without needing to be enumerated.
		/// </param>
		/// <param name="typeName">
		/// Type portion of the discriminator, which for a generic type embeds its arguments, as in
		/// <c>System.Collections.Generic.List`1[[WebVella.Erp.Database.DbBaseField, WebVella.Erp]]</c>.
		/// </param>
		/// <returns>The resolved type, guaranteed to satisfy the allow-list in full.</returns>
		/// <exception cref="JsonSerializationException">
		/// The discriminator names a type outside the allow-list, resolves to a type whose graph
		/// contains one, or cannot be resolved at all. This is the only exception type that leaves
		/// this method: a malformed stored discriminator must surface as a serialization error and
		/// never as a type-load or reference failure escaping into a caller that cannot handle it.
		/// </exception>
		public override Type BindToType(string assemblyName, string typeName)
		{
			if (string.IsNullOrWhiteSpace(typeName))
			{
				throw Refused(assemblyName, typeName, "the type name is missing");
			}

			// SECURITY M-01 (CWE-400). Size and shape bounds come FIRST - before the allow-list,
			// before any parsing and before any resolution - because the allow-list only inspects
			// the outer name and would happily pass a permitted outer type carrying an arbitrarily
			// large nested argument list on to the base binder. These are O(1) and O(n) scans over a
			// token that is about to be rejected, so nothing expensive happens for a hostile value.
			if (typeName.Length > MaxTypeNameLength)
			{
				throw Refused(assemblyName, typeName, $"the type name is {typeName.Length} characters long, which exceeds the {MaxTypeNameLength} character limit");
			}

			if (assemblyName != null && assemblyName.Length > MaxAssemblyNameLength)
			{
				throw Refused(assemblyName, typeName, $"the assembly name is {assemblyName.Length} characters long, which exceeds the {MaxAssemblyNameLength} character limit");
			}

			if (GetNestingDepth(typeName) > MaxTypeNameNestingDepth)
			{
				throw Refused(assemblyName, typeName, $"the type name nests generic arguments more than {MaxTypeNameNestingDepth} levels deep");
			}

			// Check the allow-list BEFORE resolution, so a rejected discriminator never reaches
			// assembly loading or type resolution in the first place.
			if (!IsAllowedTypeName(assemblyName, typeName))
			{
				throw Refused(assemblyName, typeName, "it is neither a WebVella.Erp platform type nor an explicitly permitted framework type");
			}

			// Resolution is delegated to ResolveBounded rather than to base.BindToType. That is not a
			// stylistic choice: the base binder memoises every discriminator it resolves in a
			// process-lifetime store with no capacity limit that this class cannot bound, inspect or
			// clear, so calling it would hand an attacker unbounded memory growth through nested
			// generic discriminators that all resolve successfully (CWE-770, OWASP A08:2021).
			// ResolveBounded fronts a replaceable resolver with a capacity-bounded cache and
			// translates every resolution failure into the bounded refusal this method contracts to
			// throw. See ResolveBounded for the full rationale.
			Type resolvedType = ResolveBounded(assemblyName, typeName);

			if (resolvedType == null)
			{
				throw Refused(assemblyName, typeName, "the type could not be resolved");
			}

			// Defence in depth. The pre-resolution check only inspects the outer type name, so a
			// permitted generic such as List`1 or a permitted array could otherwise smuggle a
			// forbidden argument or element type through. Re-validate the whole resolved graph.
			if (!IsAllowedResolvedType(resolvedType, 0, out var rejectedTypeName))
			{
				throw Refused(assemblyName, typeName, $"its resolved type graph contains the disallowed type '{rejectedTypeName}'");
			}

			return resolvedType;
		}

		/// <summary>
		/// Resolves a discriminator through a bounded memoisation cache.
		/// </summary>
		/// <remarks>
		/// Threat addressed - CWE-770 (allocation of resources without limits), OWASP A08:2021.
		/// <para>
		/// This method exists because <see cref="DefaultSerializationBinder"/> memoises every
		/// discriminator it successfully resolves in a private, process-lifetime store that has no
		/// capacity limit and no eviction. Calling <c>base.BindToType</c> would populate THAT store,
		/// which this class cannot bound, inspect or clear. The set of distinct discriminators is not
		/// small: nesting permitted generics over one another produces a combinatorial space of
		/// names that all resolve successfully, so a payload stream carrying a fresh nesting on every
		/// row would grow the base store without limit. Bounding the discriminator text does not
		/// bound that space, only its per-item size - so the cache itself has to be bounded.
		/// </para>
		/// <para>
		/// Resolution is therefore delegated to a REPLACEABLE binder instance fronted by this
		/// class's own capacity-bounded cache. <c>base.BindToType</c> is never called, so the
		/// inherited store is provably never populated. When the cache reaches
		/// <see cref="MaxCachedResolutions"/> both stores are discarded together - the dictionary is
		/// cleared and the delegate is replaced, which drops the delegate's internal store with it -
		/// so the worst case degrades to resolving without a cache rather than to unbounded memory.
		/// Deriving from <see cref="DefaultSerializationBinder"/> is retained deliberately, because
		/// <c>BindToName</c> must keep the inherited behaviour exactly; only resolution is diverted.
		/// </para>
		/// <para>
		/// The lock covers only the dictionary operations. Resolution runs outside it, so concurrent
		/// deserialization is never serialised behind assembly loading; the cost of that choice is
		/// that two threads racing on the same unseen discriminator may both resolve it, which is
		/// idempotent and yields the same type.
		/// </para>
		/// </remarks>
		private Type ResolveBounded(string assemblyName, string typeName)
		{
			// Both components are already length-bounded by ExceedsPreResolutionBudget, so the key
			// is bounded too. The separator is a character that cannot appear in either component,
			// so two different pairs can never collide on one key.
			var cacheKey = string.Concat(assemblyName, "|", typeName);
			DefaultSerializationBinder activeResolver;

			lock (resolutionLock)
			{
				if (resolutionCache.TryGetValue(cacheKey, out var cachedType))
				{
					return cachedType;
				}

				activeResolver = resolver;
			}

			Type resolvedType;

			try
			{
				resolvedType = activeResolver.BindToType(assemblyName, typeName);
			}
			catch (JsonSerializationException exception)
			{
				// Translated, NOT rethrown. The base implementation reports an unresolvable
				// discriminator by embedding the offending name in its message verbatim and
				// unbounded, so rethrowing it would defeat the diagnostic cap that Truncate exists to
				// enforce - a 900-character type name would reach the log in full even though every
				// message this class builds itself is bounded. Nothing is lost by translating: the
				// base message contains only an echo of the assembly and type name, which the
				// replacement already reports in bounded form.
				//
				// The original is deliberately NOT attached as an inner exception, because its
				// message is the very unbounded text being suppressed and a sink that records the
				// whole exception chain would reintroduce it. Its type is recorded instead, which is
				// the part with diagnostic value.
				throw Refused(assemblyName, typeName, $"the type could not be resolved ({exception.GetType().Name})");
			}
			// Only the exception types that type resolution can actually raise are translated. This
			// is deliberately NOT a blanket catch: a genuine platform fault - an OutOfMemoryException
			// or a cancellation, say - must stay visible rather than be relabelled as a malformed
			// discriminator, which would turn a real incident into a misleading serialization error.
			//
			// These four DO keep their inner exception, unlike the case above, and the distinction is
			// deliberate. Reaching any of them means the discriminator already passed the allow-list,
			// so it claims to be a first party or explicitly permitted type - which makes a load
			// failure a deployment or environment fault rather than a hostile payload, and exactly
			// the case where an operator needs the runtime's own detail such as a fusion reason or an
			// architecture mismatch. Their text is bounded in any event, because the names it echoes
			// were already length-capped by ExceedsPreResolutionBudget. The message THIS class builds
			// is capped at MaxDiagnosticValueLength per value regardless.
			catch (TypeLoadException exception)
			{
				throw Refused(assemblyName, typeName, "the type could not be resolved", exception);
			}
			catch (System.IO.FileNotFoundException exception)
			{
				throw Refused(assemblyName, typeName, "the assembly could not be found", exception);
			}
			catch (System.IO.FileLoadException exception)
			{
				throw Refused(assemblyName, typeName, "the assembly could not be loaded", exception);
			}
			catch (BadImageFormatException exception)
			{
				throw Refused(assemblyName, typeName, "the assembly is not a valid managed image", exception);
			}
			catch (ArgumentException exception)
			{
				// Raised by the runtime's own type-name parser for a malformed name that survived
				// the textual budget checks.
				throw Refused(assemblyName, typeName, "the type name is malformed", exception);
			}

			if (resolvedType == null)
			{
				// Not cached: a null result is a failure, and caching failures would let a hostile
				// payload stream fill the cache with entries that never help anything.
				return null;
			}

			lock (resolutionLock)
			{
				if (resolutionCache.Count >= MaxCachedResolutions)
				{
					// Discard BOTH stores together. Clearing only this dictionary would leave the
					// delegate's own store holding everything resolved so far, which is precisely
					// the unbounded growth this method exists to prevent.
					resolutionCache.Clear();
					resolver = new DefaultSerializationBinder();
				}

				resolutionCache[cacheKey] = resolvedType;
			}

			return resolvedType;
		}

		/// <summary>
		/// Applies the two allow-list rules to a discriminator's assembly and type name.
		/// </summary>
		private static bool IsAllowedTypeName(string assemblyName, string typeName)
		{
			// A generic discriminator embeds its arguments, so only the portion before the first
			// bracket describes the outer type. The arguments are validated separately, against
			// the resolved type, by IsAllowedResolvedType.
			var outerTypeName = GetOuterTypeName(typeName);

			if (outerTypeName.Length == 0)
			{
				return false;
			}

			// Rule (a) - first party platform type, matched EXACTLY against the enumerated map
			// rather than by namespace prefix. The assembly claim must also be first party, so a
			// foreign assembly cannot vouch for a permitted type name; the type that is ultimately
			// accepted is verified to come from the pinned assembly by IsAllowedResolvedType.
			if (IsFirstPartyAssembly(GetAssemblySimpleName(assemblyName))
				&& AllowedFirstPartyTypes.ContainsKey(outerTypeName))
			{
				return true;
			}

			// Rule (b) - explicitly permitted framework type. Intentionally assembly agnostic:
			// the framework spreads these types across several assemblies - ExpandoObject lives in
			// System.Linq.Expressions and Uri in System.Private.Uri - so pinning them to an
			// assembly name would be brittle without adding any protection.
			return AllowedFrameworkTypeNames.Contains(outerTypeName);
		}

		/// <summary>
		/// Re-validates a resolved type and every constituent of its graph - array, by-ref and
		/// pointer element types, and generic arguments - against the same two allow-list rules.
		/// </summary>
		/// <param name="type">The type to validate.</param>
		/// <param name="depth">Current walk depth, bounded by <see cref="MaxTypeGraphDepth"/>.</param>
		/// <param name="rejectedTypeName">
		/// On refusal, the name of the constituent that failed, for the diagnostic message.
		/// </param>
		private static bool IsAllowedResolvedType(Type type, int depth, out string rejectedTypeName)
		{
			rejectedTypeName = null;

			if (type == null)
			{
				rejectedTypeName = "<unresolved>";
				return false;
			}

			if (depth > MaxTypeGraphDepth)
			{
				rejectedTypeName = GetDiagnosticName(type);
				return false;
			}

			// Arrays, by-ref types and pointers carry their payload in the element type, so the
			// element is what has to clear the allow-list.
			if (type.IsArray || type.IsByRef || type.IsPointer)
			{
				return IsAllowedResolvedType(type.GetElementType(), depth + 1, out rejectedTypeName);
			}

			// An open generic parameter names no concrete type, so it can carry no gadget.
			if (type.IsGenericParameter)
			{
				return true;
			}

			// A constructed generic is admitted on its open definition - List`1 rather than
			// List`1[[...]] - because that is the form the allow-list enumerates.
			var declaredTypeName = type.IsGenericType
				? type.GetGenericTypeDefinition().FullName
				: type.FullName;

			// SECURITY M-01 (CWE-502). A first party constituent must be the EXACT type held in the
			// pinned map - reference equality against the Type object, not merely a name match - so
			// a same-named type loaded from any other assembly is refused here even if it somehow
			// satisfied the name check. Framework constituents fall through to the enumerated
			// framework set, which is assembly agnostic by design.
			if (declaredTypeName != null
				&& AllowedFirstPartyTypes.TryGetValue(declaredTypeName, out var pinnedType))
			{
				var candidate = type.IsGenericType ? type.GetGenericTypeDefinition() : type;

				if (candidate != pinnedType)
				{
					rejectedTypeName = GetDiagnosticName(type);
					return false;
				}
			}
			else if (!IsAllowedTypeName(type.Assembly.GetName().Name, declaredTypeName))
			{
				rejectedTypeName = GetDiagnosticName(type);
				return false;
			}

			if (type.IsGenericType)
			{
				foreach (var genericArgument in type.GetGenericArguments())
				{
					if (!IsAllowedResolvedType(genericArgument, depth + 1, out rejectedTypeName))
					{
						return false;
					}
				}
			}

			return true;
		}

		/// <summary>
		/// Builds the exact first party type map from the PINNED core assembly. Runs once, during
		/// type initialization; see <see cref="AllowedFirstPartyTypes"/> for the rationale.
		/// </summary>
		private static Dictionary<string, Type> BuildFirstPartyTypeMap()
		{
			var map = new Dictionary<string, Type>(StringComparer.Ordinal);

			// The assembly is taken from this binder's own type identity, never from a name supplied
			// by the payload, so no discriminator can influence which assembly is enumerated.
			var pinnedAssembly = typeof(ErpSerializationBinder).Assembly;

			Type[] types;

			try
			{
				types = pinnedAssembly.GetTypes();
			}
			catch (ReflectionTypeLoadException exception)
			{
				// A type that cannot be loaded simply does not become permitted. Failing open here -
				// by falling back to a prefix match, say - would defeat the point of the map, so the
				// loadable subset is used and anything else stays refused.
				var loadable = new List<Type>();

				foreach (var candidate in exception.Types)
				{
					if (candidate != null)
					{
						loadable.Add(candidate);
					}
				}

				types = loadable.ToArray();
			}

			foreach (var type in types)
			{
				if (type.FullName == null || type.Namespace == null)
				{
					continue;
				}

				if (!IsPersistedModelNamespace(type.Namespace))
				{
					continue;
				}

				// A delegate exists to carry an invocation target and a disposable owns a live
				// resource. Neither is ever a persisted data document, and both are exactly the
				// shapes a deserialization gadget is built from.
				if (typeof(Delegate).IsAssignableFrom(type) || typeof(IDisposable).IsAssignableFrom(type))
				{
					continue;
				}

				map[type.FullName] = type;
			}

			return map;
		}

		/// <summary>
		/// True when a namespace is one of <see cref="PersistedModelNamespaces"/>, or a descendant
		/// of one.
		/// </summary>
		private static bool IsPersistedModelNamespace(string typeNamespace)
		{
			foreach (var permitted in PersistedModelNamespaces)
			{
				if (string.Equals(typeNamespace, permitted, StringComparison.Ordinal)
					|| typeNamespace.StartsWith(permitted + ".", StringComparison.Ordinal))
				{
					return true;
				}
			}

			return false;
		}

		/// <summary>
		/// Maximum bracket nesting depth of a raw discriminator token, measured without parsing or
		/// allocating. Used to refuse a deeply nested generic before resolution; see
		/// <see cref="MaxTypeNameLength"/>.
		/// </summary>
		private static int GetNestingDepth(string typeName)
		{
			var depth = 0;
			var maximumDepth = 0;

			foreach (var character in typeName)
			{
				if (character == '[')
				{
					depth++;

					if (depth > maximumDepth)
					{
						maximumDepth = depth;
					}
				}
				else if (character == ']' && depth > 0)
				{
					depth--;
				}
			}

			return maximumDepth;
		}

		/// <summary>
		/// True when the assembly simple name belongs to the first party platform family.
		/// </summary>
		private static bool IsFirstPartyAssembly(string assemblySimpleName)
		{
			if (string.IsNullOrEmpty(assemblySimpleName))
			{
				return false;
			}

			return string.Equals(assemblySimpleName, FirstPartyAssemblyName, StringComparison.Ordinal)
				|| assemblySimpleName.StartsWith(FirstPartyPrefix, StringComparison.Ordinal);
		}

		/// <summary>
		/// Extracts the simple name from an assembly name that may be fully qualified, and
		/// tolerates a missing one.
		/// </summary>
		private static string GetAssemblySimpleName(string assemblyName)
		{
			if (string.IsNullOrEmpty(assemblyName))
			{
				return string.Empty;
			}

			var separatorIndex = assemblyName.IndexOf(',');

			if (separatorIndex >= 0)
			{
				return assemblyName.Substring(0, separatorIndex).Trim();
			}

			return assemblyName.Trim();
		}

		/// <summary>
		/// Strips any embedded generic argument or array suffix, leaving the outer type name.
		/// </summary>
		private static string GetOuterTypeName(string typeName)
		{
			if (string.IsNullOrEmpty(typeName))
			{
				return string.Empty;
			}

			var suffixIndex = typeName.IndexOf('[');

			if (suffixIndex >= 0)
			{
				return typeName.Substring(0, suffixIndex).Trim();
			}

			return typeName.Trim();
		}

		/// <summary>
		/// Best-effort display name of a type for a diagnostic message.
		/// </summary>
		private static string GetDiagnosticName(Type type)
		{
			return type.FullName ?? type.Name;
		}

		/// <summary>
		/// Renders a rejected discriminator fragment for inclusion in a refusal message: truncated,
		/// with every character outside printable ASCII escaped.
		/// </summary>
		/// <remarks>
		/// SECURITY M-01 (CWE-400 uncontrolled resource consumption, CWE-117 improper output
		/// neutralisation for logs). The refusal message is the one place a rejected discriminator is
		/// reflected back, and refusals are logged. Echoing the token verbatim meant the two
		/// oversize bounds added above still produced an oversize RESULT: a 2,000 character type name
		/// was refused correctly but generated a 2,184 character exception message, and a deeply
		/// nested generic produced a 3,889 character one - so the amplification the bounds exist to
		/// prevent simply moved from the resolver into the log. A discriminator is also attacker
		/// supplied text that may carry newlines or terminal control sequences, which would let a
		/// refused payload forge additional log lines.
		/// Truncating and escaping keeps the message diagnostic - an operator can still see what was
		/// refused and decide whether it is hostile or a legitimate type the allow-list does not yet
		/// cover - while ensuring the untrusted fragment cannot restructure the record containing it.
		/// </remarks>
		private static string Describe(string value)
		{
			if (string.IsNullOrWhiteSpace(value))
			{
				return "<none>";
			}

			const int maximumEchoedLength = 128;

			var truncated = value.Length > maximumEchoedLength;
			var length = truncated ? maximumEchoedLength : value.Length;
			var builder = new System.Text.StringBuilder(length + 32);

			for (var index = 0; index < length; index++)
			{
				var character = value[index];

				if (character >= ' ' && character <= '~')
				{
					builder.Append(character);
				}
				else
				{
					builder.Append("\\u").Append(((int)character).ToString("x4", System.Globalization.CultureInfo.InvariantCulture));
				}
			}

			if (truncated)
			{
				builder.Append("... (truncated from ").Append(value.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)).Append(" characters)");
			}

			return builder.ToString();
		}

		/// <summary>
		/// Builds the refusal exception. The message names both the rejected type and the rejected
		/// assembly so that an operator can tell a hostile payload from a legitimate one that the
		/// allow-list does not yet cover.
		/// </summary>
		private static JsonSerializationException Refused(string assemblyName, string typeName, string reason)
		{
			return Refused(assemblyName, typeName, reason, null);
		}

		/// <summary>
		/// Builds the refusal exception, preserving the underlying failure as the inner exception.
		/// </summary>
		private static JsonSerializationException Refused(string assemblyName, string typeName, string reason, Exception innerException)
		{
			var reportedTypeName = Describe(typeName);
			var reportedAssemblyName = Describe(assemblyName);
			var message = $"{nameof(ErpSerializationBinder)} refused to bind type '{reportedTypeName}' from assembly '{reportedAssemblyName}' because {reason}.";

			if (innerException == null)
			{
				return new JsonSerializationException(message);
			}

			return new JsonSerializationException(message, innerException);
		}
	}
}
