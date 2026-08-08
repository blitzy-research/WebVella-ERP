using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

// SECURITY H-10 (CWE-502 deserialization of untrusted data / OWASP A08:2021): polymorphic type handling
// (TypeNameHandling.All/.Auto) lets a persisted $type discriminator instantiate an arbitrary type. This
// binder constrains TYPE RESOLUTION to an explicit allow-list of the platform's own persisted types
// rather than disabling polymorphism, precisely so already-persisted payloads continue to deserialise.
// BindToName is left to the base implementation: serialisation is not the CWE-502 attack surface, and
// constraining it would break SDK code generation and entity/relation persistence.

namespace WebVella.Erp.Api.Models
{
	/// <summary>
	/// Allow-list serialization binder for every deserialization site that enables polymorphic type
	/// handling. A stored <c>$type</c> discriminator is honoured only when the type it names is either one of
	/// the explicitly enumerated core library types the platform persists - see
	/// <see cref="PersistedModelTypes"/>, matched by EXACT full name and claimed by a first party assembly -
	/// or one of the small enumerated framework types the platform's own payloads legitimately carry.
	/// Everything else is refused with a <see cref="JsonSerializationException"/> naming the rejected
	/// assembly and type, so a refusal is diagnosable and can never silently degrade into permissiveness.
	/// </summary>
	/// <remarks>
	/// A deserialization site keeps the type handling value it already has and additionally attaches the
	/// shared <see cref="Instance"/>; this binder configures no serializer option of its own, which is why
	/// already-persisted discriminators keep round-tripping.
	/// The shared instance is NOT stateless: it owns a bounded resolution cache and a replaceable resolver,
	/// both described on <see cref="ResolveBounded"/> and guarded by <see cref="resolutionLock"/>. The static
	/// allow-list collections are a separate matter - populated once by the type initializer and never
	/// written to afterwards.
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
		/// Upper bound on the length of a <c>$type</c> token, applied before any resolution is attempted.
		/// </summary>
		/// <remarks>
		/// SECURITY H-10 hardening (CWE-400 uncontrolled resource consumption). <see cref="MaxTypeGraphDepth"/>
		/// bounds the walk over an ALREADY RESOLVED type, which is too late to be the only bound: the outer-name
		/// allow-list inspects only the portion before the first bracket, so a token nesting a permitted generic
		/// thousands of levels deep clears the allow-list and is then handed to the base binder, which parses and
		/// resolves the entire structure, loading assemblies as it goes, before the depth bound is consulted.
		/// These bounds are therefore enforced on the RAW token first. Real discriminators here are around sixty
		/// characters, so the limit leaves generous headroom while removing the amplification.
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
		/// Upper bound on the number of resolved discriminators memoised at any one time (CWE-770, OWASP
		/// A08:2021). See <see cref="ResolveBounded"/> for why memoisation cannot be left to the base binder.
		/// 256 comfortably exceeds what a real deployment persists while capping the retained set at a few tens
		/// of kilobytes of keys plus 256 type references.
		/// </summary>
		private const int MaxCachedResolutions = 256;

		/// <summary>
		/// Upper bound on the length of a <c>$type</c> token, applied before any resolution is attempted.
		/// </summary>
		/// <remarks>
		/// SECURITY H-10 hardening (CWE-400). <see cref="MaxTypeGraphDepth"/> bounds the walk over an ALREADY
		/// RESOLVED type, which is too late to be the only bound: the allow-list inspects only the portion before
		/// the first bracket, so a token nesting a permitted generic thousands of levels deep clears it and is
		/// then handed to the base binder, which parses and resolves the whole structure, loading assemblies as
		/// it goes, before the depth bound is consulted. Real discriminators are around sixty characters.
		/// </remarks>
		private static readonly Type[] PersistedModelTypes =
		{
			// Entity and relation documents. Read at DbEntityRepository, DbRelationRepository and
			// CodeGenService. DbEntity.Fields is declared List<DbBaseField> while its elements are
			// concrete subclasses, so every subclass below has to remain nameable or an entity stops
			// loading - which is exactly why polymorphism is constrained here rather than disabled.
			typeof(WebVella.Erp.Database.DbDocumentBase),
			typeof(WebVella.Erp.Database.DbEntity),
			typeof(WebVella.Erp.Database.DbEntityRelation),

			// The fourth and last DbDocumentBase subclass, retained defensively: no deserialization site reads it,
			// but DbDocumentBase is abstract and appears as a GENERIC ARGUMENT in collection discriminators, so
			// keeping the subclass set complete stops such a discriminator being refused for naming a sibling.
			typeof(WebVella.Erp.Database.DbSystemSettings),

			typeof(WebVella.Erp.Database.DbEntityRelationOptions),
			typeof(WebVella.Erp.Database.DbRecordPermissions),
			typeof(WebVella.Erp.Database.DbFieldPermissions),
			typeof(WebVella.Erp.Database.DbBaseField),
			typeof(WebVella.Erp.Database.DbAutoNumberField),
			typeof(WebVella.Erp.Database.DbCheckboxField),
			typeof(WebVella.Erp.Database.DbCurrencyField),
			typeof(WebVella.Erp.Database.DbDateField),
			typeof(WebVella.Erp.Database.DbDateTimeField),
			typeof(WebVella.Erp.Database.DbEmailField),
			typeof(WebVella.Erp.Database.DbFileField),
			typeof(WebVella.Erp.Database.DbGeographyField),
			typeof(WebVella.Erp.Database.DbGuidField),
			typeof(WebVella.Erp.Database.DbHtmlField),
			typeof(WebVella.Erp.Database.DbImageField),
			typeof(WebVella.Erp.Database.DbMultiLineTextField),
			typeof(WebVella.Erp.Database.DbMultiSelectField),
			typeof(WebVella.Erp.Database.DbNumberField),
			typeof(WebVella.Erp.Database.DbPasswordField),
			typeof(WebVella.Erp.Database.DbPercentField),
			typeof(WebVella.Erp.Database.DbPhoneField),
			typeof(WebVella.Erp.Database.DbSelectField),
			typeof(WebVella.Erp.Database.DbTextField),
			typeof(WebVella.Erp.Database.DbTreeSelectField),
			typeof(WebVella.Erp.Database.DbUrlField),

			// Value holders and enumerations the field hierarchy above reaches by data member.
			// CurrencySymbolPlacement sits in WebVella.Erp, not WebVella.Erp.Database.
			typeof(WebVella.Erp.Database.DbSelectOption),
			typeof(WebVella.Erp.Database.DbCurrencyType),
			typeof(WebVella.Erp.Database.DbGeographyFieldFormat),
			typeof(WebVella.Erp.Api.CurrencySymbolPlacement),
			typeof(WebVella.Erp.Api.Models.EntityRelationType),

			// Job and schedule graph. JobResultWrapper is the current shape of the jobs.result
			// column and is the one deserialization target whose payload member is declared dynamic,
			// so it is the site where the allow-list does the most work. It is internal, and it is
			// referenced here only inside this private array - never in a public signature.
			typeof(WebVella.Erp.Jobs.Job),
			typeof(WebVella.Erp.Jobs.JobResultWrapper),
			typeof(WebVella.Erp.Jobs.JobStatus),
			typeof(WebVella.Erp.Jobs.JobPriority),
			typeof(WebVella.Erp.Jobs.JobType),
			typeof(WebVella.Erp.Jobs.SchedulePlan),
			typeof(WebVella.Erp.Jobs.SchedulePlanType),
			typeof(WebVella.Erp.Jobs.SchedulePlanDaysOfWeek),
			typeof(WebVella.Erp.Jobs.OutputSchedulePlan),

			// PostgreSQL NOTIFY payload. Anything able to issue a NOTIFY on the channel controls the
			// discriminator, which makes this the least trusted deserialization input in the platform.
			typeof(WebVella.Erp.Notifications.Notification),

			// The dynamic record. Unlike ExpandoObject, which the serializer resolves internally
			// without ever consulting a binder, this type derives from DynamicObject and its member
			// values ARE resolved here, so it has to be nameable.
			typeof(WebVella.Erp.Api.Models.EntityRecord)
		};

		/// <summary>
		/// The exact, enumerated set of first party types a discriminator may name, keyed by full type name.
		/// Built once from <see cref="PersistedModelTypes"/>.
		/// </summary>
		/// <remarks>
		/// SECURITY H-10 (CWE-502). Admission is EXACT full-name matching, never a name prefix and never a
		/// namespace scan: either of those admits whatever the matching namespace or assembly happens to contain,
		/// which is an allow-list in name only. The assembly is pinned by construction, every entry being a
		/// <c>typeof</c> in this assembly, and <see cref="IsAllowedResolvedType"/> confirms the accepted type is
		/// that very <see cref="Type"/> instance BY REFERENCE, so a same-named type from anywhere else is
		/// refused. Delegates and <see cref="IDisposable"/> implementors are excluded as a standing guard.
		/// </remarks>
		private static readonly Dictionary<string, Type> AllowedFirstPartyTypes = BuildFirstPartyTypeMap();

		/// <summary>
		/// The framework types the platform's own persisted payloads legitimately carry, each pinned to the exact
		/// <see cref="Type"/> a <c>typeof</c> resolves.
		/// </summary>
		/// <remarks>
		/// Required rather than cosmetic: <c>TypeNameHandling.All</c> stamps a <c>$type</c> discriminator on every
		/// object AND every array in a graph, and a job's <c>attributes</c> and <c>result</c> are declared
		/// <c>dynamic</c>, so persisted job JSON routinely carries discriminators for <c>ExpandoObject</c>,
		/// <c>List&lt;object&gt;</c>, <c>Dictionary&lt;string, object&gt;</c> and <c>object[]</c>; refusing those
		/// would break every read of an already-persisted job rather than harden anything.
		/// <para>
		/// THREAT ADDRESSED - CWE-502 reached by ASSEMBLY CONFUSION, OWASP A08:2021. A set of NAMES alone is not
		/// sufficient: any assembly loaded into the process may declare a public <c>System.Uri</c> or
		/// <c>System.Collections.Generic.List`1</c>, and a discriminator naming it then satisfies a name test and
		/// is constructed. The map therefore carries the pinned <see cref="Type"/> for the post-resolution
		/// reference-equality test as well as the name for the pre-resolution one, and is never widened into a
		/// namespace wildcard.
		/// </para>
		/// </remarks>
		private static readonly Dictionary<string, Type> AllowedFrameworkTypes = BuildFrameworkTypeMap();

		/// <summary>
		/// The names in <see cref="AllowedFrameworkTypes"/>, plus the two array discriminators, for the
		/// pre-resolution name test in <see cref="IsAllowedTypeName"/>.
		/// </summary>
		/// <remarks>
		/// SECURITY H-10 (CWE-502). Derived from the pinned map rather than written out a second time, so the two
		/// cannot disagree - a name here but absent from the map would pass the name test and then be refused by
		/// the reference test, which is safe but reports the wrong reason, while the reverse would be a hole. The
		/// two array forms are added because a discriminator spells an array as <c>System.Object[]</c> whereas the
		/// resolved graph is walked through <see cref="Type.GetElementType"/>.
		/// </remarks>
		private static readonly HashSet<string> AllowedFrameworkTypeNames = BuildFrameworkTypeNameSet();

		/// <summary>
		/// The shared binder instance every deserialization site attaches. Deserialization runs once per
		/// database row and this binder runs once per <c>$type</c> token, so the sites that attach it reuse
		/// this instance instead of allocating a binder per row. It is NOT stateless - it carries the
		/// mutable resolution state described on <see cref="ResolveBounded"/>, guarded by
		/// <see cref="resolutionLock"/>.
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
		/// Resolves a stored <c>$type</c> discriminator to a <see cref="Type"/>, refusing anything the allow-list
		/// does not admit.
		/// </summary>
		/// <param name="assemblyName">
		/// Assembly portion of the discriminator. May be <c>null</c>, a simple name, or a qualified name carrying
		/// comma-delimited attributes; only the portion before the first comma is significant, so any further
		/// attribute the runtime appends is tolerated without being enumerated.
		/// </param>
		/// <param name="typeName">Type portion, which for a generic type embeds its arguments.</param>
		/// <returns>The resolved type, guaranteed to satisfy the allow-list in full.</returns>
		/// <exception cref="JsonSerializationException">
		/// The discriminator names a type outside the allow-list, resolves to a type whose graph contains one, or
		/// cannot be resolved at all. This is the ONLY exception type that leaves this method: a malformed stored
		/// discriminator must surface as a serialization error, never as a type-load or reference failure
		/// escaping into a caller that cannot handle it.
		/// </exception>
		public override Type BindToType(string assemblyName, string typeName)
		{
			if (string.IsNullOrWhiteSpace(typeName))
			{
				throw Refused(assemblyName, typeName, "the type name is missing");
			}

			// SECURITY H-10 hardening (CWE-400). Size and shape bounds come FIRST - before the allow-list, before
			// any parsing and before any resolution - because the allow-list inspects only the outer name and would
			// pass a permitted outer type carrying an arbitrarily large nested argument list on to the base binder.
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

			// Resolution is delegated to ResolveBounded rather than to base.BindToType, and that is not stylistic:
			// the base binder memoises every discriminator it resolves in a process-lifetime store with no capacity
			// limit that this class cannot bound, inspect or clear, so calling it would hand an attacker unbounded
			// memory growth through nested generic discriminators that all resolve successfully (CWE-770).
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
		/// THREAT ADDRESSED - CWE-770 (allocation of resources without limits), OWASP A08:2021.
		/// <see cref="DefaultSerializationBinder"/> memoises every discriminator it resolves in a private,
		/// process-lifetime store with no capacity limit and no eviction, and nesting permitted generics produces
		/// a combinatorial space of names that all resolve successfully, so a payload stream carrying a fresh
		/// nesting per row would grow that store without limit.
		/// <para>
		/// Resolution is therefore delegated to a REPLACEABLE binder fronted by this class's own capacity-bounded
		/// cache; <c>base.BindToType</c> is never called, so the inherited store is provably never populated. At
		/// <see cref="MaxCachedResolutions"/> both stores are discarded together - the dictionary cleared and the
		/// delegate replaced - so the worst case degrades to resolving without a cache rather than to unbounded
		/// memory. Deriving from <see cref="DefaultSerializationBinder"/> is retained because <c>BindToName</c>
		/// must keep the inherited behaviour exactly. The lock covers only the dictionary operations, so
		/// concurrent deserialization is never serialised behind assembly loading; two threads racing on the same
		/// unseen discriminator may both resolve it, which is idempotent.
		/// </para>
		/// </remarks>
		private Type ResolveBounded(string assemblyName, string typeName)
		{
			// Both components are already length-bounded by the MaxTypeNameLength and MaxAssemblyNameLength
			// checks at the top of BindToType, so the key
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
				// Translated, NOT rethrown. The base implementation embeds the offending name in its message verbatim
				// and unbounded, so rethrowing would defeat the diagnostic cap Describe exists to enforce. Nothing is
				// lost: the base message contains only an echo of the assembly and type name, which the replacement
				// already reports in bounded form. The original is deliberately NOT attached as an inner exception,
				// because its message is the very unbounded text being suppressed; its type is recorded instead.
				throw Refused(assemblyName, typeName, $"the type could not be resolved ({exception.GetType().Name})");
			}
			// Only the exception types type resolution can actually raise are translated - deliberately NOT a
			// blanket catch, because a genuine platform fault must stay visible rather than be relabelled as a
			// malformed discriminator. These four DO keep their inner exception, unlike the case above: reaching
			// one means the discriminator already passed the allow-list, so a load failure is a deployment or
			// environment fault and exactly the case where an operator needs the runtime's own detail. Their text
			// is bounded in any event, because the names it echoes were length-capped at the top of BindToType.
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

			// Rule (a) - first party platform type. The assembly simple name must belong to the WebVella.Erp family
			// AND the outer type name must be present in the ENUMERATED map built from PersistedModelTypes. Both
			// halves are required: a foreign assembly may not vouch for a first party type name, and a first party
			// assembly may not vouch for a type the inventory does not list.
			//
			// SECURITY H-10 (CWE-502 / OWASP A08:2021). The test is an EXACT map lookup, deliberately NOT a
			// namespace-prefix test, and must not be relaxed into one: a prefix test on "WebVella.Erp." admits every
			// repository, manager, page model and hook implementation across the core library, the web framework and
			// all six plugin assemblies, and would make PersistedModelTypes dead code. Such types are reachable in
			// practice, because a discriminator in the jobs.result column resolves here.
			//
			// What additionally keeps resolution safe is enforced against the RESOLVED type by
			// IsAllowedResolvedType: the real assembly is re-tested, delegates and IDisposable implementors are
			// rejected outright, a listed type must match the pinned map by reference equality, and the whole
			// generic and array graph is re-walked under a depth bound.
			if (IsFirstPartyAssembly(GetAssemblySimpleName(assemblyName))
				&& AllowedFirstPartyTypes.ContainsKey(outerTypeName))
			{
				return true;
			}

			// Rule (b) - explicitly permitted framework type. This stage is a NAME test only, and it is deliberately
			// assembly agnostic HERE because it runs before resolution: the framework spreads these types across
			// several assemblies - ExpandoObject in System.Linq.Expressions, Uri in System.Private.Uri - and the
			// discriminator's assembly component is attacker-supplied text, so testing it would reject legitimate
			// payloads while proving nothing about what is loaded.
			// WHAT ACTUALLY PINS THE ASSEMBLY is IsAllowedResolvedType, which looks the RESOLVED type up in
			// AllowedFrameworkTypes and requires reference equality with the pinned typeof. This stage is a cheap
			// textual pre-filter; it is not the last word.
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

			// SECURITY H-10 (CWE-502). Gadget-shape rejection, applied to EVERY resolved type rather than only to
			// the entries of the pinned map: a delegate exists to carry an invocation target and an IDisposable owns
			// a live resource, neither is ever part of a persisted data document, and both are precisely the shapes
			// a deserialization gadget is built from. This is also what makes the first party FAMILY rule in
			// IsAllowedTypeName safe - the map builder filters these two shapes out of the core map, but a type
			// admitted by the family rule never passes through that builder. It is a no-op for the permitted
			// framework set, so nothing that legitimately round-trips today is affected.
			if (typeof(Delegate).IsAssignableFrom(type) || typeof(IDisposable).IsAssignableFrom(type))
			{
				rejectedTypeName = GetDiagnosticName(type);
				return false;
			}

			// A constructed generic is admitted on its open definition - List`1 rather than
			// List`1[[...]] - because that is the form the allow-list enumerates.
			var declaredTypeName = type.IsGenericType
				? type.GetGenericTypeDefinition().FullName
				: type.FullName;

			// SECURITY H-10 (CWE-502) reached by assembly confusion. EVERY admitted constituent must be the EXACT
			// Type held in one of the two pinned maps - reference equality against the Type object, never a name
			// match - so a same-named type loaded from any other assembly is refused whatever the discriminator
			// claimed. There is deliberately no name-only fallback: one would ask merely whether the NAME was on the
			// list, so a type called System.Uri declared by a plugin or a code-generated assembly would be admitted
			// and constructed, with only the delegate/disposable shape rejection above standing in its way. No
			// legitimate resolved type is refused by requiring the reference: both maps are consulted below, and the
			// two array spellings in the name set never reach this point because arrays are unwrapped to their
			// element type at the top of this method.
			var candidate = type.IsGenericType ? type.GetGenericTypeDefinition() : type;
			Type pinnedType = null;

			if (declaredTypeName == null
				|| (!AllowedFirstPartyTypes.TryGetValue(declaredTypeName, out pinnedType)
					&& !AllowedFrameworkTypes.TryGetValue(declaredTypeName, out pinnedType)))
			{
				rejectedTypeName = GetDiagnosticName(type);
				return false;
			}

			if (candidate != pinnedType)
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
		/// Builds the exact first party type map by indexing <see cref="PersistedModelTypes"/> by full type name.
		/// Runs once, during type initialization.
		/// </summary>
		/// <remarks>
		/// Threat addressed - CWE-502, OWASP A08:2021. There is deliberately NO reflection here: enumerating an
		/// assembly or a namespace tree is what makes services, repositories, managers and ambient contexts
		/// instantiable from a persisted discriminator, whereas indexing a hand-enumerated list means the
		/// permitted set cannot grow as a side effect of adding a class to a namespace. Assembly pinning is
		/// inherent rather than enforced, every entry being a <c>typeof</c> resolved by the compiler against this
		/// assembly.
		/// </remarks>
		private static Dictionary<string, Type> BuildFirstPartyTypeMap()
		{
			var map = new Dictionary<string, Type>(StringComparer.Ordinal);

			foreach (var type in PersistedModelTypes)
			{
				// Standing guard on future edits to PersistedModelTypes, which contains neither shape today: a delegate
				// carries an invocation target and a disposable owns a live resource, and both are exactly the shapes a
				// deserialization gadget is built from (CWE-502).
				if (typeof(Delegate).IsAssignableFrom(type) || typeof(IDisposable).IsAssignableFrom(type))
				{
					continue;
				}

				if (type.FullName != null)
				{
					map[type.FullName] = type;
				}
			}

			return map;
		}

		/// <summary>
		/// Builds the pinned framework type map. Runs once, during type initialization; see
		/// <see cref="AllowedFrameworkTypes"/> for the rationale.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - CWE-502 reached by assembly confusion, OWASP A08:2021. Every entry is a
		/// <c>typeof</c> expression, so the assembly is pinned by the compiler rather than by a string a
		/// discriminator could satisfy. Open generic definitions are used - <c>List&lt;&gt;</c> rather than
		/// <c>List&lt;object&gt;</c> - because that is the form both the discriminator name and
		/// <see cref="IsAllowedResolvedType"/> reduce a constructed generic to.
		/// </remarks>
		private static Dictionary<string, Type> BuildFrameworkTypeMap()
		{
			var frameworkTypes = new Type[]
			{
				typeof(System.Dynamic.ExpandoObject),
				typeof(object),
				typeof(string),
				typeof(bool),
				typeof(byte),
				typeof(sbyte),
				typeof(short),
				typeof(ushort),
				typeof(int),
				typeof(uint),
				typeof(long),
				typeof(ulong),
				typeof(float),
				typeof(double),
				typeof(decimal),
				typeof(char),
				typeof(DateTime),
				typeof(DateTimeOffset),
				typeof(TimeSpan),
				typeof(Guid),
				typeof(Uri),
				typeof(List<>),
				typeof(Dictionary<,>),
				typeof(HashSet<>),
				typeof(KeyValuePair<,>)
			};

			var map = new Dictionary<string, Type>(StringComparer.Ordinal);

			foreach (var type in frameworkTypes)
			{
				// The same standing guard the first party map carries. None of the entries above is a
				// delegate or an IDisposable today; the check stays so that adding one cannot quietly
				// widen the attack surface, and so the two maps are governed by one identical rule.
				if (typeof(Delegate).IsAssignableFrom(type) || typeof(IDisposable).IsAssignableFrom(type))
				{
					continue;
				}

				if (type.FullName != null)
				{
					map[type.FullName] = type;
				}
			}

			return map;
		}

		/// <summary>
		/// Derives the pre-resolution framework name set from the pinned map, adding the two array
		/// discriminator spellings. See <see cref="AllowedFrameworkTypeNames"/>.
		/// </summary>
		private static HashSet<string> BuildFrameworkTypeNameSet()
		{
			var names = new HashSet<string>(AllowedFrameworkTypes.Keys, StringComparer.Ordinal);

			// A discriminator spells an array as "System.Object[]" or "System.String[]". The resolved graph
			// is walked through Type.GetElementType, so these two never reach the reference-equality test
			// and correctly have no pinned entry - their ELEMENT type carries the pin instead.
			names.Add("System.Object[]");
			names.Add("System.String[]");

			return names;
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
		/// Renders a rejected discriminator fragment for a refusal message: truncated, with every character
		/// outside printable ASCII escaped.
		/// </summary>
		/// <remarks>
		/// SECURITY H-10 hardening (CWE-400 uncontrolled resource consumption, CWE-117 improper output
		/// neutralisation for logs). The refusal message is the one place a rejected discriminator is reflected
		/// back, and refusals are logged, so echoing the token verbatim would let the length and nesting bounds
		/// above still produce an oversize RESULT, moving the amplification from the resolver into the log. A
		/// discriminator is also attacker-supplied text that may carry newlines or terminal control sequences,
		/// which would let a refused payload forge log lines.
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
