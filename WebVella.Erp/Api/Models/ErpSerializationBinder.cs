using System;
using System.Collections.Generic;
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

			// Check the allow-list BEFORE resolution, so a rejected discriminator never reaches
			// assembly loading or type resolution in the first place.
			if (!IsAllowedTypeName(assemblyName, typeName))
			{
				throw Refused(assemblyName, typeName, "it is neither a WebVella.Erp platform type nor an explicitly permitted framework type");
			}

			Type resolvedType;

			try
			{
				resolvedType = base.BindToType(assemblyName, typeName);
			}
			catch (JsonSerializationException)
			{
				// The base binder already reports the missing assembly or type, and it reports it
				// as the expected exception type, so its diagnostic is preserved verbatim.
				throw;
			}
			catch (Exception exception)
			{
				// Anything else - a type load, missing or unloadable file, bad image or null
				// reference - is translated. A corrupt discriminator must not become an unhandled
				// crash on a read path that has no exception guard of its own.
				throw Refused(assemblyName, typeName, "the type could not be resolved", exception);
			}

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

			// Rule (a) - first party platform type. Both halves are required: a first party
			// assembly must not be able to vouch for a framework type name, and a first party
			// type name must not be honoured when it is claimed by a foreign assembly.
			if (IsFirstPartyAssembly(GetAssemblySimpleName(assemblyName))
				&& outerTypeName.StartsWith(FirstPartyPrefix, StringComparison.Ordinal))
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

			if (!IsAllowedTypeName(type.Assembly.GetName().Name, declaredTypeName))
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
			var reportedTypeName = string.IsNullOrWhiteSpace(typeName) ? "<none>" : typeName;
			var reportedAssemblyName = string.IsNullOrWhiteSpace(assemblyName) ? "<none>" : assemblyName;
			var message = $"{nameof(ErpSerializationBinder)} refused to bind type '{reportedTypeName}' from assembly '{reportedAssemblyName}' because {reason}.";

			if (innerException == null)
			{
				return new JsonSerializationException(message);
			}

			return new JsonSerializationException(message, innerException);
		}
	}
}
