using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Web.Utils;

namespace WebVella.Erp.Plugins.Project.Utils
{
	public static class EntityRecordUtils
	{
		/// <summary>
		/// The record fields that the project activity bundles render as MARKUP rather than as text.
		/// </summary>
		private static readonly HashSet<string> MARKUP_RENDERED_FIELDS = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "body", "subject" };

		/// <summary>
		/// Returns copies of <paramref name="records"/> whose markup-rendered fields have been reduced to the
		/// allow-listed vocabulary, ready to be serialized for a client that assigns them to innerHTML.
		/// </summary>
		/// <remarks>
		/// <para>
		/// THREAT ADDRESSED - stored cross-site scripting, CWE-79, OWASP A03:2021. Review finding SR-05 (seam/M-01). The
		/// write paths are sanitized at their own choke points, which protects everything stored FROM NOW ON
		/// and nothing stored before. Any payload already sitting in a comment, timelog or feed row stays
		/// live for every reader until it is neutralised on the way out, and the platform's remediation scope
		/// excludes rewriting stored data - so the read path is the only place that exposure can be closed.
		/// This runs immediately before serialization, which is the last point at which the value is still a
		/// string this code controls.
		/// </para>
		/// <para>
		/// COPIES, not in-place edits. The records belong to the request's data model and are handed to the
		/// view as well as to the serializer, so rewriting them here would change what an unrelated consumer
		/// sees. Copying keeps this change confined to the one JSON payload that feeds the innerHTML sink.
		/// Only the two markup-rendered fields are touched; every other value is carried across by reference,
		/// so nothing is re-typed, re-formatted or lost.
		/// </para>
		/// <para>
		/// Nested replies are reached through the same <c>nodes</c> collection this class builds, because a
		/// reply is rendered by the same bundle through the same sink as its parent.
		/// </para>
		/// </remarks>
		public static List<EntityRecord> SanitizeMarkupRenderedFields(List<EntityRecord> records, string childNodesName = "nodes")
		{
			var result = new List<EntityRecord>();
			if (records == null)
			{
				return result;
			}

			foreach (var record in records)
			{
				result.Add(SanitizeMarkupRenderedFields(record, childNodesName));
			}

			return result;
		}

		/// <summary>
		/// Returns a copy of <paramref name="record"/> with its markup-rendered fields sanitized.
		/// </summary>
		public static EntityRecord SanitizeMarkupRenderedFields(EntityRecord record, string childNodesName = "nodes")
		{
			if (record == null)
			{
				return null;
			}

			var sanitized = new EntityRecord();
			foreach (var property in record.Properties)
			{
				var value = property.Value;

				if (MARKUP_RENDERED_FIELDS.Contains(property.Key) && value is string markup)
				{
					sanitized[property.Key] = HtmlSanitizer.Sanitize(markup);
					continue;
				}

				//A reply list is recursed into rather than copied by reference, so a payload stored on a
				//nested reply is neutralised on exactly the same terms as one on a top-level post.
				if (string.Equals(property.Key, childNodesName, StringComparison.OrdinalIgnoreCase) && value is List<EntityRecord> children)
				{
					sanitized[property.Key] = SanitizeMarkupRenderedFields(children, childNodesName);
					continue;
				}

				sanitized[property.Key] = value;
			}

			return sanitized;
		}

		public static List<EntityRecord> ConvertRecordListToTree(List<EntityRecord> input, List<EntityRecord> result, Guid? parentId = null, 
					string parentIdFieldName = "parent_id", string childNodesName = "nodes", string createdDateFieldName = "created_on", string sortOrder = "asc" ) {

			var childNodes = input.FindAll(x => (Guid?)x[parentIdFieldName] == parentId).ToList();

			if (sortOrder.ToLowerInvariant() == "desc")
			{
				childNodes = childNodes.OrderByDescending(x => (DateTime)x[createdDateFieldName]).ToList();
			}
			else {
				childNodes = childNodes.OrderBy(x => (DateTime)x[createdDateFieldName]).ToList();
			}

			foreach (var childNode in childNodes)
			{
				if (parentId == null)
				{
					result.Add(childNode);
				}
				else {
					var parentNode = result.First(x => (Guid)x["id"] == parentId);
					if (!parentNode.Properties.ContainsKey(childNodesName)) {
						parentNode[childNodesName] = new List<EntityRecord>();
					}
					((List<EntityRecord>)parentNode[childNodesName]).Add(childNode);
				}
				ConvertRecordListToTree(input, result, (Guid)childNode["id"], parentIdFieldName, childNodesName, createdDateFieldName, sortOrder);
			}

			return result;
		}
	}
}
