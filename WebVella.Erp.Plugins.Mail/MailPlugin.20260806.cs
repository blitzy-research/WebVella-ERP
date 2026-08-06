using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using WebVella.Erp.Api;
using WebVella.Erp.Database;
using WebVella.Erp.Web.Models;
using WebVella.Erp.Web.Services;

namespace WebVella.Erp.Plugins.Mail
{
	public partial class MailPlugin : ErpPlugin
	{
		/// <summary>
		/// Encodes the untrusted SMTP response text that the provisioned e-mail list renders into an HTML
		/// attribute, on installations that an earlier release already provisioned.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding INT-14 (Major), CWE-79 improper neutralisation of input during web page
		/// generation (STORED cross-site scripting), CWE-116 improper encoding or escaping of output,
		/// OWASP A03:2021 Injection.
		/// THREAT: the <c>all_emails</c> page carries a <c>PcFieldHtml</c> node whose value is a code variable
		/// that interpolates the e-mail row's <c>server_error</c> column into a single-quoted HTML
		/// <c>title</c> attribute and returns it as raw markup. That column holds the exception message from a
		/// failed send, which for a relay error is the SMTP PEER'S OWN RESPONSE TEXT - data from outside this
		/// trust boundary, and text a peer can be induced to echo. An apostrophe in it closed the attribute and
		/// injected markup that then executed for every administrator who opened the e-mail list.
		/// <para>
		/// WHY THIS PATCH EXISTS AT ALL: the seed in <see cref="Patch20190215"/> is corrected in the same
		/// change, but a seed only protects databases provisioned after it. Everywhere else the node code
		/// already sits in <c>app_page_body_node.options</c> and is what actually runs, so without this patch
		/// the source would look remediated while the sink stayed live on every deployed instance. This is the
		/// same seed-plus-migration pairing used for the platform's own credential findings and for
		/// <see cref="Patch20260802"/>.
		/// </para>
		/// <para>
		/// A NO-OP ON A FRESH INSTALL, by construction rather than by a version test: on first provisioning
		/// <see cref="Patch20190215"/> creates the node inside this same uncommitted transaction, while the
		/// lookup below reads through the page service's own connection and therefore cannot see it. The patch
		/// finds nothing, changes nothing, and the already-corrected seed stands. That is also why a missing
		/// node is treated as success rather than as an error.
		/// </para>
		/// <para>
		/// IDEMPOTENT, and safe against local customisation: the migration rewrites exactly one fragment of the
		/// stored code and only when that fragment is present verbatim. Re-running finds the encoded form, not
		/// the legacy one, and does nothing. An installation whose node code was rewritten by hand past
		/// recognition is left untouched rather than overwritten - its owner is told to encode the value
		/// themselves in docs/security/security-audit-report.md - because silently replacing a customised
		/// screen would breach the preservation requirement.
		/// </para>
		/// <para>
		/// FAILURE PATHS THROW <c>InvalidOperationException</c>, matching <see cref="Patch20260802"/>: the
		/// harness in <c>MailPlugin._.cs</c> catches, rolls the transaction back and rethrows, so a half-applied
		/// migration is impossible.
		/// </para>
		/// </remarks>
		/// <param name="entMan">Unused. No entity metadata is altered by this patch.</param>
		/// <param name="relMan">Unused. Present because the patch harness invokes every patch uniformly.</param>
		/// <param name="recMan">Unused. No record data is altered by this patch, only a page node's options.</param>
		private static void Patch20260806(EntityManager entMan, EntityRelationManager relMan, RecordManager recMan)
		{
			EncodeMailListServerErrorSink20260806();
		}

		/// <summary>
		/// Identifier of the <c>all_emails</c> page that carries the error-icon node.
		/// </summary>
		private static readonly Guid AllEmailsPageId20260806 = new Guid("3374a8ee-653b-43f6-a4e8-c6db9a4f76d2");

		/// <summary>
		/// Identifier of the <c>PcFieldHtml</c> node whose code variable renders <c>server_error</c>.
		/// </summary>
		private static readonly Guid ServerErrorIconNodeId20260806 = new Guid("555c9704-efe8-4e15-832f-9f49ef553e16");

		/// <summary>
		/// The vulnerable composition, exactly as the stored node code spells it.
		/// </summary>
		/// <remarks>
		/// Review finding INT-14. Matching the COMPOSITION rather than the attribute interpolation is
		/// deliberate: the prefix carries a literal <c>&amp;#xA;</c> that is an intentional line break inside the
		/// tooltip, so only the untrusted value may be encoded - encoding the composed string would render that
		/// entity as visible text and change what an administrator sees.
		/// </remarks>
		private const string LegacyServerErrorComposition20260806 = "$\"Atempts to send: {retriesCount}&#xA;Error: \" + serverError;";

		/// <summary>
		/// The encoded composition, identical to the corrected seed in <see cref="Patch20190215"/>.
		/// </summary>
		/// <remarks>
		/// Review finding INT-14. <c>System.Net.WebUtility.HtmlEncode</c> encodes <c>'</c> as <c>&amp;#39;</c> and
		/// <c>"</c> as <c>&amp;quot;</c> as well as <c>&lt;</c>, <c>&gt;</c> and <c>&amp;</c>, so the value can neither close
		/// the attribute nor open a tag. The type lives in System.Private.CoreLib, so it resolves inside the
		/// runtime-compiled script, which references the loaded domain assemblies.
		/// </remarks>
		private const string EncodedServerErrorComposition20260806 = "$\"Atempts to send: {retriesCount}&#xA;Error: \" + System.Net.WebUtility.HtmlEncode(serverError);";

		/// <summary>
		/// Rewrites the stored error-icon node so the untrusted value is encoded before it reaches the
		/// attribute.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding INT-14; see <see cref="Patch20260806"/> for the threat and for why a
		/// missing node is success. The page service is the only available route: the node repository is
		/// internal to <c>WebVella.Erp.Web</c>, and <c>GetPageNodes</c> is used rather than
		/// <c>GetPageNodeById</c> because the latter throws for an absent node, which is an expected state
		/// here rather than an error. The write passes the ambient patch transaction, so it commits or rolls
		/// back with the rest of the upgrade.
		/// </remarks>
		private static void EncodeMailListServerErrorSink20260806()
		{
			PageService pageService = new PageService();

			PageBodyNode node = pageService
				.GetPageNodes(AllEmailsPageId20260806)
				.FirstOrDefault(pageNode => pageNode.Id == ServerErrorIconNodeId20260806);

			if (node == null || string.IsNullOrWhiteSpace(node.Options))
				return;

			string migratedOptions = EncodeServerErrorSinkInOptions20260806(node.Options);
			if (migratedOptions == null)
				return;

			pageService.UpdatePageBodyNodeOptions(ServerErrorIconNodeId20260806, migratedOptions, DbContext.Current.Transaction);
		}

		/// <summary>
		/// Returns the node options with the untrusted value encoded, or <c>null</c> when there is nothing to
		/// change.
		/// </summary>
		/// <remarks>
		/// SECURITY - review finding INT-14. The stored options are JSON whose <c>value</c> property is itself
		/// a JSON document whose <c>string</c> property holds the C# of the code variable, so the fragment is
		/// located after both layers are decoded rather than against the doubly escaped raw text: an
		/// installation whose options were re-serialised by the page designer escapes those quotes differently,
		/// and a raw-text match would silently miss it - the worst outcome for a security migration, because it
		/// reports success while leaving the sink open.
		/// <para>
		/// EVERY BAIL-OUT RETURNS <c>null</c> rather than throwing. A node whose options are not the shipped
		/// shape - malformed JSON, a value that is not a code variable, or code already carrying the encoder -
		/// is not a broken upgrade; it is a node this migration has no business rewriting.
		/// </para>
		/// </remarks>
		/// <param name="options">The stored node options.</param>
		/// <returns>The rewritten options, or <c>null</c> when the legacy fragment is absent.</returns>
		private static string EncodeServerErrorSinkInOptions20260806(string options)
		{
			JObject storedOptions;
			JObject storedValue;
			try
			{
				storedOptions = JObject.Parse(options);
				string value = storedOptions["value"]?.Value<string>();
				if (string.IsNullOrWhiteSpace(value))
					return null;

				storedValue = JObject.Parse(value);
			}
			catch (JsonException)
			{
				return null;
			}

			string code = storedValue["string"]?.Value<string>();
			if (string.IsNullOrEmpty(code) || !code.Contains(LegacyServerErrorComposition20260806, StringComparison.Ordinal))
				return null;

			storedValue["string"] = code.Replace(LegacyServerErrorComposition20260806, EncodedServerErrorComposition20260806, StringComparison.Ordinal);
			storedOptions["value"] = storedValue.ToString(Formatting.None);

			return storedOptions.ToString(Formatting.Indented);
		}
	}
}
