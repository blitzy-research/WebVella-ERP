namespace WebVella.Erp.WebAssembly.Models;

/// <summary>
/// The failure envelope this platform's API actually returns.
/// </summary>
/// <remarks>
/// <para>
/// Review finding M-04. The previous shape - <c>Type</c>, <c>Message</c>, <c>StackTrace</c>,
/// <c>ValidationData</c> - described a contract the server has never emitted. Every ERP response is a
/// <c>BaseResponseModel</c>: <c>timestamp</c>, <c>success</c>, <c>message</c>, <c>hash</c>, <c>errors</c>,
/// <c>accessWarnings</c>, and for the derived response type an <c>object</c>. So <c>StackTrace</c> and
/// <c>ValidationData</c> deserialized to null on every single failure, and the absent <c>Type</c>
/// defaulted to 0 - which happened to be the enum member the 400 branch handled, so validation errors
/// worked BY ACCIDENT while a 500 fell through to a "Not supported ApiErrorType" throw that replaced the
/// server's real message with a description of the client's own parsing confusion.
/// </para>
/// <para>
/// The discriminator is deliberately NOT reintroduced. The HTTP status code already carries that
/// information and is the only part of the contract both sides agree on, so <see cref="Utilities.HttpExt"/>
/// switches on the status and reads the message from this envelope. Property names are matched
/// case-insensitively by <c>System.Text.Json</c>'s web defaults, which is what
/// <c>HttpContent.ReadFromJsonAsync</c> uses, so the server's camelCase names bind to these members
/// without per-property attributes.
/// </para>
/// </remarks>
public class ApiErrorModel
{
	public DateTime Timestamp { get; set; }

	/// <summary>
	/// The platform sets this false on every failure envelope. Present so a caller can distinguish a
	/// genuine error envelope from a success body that merely arrived on an unexpected status.
	/// </summary>
	public bool Success { get; set; }

	/// <summary>
	/// The human-readable reason. This is the value that must reach the user; losing it was the substance
	/// of finding M-04.
	/// </summary>
	public string Message { get; set; }

	public string Hash { get; set; }

	/// <summary>
	/// Per-field validation failures. Replaces the never-populated <c>ValidationData</c> dictionary.
	/// </summary>
	public List<ApiErrorItemModel> Errors { get; set; }

	public List<ApiAccessWarningModel> AccessWarnings { get; set; }
}

/// <summary>
/// One field-level error, matching the platform's <c>ErrorModel</c>.
/// </summary>
public class ApiErrorItemModel
{
	/// <summary>Field name the error belongs to, or empty for a record-level error.</summary>
	public string Key { get; set; }

	/// <summary>The rejected value, when the server chose to echo it.</summary>
	public string Value { get; set; }

	public string Message { get; set; }
}

/// <summary>
/// One access warning, matching the platform's <c>AccessWarningModel</c>, which carries THREE members -
/// <c>key</c>, <c>code</c> and <c>message</c>. All three are declared because <c>System.Text.Json</c>
/// silently discards a JSON member it cannot bind, so an incomplete model would drop the very fields that
/// identify WHICH access was warned about and WHY - reproducing, in miniature, the contract mismatch that
/// finding M-04 exists to correct.
/// </summary>
public class ApiAccessWarningModel
{
	/// <summary>The field or object the warning belongs to.</summary>
	public string Key { get; set; }

	/// <summary>The platform's machine-readable warning code.</summary>
	public string Code { get; set; }

	public string Message { get; set; }
}
