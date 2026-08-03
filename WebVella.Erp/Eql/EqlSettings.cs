using Newtonsoft.Json;

namespace WebVella.Erp.Eql
{
	public class EqlSettings
	{
		[JsonProperty(PropertyName = "include_total")]
		public bool IncludeTotal { get; init; } = true;

		[JsonProperty(PropertyName = "distinct")]
		public bool Distinct { get; init; } = false;

		// The credential redaction opt-out deliberately does NOT live here.
		//
		// SECURITY - finding C-02 (CWE-200 / CWE-522, OWASP A01 + A02). EQL carries its own projection,
		// separate from the record projections in Api/RecordManager.cs and Database/DbRecordRepository.cs,
		// and it redacts the value of an encrypted PasswordField unless the caller explicitly opts out.
		// That opt-out is EqlCommand.IncludeEncryptedFieldValues - internal, init-only, and settable only
		// in an object initializer by code compiled into this assembly.
		//
		// It is deliberately not a property of THIS type, and the distinction is a security one rather
		// than a matter of taste: EqlSettings is public and instances of it are built from stored
		// data-source definitions (see Api/DataSourceManager.cs), so a credential-disclosure switch
		// living here would sit on a type that data - not just code - reaches. Nothing deserializes an
		// EqlCommand and no route model binds to one, so placing it there keeps the switch reachable by
		// code alone. Do not add such a flag to this type.
	}
}
