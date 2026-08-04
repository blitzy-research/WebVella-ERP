using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Npgsql;
using NpgsqlTypes;
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Api.Models.AutoMapper;
using WebVella.Erp.Database.Models;
using WebVella.Erp.Exceptions;
using WebVella.Erp.Fts;
using WebVella.Erp.Utilities;

namespace WebVella.Erp.Database
{
    public class DbRecordRepository
    {
        #region <--- Constants --->

        private const string WILDCARD_SYMBOL = "*";
        private const char FIELDS_SEPARATOR = ',';
        private const char RELATION_SEPARATOR = '.';
        private const char RELATION_NAME_RESULT_SEPARATOR = '$';

        internal const string RECORD_COLLECTION_PREFIX = "rec_";
        const string BEGIN_OUTER_SELECT = @"SELECT row_to_json( X ) FROM (";
        const string BEGIN_SELECT = @"SELECT ";
        const string REGULAR_FIELD_SELECT = @" {1}.""{0}"" AS ""{0}"",";
        const string END_SELECT = @"";
        const string BEGIN_SELECT_DISTINCT = @"SELECT DISTINCT ";
        const string END_OUTER_SELECT = @") X";
        const string FROM = @"FROM {0}";

        //const string GROUPBY = @"GROUP BY {0}";

        const string OTM_RELATION_TEMPLATE = @"	(SELECT  COALESCE( array_to_json( array_agg( row_to_json(d) )), '[]') FROM ( 
					SELECT {1} 
					FROM {2} {3}
					WHERE {3}.{4} = {5}.{6} ) d )::jsonb AS ""{0}"",";

        const string MTM_RELATION_TEMPLATE = @"( SELECT  COALESCE(  array_to_json(array_agg( row_to_json(d))), '[]') FROM ( 
					SELECT {1}
					FROM {2} {3}
					LEFT JOIN  {4} {5} ON {6}.{7} = {8}.{9}
					WHERE {10}.{11} = {12}.{13} )d  )::jsonb AS ""{0}"",";

        const string FILTER_JOIN = @"LEFT OUTER JOIN  {0} {1} ON {2}.{3} = {4}.{5}";



        #endregion

        EntityManager entMan;
        EntityRelationManager relMan;
		FtsAnalyzer ftsAnalyzer = new FtsAnalyzer();
		private DbContext suppliedContext = null;
		public DbContext CurrentContext
		{
			get
			{
				if (suppliedContext != null)
					return suppliedContext;
				else
					return DbContext.Current;
			}
			set
			{
				suppliedContext = value;
			}
		}
		public DbRecordRepository(DbContext currentContext)
		{
			if (currentContext != null)
				suppliedContext = currentContext;

			entMan = new EntityManager(CurrentContext);
			relMan = new EntityRelationManager(CurrentContext);
		}


		public void Create(string entityName, IEnumerable<KeyValuePair<string, object>> recordData)
		{
			Entity entity = entMan.ReadEntity(entityName).Object;

			List<DbParameter> parameters = new List<DbParameter>();

			foreach (var record in recordData)
			{
				Field field = entity.Fields.FirstOrDefault(f => f.Name.ToLowerInvariant() == record.Key.ToLowerInvariant());

				DbParameter param = new DbParameter();
				param.Name = field.Name;
				param.Value = record.Value ?? DBNull.Value;
				if (field.GetFieldType() == FieldType.GeographyField)
				{
					// this is set as text because later
					// the generated SQL will be something like

					// INSERT INTO places 
					//  (id, 
					//  border) 
					// VALUES 
					//  (@id, 
					//  ST_Transform(ST_GeomFromGeoJSON(@border),4326)::geography)
					// 
					param.Type = NpgsqlDbType.Text;
					GeographyField geo = (field as GeographyField);

					if (param.Value == null || (string)param.Value == "")
					{
						if (geo.Format == GeographyFieldFormat.GeoJSON)
						{
							param.Value = "{\"type\":\"GeometryCollection\",\"geometries\":[]}";
						}
						else if (geo.Format == GeographyFieldFormat.Text)
						{
							param.Value = "GEOMETRYCOLLECTION EMPTY";
						}

					}

					param.ValueOverride = $"ST_Transform(ST_GeomFrom{geo.Format.Value.ToString()}(@{param.Name}{(geo.Format.Value == GeographyFieldFormat.Text ? ", " + geo.SRID : "")}),{geo.SRID})::geography";

				}
				else
				{
					param.Type = DbTypeConverter.ConvertToDatabaseType(field.GetFieldType());
				}
				parameters.Add(param);
			}

			string tableName = GetTableNameForEntity(entityName);
			DbRepository.InsertRecord(tableName, parameters);
		}
		public void Update(string entityName, IEnumerable<KeyValuePair<string, object>> recordData)
		{
			Entity entity = entMan.ReadEntity(entityName).Object;

			List<DbParameter> parameters = new List<DbParameter>();
			Guid? id = null;

			foreach (var record in recordData)
			{
				Field field = entity.Fields.FirstOrDefault(f => f.Name.ToLowerInvariant() == record.Key.ToLowerInvariant());

				if (field.Name == "id")
					id = (Guid)record.Value;

				DbParameter param = new DbParameter();
				param.Name = field.Name;
				if (field.GetFieldType() == FieldType.GeographyField)
				{
					// this is set as text because later
					// the generated SQL will be something like

					// INSERT INTO places 
					//  (id, 
					//  border) 
					// VALUES 
					//  (@id, 
					//  ST_Transform(ST_GeomFromGeoJSON(@border),4326)::geography)
					// 
					param.Type = NpgsqlDbType.Text;
					GeographyField geo = (field as GeographyField);
					param.Value = record.Value;

					param.ValueOverride = $"ST_Transform(ST_GeomFrom{geo.Format.Value.ToString()}(@{param.Name}{(geo.Format.Value == GeographyFieldFormat.Text ? ", " + geo.SRID : "")}),{geo.SRID})::geography";

				}
				else
				{
					param.Value = record.Value ?? DBNull.Value;
					param.Type = DbTypeConverter.ConvertToDatabaseType(field.GetFieldType());
				}
				parameters.Add(param);

			}

			if (!id.HasValue)
				throw new StorageException("ID is missing. Cannot update records without ID specified.");

			string tableName = GetTableNameForEntity(entityName);

			var updateSuccess = DbRepository.UpdateRecord(tableName, parameters);
			if (!updateSuccess)
				throw new StorageException("Failed to update record.");
		}

		public void Delete(string entityName, Guid id)
        {
            string tableName = GetTableNameForEntity(entityName);

            EntityRecord outRecord = Find(entityName, id);
            if (outRecord == null)
                throw new StorageException("There is no record with such id to update.");

            DbRepository.DeleteRecord(tableName, id);
        }

        public EntityRecord FindTreeNodeRecord(string entityName, Guid id)
        {
            string tableName = GetTableNameForEntity(entityName);

            EntityRecord record = new EntityRecord();

            using (DbConnection con = DbContext.Current.CreateConnection())
            {

                NpgsqlCommand command = con.CreateCommand($"SELECT * FROM {tableName} WHERE id=@id;");

                var parameter = command.CreateParameter() as NpgsqlParameter;
                parameter.ParameterName = "id";
                parameter.Value = id;
                parameter.NpgsqlDbType = NpgsqlDbType.Uuid;
                command.Parameters.Add(parameter);

                using (var reader = command.ExecuteReader())
                {

                    int fieldcount = reader.FieldCount;

                    if (reader.Read())
                    {

                        for (int index = 0; index < fieldcount; index++)
                            record[reader.GetName(index)] = reader[index] == DBNull.Value ? null : reader[index];

                    }
                    else
                    {
                        return null;
                    }

                    reader.Close();

                }
                return record;
            }
        }

        // Finding F-03. Command timeout applied to any query carrying a regex predicate. Deliberately
        // a client-side timeout rather than a server-side "SET statement_timeout": DbContext's
        // CreateConnection returns a TRANSACTION-BOUND SHARED connection when a transaction is
        // active, so a session-level setting applied here could outlive this query and silently
        // truncate an unrelated long-running statement on the same connection, while "SET LOCAL"
        // only takes effect inside a transaction and so would do nothing on the common path. The
        // client cancel was verified to interrupt a running regex scan, cancelling at 2000 ms
        // against a two-second bound, so the simpler mechanism is also the effective one.
        private const int REGEX_QUERY_COMMAND_TIMEOUT_SECONDS = 60;

        // Preserves this method's original ten-minute ceiling verbatim for every non-regex query, so
        // the F-03 change narrows one case rather than re-tuning the data layer.
        private const int DEFAULT_QUERY_COMMAND_TIMEOUT_SECONDS = 600;

        // Finding F-03. Walks the whole query tree, because a regex predicate can sit at any depth
        // inside nested AND/OR groups and a top-level-only test would miss it. Modelled directly on
        // ContainsRelationalQuery below, which already does this walk for a different property, so
        // the traversal shape is the one this file established rather than a new idiom.
        private static bool ContainsRegexQuery(QueryObject query)
        {
            if (query == null)
                return false;

            Queue<QueryObject> queue = new Queue<QueryObject>();
            queue.Enqueue(query);
            while (queue.Count > 0)
            {
                var q = queue.Dequeue();
                if (q.QueryType == QueryType.REGEX)
                    return true;

                if (q.SubQueries != null && q.SubQueries.Count > 0)
                {
                    foreach (var sq in q.SubQueries)
                        queue.Enqueue(sq);
                }
            }

            return false;
        }

        private static bool ContainsRelationalQuery(QueryObject query)
        {
            Queue<QueryObject> queue = new Queue<QueryObject>();

            if (query == null)
                return false;

            queue.Enqueue(query);
            while(queue.Count > 0 )
            {
                var q = queue.Dequeue();
                if( q.SubQueries != null && q.SubQueries.Count > 0 )
                {
                    foreach (var sq in q.SubQueries)
                        queue.Enqueue(sq);
                }
                if (q.FieldName != null && q.FieldName.Contains(RELATION_SEPARATOR))
                    return true;
            }

            return false;

        }

        public long Count(EntityQuery query)
        {
            string tableName = GetTableNameForEntity(query.EntityName);
            using (DbConnection con = DbContext.Current.CreateConnection())
            {
                string sql = $"SELECT COUNT( {tableName}.id ) FROM {tableName} ";
                if(ContainsRelationalQuery(query.Query))
                    sql = $"SELECT COUNT( DISTINCT {tableName}.id ) FROM {tableName} ";

                string whereSql = string.Empty;
                string whereJoinSql = string.Empty;

                Entity entity = new EntityManager().ReadEntity(query.EntityName).Object;
                List<NpgsqlParameter> parameters = new List<NpgsqlParameter>();
				if( query != null )
					GenerateWhereClause(query.Query, entity, ref whereSql, ref whereJoinSql, ref parameters, query.OverwriteArgs);

                if (whereJoinSql.Length > 0)
                    sql = sql + "  " + whereJoinSql;

                if (whereSql.Length > 0)
                    sql = sql + " WHERE " + whereSql;

                NpgsqlCommand command = con.CreateCommand(sql);

                // THREAT ADDRESSED - finding F-03, CWE-400. This method evaluates the SAME
                // caller-supplied predicate as Find, and set no timeout at all, so a regex count
                // inherited the connection string's two-minute default. Every paged list issues a
                // count beside its page, so leaving this unbounded would have left half the request
                // unprotected. Narrowed only when a regex predicate is actually present, so
                // ordinary counts keep the connection default untouched.
                if (query != null && ContainsRegexQuery(query.Query))
                    command.CommandTimeout = REGEX_QUERY_COMMAND_TIMEOUT_SECONDS;

                if (parameters.Count > 0)
                    command.Parameters.AddRange(parameters.ToArray());

                return (long)command.ExecuteScalar();
            }
        }


        public void CreateRecordField(string entityName, Field field)
        {
            string tableName = GetTableNameForEntity(entityName);

            DbRepository.CreateColumn(tableName, field);
            if (field.Unique)
                DbRepository.CreateUniqueConstraint("idx_u_" + entityName + "_" + field.Name, tableName, new List<string> { field.Name });
            if (field.Searchable)
                DbRepository.CreateIndex("idx_s_" + entityName + "_" + field.Name, tableName, field.Name, field);
        }

        public void UpdateRecordField(string entityName, Field field)
        {
			//don't update default value for auto number field
			if (field.GetFieldType() == FieldType.AutoNumberField)
				return;

            string tableName = GetTableNameForEntity(entityName);

			bool overrideNulls = field.Required && field.GetFieldDefaultValue() != null;
			DbRepository.SetColumnDefaultValue(GetTableNameForEntity(entityName), field, overrideNulls);

			DbRepository.SetColumnNullable(GetTableNameForEntity(entityName), field.Name, !field.Required);
			
           


            if (field.Searchable)
                DbRepository.CreateIndex("idx_s_" + entityName + "_" + field.Name, tableName, field.Name, field);
            else
                DbRepository.DropIndex("idx_s_" + entityName + "_" + field.Name);
        }

        public void RemoveRecordField(string entityName, Field field)
        {
            string tableName = GetTableNameForEntity(entityName);

            //probably constraint will be removed automatically by postgresql, but to be sure
            if (field.Unique)
                DbRepository.DropUniqueConstraint("idx_u_" + entityName + "_" + field.Name, tableName);
            if (field.Searchable)
                DbRepository.CreateIndex("idx_s_" + entityName + "_" + field.Name, tableName, field.Name, field);

            DbRepository.DeleteColumn(tableName, field.Name);
        }

        private EntityRecord ConvertJObjectToEntityRecord(JObject jObj, List<Field> fields)
        {
            EntityRecord record = new EntityRecord();
            foreach (Field field in fields)
            {
                if (!(field is RelationFieldMeta))
                {
                    //SECURITY C-02 (CWE-200 / CWE-522, OWASP A01:2021 + A02:2021): relational read
                    //projection seam. See RedactEncryptedFieldValue for the full rationale. This
                    //private helper is reached only from within this class - the recursion just
                    //below and Find(EntityQuery) - so the redaction here is UNCONDITIONAL and is
                    //deliberately not subject to the credential-read scope that ExtractFieldValue's
                    //own read gate honours. Neither of this class's two Find seams is ever the
                    //credential path: SecurityManager's credential-resolution queries reach the
                    //separate private ConvertJObjectToEntityRecord in Eql/EqlCommand.cs, and the one
                    //single-column read of a stored hash is SecurityManager.ReadStoredPasswordHash,
                    //which issues its own parameterized query and never passes through a projection.
                    record[field.Name] = RedactEncryptedFieldValue(ExtractFieldValue(jObj[field.Name], field), field);
                }
                else
                {
                    List<EntityRecord> relRecords = new List<EntityRecord>();
                    var relFields = ((RelationFieldMeta)field).Fields;
                    JArray relatedJsonRecords = jObj[field.Name].Value<JArray>();
                    foreach (JObject relatedObj in relatedJsonRecords)
                        relRecords.Add(ConvertJObjectToEntityRecord(relatedObj, relFields));

                    record[field.Name] = relRecords;
                }
            }
            return record;
        }

        /// <summary>
        /// Replaces the value of an encrypted <see cref="PasswordField"/> with
        /// <see cref="RecordManager.EncryptedFieldRedactedValue"/> on the way out of a record query
        /// projection, so a stored credential hash never leaves the server. Every other field type,
        /// and a password field that is not flagged as encrypted, passes through untouched.
        /// </summary>
        /// <param name="value">The already-extracted projection value.</param>
        /// <param name="field">The field the value was projected from.</param>
        /// <returns>
        /// <see cref="RecordManager.EncryptedFieldRedactedValue"/> when <paramref name="field"/> is
        /// an encrypted <see cref="PasswordField"/> and a value is actually present; otherwise
        /// <paramref name="value"/> unchanged. A null value stays null: inventing a marker where
        /// there was no value would change observable behaviour, and the write-side guard keys on
        /// the marker rather than on null.
        /// </returns>
        /// <remarks>
        /// SECURITY C-02 (CWE-200 exposure of sensitive information to an unauthorized actor,
        /// CWE-522 insufficiently protected credentials / OWASP A01:2021 Broken Access Control +
        /// A02:2021 Cryptographic Failures).
        ///
        /// THREAT ADDRESSED: a stored password hash was returned verbatim by every record query
        /// projection, to callers of any role. Field permissions are enforced ONLY in the
        /// presentation layer - WebVella.Erp.Web/Components/PcFieldBase/PcFieldBase.cs gates the
        /// whole field-permission evaluation behind "if (entityField.EnableSecurity)", and
        /// EnableSecurity is a plain bool defaulting to false in
        /// WebVella.Erp/Api/Models/FieldTypes/BaseField.cs - and there is no data-layer equivalent
        /// anywhere. The mandated Authorization Enforcement standard requires authorization to be
        /// validated "on every request, not just in the UI", so the value is replaced here, in the
        /// repository's own query projection, and a hash never leaves the server.
        ///
        /// Redaction is UNCONDITIONAL with respect to role, including administrators: the
        /// acceptance criterion is "no API response and no query projection returns a password
        /// hash, for any role". It is deliberately NOT conditional on SecurityContext, on an
        /// ignoreSecurity flag or on role membership - a role-conditional projection would both
        /// leave the hash reachable and add exactly the complexity the Minimal Change Clause
        /// forbids.
        ///
        /// WHY THIS HELPER STILL EXISTS ALONGSIDE THE GATE INSIDE
        /// <see cref="ExtractFieldValue(object, Field, bool)"/> - this is the part that must not be
        /// "simplified". That method is public static and serves BOTH directions: called with
        /// encryptPasswordFields: true it is the plaintext-to-hash WRITE conversion, so redacting
        /// inside it would store the marker as a credential and destroy every password it converted.
        /// Redaction therefore has to sit at the read-projection seams, which is what this helper is.
        /// 
        /// CALL SITES - it is deliberately internal rather than private, because there are three
        /// projection seams in this assembly and they must not drift apart:
        ///   the non-relational reader loop and the private ConvertJObjectToEntityRecord of
        ///   Find(EntityQuery), both in this file, which this helper covers UNCONDITIONALLY;
        ///   the private ConvertJObjectToEntityRecord of WebVella.Erp/Eql/EqlCommand.cs, which is a
        ///   separate method reached by every EQL query including the api/v3/en_US/eql, eql-ds and
        ///   eql-ds-select2 routes (finding C-02). Leaving that seam out was a Critical gap,
        ///   because all three routes serialise an EqlCommand result straight into a response and
        ///   stored data sources shipped by the Project plugin select the user entity's password
        ///   column outright. It redacts DENY-BY-DEFAULT and can only be opted out of through the
        ///   internal EqlCommand.IncludeEncryptedFieldValues flag (the opt-in lives on the COMMAND,
        ///   never on the public EqlSettings, which is built from stored data-source definitions).
        /// 
        /// TWO INDEPENDENT GATES PROTECT THE EQL SEAM, and both must be satisfied before a real
        /// hash is projected. ExtractFieldValue carries the deeper one on its read fall-through,
        /// because that method is public static and any present or future caller can reach it
        /// without passing through this class or RecordManager; that gate is CONDITIONAL, suppressed
        /// only while SecurityManager's credential-read scope (RecordManager.OpenCredentialReadScope)
        /// is open. EqlCommand then applies the second gate, keyed on its own
        /// IncludeEncryptedFieldValues flag. The two Find seams in this file stay redacted even for
        /// the internal credential path, because this helper ignores the scope, so the exemption is
        /// as narrow as it can be; redaction is idempotent, so a double application is harmless.
        /// 
        /// CREDENTIAL RESOLUTION IS THE ONLY EXEMPTION. SecurityManager.GetUser(Guid) - the overload
        /// SaveUser and the schema-version-4 migration in WebVella.Erp/ERPService.cs read through -
        /// and SecurityManager.GetUser(email, password) each open the scope AND set the command flag,
        /// and nothing else in the platform does either. The stored hash a login verifies against is
        /// read by SecurityManager.ReadStoredPasswordHash, an internal, parameterized, single-column,
        /// single-row query that bypasses every projection.
        /// Do NOT "restore" a projection-based hash read here or in EqlCommand to make some other
        /// code path convenient - route it through ReadStoredPasswordHash instead, and do NOT open
        /// the credential-read scope around a controller, hook, job, import or bulk user listing.
        ///
        /// Keyed on the EXISTING Encrypted flag only. Blanket field-permission enforcement across
        /// every field type and every projection is explicitly out of scope: an empty read
        /// permission is treated as denial by the presentation layer, so a blanket port would hide
        /// fields wholesale. The residual general gap is recorded in
        /// docs/security/risk-register.md rather than fixed here.
        /// <para>
        /// Widened from private to internal for finding F16: EqlCommand carries its own private
        /// ConvertJObjectToEntityRecord and so has its own projection seam, which was calling
        /// ExtractFieldValue directly and returning stored hashes. internal keeps the member inside
        /// this assembly - every consumer, EqlCommand included, is in WebVella.Erp - so no public
        /// API surface changes, and there is still exactly ONE redaction implementation rather than a
        /// copy per projection.
        /// </para>
        /// </remarks>
        internal static object RedactEncryptedFieldValue(object value, Field field)
        {
            //Encrypted is bool?, so the comparison is written "== true" on purpose: it treats null
            //as "not encrypted", which is the semantics every other PasswordField test in this file
            //already has. Never write a bare truthiness test or "!= false" here.
            if (value != null && field is PasswordField && ((PasswordField)field).Encrypted == true)
            {
                return RecordManager.EncryptedFieldRedactedValue;
            }

            return value;
        }

        public static object ExtractFieldValue(object value, Field field, bool encryptPasswordFields = false)
        {
            if (value == null)
                return field.GetFieldDefaultValue();

			if (value is JToken)
			{
				//we convert JToken to string for specified types, because when date formated string 
				//is saved in JToken value, it get converted to DateTime. It may happen with other specific texts also.
				if( field is EmailField || field is FileField || field is ImageField ||
					field is HtmlField || field is MultiLineTextField || field is PasswordField ||
					field is PhoneField || field is SelectField || field is TextField || field is UrlField ||
					field is GeographyField)
					value = ((JToken)value).ToObject<string>();
				else
					value = ((JToken)value).ToObject<object>();
			}

			if (field is AutoNumberField)
			{
				if (value == null)
					return null;
				if (value is string)
					return decimal.Parse(value as string);

				return Convert.ToDecimal(value);
			}
			else if (field is CheckboxField)
				return value as bool?;
			else if (field is CurrencyField)
			{
				if (value == null)
					return null;
				if (value is string)
				{
					if (string.IsNullOrWhiteSpace(value as string))
						return null;
					if ((value as string).StartsWith("$"))
						value = (value as string).Substring(1);
					return decimal.Parse(value as string);
				}

				return Convert.ToDecimal(value);
			}
			else if (field is DateField)
			{
				if (value == null)
					return null;

				DateTime? date = null;
				if (value is string)
				{
					if (string.IsNullOrWhiteSpace(value as string))
						return null;
					date = DateTime.Parse(value as string);
					switch (date.Value.Kind)
					{
						case DateTimeKind.Utc:
							return date.Value.ConvertToAppDate();
						case DateTimeKind.Local:
							return date.Value.ConvertToAppDate();
						case DateTimeKind.Unspecified:
							return date.Value;
					}
				}
				else
				{
					date = value as DateTime?;
					switch (date.Value.Kind)
					{
						case DateTimeKind.Utc:
							return date.Value.ConvertToAppDate();
						case DateTimeKind.Local:
							return date.Value.ConvertToAppDate();
						case DateTimeKind.Unspecified:
							return date.Value;
					}
				}
				return date;
			}
			else if (field is DateTimeField)
			{
				if (value == null)
					return null;

				DateTime? date = null;
				if (value is string)
				{
					if (string.IsNullOrWhiteSpace(value as string))
						return null;
					date = DateTime.Parse(value as string);
					////date can be local, utc and unspecified
					////if local convert to utc, unspecified is used as is
					//if (date.HasValue && date.Value.Kind == DateTimeKind.Local)
					//	date = date.Value.ToUniversalTime();

					switch (date.Value.Kind)
					{
						case DateTimeKind.Utc:
							return date;
						case DateTimeKind.Local:
							return date.Value.ToUniversalTime();
						case DateTimeKind.Unspecified:
							{
								var erpTimeZone = TimeZoneInfo.FindSystemTimeZoneById(ErpSettings.TimeZoneName);
								return TimeZoneInfo.ConvertTimeToUtc(date.Value, erpTimeZone);
							}
					}
				}
				else
				{
					date = value as DateTime?;
					////date can be local, utc and unspecified
					////if local convert to utc, unspecified is used as is
					//if (date.HasValue && date.Value.Kind == DateTimeKind.Local)
					//	date = date.Value.ToUniversalTime();

					switch (date.Value.Kind)
					{
						case DateTimeKind.Utc:
							return date;
						case DateTimeKind.Local:
							return date.Value.ToUniversalTime();
						case DateTimeKind.Unspecified:
							{
								var erpTimeZone = TimeZoneInfo.FindSystemTimeZoneById(ErpSettings.TimeZoneName);
								return TimeZoneInfo.ConvertTimeToUtc(date.Value, erpTimeZone);
							}
					}
				}

				//if (date != null)
				//	return new DateTime(date.Value.Year, date.Value.Month, date.Value.Day, 0, 0, 0, DateTimeKind.Utc);
				return date;
			}

			else if (field is EmailField)
				return value as string;
			else if (field is FileField)
				//TODO convert file path to url path
				return value as string;
			else if (field is ImageField)
				//TODO convert image path to url path
				return value as string;
			else if (field is HtmlField)
				return value as string;
			else if (field is MultiLineTextField)
				return value as string;
			else if (field is GeographyField)
				return value as string;
			else if (field is MultiSelectField)
			{
				if (value == null)
					return null;
				else if (value is JArray)
					return ((JArray)value).Select(x => ((JToken)x).Value<string>()).ToList<string>();
				else if (value is List<object>)
					return ((List<object>)value).Select(x => ((object)x).ToString()).ToList<string>();
				else if (value is string[])
					return new List<string>(value as string[]);
				else
					return value as IEnumerable<string>;
			}
			else if (field is NumberField)
			{
				if (value == null)
					return null;
				if (value is string)
					return decimal.Parse(value as string);

				return Convert.ToDecimal(value);
			}
			else if (field is PasswordField)
			{
				if (encryptPasswordFields)
				{
					if (((PasswordField)field).Encrypted == true)
					{
						if (string.IsNullOrWhiteSpace(value as string))
							return null;

						//SECURITY C-02 guard - DATA-INTEGRITY CRITICAL. A caller that read this
						//record through a query projection receives
						//RecordManager.EncryptedFieldRedactedValue in place of the stored hash (see
						//RedactEncryptedFieldValue above). If that marker is round-tripped back into
						//a write it must NEVER be hashed: doing so would replace the account's real
						//credential with a hash of the marker and PERMANENTLY DESTROY it, because
						//both MD5 and PBKDF2 are one-way. On a multi-record round-trip that would
						//destroy every affected account's password at once - a data-destroying
						//outcome from a fix whose whole purpose is to prevent disclosure.
						//
						//null is returned rather than the marker, an empty string, or a hash. It is
						//this branch's own established "do not write a real value here" signal - the
						//IsNullOrWhiteSpace guard immediately above already returns null - and it is
						//the value the record-write collectors in WebVella.Erp/Api/RecordManager.cs
						//already treat as "omit this field", leaving the persisted column
						//byte-identical. That omission in RecordManager is the primary (Layer 1)
						//control; this check is defence in depth (Layer 2) so no present or future
						//caller of this method can reintroduce the defect.
						//
						//StringComparison.Ordinal is mandatory: a culture-sensitive or
						//case-insensitive comparison could either miss the marker (destroying a
						//credential) or match a value that is not the marker.
						if (string.Equals(value as string, RecordManager.EncryptedFieldRedactedValue, StringComparison.Ordinal))
							return null;

						//THREAT ADDRESSED - finding M-13, CWE-521, OWASP A07:2021. Defence in depth
						//behind the identical check in RecordManager.ExtractFieldValue, which is the
						//primary control because it is the seam the record write path actually uses.
						//This copy exists because this method is PUBLIC and STATIC: any present or
						//future caller can reach the hashing branch directly without passing through
						//RecordManager, and a policy enforced at only one of two equivalent seams is a
						//policy that a single new call site silently removes. The reason text carries no
						//plaintext and no length, for the same CWE-532 reason documented there.
						string passwordPolicyFailure = PasswordUtil.ValidatePasswordPolicy(value as string);
						if (passwordPolicyFailure != null)
							throw new ArgumentException("The supplied password does not meet the password policy: "
								+ passwordPolicyFailure + ".");

						//THREAT ADDRESSED - finding C-03, CWE-916 / CWE-759, OWASP A02:2021. Was an
						//unsalted single-pass MD5 digest; now a salted, work-factored
						//PBKDF2-HMAC-SHA-256 value. See WebVella.Erp/Utilities/PasswordUtil.cs.
						return PasswordUtil.HashPassword(value as string);
					}
				}

				//THREAT ADDRESSED - finding C-02, CWE-200 (exposure of sensitive information to an
				//unauthorized actor) and CWE-522 (insufficiently protected credentials), OWASP
				//A01:2021 Broken Access Control + A02:2021 Cryptographic Failures. This is the READ
				//fall-through of the password branch, and it is the one projection seam the two
				//companion redactions in this class could not cover: this method is public static
				//and is also called from WebVella.Erp/Eql/EqlCommand.cs, whose own private
				//ConvertJObjectToEntityRecord bypasses both RecordManager.Find and this class's
				//record-projection seams. The generic EQL surface therefore returned the stored
				//credential hash verbatim - it authorises the ENTITY only, the Regular role retains
				//read access to the user entity, and the surface is reachable over HTTP - so an
				//authenticated regular user could project user.password.
				//
				//The reason this redaction could not simply be placed here before is that
				//WebVella.Erp/Api/SecurityManager.cs resolves credentials through that same EQL path
				//and needs the REAL stored hash in order to verify a login. The ambient opt-in
				//resolves the conflict: SecurityManager opens RecordManager's credential-read scope
				//around its own credential-resolution queries and nothing else, so verification
				//still sees the hash while every other caller - EQL included - sees the marker. The
				//gate is deny-by-default, so a read path added in future is redacted without having
				//to opt in. Do NOT widen the scope to a controller, hook, job, bulk user listing or
				//import: that would reopen exactly the surface this closes.
				//
				//Encrypted is bool?, so the comparison is written "== true" on purpose: it treats
				//null as "not encrypted", which is the semantics every other PasswordField test in
				//this file already has. Never write a bare truthiness test or "!= false" here. A
				//null value stays null, matching RedactEncryptedFieldValue above, so no marker is
				//invented where there was no value.
				//
				//This gate cannot affect a WRITE. Every write caller passes encryptPasswordFields
				//true, and when that flag is set on an encrypted field the branch above returns on
				//all three of its paths, so execution can only reach this line for a read or for a
				//field that is not flagged encrypted.
				if (!RecordManager.IsCredentialReadScopeOpen && value != null && ((PasswordField)field).Encrypted == true)
				{
					return RecordManager.EncryptedFieldRedactedValue;
				}

				return value;
			}
			else if (field is PercentField)
			{
				if (value == null)
					return null;
				if (value is string)
					return decimal.Parse(value as string);

				return Convert.ToDecimal(value);
			}
			else if (field is PhoneField)
				return value as string;
			else if (field is GuidField)
			{
				if (value is string)
				{
					if (string.IsNullOrWhiteSpace(value as string))
						return null;

					return new Guid(value as string);
				}

				if (value is Guid)
					return (Guid?)value;

				if (value == null)
					return (Guid?)null;

				throw new Exception("Invalid Guid field value.");
			}
			else if (field is SelectField)
				return value as string;
			else if (field is TextField)
				return value as string;
			else if (field is UrlField)
				return value as string;

            throw new Exception("System Error. A field type is not supported in field value extraction process.");
        }

        public EntityRecord Find(string entityName, Guid id)
        {
            EntityQuery query = new EntityQuery(entityName, "*", EntityQuery.QueryEQ("id", id));
            var results = Find(query);
            return results.FirstOrDefault();
        }

        public List<EntityRecord> Find(EntityQuery query)
        {
            Entity entity = entMan.ReadEntity(query.EntityName).Object;
            var fields = ExtractQueryFieldsMeta(query);
            StringBuilder sql = new StringBuilder();
            StringBuilder sqlJoins = new StringBuilder();
            //StringBuilder sqlGroupBy = new StringBuilder();
            List<NpgsqlParameter> parameters = new List<NpgsqlParameter>();
            bool containsRelationalQuery = ContainsRelationalQuery(query.Query);

            //there is a problem when select distinct rows and sort on field not included in select
            //so we add field we sort on and later remove it, only then distinct (containsRelationalQuery) is used
            List<Field> missingSortFields = new List<Field>();
            if (containsRelationalQuery && query.Sort != null && query.Sort.Length > 0)
            {
                foreach (var s in query.Sort)
                {
                    if (s.FieldName.Trim().StartsWith("{"))
                    {
                        //process json
                        dynamic parametrizedSort = ExtractSortFieldJsonValue(s.FieldName, query.OverwriteArgs);
                        if (parametrizedSort != null)
                        {
                            var sortField = entity.Fields.SingleOrDefault(x => x.Name == parametrizedSort.Field );
                            if (sortField == null) //we skip sorf fields not found in entity
                                continue;
                          
                            if(!fields.Any(f=>f.Id == sortField.Id))
                            {
                                fields.Add(sortField);
                                missingSortFields.Add(sortField);
                            }

                        }
                    }
                    else
                    {
                        var sortField = entity.Fields.SingleOrDefault(x => x.Name == s.FieldName);
                        if (sortField == null) //we skip sorf fields not found in entity
                            continue;

                        if (!fields.Any(f => f.Id == sortField.Id))
                        {
                            fields.Add(sortField);
                            missingSortFields.Add(sortField);
                        }
                    }
                }
            }

            bool noSelectRelations = !fields.Any(field => field is RelationFieldMeta);
            if (noSelectRelations)
            {
                #region no relations 

                var tableName = GetTableNameForEntity(entity);
				string columnNames = String.Join(",", fields.Select(x => x.GetFieldType() == FieldType.GeographyField ? "ST_As" + (x as GeographyField).Format + "(" + tableName + ".\"" + x.Name + "\") AS \"" + x.Name + "\"" : tableName + ".\"" + x.Name + "\""));
								
                if(!containsRelationalQuery)
                    sql.AppendLine("SELECT " + columnNames + " FROM " + tableName);
                else
                    sql.AppendLine("SELECT DISTINCT " + columnNames + " FROM " + tableName);

                if (query.Query != null)
                {
                    string whereSql = string.Empty;
                    string whereJoinSql = string.Empty;

                    GenerateWhereClause(query.Query, entity, ref whereSql, ref whereJoinSql, ref parameters, query.OverwriteArgs);

                    if (whereJoinSql.Length > 0)
                        sql.AppendLine(whereJoinSql);

                    if (whereSql.Length > 0)
                        sql.AppendLine("WHERE " + whereSql);
                }

                //sorting
                if (query.Sort != null && query.Sort.Length > 0)
                {
                    string sortSql = "ORDER BY ";

                    foreach (var s in query.Sort)
                    {
                        if (s.FieldName.Trim().StartsWith("{"))
                        {
                            //process json
                            dynamic parametrizedSort = ExtractSortFieldJsonValue(s.FieldName, query.OverwriteArgs);
                            if (parametrizedSort != null)
                            {
                                var sortField = parametrizedSort.Field;
                                var sortOrder = parametrizedSort.Order;

                                //SECURITY C-REV-08 (CWE-89 / OWASP A03:2021). The sort identifier
                                //here originates in the caller's URL arguments, so it is resolved
                                //against this entity's own field metadata and only the stored name is
                                //emitted, quoted. Field not found - skip, exactly as before.
                                string sortColumn = BuildSortColumnReference(entity, (string)sortField);
                                if (sortColumn == null)
                                    continue;

                                sortSql = sortSql + " " + sortColumn;
                                if (string.IsNullOrEmpty(sortOrder))
                                {
                                    if (s.SortType == QuerySortType.Ascending)
                                        sortSql = sortSql + " ASC,";
                                    else
                                        sortSql = sortSql + " DESC,";
                                }
                                else
                                {
                                    if (sortOrder == "asc")
                                        sortSql = sortSql + " ASC,";
                                    else
                                        sortSql = sortSql + " DESC,";
                                }

                            }
                        }
                        else
                        {
                            //SECURITY C-REV-08 (CWE-89 improper neutralization of special elements in
                            //an SQL command, OWASP A03:2021 Injection). s.FieldName arrives unresolved
                            //from the network - see RelatedFieldMultiSelect and GetQuickSearch in
                            //WebVella.Erp.Web/Controllers/WebApiController.cs - and was previously
                            //interpolated raw between hand-written double quotes, so a single embedded
                            //double quote terminated the quoting and injected arbitrary SQL into a
                            //fully expression-capable ORDER BY position. It is now resolved against
                            //entity metadata and emitted quoted; an unresolvable name is skipped,
                            //matching the JSON branch above and the distinct-select pre-pass earlier
                            //in this method.
                            string sortColumn = BuildSortColumnReference(entity, s.FieldName);
                            if (sortColumn == null)
                                continue;

                            sortSql = sortSql + " " + sortColumn;
                            if (s.SortType == QuerySortType.Ascending)
                                sortSql = sortSql + " ASC,";
                            else
                                sortSql = sortSql + " DESC,";
                        }
                    }

                    sortSql = sortSql.Remove(sortSql.Length - 1, 1);
                    if (sortSql.Trim() != "ORDER BY")
                        sql.AppendLine(sortSql);
                }

				//paging 
				if (query.Limit != null || query.Skip != null)
				{
					string pagingSql = "LIMIT ";
					if (query.Limit.HasValue && query.Limit != 0)
						pagingSql = pagingSql + query.Limit + " ";
					else
						pagingSql = pagingSql + "ALL ";

					if (query.Skip.HasValue)
						pagingSql = pagingSql + " OFFSET " + query.Skip;

					sql.AppendLine(pagingSql);
				}

				using (var conn = DbContext.Current.CreateConnection())
                {
                    List<EntityRecord> result = new List<EntityRecord>();
                    NpgsqlCommand command = conn.CreateCommand(sql.ToString());
                    command.Parameters.AddRange(parameters.ToArray());
                    using (var reader = command.ExecuteReader())
                    {
                        try
                        {
                            //remove not needed fields
                            if (missingSortFields.Any())
                            {
                                foreach (var sf in missingSortFields)
                                {
                                    var selectedField = fields.Single(f => f.Id == sf.Id);
                                    fields.Remove(selectedField);
                                }
                            }

                            int fieldcount = fields.Count;
                            while (reader.Read())
                            {
                                EntityRecord record = new EntityRecord();
                                for (int index = 0; index < fieldcount; index++)
                                {
                                    string fieldName = reader.GetName(index);
                                    Field field = fields.Single(x => x.Name == fieldName);
                                    //SECURITY C-02 (CWE-200 / CWE-522, OWASP A01:2021 + A02:2021):
                                    //non-relational read projection seam. See
                                    //RedactEncryptedFieldValue for the full rationale. The redaction
                                    //here is UNCONDITIONAL and is deliberately not subject to the
                                    //credential-read scope that ExtractFieldValue's own gate
                                    //honours, so this seam stays redacted even for the internal
                                    //credential path. The existing DBNull.Value-to-null
                                    //normalisation is preserved and still runs first, so an absent
                                    //value stays null rather than becoming a marker.
                                    record[fieldName] = RedactEncryptedFieldValue(reader[index] == DBNull.Value ? null : ExtractFieldValue(reader[index], field), field); ;
                                }

                                result.Add(record);
                            }
                        }
                        finally
                        {
                            reader.Close();
                        }

                        return result;
                    }
                }

                #endregion
            }
            else
            {
                #region relational 

                sql.AppendLine(BEGIN_OUTER_SELECT);

                if (!containsRelationalQuery)
                    sql.AppendLine(BEGIN_SELECT);
                else
                    sql.AppendLine(BEGIN_SELECT_DISTINCT);

                foreach (var field in fields)
                {
                    if (!(field is RelationFieldMeta))
                    {
                        sql.AppendLine(string.Format(REGULAR_FIELD_SELECT, field.Name, GetTableNameForEntity(entity.Name)));
                        //sqlGroupBy.Append(GetTableNameForEntity(entity) + "." + field.Name + ",");
                    }
                    else
                    {
                        RelationFieldMeta relationField = (RelationFieldMeta)field;
                        var relationName = relationField.Relation.Name;

                        //here we don't have any direction, because it is set by join clause bellow
                        StringBuilder sbRelatedFields = new StringBuilder();
                        foreach (var f in relationField.Fields)
                            sbRelatedFields.Append(string.Format("{0}.{1},", relationName, f.Name));

                        sbRelatedFields.Remove(sbRelatedFields.Length - 1, 1);

                        //sql.AppendLine(string.Format(JOIN_FIELD_SELECT, field.Name, sbRelatedFields));

                        if (relationField.Relation.RelationType == EntityRelationType.OneToOne)
                        {
                            //when the relation is origin -> target entity
                            if (relationField.Relation.OriginEntityId == entity.Id)
                            {
                                //join target entity
                                //sqlJoins.AppendLine(string.Format(JOIN, GetTableNameForEntity(relationField.TargetEntity), relationName, relationName,
                                //	relationField.TargetField.Name, GetTableNameForEntity(relationField.OriginEntity), relationField.OriginField.Name));

                                sql.AppendLine(string.Format(OTM_RELATION_TEMPLATE,
                                    relationField.Name,
                                    sbRelatedFields.ToString(),
                                    GetTableNameForEntity(relationField.TargetEntity),
                                    relationName,
                                    relationField.TargetField.Name,
                                    GetTableNameForEntity(relationField.OriginEntity),
                                    relationField.OriginField.Name));
                            }
                            else //when the relation is target -> origin, we have to query origin entity
                            {
                                //join origin entity
                                //sqlJoins.AppendLine(string.Format(JOIN, GetTableNameForEntity(relationField.OriginEntity), relationName, relationName,
                                //	relationField.OriginField.Name, GetTableNameForEntity(relationField.TargetEntity), relationField.TargetField.Name));

                                sql.AppendLine(string.Format(OTM_RELATION_TEMPLATE,
                                    relationField.Name,
                                    sbRelatedFields.ToString(),
                                    GetTableNameForEntity(relationField.OriginEntity),
                                    relationName,
                                    relationField.OriginField.Name,
                                    GetTableNameForEntity(relationField.TargetEntity),
                                    relationField.TargetField.Name));
                            }
                        }
                        else if (relationField.Relation.RelationType == EntityRelationType.OneToMany)
                        {
                            //when origin and target entity are different, then direction don't matter
                            if (relationField.Relation.OriginEntityId != relationField.Relation.TargetEntityId)
                            {
                                //when the relation is origin -> target entity
                                if (relationField.Relation.OriginEntityId == entity.Id)
                                {
                                    //join target entity
                                    //sqlJoins.AppendLine(string.Format(JOIN, GetTableNameForEntity(relationField.TargetEntity), relationName, relationName,
                                    //	relationField.TargetField.Name, GetTableNameForEntity(relationField.OriginEntity), relationField.OriginField.Name));

                                    sql.AppendLine(string.Format(OTM_RELATION_TEMPLATE,
                                        relationField.Name,
                                        sbRelatedFields.ToString(),
                                        GetTableNameForEntity(relationField.TargetEntity),
                                        relationName,
                                        relationField.TargetField.Name,
                                        GetTableNameForEntity(relationField.OriginEntity),
                                        relationField.OriginField.Name));
                                }
                                else //when the relation is target -> origin, we have to query origin entity
                                {
                                    //join origin entity
                                    //sqlJoins.AppendLine(string.Format(JOIN, GetTableNameForEntity(relationField.OriginEntity), relationName, relationName,
                                    //	relationField.OriginField.Name, GetTableNameForEntity(relationField.TargetEntity), relationField.TargetField.Name));
                                    sql.AppendLine(string.Format(OTM_RELATION_TEMPLATE,
                                        relationField.Name,
                                        sbRelatedFields.ToString(),
                                        GetTableNameForEntity(relationField.OriginEntity),
                                        relationName,
                                        relationField.OriginField.Name,
                                        GetTableNameForEntity(relationField.TargetEntity),
                                        relationField.TargetField.Name));
                                }
                            }
                            else //when the origin entity is same as target entity direction matters
                            {
                                if (relationField.Direction == "target-origin")
                                {
                                    //join origin entity
                                    //sqlJoins.AppendLine(string.Format(JOIN, GetTableNameForEntity(relationField.OriginEntity), relationName, relationName,
                                    //	relationField.OriginField.Name, GetTableNameForEntity(relationField.TargetEntity), relationField.TargetField.Name));

                                    sql.AppendLine(string.Format(OTM_RELATION_TEMPLATE,
                                        relationField.Name,
                                        sbRelatedFields.ToString(),
                                        GetTableNameForEntity(relationField.OriginEntity),
                                        relationName,
                                        relationField.OriginField.Name,
                                        GetTableNameForEntity(relationField.TargetEntity),
                                        relationField.TargetField.Name));
                                }
                                else
                                {
                                    //join target entity
                                    //sqlJoins.AppendLine(string.Format(JOIN, GetTableNameForEntity(relationField.TargetEntity), relationName, relationName,
                                    //	relationField.TargetField.Name, GetTableNameForEntity(relationField.OriginEntity), relationField.OriginField.Name));
                                    sql.AppendLine(string.Format(OTM_RELATION_TEMPLATE,
                                        relationField.Name,
                                        sbRelatedFields.ToString(),
                                        GetTableNameForEntity(relationField.TargetEntity),
                                        relationName,
                                        relationField.TargetField.Name,
                                        GetTableNameForEntity(relationField.OriginEntity),
                                        relationField.OriginField.Name));
                                }
                            }
                        }
                        else if (relationField.Relation.RelationType == EntityRelationType.ManyToMany)
                        {
                            string relationTable = GetTableNameForRelation(relationField.Relation.Name);
                            string targetJoinAlias = relationName + "_target";
                            string originJoinAlias = relationName + "_origin";


                            if (relationField.Relation.OriginEntityId == relationField.Relation.TargetEntityId)
                            {
                                if (relationField.Direction == "target-origin")
                                {
                                    //sqlJoins.AppendLine(string.Format(JOIN, relationTable, targetJoinAlias,
                                    //	 targetJoinAlias, "target_id", GetTableNameForEntity(entity), relationField.TargetField.Name));

                                    //sqlJoins.AppendLine(string.Format(JOIN, GetTableNameForEntity(relationField.OriginEntity), relationName,
                                    //			 relationName, relationField.OriginField.Name, targetJoinAlias, "origin_id"));

                                    sql.AppendLine(string.Format(MTM_RELATION_TEMPLATE,
                                        relationField.Name,
                                        sbRelatedFields.ToString(),
                                        GetTableNameForEntity(relationField.OriginEntity),
                                        relationName,
                                        relationTable,
                                        targetJoinAlias,
                                        targetJoinAlias,
                                        "target_id",
                                        GetTableNameForEntity(entity),
                                        relationField.TargetField.Name,
                                        relationName,
                                        relationField.OriginField.Name,
                                        targetJoinAlias,
                                        "origin_id"));
                                }
                                else
                                {
                                    //sqlJoins.AppendLine(string.Format(JOIN, relationTable, originJoinAlias,
                                    //	originJoinAlias, "origin_id", GetTableNameForEntity(entity), relationField.OriginField.Name));

                                    //sqlJoins.AppendLine(string.Format(JOIN, GetTableNameForEntity(relationField.TargetEntity), relationName,
                                    //	 originJoinAlias, "target_id", relationName, relationField.TargetField.Name));

                                    sql.AppendLine(string.Format(MTM_RELATION_TEMPLATE,
                                        relationField.Name,
                                        sbRelatedFields.ToString(),
                                        GetTableNameForEntity(relationField.TargetEntity),
                                        relationName,
                                        relationTable,
                                        originJoinAlias,
                                        originJoinAlias,
                                        "origin_id",
                                        GetTableNameForEntity(entity),
                                        relationField.OriginField.Name,
                                        relationName,
                                        relationField.OriginField.Name,
                                        originJoinAlias,
                                        "target_id"));
                                }
                            }
                            else if (relationField.Relation.OriginEntityId == entity.Id)
                            {
                                //sqlJoins.AppendLine(string.Format(JOIN, relationTable, originJoinAlias,
                                //	 originJoinAlias, "origin_id", GetTableNameForEntity(entity), relationField.OriginField.Name));

                                //sqlJoins.AppendLine(string.Format(JOIN, GetTableNameForEntity(relationField.TargetEntity), relationName,
                                //				 originJoinAlias, "target_id", relationName, relationField.TargetField.Name));

                                //		const string MTM_RELATION_TEMPLATE = @"'{0}', ( SELECT  COALESCE(  array_to_json(array_agg( row_to_json(d))), '[]') FROM ( 
                                //			SELECT {1}
                                //			FROM {2} {3}
                                //			LEFT JOIN  {4} {5} ON {6}.{7} = {8}.{9}
                                //			WHERE {10}.{11} = {12}.{13} )d  ),";


                                sql.AppendLine(string.Format(MTM_RELATION_TEMPLATE,
                                        relationField.Name,
                                        sbRelatedFields.ToString(),
                                        GetTableNameForEntity(relationField.TargetEntity),
                                        relationName,
                                        relationTable,
                                        originJoinAlias,
                                        originJoinAlias,
                                        "origin_id",
                                        GetTableNameForEntity(entity),
                                        relationField.OriginField.Name,
                                        relationName,
                                        relationField.OriginField.Name,
                                        originJoinAlias,
                                        "target_id"));
                            }
                            else //when the relation is target -> origin, we have to query origin entity
                            {
                                //sqlJoins.AppendLine(string.Format(JOIN, relationTable, targetJoinAlias,
                                //		 targetJoinAlias, "target_id", GetTableNameForEntity(entity), relationField.TargetField.Name));

                                //sqlJoins.AppendLine(string.Format(JOIN, GetTableNameForEntity(relationField.OriginEntity), relationName,
                                //			targetJoinAlias, "origin_id", relationName, relationField.OriginField.Name));

                                sql.AppendLine(string.Format(MTM_RELATION_TEMPLATE,
                                        relationField.Name,
                                        sbRelatedFields.ToString(),
                                        GetTableNameForEntity(relationField.OriginEntity),
                                        relationName,
                                        relationTable,
                                        targetJoinAlias,
                                        targetJoinAlias,
                                        "target_id",
                                        GetTableNameForEntity(entity),
                                        relationField.TargetField.Name,
                                        relationName,
                                        relationField.OriginField.Name,
                                        targetJoinAlias,
                                        "origin_id"));
                            }
                        }
                    }
                }
                // The trailing "," and the newline StringBuilder.AppendLine added must both go so FROM can follow
                // the projection list, and the newline is removed by INSPECTING it rather than assuming its width:
                // AppendLine emits Environment.NewLine, which is one character on Linux and two on Windows, so a
                // fixed count of 3 would remove the closing double quote of the last projected column's alias on
                // Linux and PostgreSQL would refuse the statement with 42601 "unterminated quoted identifier".
                // Inspecting also cannot over-trim an empty builder.
                while (sql.Length > 0 && (sql[sql.Length - 1] == '\n' || sql[sql.Length - 1] == '\r'))
                    sql.Remove(sql.Length - 1, 1);

                if (sql.Length > 0 && sql[sql.Length - 1] == ',')
                    sql.Remove(sql.Length - 1, 1);

                sql.AppendLine(END_SELECT);
                sql.AppendLine(string.Format(FROM, GetTableNameForEntity(entity)));

                //where clause

                if (query.Query != null)
                {
                    string whereSql = string.Empty;
                    string whereJoinSql = string.Empty;

                    GenerateWhereClause(query.Query, entity, ref whereSql, ref whereJoinSql, ref parameters, query.OverwriteArgs);

                    if (whereJoinSql.Length > 0)
                        sql.AppendLine(whereJoinSql);

                    if (whereSql.Length > 0)
                        sql.AppendLine("WHERE " + whereSql);
                }

                //sorting
                if (query.Sort != null && query.Sort.Length > 0)
                {
                    string sortSql = "ORDER BY ";

                    foreach (var s in query.Sort)
                    {
                        if (s.FieldName.Trim().StartsWith("{"))
                        {
                            //process json
                            dynamic parametrizedSort = ExtractSortFieldJsonValue(s.FieldName, query.OverwriteArgs);
                            if (parametrizedSort != null)
                            {
                                var sortField = parametrizedSort.Field;
                                var sortOrder = parametrizedSort.Order;

                                //SECURITY C-REV-08 (CWE-89 / OWASP A03:2021). As in the sibling sort
                                //construction earlier in this file: resolve the caller-supplied
                                //identifier against entity metadata and emit only the stored name,
                                //quoted. Field not found - skip, exactly as before.
                                string sortColumn = BuildSortColumnReference(entity, (string)sortField);
                                if (sortColumn == null)
                                    continue;

                                sortSql = sortSql + " " + sortColumn;
                                if (sortOrder == null)
                                {
                                    if (s.SortType == QuerySortType.Ascending)
                                        sortSql = sortSql + " ASC,";
                                    else
                                        sortSql = sortSql + " DESC,";
                                }
                                else
                                {
                                    if (sortOrder == "asc")
                                        sortSql = sortSql + " ASC,";
                                    else
                                        sortSql = sortSql + " DESC,";
                                }

                            }
                        }
                        else
                        {
                            //SECURITY C-REV-08 (CWE-89 improper neutralization of special elements in
                            //an SQL command, OWASP A03:2021 Injection). THE PRIMARY REPORTED SITE.
                            //s.FieldName arrives unresolved from the network and was concatenated here
                            //with no metadata check and no quoting whatsoever, so a value such as
                            //  id ASC, (SELECT ...) --
                            //executed verbatim inside ORDER BY under the application's database role.
                            //It is now resolved against entity metadata and emitted quoted; an
                            //unresolvable name is skipped, matching the JSON branch above.
                            string sortColumn = BuildSortColumnReference(entity, s.FieldName);
                            if (sortColumn == null)
                                continue;

                            sortSql = sortSql + " " + sortColumn;
                            if (s.SortType == QuerySortType.Ascending)
                                sortSql = sortSql + " ASC,";
                            else
                                sortSql = sortSql + " DESC,";
                        }
                    }

                    sortSql = sortSql.Remove(sortSql.Length - 1, 1);
                    if (sortSql.Trim() != "ORDER BY")
                        sql.AppendLine(sortSql);
                }

                //paging 
                if ((query.Limit != 0 && query.Limit != null) || query.Skip != null)
                {
                    string pagingSql = "LIMIT ";
                    if (query.Limit.HasValue)
                        pagingSql = pagingSql + query.Limit + " ";
                    else
                        pagingSql = pagingSql + "ALL ";

                    if (query.Skip.HasValue)
                        pagingSql = pagingSql + " OFFSET " + query.Skip;

                    sql.AppendLine(pagingSql);
                }

                sql.AppendLine(END_OUTER_SELECT);

                DataTable dt = new DataTable();
                using (var conn = DbContext.Current.CreateConnection())
                {
                    NpgsqlCommand command = conn.CreateCommand(sql.ToString());
                    // THREAT ADDRESSED - finding F-03, CWE-400. Defence in depth behind the
                    // complexity bound enforced in GenerateWhereClause: an ADMISSIBLE pattern is
                    // still evaluated once per row, so on a large enough table a legitimate one can
                    // run for a long time, and the ten-minute ceiling meant a single request could
                    // hold a pooled connection and a CPU core for ten minutes. Measured worst case
                    // for a pattern this platform now admits is 97 ms per 20,000 rows, so the
                    // shorter ceiling below still leaves ample room for a genuine filter over
                    // millions of rows while cutting the abuse window by an order of magnitude.
                    // Non-regex queries keep the original ten minutes exactly, so no existing
                    // report or export changes behaviour.
                    command.CommandTimeout = ContainsRegexQuery(query.Query) ? REGEX_QUERY_COMMAND_TIMEOUT_SECONDS : DEFAULT_QUERY_COMMAND_TIMEOUT_SECONDS;
                    command.Parameters.AddRange(parameters.ToArray());
                    new NpgsqlDataAdapter(command).Fill(dt);
                }

                List<EntityRecord> result = new List<EntityRecord>();

                if( missingSortFields.Any() )
                {
                    foreach( var sf in missingSortFields )
                    {
                        var selectedField = fields.Single(f => f.Id == sf.Id);
                        fields.Remove(selectedField);
                    }
                }

                foreach (DataRow dr in dt.Rows)
                {
                    var jObj = JObject.Parse((string)dr[0]);
                    result.Add(ConvertJObjectToEntityRecord(jObj, fields));
                }

                return result;

                #endregion
            }
        }

        private void GenerateWhereClause(QueryObject query, Entity entity, ref string sql, ref string joinSql, ref List<NpgsqlParameter> parameters,
                                        List<KeyValuePair<string, string>> overwriteArgs = null)
        {

			if (query == null)
				return;

            Field field = null;
            FieldType fieldType = FieldType.GuidField;
            string paramName = null;
            string completeFieldName = null;
            if (!string.IsNullOrWhiteSpace(query.FieldName))
            {
                if (!query.FieldName.Contains(RELATION_NAME_RESULT_SEPARATOR))
                {
                    field = entity.Fields.SingleOrDefault(x => x.Name == query.FieldName);
					if(field == null) {
						throw new Exception("Queried field '" + query.FieldName + "' does not exist");
					}
                    fieldType = field.GetFieldType();
                    string entityTablePrefix = GetTableNameForEntity(entity) + ".";
                    completeFieldName = entityTablePrefix + query.FieldName;
                    paramName = "@" + query.FieldName + "_" + Guid.NewGuid().ToString().Replace("-", "");

                    //SECURITY CONTRACT - finding F-01. skipClause drops this predicate entirely, so it
                    //must only ever be set for a clause whose ABSENCE is the caller's intent. Exactly
                    //one path sets it: ExtractQueryFieldJsonValue, when an optional query parameter is
                    //absent and its declared default is null. A security-sensitive operand must NEVER
                    //reach it - ExtractQueryFieldValue therefore refuses an encrypted credential filter
                    //rather than signalling skipClause, because omitting such a predicate broadens the
                    //result set instead of narrowing it. The relation branch below carries the same
                    //contract; both paths must be kept in step.
                    bool skipClause;
                    var value = ExtractQueryFieldValue(query.FieldValue, field, overwriteArgs, out skipClause) ?? DBNull.Value;
                    if (skipClause)
                        return;
					query.FieldValue = value;
                    parameters.Add(new NpgsqlParameter(paramName, value));
                }
                else
                {
                    var relationData = query.FieldName.Split(RELATION_SEPARATOR).Select(x => x.Trim()).Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
                    if (relationData.Count > 2)
                        throw new Exception(string.Format("The specified query filter field '{0}' is incorrect. Only first level relation can be specified.", query.FieldName));

                    string relationName = relationData[0];
                    string relationFieldName = relationData[1];
                    string direction = "origin-target";

                    if (string.IsNullOrWhiteSpace(relationName) || relationName == "$" || relationName == "$$")
                        throw new Exception(string.Format("Invalid relation '{0}'. The relation name is not specified.", query.FieldName));
                    else if (!relationName.StartsWith("$"))
                        throw new Exception(string.Format("Invalid relation '{0}'. The relation name is not correct.", query.FieldName));
                    else
                        relationName = relationName.Substring(1);

                    //check for target priority mark $$
                    if (relationName.StartsWith("$"))
                    {
                        direction = "target-origin";
                        relationName = relationName.Substring(1);
                    }

                    if (string.IsNullOrWhiteSpace(relationFieldName))
                        throw new Exception(string.Format("Invalid query result field '{0}'. The relation field name is not specified.", query.FieldName));


                    RelationFieldMeta relationFieldMeta = new RelationFieldMeta();
                    relationFieldMeta.Name = "$" + relationName;
                    relationFieldMeta.Direction = direction;

                    relationFieldMeta.Relation = relMan.Read().Object.SingleOrDefault(x => x.Name == relationName);
                    if (relationFieldMeta.Relation == null)
                        throw new Exception(string.Format("Invalid relation '{0}'. The relation does not exist.", query.FieldName));

                    if (relationFieldMeta.Relation.TargetEntityId != entity.Id && relationFieldMeta.Relation.OriginEntityId != entity.Id)
                        throw new Exception(string.Format("Invalid relation '{0}'. The relation does relate to queries entity.", query.FieldName));

                    if (relationFieldMeta.Direction != direction)
                        throw new Exception(string.Format("You are trying to query relation '{0}' from origin->target and target->origin direction in single query. This is not allowed.", query.FieldName));

                    //Entity entity = entMan.ReadEntity(query.EntityName).Object;
                    relationFieldMeta.TargetEntity = entMan.ReadEntity(relationFieldMeta.Relation.TargetEntityId).Object;
                    relationFieldMeta.OriginEntity = entMan.ReadEntity(relationFieldMeta.Relation.OriginEntityId).Object;

                    //this should not happen in a perfect (no bugs) world
                    if (relationFieldMeta.OriginEntity == null)
                        throw new Exception(string.Format("Invalid query result field '{0}'. Related (origin)entity is missing.", query.FieldName));
                    if (relationFieldMeta.TargetEntity == null)
                        throw new Exception(string.Format("Invalid query result field '{0}'. Related (target)entity is missing.", query.FieldName));

                    relationFieldMeta.TargetField = relationFieldMeta.TargetEntity.Fields.Single(x => x.Id == relationFieldMeta.Relation.TargetFieldId);
                    relationFieldMeta.OriginField = relationFieldMeta.OriginEntity.Fields.Single(x => x.Id == relationFieldMeta.Relation.OriginFieldId);

                    //this should not happen in a perfect (no bugs) world
                    if (relationFieldMeta.OriginField == null)
                        throw new Exception(string.Format("Invalid query result field '{0}'. Related (origin)field is missing.", query.FieldName));
                    if (relationFieldMeta.TargetField == null)
                        throw new Exception(string.Format("Invalid query result field '{0}'. Related (target)field is missing.", query.FieldName));

                    Entity joinToEntity = null;
                    if (relationFieldMeta.TargetEntity.Id == entity.Id)
                        joinToEntity = relationFieldMeta.OriginEntity;
                    else
                        joinToEntity = relationFieldMeta.TargetEntity;

                    relationFieldMeta.Entity = joinToEntity;

                    var relatedField = joinToEntity.Fields.SingleOrDefault(x => x.Name == relationFieldName);
                    if (relatedField == null)
                        throw new Exception(string.Format("Invalid query result field '{0}'. The relation field does not exist.", query.FieldName));


                    string relationJoinSql = string.Empty;
                    completeFieldName = relationName + "." + relationFieldName;
                    fieldType = relatedField.GetFieldType();
                    paramName = "@" + relationFieldName + "_" + Guid.NewGuid().ToString().Replace("-", "");

                    //SECURITY CONTRACT - finding F-01, the relation-predicate half of the same contract
                    //documented at the direct-field branch above. A related entity's encrypted
                    //credential field is refused by ExtractQueryFieldValue rather than dropped here, so
                    //a filter across a relation cannot silently widen the join either.
                    bool skipClause;
                    var value = ExtractQueryFieldValue(query.FieldValue, relatedField, overwriteArgs, out skipClause) ?? DBNull.Value;
                    if (skipClause)
                        return;

                    parameters.Add(new NpgsqlParameter(paramName, value));

                    if (relationFieldMeta.Relation.RelationType == EntityRelationType.OneToOne)
                    {
                        //when the relation is origin -> target entity
                        if (relationFieldMeta.Relation.OriginEntityId == entity.Id)
                        {
                            relationJoinSql = string.Format(FILTER_JOIN,
                                GetTableNameForEntity(relationFieldMeta.TargetEntity), relationName,
                                relationName, relationFieldMeta.TargetField.Name,
                                GetTableNameForEntity(relationFieldMeta.OriginEntity), relationFieldMeta.OriginField.Name);
                        }
                        else //when the relation is target -> origin, we have to query origin entity
                        {
                            relationJoinSql = string.Format(FILTER_JOIN,
                                   GetTableNameForEntity(relationFieldMeta.OriginEntity), relationName,
                                   relationName, relationFieldMeta.OriginField.Name,
                                   GetTableNameForEntity(relationFieldMeta.TargetEntity), relationFieldMeta.TargetField.Name);
                        }
                    }
                    else if (relationFieldMeta.Relation.RelationType == EntityRelationType.OneToMany)
                    {
                        //when origin and target entity are different, then direction don't matter
                        if (relationFieldMeta.Relation.OriginEntityId != relationFieldMeta.Relation.TargetEntityId)
                        {
                            //when the relation is origin -> target entity
                            if (relationFieldMeta.Relation.OriginEntityId == entity.Id)
                            {
                                relationJoinSql = string.Format(FILTER_JOIN,
                                    GetTableNameForEntity(relationFieldMeta.TargetEntity), relationName,
                                    relationName, relationFieldMeta.TargetField.Name,
                                    GetTableNameForEntity(relationFieldMeta.OriginEntity), relationFieldMeta.OriginField.Name);
                            }
                            else //when the relation is target -> origin, we have to query origin entity
                            {
                                relationJoinSql = string.Format(FILTER_JOIN,
                                    GetTableNameForEntity(relationFieldMeta.OriginEntity), relationName,
                                    relationName, relationFieldMeta.OriginField.Name,
                                    GetTableNameForEntity(relationFieldMeta.TargetEntity), relationFieldMeta.TargetField.Name);
                            }
                        }
                        else //when the origin entity is same as target entity direction matters
                        {
                            if (relationFieldMeta.Direction == "target-origin")
                            {
                                relationJoinSql = string.Format(FILTER_JOIN,
                                   GetTableNameForEntity(relationFieldMeta.OriginEntity), relationName,
                                   relationName, relationFieldMeta.OriginField.Name,
                                   GetTableNameForEntity(relationFieldMeta.TargetEntity), relationFieldMeta.TargetField.Name);
                            }
                            else
                            {
                                relationJoinSql = string.Format(FILTER_JOIN,
                                    GetTableNameForEntity(relationFieldMeta.TargetEntity), relationName,
                                    relationName, relationFieldMeta.TargetField.Name,
                                    GetTableNameForEntity(relationFieldMeta.OriginEntity), relationFieldMeta.OriginField.Name);
                            }
                        }
                    }
                    else if (relationFieldMeta.Relation.RelationType == EntityRelationType.ManyToMany)
                    {
                        string relationTable = GetTableNameForRelation(relationFieldMeta.Relation.Name);
                        string targetJoinAlias = relationName + "_target";
                        string originJoinAlias = relationName + "_origin";
                        string targetJoinTable = GetTableNameForEntity(relationFieldMeta.TargetEntity);
                        string originJoinTable = GetTableNameForEntity(relationFieldMeta.OriginEntity);

                        //if target is entity we query
                        if (entity.Id == relationFieldMeta.TargetEntity.Id)
                        {
                            relationJoinSql = string.Format(FILTER_JOIN,
                                     /*LEFT OUTER JOIN*/ relationTable, /* */ targetJoinAlias /*ON*/,
                                     targetJoinAlias, /*.*/ "target_id", /* =  */
                                     targetJoinTable, /*.*/ relationFieldMeta.TargetField.Name);

                            relationJoinSql = relationJoinSql + Environment.NewLine + string.Format(FILTER_JOIN,
                                    /*LEFT OUTER JOIN*/ originJoinTable, /* */ originJoinAlias /*ON*/,
                                    targetJoinAlias, /*.*/ "origin_id", /* =  */
									originJoinAlias, /*.*/ relationFieldMeta.OriginField.Name);

                            completeFieldName = originJoinAlias + "." + relationFieldName;
                        }
                        else // if origin is entity we query
                        {
                            relationJoinSql = string.Format(FILTER_JOIN,
                                    /*LEFT OUTER JOIN*/ relationTable, /* */ originJoinAlias /*ON*/,
                                    originJoinAlias, /*.*/ "origin_id", /* =  */
                                    originJoinTable, /*.*/ relationFieldMeta.OriginField.Name);

                            relationJoinSql = relationJoinSql + Environment.NewLine + string.Format(FILTER_JOIN,
                                      /*LEFT OUTER JOIN*/ targetJoinTable, /* */ targetJoinAlias /*ON*/,
                                    originJoinAlias, /*.*/ "target_id", /* =  */
                                    targetJoinAlias, /*.*/ relationFieldMeta.TargetField.Name);

                            completeFieldName = targetJoinAlias + "." + relationFieldName;
                        }
                    }


                    if (!joinSql.Contains(relationJoinSql))
                        joinSql = joinSql + Environment.NewLine + relationJoinSql;



                }

                if (fieldType == FieldType.MultiSelectField &&	
						!(query.QueryType == QueryType.EQ || query.QueryType == QueryType.NOT || query.QueryType == QueryType.CONTAINS ))
                    throw new Exception("The query operator is not supported on field '" + fieldType.ToString() + "'");
			}

            if (sql.Length > 0)
                sql = sql + " AND ";

            switch (query.QueryType)
            {
                case QueryType.EQ:
                    {
						if (query.FieldValue == null || DBNull.Value == query.FieldValue)
							sql = sql + " " + completeFieldName + " IS NULL";
						else
							sql = sql + " " + completeFieldName + "=" + paramName;

						return;
                    }
                case QueryType.NOT:
                    {
						if (query.FieldValue == null || DBNull.Value == query.FieldValue)
							sql = sql + " " + completeFieldName + " IS NOT NULL";
						else
							sql = sql + " " + completeFieldName + "<>" + paramName;

                        return;
                    }
                case QueryType.LT:
                    {
                        sql = sql + " " + completeFieldName + "<" + paramName;
                        return;
                    }
                case QueryType.LTE:
                    {
                        sql = sql + " " + completeFieldName + "<=" + paramName;
                        return;
                    }
                case QueryType.GT:
                    {
                        sql = sql + " " + completeFieldName + ">" + paramName;
                        return;
                    }
                case QueryType.GTE:
                    {
                        sql = sql + " " + completeFieldName + ">=" + paramName;
                        return;
                    }
                case QueryType.CONTAINS:
                    {
						var parameter = parameters.Single(x => x.ParameterName == paramName);

						if (fieldType == FieldType.MultiSelectField)
						{
							//parameter here is array of text
							sql = sql + " " + completeFieldName + " @> " + paramName;
						}
						else
						{
							//parameter value here is just text
							parameter.Value = "%" + parameter.Value + "%";
							sql = sql + " " + completeFieldName + " ILIKE " + paramName;
						}

						return;
                    }
                case QueryType.STARTSWITH:
                    {
                        var parameter = parameters.Single(x => x.ParameterName == paramName);
                        parameter.Value = parameter.Value + "%";
						sql = sql + " " + completeFieldName + " ILIKE " + paramName;
						return;
                    }
                case QueryType.REGEX:
                    {
                        // THREAT ADDRESSED - finding F-03 (CWE-1333 inefficient regular expression
                        // complexity, CWE-400 uncontrolled resource consumption), OWASP A03/A05. The
                        // pattern is bound to a parameter below, so this is NOT an injection seam -
                        // it is a COST seam: PostgreSQL evaluates the pattern once per row, so a
                        // pattern whose own match cost is milliseconds becomes minutes across a
                        // table scan. Enforced here, at the point the predicate is generated, rather
                        // than in the calling controller, because there are two entry points and
                        // only one is an API action: the SDK administrative record filter passes a
                        // submitted value straight to EntityQuery.QueryRegex. A caller-side check
                        // alone would leave that path unbounded. Fails hard by design; the callers'
                        // own catch turns it into a generic, non-disclosing failure.
                        DbRegexPattern.Validate(query.FieldValue);

                        var regexOperator = "~";
                        switch (query.RegexOperator)
                        {
                            case QueryObjectRegexOperator.MatchCaseSensitive:
                                regexOperator = "~";
                                break;
                            case QueryObjectRegexOperator.MatchCaseInsensitive:
                                regexOperator = "~*";
                                break;
                            case QueryObjectRegexOperator.DontMatchCaseSensitive:
                                regexOperator = "!~";
                                break;
                            case QueryObjectRegexOperator.DontMatchCaseInsensitive:
                                regexOperator = "!~*";
                                break;
                        }

                        sql = sql + " " + completeFieldName + " " + regexOperator + " " + paramName;
                        return;
                    }
				case QueryType.FTS:
					{
						//make text which we search lower case
						var parameter = parameters.Single(x => x.ParameterName == paramName);
						string text = (string)parameter.Value;

						bool singleWord = true;
						if (!string.IsNullOrWhiteSpace(text))
						{
							string analizedText = ftsAnalyzer.ProcessText(text);
							parameter.Value = analizedText;
							singleWord = analizedText.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).Count() == 1;
						}

						if (singleWord)
						{
							parameter.Value = parameter.Value + ":*"; //search for all lexemes starting with this word 
							if (string.IsNullOrWhiteSpace(query.FtsLanguage))
								sql = sql + " to_tsvector( 'simple', " + completeFieldName + ") @@ to_tsquery( 'simple', " + paramName + ") ";
							else
								sql = sql + " to_tsvector( '" + query.FtsLanguage + "' , " + completeFieldName + ") @@ to_tsquery( '" + query.FtsLanguage + "' ," + paramName + ") ";

						}
						else
						{
							if (string.IsNullOrWhiteSpace(query.FtsLanguage))
								sql = sql + " to_tsvector( 'simple', " + completeFieldName + ") @@ plainto_tsquery( 'simple', " + paramName + ") ";
							else
								sql = sql + " to_tsvector( '" + query.FtsLanguage + "' , " + completeFieldName + ") @@ plainto_tsquery( '" + query.FtsLanguage + "' ," + paramName + ") ";
						}
						return;
					}
				case QueryType.RELATED:
                    {
                        //TODO
                        throw new NotImplementedException();
                    }
                case QueryType.NOTRELATED:
                    {
                        //TODO
                        throw new NotImplementedException();
                    }
                case QueryType.AND:
                    {
                        if (query.SubQueries.Count == 1)
                            GenerateWhereClause(query.SubQueries[0], entity, ref sql, ref joinSql, ref parameters, overwriteArgs);
                        else
                        {
                            string andSql = string.Empty;
                            foreach (var q in query.SubQueries)
                            {
                                string subQuerySql = string.Empty;
                                GenerateWhereClause(q, entity, ref subQuerySql, ref joinSql, ref parameters, overwriteArgs);
                                if (andSql.Length == 0)
                                    andSql = subQuerySql;
                                else if (subQuerySql.Length > 0)
                                    andSql = andSql + " AND " + subQuerySql;
                            }

                            if (andSql.Length > 0)
                                sql = sql + " ( " + andSql + " )";
                        }
                        return;
                    }
                case QueryType.OR:
                    {
                        if (query.SubQueries.Count == 1)
                            GenerateWhereClause(query.SubQueries[0], entity, ref sql, ref joinSql, ref parameters, overwriteArgs);
                        else
                        {
                            string orSql = string.Empty;
                            foreach (var q in query.SubQueries)
                            {
                                string subQuerySql = string.Empty;
                                GenerateWhereClause(q, entity, ref subQuerySql, ref joinSql, ref parameters, overwriteArgs);
                                if (orSql.Length == 0)
                                    orSql = subQuerySql;
                                else if (subQuerySql.Length > 0)
                                    orSql = orSql + " OR " + subQuerySql;
                            }

                            if (orSql.Length > 0)
                                sql = sql + " ( " + orSql + " )";
                        }
                        return;
                    }
                default:
                    throw new Exception("Not supported query type");
            }
        }

        private string GetTableNameForEntity(Entity entity)
        {
            return GetTableNameForEntity(entity.Name);
        }

        // SECURITY H-09 (CWE-89 SQL injection / OWASP A03:2021 Injection). Every value in this
        // repository is already bound as a parameter, but PostgreSQL cannot parameterise an
        // IDENTIFIER, so the record table name is necessarily concatenated into SQL text. This
        // method is the single chokepoint through which that name is built for the whole class -
        // roughly sixty call sites reach SQL through it - so validating here closes the identifier
        // injection exposure for all of them at once instead of patching each construction.
        //
        // DbIdentifier.Validate is used rather than DbIdentifier.Quote deliberately. Validate
        // returns the identifier BYTE-FOR-BYTE unchanged once it is proven to match the allow-list,
        // so every caller receives exactly the string it received before this change: the bare
        // "rec_<name>". That matters because the returned value is not only dropped into FROM and
        // JOIN positions but is also used to build a textual column prefix - see the
        // entityTablePrefix concatenation in GenerateWhereClause - and is embedded in the
        // REGULAR_FIELD_SELECT format. Quoting would alter every one of those strings, and the
        // security benefit would be nil: the allow-list already rejects the double quote, upper
        // case, whitespace, semicolons, comment markers and every other character injection
        // depends on, which makes injection impossible by construction. Quoting would only add
        // behavioural risk to a fix that is otherwise byte-identical for all legitimate input.
        //
        // A rejected name throws DbException rather than being sanitised: silently repairing a
        // hostile identifier would leave the vulnerability open while making the finding read as
        // closed.
        private string GetTableNameForEntity(string entityName)
        {
            return DbIdentifier.Validate(RECORD_COLLECTION_PREFIX + entityName);
        }

        /// <summary>
        /// Resolves one caller-supplied sort identifier against the queried entity's own field
        /// metadata and renders it as a qualified, quoted column reference fit for an ORDER BY
        /// position. Returns null when the identifier names no field of this entity, which the
        /// callers treat as "skip this sort term".
        /// </summary>
        /// <remarks>
        /// THREAT ADDRESSED - finding C-REV-08 (Critical), CWE-89 (improper neutralization of
        /// special elements used in an SQL command) and CWE-20 (improper input validation), OWASP
        /// A03:2021 Injection.
        ///
        /// Every VALUE in this repository is already bound as a parameter, and both the FROM target
        /// and the SELECT list are already safe - the table name passes through the
        /// <see cref="GetTableNameForEntity(string)"/> allow-list chokepoint, and
        /// <see cref="ExtractQueryFieldsMeta(EntityQuery)"/> resolves every projected column against
        /// entity.Fields and THROWS on an unknown token. ORDER BY was the one construction that did
        /// neither: the sort identifier was concatenated into the statement exactly as the caller
        /// supplied it, with no metadata resolution and, at one of the two sites, no quoting at all.
        ///
        /// That identifier is reachable from the network as a bare query-string parameter. Two
        /// examples, both on the authenticated API surface:
        /// WebVella.Erp.Web/Controllers/WebApiController.cs RelatedFieldMultiSelect takes
        /// "fieldName" and passes it straight into a QuerySortObject, and GetQuickSearch does the
        /// same with "sortField". A value such as
        ///   id ASC, (SELECT ...) --
        /// therefore landed verbatim inside ORDER BY, and at the site that wrapped the name in
        /// hand-written double quotes a single embedded double quote terminated that quoting and
        /// reopened the same hole. ORDER BY is a fully expression-capable position in PostgreSQL, so
        /// this was arbitrary sub-SELECT execution under the application's own database role, not a
        /// mere sort-order nuisance.
        ///
        /// WHY RESOLUTION RATHER THAN ESCAPING, and why a shared helper: the identifier is compared
        /// for equality against the entity's declared field names and what reaches SQL is the NAME
        /// TAKEN FROM METADATA, never the caller's text. Escaping the caller's text would still emit
        /// caller-controlled bytes; resolution emits only bytes the platform itself stored. The same
        /// defect occurred at four sites across two methods, so one reviewable helper is used for
        /// all four rather than four independent patches that are free to drift apart - the same
        /// reasoning that produced Database/DbIdentifier.cs.
        ///
        /// WHY SKIP RATHER THAN THROW on an unresolved name: it is the semantics this method's own
        /// callers already have. The JSON sort branch at both sites, and the distinct-select
        /// pre-pass in <see cref="Find(EntityQuery)"/>, already resolve against entity.Fields and
        /// "continue" when the lookup fails - the comment there reads "we skip sorf fields not found
        /// in entity". Throwing would turn a request that previously returned unsorted rows into a
        /// server error, which the preservation requirement forbids. Nothing legitimate is lost: a
        /// relation-qualified sort name never resolved here before this change either, and at the
        /// unquoted site it produced invalid SQL and a hard failure, so resolve-and-skip strictly
        /// improves on the previous behaviour. Both callers already handle every term being skipped:
        /// the "ORDER BY" clause is only appended when at least one term survived.
        ///
        /// The emitted shape is bare validated table plus double-quoted column -
        /// rec_user."created_on" - which is byte-identical to what the SELECT list construction in
        /// <see cref="Find(EntityQuery)"/> already writes by hand, and byte-identical to what the
        /// quoted sort site already emitted for a legitimate field. The table is deliberately left
        /// bare rather than quoted, for the reason set out on
        /// <see cref="GetTableNameForEntity(string)"/>: the allow-list makes quoting security-neutral
        /// there while changing strings that are reused elsewhere. Quoting is behaviour-preserving
        /// for the column because DbIdentifier's allow-list rejects upper case, so every accepted
        /// name is already lower case and folds to itself.
        /// </remarks>
        /// <param name="entity">The entity being queried, and the sole authority on which names are valid.</param>
        /// <param name="fieldName">The caller-supplied sort identifier. Never trusted.</param>
        /// <returns>A qualified quoted column reference, or null when the name resolves to no field.</returns>
        /// <exception cref="DbException">
        /// Thrown only when a name that IS present in entity metadata fails the identifier
        /// allow-list, which would mean the stored metadata itself is unusable in SQL. That is a
        /// hard fault by design and is never sanitised away.
        /// </exception>
        private string BuildSortColumnReference(Entity entity, string fieldName)
        {
            // A null, empty or whitespace-only identifier names no field, so it is refused before any
            // lookup or concatenation. Defence in depth rather than the primary guard: the two
            // network-reachable callers in WebVella.Erp.Web/Controllers/WebApiController.cs both
            // reject a blank identifier before constructing a QuerySortObject, and the branch
            // selector in the loops above dereferences FieldName ahead of this call. Refusing it here
            // means no future caller can reach the resolution below with nothing to resolve.
            if (string.IsNullOrWhiteSpace(fieldName))
                return null;

            // FirstOrDefault rather than SingleOrDefault on purpose: duplicate field names cannot
            // occur, but if metadata were ever inconsistent SingleOrDefault would raise on a read
            // path, converting a data problem into a request failure. The lookup is ordinal and
            // case-sensitive, matching how entity.Fields is compared everywhere else in this class.
            Field sortField = entity.Fields.FirstOrDefault(x => x.Name == fieldName);
            if (sortField == null)
                return null;

            // sortField.Name, not fieldName. They compare equal, but taking the value from metadata
            // makes it unambiguous at a glance that no caller-supplied text reaches the statement.
            return GetTableNameForEntity(entity) + "." + DbIdentifier.Quote(sortField.Name);
        }

        // SECURITY H-09 (CWE-89 SQL injection / OWASP A03:2021 Injection). Companion chokepoint for
        // many-to-many relation tables, which are emitted as JOIN targets and as join aliases in the
        // generated SQL. Validate rather than Quote for the same reason as above: the returned value
        // is reused to build alias and column-prefix strings, so it must stay byte-identical.
        private static string GetTableNameForRelation(string relationName)
        {
            return DbIdentifier.Validate("rel_" + relationName);
        }

        internal List<Field> ExtractQueryFieldsMeta(EntityQuery query)
        {
            List<EntityRelation> relations = relMan.Read().Object;
            List<Field> result = new List<Field>();

            //split field string into tokens speparated by FIELDS_SEPARATOR
            List<string> tokens = query.Fields.Split(FIELDS_SEPARATOR).Select(x => x.Trim()).Where(x => !string.IsNullOrWhiteSpace(x)).ToList();

            //check the query tokens for widcard symbol and validate it is only that symbol - //UPDATE: allow Wildcard and field names mix. WILL NOT BE DUPLICATED
            //if (tokens.Count > 1 && tokens.Any(x => x == WILDCARD_SYMBOL))
            //	throw new Exception("Invalid query syntax. Wildcard symbol can be used only with no other fields.");

            Entity entity = entMan.ReadEntity(query.EntityName).Object;
            if (entity == null)
                throw new Exception(string.Format("The entity '{0}' does not exists.", query.EntityName));

            //We check for wildcard symbol and if present include all fields of the queried entity 
            bool wildcardSelectionEnabled = tokens.Any(x => x == WILDCARD_SYMBOL);
            if (wildcardSelectionEnabled)
            {
                result.AddRange(entity.Fields);
                //return result; //UPDATE: allow Wildcard and field names mix. WILL NOT BE DUPLICATED
                tokens.Remove(WILDCARD_SYMBOL); //UPDATE: NULL Exception is triggered if not removed.
            }

            //process only tokens do not contain RELATION_SEPARATOR 
            foreach (var token in tokens)
            {
                if (!token.Contains(RELATION_SEPARATOR))
                {
                    //locate the field
                    var field = entity.Fields.SingleOrDefault(x => x.Name == token);

                    //found no field for specified token
                    if (field == null)
                        throw new Exception(string.Format("Invalid query result field '{0}'. The field name is incorrect.", token));

                    //check for duplicated field tokens and ignore them
                    if (!result.Any(x => x.Id == field.Id))
                        result.Add(field);
                }
                else
                {
                    var relationData = token.Split(RELATION_SEPARATOR).Select(x => x.Trim()).Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
                    if (relationData.Count > 2)
                        throw new Exception(string.Format("The specified query result  field '{0}' is incorrect. Only first level relation can be specified.", token));

                    string relationName = relationData[0];
                    string relationFieldName = relationData[1];
                    string direction = "origin-target";

                    if (string.IsNullOrWhiteSpace(relationName) || relationName == "$" || relationName == "$$")
                        throw new Exception(string.Format("Invalid relation '{0}'. The relation name is not specified.", token));
                    else if (!relationName.StartsWith("$"))
                        throw new Exception(string.Format("Invalid relation '{0}'. The relation name is not correct.", token));
                    else
                        relationName = relationName.Substring(1);

                    //check for target priority mark $$
                    if (relationName.StartsWith("$"))
                    {
                        direction = "target-origin";
                        relationName = relationName.Substring(1);
                    }

                    if (string.IsNullOrWhiteSpace(relationFieldName))
                        throw new Exception(string.Format("Invalid query result field '{0}'. The relation field name is not specified.", token));



                    Field field = result.SingleOrDefault(x => x.Name == "$" + relationName);
                    RelationFieldMeta relationFieldMeta = null;
                    if (field == null)
                    {
                        relationFieldMeta = new RelationFieldMeta();
                        relationFieldMeta.Name = "$" + relationName;
                        relationFieldMeta.Direction = direction;
                        result.Add(relationFieldMeta);
                    }
                    else
                        relationFieldMeta = (RelationFieldMeta)field;


                    relationFieldMeta.Relation = relations.SingleOrDefault(x => x.Name == relationName);
                    if (relationFieldMeta.Relation == null)
                        throw new Exception(string.Format("Invalid relation '{0}'. The relation does not exist.", token));

                    if (relationFieldMeta.Relation.TargetEntityId != entity.Id && relationFieldMeta.Relation.OriginEntityId != entity.Id)
                        throw new Exception(string.Format("Invalid relation '{0}'. The relation does relate to queries entity.", token));

                    if (relationFieldMeta.Direction != direction)
                        throw new Exception(string.Format("You are trying to query relation '{0}' from origin->target and target->origin direction in single query. This is not allowed.", token));

                    //Entity entity = entMan.ReadEntity(query.EntityName).Object;
                    relationFieldMeta.TargetEntity = entMan.ReadEntity(relationFieldMeta.Relation.TargetEntityId).Object;
                    relationFieldMeta.OriginEntity = entMan.ReadEntity(relationFieldMeta.Relation.OriginEntityId).Object;

                    //this should not happen in a perfect (no bugs) world
                    if (relationFieldMeta.OriginEntity == null)
                        throw new Exception(string.Format("Invalid query result field '{0}'. Related (origin)entity is missing.", token));
                    if (relationFieldMeta.TargetEntity == null)
                        throw new Exception(string.Format("Invalid query result field '{0}'. Related (target)entity is missing.", token));

                    relationFieldMeta.TargetField = relationFieldMeta.TargetEntity.Fields.Single(x => x.Id == relationFieldMeta.Relation.TargetFieldId);
                    relationFieldMeta.OriginField = relationFieldMeta.OriginEntity.Fields.Single(x => x.Id == relationFieldMeta.Relation.OriginFieldId);

                    //this should not happen in a perfect (no bugs) world
                    if (relationFieldMeta.OriginField == null)
                        throw new Exception(string.Format("Invalid query result field '{0}'. Related (origin)field is missing.", token));
                    if (relationFieldMeta.TargetField == null)
                        throw new Exception(string.Format("Invalid query result field '{0}'. Related (target)field is missing.", token));

                    Entity joinToEntity = null;
                    if (relationFieldMeta.TargetEntity.Id == entity.Id)
                        joinToEntity = relationFieldMeta.OriginEntity;
                    else
                        joinToEntity = relationFieldMeta.TargetEntity;

                    relationFieldMeta.Entity = joinToEntity;

                    var relatedField = joinToEntity.Fields.SingleOrDefault(x => x.Name == relationFieldName);
                    if (relatedField == null)
                        throw new Exception(string.Format("Invalid query result field '{0}'. The relation field does not exist.", token));

                    //add id field of related entity
                    if (relatedField.Name != "id")
                    {
                        var relatedIdField = joinToEntity.Fields.SingleOrDefault(x => x.Name == "id");

                        //if field already added
                        if (!relationFieldMeta.Fields.Any(x => x.Id == relatedIdField.Id))
                            relationFieldMeta.Fields.Add(relatedIdField);
                    }

                    //if field already added
                    if (relationFieldMeta.Fields.Any(x => x.Id == relatedField.Id))
                        continue;


                    relationFieldMeta.Fields.Add(relatedField);
                }
            }

            return result;
        }


        private object ExtractQueryFieldValue(object value, Field field, List<KeyValuePair<string, string>> overwriteArgs, out bool skipClause)
        {
            skipClause = false;

            if (value == null)
                return null;

            if (value is JToken)
                value = ((JToken)value).ToObject<object>();

            if (value is string && ((string)value).Trim().StartsWith("{"))
            {
                value = ExtractQueryFieldJsonValue((string)value, field, overwriteArgs, out skipClause);
                if (skipClause)
                    return null;
            }

            if (field is AutoNumberField)
            {
                if (value == null)
                    return null;
                if (value is string)
                    return decimal.Parse(value as string);

                return Convert.ToDecimal(value);
            }
            else if (field is CheckboxField)
            {
                if (value == null)
                    return null;
                if (value is string)
                    return bool.Parse(value as string);
                return value as bool?;
            }
            else if (field is CurrencyField)
            {
                if (value == null)
                    return null;
                if (value is string)
                {
                    if (string.IsNullOrWhiteSpace(value as string))
                        return null;
                    if ((value as string).StartsWith("$"))
                        value = (value as string).Substring(1);
                    return decimal.Parse(value as string);
                }

                return Convert.ToDecimal(value);
            }
            else if (field is DateField)
            {
                if (value == null)
                    return null;

                DateTime? date = null;
                if (value is string)
                {
                    if (string.IsNullOrWhiteSpace(value as string))
                        return null;
                    return DateTime.Parse(value as string);
                }
                else
                    date = value as DateTime?;

                if (date != null)
                    return new DateTime(date.Value.Year, date.Value.Month, date.Value.Day, 0, 0, 0, DateTimeKind.Utc);
            }
            else if (field is DateTimeField)
            {

                if (value == null)
                    return null;

                if (value is string)
                {
                    if (string.IsNullOrWhiteSpace(value as string))
                        return null;
                    return DateTime.Parse(value as string);
                }

                return value as DateTime?;
            }
            else if (field is EmailField)
                return value as string;
            else if (field is FileField)
                return value as string;
            else if (field is ImageField)
                return value as string;
            else if (field is HtmlField)
                return value as string;
            else if (field is MultiLineTextField)
                return value as string;
			else if (field is GeographyField)
				return value as string;
			else if (field is MultiSelectField)
            {
				if (value == null)
					return null;
				else if (value is JArray)
					return ((JArray)value).Select(x => ((JToken)x).Value<string>()).ToList<string>();
				else if (value is List<object>)
					return ((List<object>)value).Select(x => ((object)x).ToString()).ToList<string>();
				else if (value is string[])
					return new List<string>(value as string[]);
				else if (value is string)
					return new List<string>(((string)value).Split(',', StringSplitOptions.RemoveEmptyEntries));
				else
					return value as IEnumerable<string>;
            }
            else if (field is NumberField)
            {
                if (value == null)
                    return null;
                if (value is string)
                    return decimal.Parse(value as string);

                return Convert.ToDecimal(value);
            }
            else if (field is PasswordField)
            {
                if (((PasswordField)field).Encrypted == true)
                {
                    if (string.IsNullOrWhiteSpace(value as string))
                        return null;

                    //THREAT ADDRESSED - finding C-03, CWE-916 / CWE-759, OWASP A02:2021, and the
                    //structural consequence of closing it. This branch is NOT a write path: its
                    //return value becomes the NpgsqlParameter of a SQL WHERE-clause predicate,
                    //consumed by the two GenerateWhereClause call sites above. Hashing here
                    //therefore produced "WHERE <table>.password = @param", and an unsalted MD5
                    //digest is deterministic, so that comparison used to work - which is precisely
                    //what made it a password confirmation ORACLE: any caller able to build a filter
                    //on the password field could confirm a guess by observing whether a row came
                    //back. A salted, work-factored hash differs on every invocation, so the same
                    //predicate can never match anything, and the value must not be bound.
                    //
                    //THREAT ADDRESSED - finding F-01, CWE-1284 (improper validation of a specified
                    //quantity) reached through OWASP A01:2021 Broken Access Control. This branch
                    //previously set skipClause and returned null, and BOTH GenerateWhereClause call
                    //sites honour skipClause by returning without emitting anything - so the entire
                    //predicate silently disappeared from the WHERE clause. A caller that intended
                    //"return the single row whose password matches" therefore received EVERY row the
                    //remaining predicates allowed. Dropping a security-sensitive filter is strictly
                    //worse than refusing the query: refusal is visible and returns no data, whereas
                    //omission is invisible and BROADENS the result set. Silently omitting it is
                    //never correct, so the query is REJECTED here instead.
                    //
                    //Rejection rather than an always-false predicate: an always-false predicate
                    //would still answer, with an empty set that is indistinguishable from "no such
                    //credential", which is the same confirmation oracle in a quieter form and also
                    //hides the caller's mistake. A thrown exception is the shape every other invalid
                    //query in this method already takes (see the guards above), so the failure is
                    //reported through the platform's existing error path with no new mechanism:
                    //RecordManager.Find catches it, returns Success = false with "The query is
                    //incorrect and cannot be executed" and no data, and records the reason - a
                    //BOUNDED refusal, not a 500 and not a widened result set.
                    //ValidationException is used rather than a bare Exception because this IS a
                    //validation failure of the submitted query, and because the platform's own
                    //validation type keeps the refusal inside its existing error taxonomy.
                    //
                    //No functionality is lost. Nothing in this repository queries by password value:
                    //WebVella.Erp/Api/SecurityManager.cs.GetUser(email, password) - the only such
                    //query that ever existed - resolves by e-mail and verifies the credential in
                    //application code via PasswordUtil.VerifyPassword. A caller reaching this line
                    //is therefore asking for something that cannot be answered correctly.
                    //
                    //It also means the redaction marker can never reach a predicate: the query is
                    //refused before any value of any shape is bound.
                    //
                    //The IsNullOrWhiteSpace guard above is deliberately left as it was, so its
                    //pre-existing behaviour - a blank operand contributes a NULL parameter rather
                    //than an error - is preserved exactly.
                    throw new ValidationException("Queried field '" + field.Name + "' stores an encrypted credential and cannot be used as a query filter. " +
                        "Credential verification is performed in application code; remove this filter from the query.");
                }
                return value;
            }
            else if (field is PercentField)
            {
                if (value == null)
                    return null;
                if (value is string)
                    return decimal.Parse(value as string);

                return Convert.ToDecimal(value);
            }
            else if (field is PhoneField)
                return value as string;
            else if (field is GuidField)
            {
                if (value is string)
                {
                    if (string.IsNullOrWhiteSpace(value as string))
                        return null;

                    return new Guid(value as string);
                }

                if (value is Guid)
                    return (Guid?)value;

                if (value == null)
                    return (Guid?)null;

				if( value is DBNull)
					return (Guid?)null;

				throw new Exception("Invalid Guid field value.");
            }
            else if (field is SelectField)
                return value as string;
            else if (field is TextField)
                return value as string;
            else if (field is UrlField)
                return value as string;


            throw new Exception("System Error. A field type is not supported in field value extraction process.");
        }


        private object ExtractQueryFieldJsonValue(string value, Field field, List<KeyValuePair<string, string>> overwriteArgs, out bool skipClause)
        {
            skipClause = false;
            JObject jObj = null;
            try
            {
                jObj = JObject.Parse(value);
            }
            catch
            {
                throw new Exception("Invalid query agrument json.");
            }


            JToken nameToken;
            if (!jObj.TryGetValue("name", out nameToken))
                throw new Exception("Invalid query agrument json. Missing name.");

            JToken optionToken;
            if (!jObj.TryGetValue("option", out optionToken))
                throw new Exception("Invalid query agrument json. Missing option.");

            JToken defaultToken;
            if (!jObj.TryGetValue("default", out defaultToken))
                throw new Exception("Invalid query agrument json. Missing default.");

            JToken settingsToken;
            if (!jObj.TryGetValue("settings", out settingsToken))
                throw new Exception("Invalid query agrument json. Missing settings.");

            if (nameToken.ToString().ToLowerInvariant() == "current_user")
            {
                //currently we have only id option so ignore options check for now
                ErpUser currentUser = SecurityContext.CurrentUser;
                if (currentUser != null)
                    return currentUser.Id;

                if (string.IsNullOrWhiteSpace(defaultToken.ToString()))
                    return null;

                return new Guid(defaultToken.ToString());
            }
            else if (nameToken.ToString().ToLowerInvariant() == "current_date")
            {
                DateTime currentDate = DateTime.UtcNow;

                if (optionToken.ToString().ToLowerInvariant() == "date")
                {
                    currentDate = currentDate.Date;
                }
                else if (optionToken.ToString().ToLowerInvariant() == "datetime")
                {
                    //already initialized, do nothing
                }
                else
                    throw new Exception("Not supported json query option:" + optionToken.ToString().ToLowerInvariant());

                int yearOffset = 0;
                int monthOffset = 0;
                int dayOffset = 0;
                int hourOffset = 0;
                int minuteOffset = 0;

                if (settingsToken.Type == JTokenType.Object)
                {
                    foreach (JProperty child in settingsToken.Children<JProperty>())
                    {
                        //skip null properties
                        if (child.Value.Type == JTokenType.Null)
                            continue;

                        switch (child.Name)
                        {
                            case "year":
                                Int32.TryParse(child.Value.ToString(), out yearOffset);
                                break;
                            case "month":
                                Int32.TryParse(child.Value.ToString(), out monthOffset);
                                break;
                            case "day":
                                Int32.TryParse(child.Value.ToString(), out dayOffset);
                                break;
                            case "hour":
                                Int32.TryParse(child.Value.ToString(), out hourOffset);
                                break;
                            case "minute":
                                Int32.TryParse(child.Value.ToString(), out minuteOffset);
                                break;
                        }
                    }
                }

                return currentDate.AddYears(yearOffset).AddMonths(monthOffset).AddDays(dayOffset).AddHours(hourOffset).AddMonths(minuteOffset);
            }
            else if (nameToken.ToString().ToLowerInvariant() == "url_query")
            {
                if (optionToken.Type == JTokenType.Null)
                    throw new Exception("Url query key not specified in json.");

                var queryParameterKey = optionToken.ToString().ToLowerInvariant();
                if (overwriteArgs != null && overwriteArgs.Any(x => x.Key.ToLowerInvariant() == queryParameterKey))
                {
                    KeyValuePair<string, string> pair = overwriteArgs.Single(x => x.Key.ToLowerInvariant() == queryParameterKey);
                    return pair.Value;
                }

                if (defaultToken.Type != JTokenType.Null)
                    return defaultToken.ToString();

                //if no query parameter and default value is null, then skip this query clause
                skipClause = true;
                return null;
            }
            else
                throw new Exception("Not supported name '" + nameToken.ToString() + "' in query json clause");

        }

        private dynamic ExtractSortFieldJsonValue(string value, List<KeyValuePair<string, string>> overwriteArgs)
        {
            JObject jObj = null;
            try
            {
                jObj = JObject.Parse(value);
            }
            catch
            {
                throw new Exception("Invalid query agrument json.");
            }


            JToken nameToken;
            if (!jObj.TryGetValue("name", out nameToken))
                throw new Exception("Invalid query agrument json. Missing name.");

            JToken optionToken;
            if (!jObj.TryGetValue("option", out optionToken))
                throw new Exception("Invalid query agrument json. Missing option.");

            JToken defaultToken;
            if (!jObj.TryGetValue("default", out defaultToken))
                throw new Exception("Invalid query agrument json. Missing default.");

            JToken settingsToken;
            if (!jObj.TryGetValue("settings", out settingsToken))
                throw new Exception("Invalid query agrument json. Missing settings.");

            if (nameToken.ToString().ToLowerInvariant() != "url_sort")
                throw new Exception("Not supported name '" + nameToken.ToString() + "' in sort json definition.");

            if (optionToken.Type == JTokenType.Null)
                throw new Exception("Url sort key not specified in json.");

            string sortField = string.Empty;
            string sortOrder = string.Empty;

            var sortParameterKey = optionToken.ToString().ToLowerInvariant();
            if (overwriteArgs != null && overwriteArgs.Any(x => x.Key.ToLowerInvariant() == sortParameterKey))
            {
                KeyValuePair<string, string> pair = overwriteArgs.Single(x => x.Key.ToLowerInvariant() == sortParameterKey);
                sortField = pair.Value;
            }
            else if (defaultToken.Type != JTokenType.Null)
                sortField = defaultToken.ToString();

            if (settingsToken.Type == JTokenType.Object)
            {
                var orderProperty = settingsToken.Children<JProperty>().SingleOrDefault(x => x.Name == "order");
                if (orderProperty != null && orderProperty.Value.Type != JTokenType.Null)
                {
                    var sortOrderParameterKey = orderProperty.Value.ToString().ToLowerInvariant();
                    if (overwriteArgs != null && overwriteArgs.Any(x => x.Key.ToLowerInvariant() == sortOrderParameterKey))
                    {
                        KeyValuePair<string, string> pair = overwriteArgs.Single(x => x.Key.ToLowerInvariant() == sortOrderParameterKey);
                        sortOrder = (pair.Value ?? "asc").Trim().ToLowerInvariant();
                        if (!(sortOrder == "asc" || sortOrder == "desc"))
                            sortOrder = null;
                    }
                }
            }

			if (string.IsNullOrWhiteSpace(sortField))
				return null;
			else
				sortField = sortField.Trim();

			if (string.IsNullOrWhiteSpace(sortOrder))
				sortOrder = sortOrder.Trim();

			return new { Field = sortField, Order = sortOrder };
        }
    }
}

