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

        // Command timeout applied to any query carrying a regex predicate (CWE-400). Deliberately a
        // client-side timeout rather than a server-side "SET statement_timeout": DbContext's CreateConnection
        // returns a TRANSACTION-BOUND SHARED connection when a transaction is active, so a session-level
        // setting applied here could outlive this query and silently truncate an unrelated long-running
        // statement on the same connection, while "SET LOCAL" only takes effect inside a transaction and so
        // would do nothing on the common path. The client cancel does interrupt a running regex scan.
        private const int REGEX_QUERY_COMMAND_TIMEOUT_SECONDS = 60;

        // Every non-regex query keeps this repository's original ten-minute ceiling, so the regex bound
        // narrows one case rather than re-tuning the data layer.
        private const int DEFAULT_QUERY_COMMAND_TIMEOUT_SECONDS = 600;

        // Walks the whole query tree, because a regex predicate can sit at any depth inside nested AND/OR
        // groups and a top-level-only test would miss it. Modelled on ContainsRelationalQuery below, which
        // already does this walk for a different property.
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

                // CWE-400. This method evaluates the SAME caller-supplied predicate as Find, and every paged list
                // issues a count beside its page, so leaving the count unbounded would leave half the request
                // unprotected. Narrowed only when a regex predicate is actually present, so ordinary counts keep the
                // connection default untouched.
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
                    //SECURITY C-02 (CWE-200 / CWE-522, OWASP A01:2021 + A02:2021): relational read projection seam.
                    //See RedactEncryptedFieldValue for the full rationale. This private helper is reached only from
                    //within this class - the recursion just below and Find(EntityQuery) - so the redaction is
                    //UNCONDITIONAL and deliberately not subject to the credential-read scope that ExtractFieldValue's
                    //own read gate honours. Neither Find seam is ever the credential path.
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
        /// projection, so a stored credential hash never leaves the server. Every other field type, and a
        /// password field not flagged as encrypted, passes through untouched.
        /// </summary>
        /// <param name="value">The already-extracted projection value.</param>
        /// <param name="field">The field the value was projected from.</param>
        /// <returns>
        /// <see cref="RecordManager.EncryptedFieldRedactedValue"/> when <paramref name="field"/> is an
        /// encrypted <see cref="PasswordField"/> and a value is actually present; otherwise
        /// <paramref name="value"/> unchanged. A NULL VALUE STAYS NULL: inventing a marker where there was no
        /// value would change observable behaviour, and the write-side guard keys on the marker, not on null.
        /// </returns>
        /// <remarks>
        /// SECURITY C-02 (CWE-200 exposure of sensitive information to an unauthorized actor, CWE-522
        /// insufficiently protected credentials / OWASP A01:2021 + A02:2021).
        /// <para>
        /// THREAT ADDRESSED: a stored password hash was returned verbatim by every record query projection, to
        /// callers of any role, because field permissions are enforced ONLY in the presentation layer -
        /// PcFieldBase gates the whole evaluation behind <c>entityField.EnableSecurity</c>, a plain bool
        /// defaulting to false - and there is no data-layer equivalent. Authorization must hold on every
        /// request rather than in the UI alone, so the value is replaced here, in the repository's own
        /// projection.
        /// </para>
        /// <para>
        /// Redaction is UNCONDITIONAL with respect to role, administrators included: no projection returns a
        /// hash for any role. It is deliberately NOT conditional on <c>SecurityContext</c>, on an
        /// ignoreSecurity flag or on role membership - a role-conditional projection would leave the hash
        /// reachable and add complexity the minimal-change constraint forbids.
        /// </para>
        /// <para>
        /// WHY THIS HELPER EXISTS ALONGSIDE THE GATE INSIDE
        /// <see cref="ExtractFieldValue(object, Field, bool)"/>, and must not be folded into it: that method
        /// is public static and serves BOTH directions - called with <c>encryptPasswordFields: true</c> it is
        /// the plaintext-to-hash WRITE conversion, so redacting inside it would store the marker as a
        /// credential and destroy every password it converted. Redaction therefore sits at the read-projection
        /// seams, which is what this helper is.
        /// </para>
        /// <para>
        /// CALL SITES - internal rather than private because the projection seams in this assembly must not
        /// drift apart: the non-relational reader loop and the private ConvertJObjectToEntityRecord of
        /// <see cref="Find(EntityQuery)"/>, both in this file, which this helper covers UNCONDITIONALLY; and
        /// the separate private ConvertJObjectToEntityRecord of WebVella.Erp/Eql/EqlCommand.cs, reached by
        /// every EQL query - including the eql, eql-ds and eql-ds-select2 routes, which serialise an
        /// EqlCommand result straight into a response, and the stored data sources that select the user
        /// entity's password column outright. That seam redacts DENY-BY-DEFAULT and can only be opted out of
        /// through the internal <c>EqlCommand.IncludeEncryptedFieldValues</c> flag, which lives on the COMMAND
        /// and never on the public EqlSettings built from stored data-source definitions.
        /// </para>
        /// <para>
        /// TWO INDEPENDENT GATES PROTECT THE EQL SEAM, and both must be satisfied before a real hash is
        /// projected. <c>ExtractFieldValue</c> carries the deeper one on its read fall-through, because it is
        /// public static and any caller can reach it without passing through this class or RecordManager; that
        /// gate is CONDITIONAL, suppressed only while <c>RecordManager.OpenCredentialReadScope</c> is open.
        /// EqlCommand then applies the second, keyed on its own flag. The two Find seams here stay redacted
        /// even for the internal credential path, so the exemption is as narrow as possible; redaction is
        /// idempotent, so a double application is harmless.
        /// </para>
        /// <para>
        /// CREDENTIAL RESOLUTION IS THE ONLY EXEMPTION. <c>SecurityManager.GetUser(Guid)</c> - which SaveUser
        /// and the schema-version-4 migration read through - and <c>SecurityManager.GetUser(email, password)</c>
        /// each open the scope AND set the command flag, and nothing else in the platform does either. The
        /// stored hash a login verifies against is read by <c>SecurityManager.ReadStoredPasswordHash</c>, an
        /// internal, parameterized, single-column, single-row query that bypasses every projection. Do NOT
        /// introduce a projection-based hash read here or in EqlCommand to make another code path convenient -
        /// route it through ReadStoredPasswordHash - and do NOT open the credential-read scope around a
        /// controller, hook, job, import or bulk user listing.
        /// </para>
        /// <para>
        /// Keyed on the EXISTING Encrypted flag only. Blanket field-permission enforcement across every field
        /// type and every projection is out of scope: an empty read permission is treated as denial by the
        /// presentation layer, so a blanket port would hide fields wholesale. The residual general gap is
        /// recorded in docs/security/risk-register.md rather than fixed here.
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

				return date;
			}

			else if (field is EmailField)
				return value as string;
			else if (field is FileField)
				//Projects the stored relative path verbatim; composing a URL from it is the caller's concern.
				return value as string;
			else if (field is ImageField)
				//Projects the stored relative path verbatim; composing a URL from it is the caller's concern.
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

						//SECURITY C-02 guard - DATA-INTEGRITY CRITICAL. A caller that read this record through a query
						//projection receives RecordManager.EncryptedFieldRedactedValue in place of the stored hash (see
						//RedactEncryptedFieldValue above). If that marker is round-tripped back into a write it must NEVER
						//be hashed: doing so would replace the account's real credential with a hash of the marker and
						//PERMANENTLY DESTROY it, because both MD5 and PBKDF2 are one-way - on a multi-record round-trip,
						//every affected account at once.
						//
						//null is returned rather than the marker, an empty string or a hash: it is this branch's own
						//established "do not write a real value here" signal - the IsNullOrWhiteSpace guard immediately
						//above already returns null - and it is what the record-write collectors in RecordManager treat as
						//"omit this field", leaving the persisted column byte-identical. That omission is the primary
						//control; this check is defence in depth so no future caller of this method can reintroduce the
						//defect. StringComparison.Ordinal is mandatory: a culture-sensitive or case-insensitive comparison
						//could either miss the marker (destroying a credential) or match a value that is not the marker.
						if (string.Equals(value as string, RecordManager.EncryptedFieldRedactedValue, StringComparison.Ordinal))
							return null;

						//SECURITY M-13 (CWE-521, OWASP A07:2021). Defence in depth behind the identical check in
						//RecordManager.ExtractFieldValue, which is the primary control because it is the seam the record
						//write path actually uses. This copy exists because this method is PUBLIC and STATIC: any caller can
						//reach the hashing branch without passing through RecordManager, and a policy enforced at only one of
						//two equivalent seams is one a single new call site silently removes. The reason text carries no
						//plaintext and no length (CWE-532).
						string passwordPolicyFailure = PasswordUtil.ValidatePasswordPolicy(value as string);
						if (passwordPolicyFailure != null)
							throw new ArgumentException("The supplied password does not meet the password policy: "
								+ passwordPolicyFailure + ".");

						//SECURITY C-03 (CWE-916 / CWE-759, OWASP A02:2021): salted, work-factored PBKDF2-HMAC-SHA-256.
						//See WebVella.Erp/Utilities/PasswordUtil.cs.
						return PasswordUtil.HashPassword(value as string);
					}
				}

				//SECURITY C-02 (CWE-200 exposure of sensitive information to an unauthorized actor, CWE-522
				//insufficiently protected credentials / OWASP A01:2021 + A02:2021). This is the READ fall-through of
				//the password branch, and the one projection seam the companion redactions in this class cannot
				//cover: this method is public static and is also called from WebVella.Erp/Eql/EqlCommand.cs, whose
				//own private ConvertJObjectToEntityRecord bypasses both RecordManager.Find and this class's
				//record-projection seams. The generic EQL surface authorises the ENTITY only, the Regular role
				//retains read access to the user entity and the surface is reachable over HTTP, so without this gate
				//an authenticated regular user could project user.password.
				//
				//The gate is CONDITIONAL because SecurityManager resolves credentials through that same EQL path and
				//needs the REAL stored hash to verify a login: it opens RecordManager's credential-read scope around
				//its own credential-resolution queries and nothing else, so verification sees the hash while every
				//other caller - EQL included - sees the marker. Deny-by-default, so a read path added in future is
				//redacted without opting in. Do NOT widen the scope to a controller, hook, job, bulk user listing or
				//import: that would reopen exactly the surface this closes.
				//
				//Encrypted is bool?, so the comparison is written "== true" on purpose: it treats null as "not
				//encrypted", which is the semantics every other PasswordField test in this file already has. Never
				//write a bare truthiness test or "!= false" here. A null value stays null, matching
				//RedactEncryptedFieldValue above, so no marker is invented where there was no value.
				//
				//This gate cannot affect a WRITE. Every write caller passes encryptPasswordFields true, and when that
				//flag is set on an encrypted field the branch above returns on all three of its paths, so execution
				//reaches this line only for a read or for a field that is not flagged encrypted.
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

                                //SECURITY H-09 residual (CWE-89 / OWASP A03:2021). The sort identifier here originates in the
                                //caller's URL arguments, so it is resolved against this entity's own field metadata and only the
                                //stored name is emitted, quoted. Field not found - skip, exactly as before.
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
                            //SECURITY H-09 residual (CWE-89 improper neutralization of special elements in an SQL command,
                            //OWASP A03:2021 Injection). s.FieldName arrives unresolved from the network - see
                            //RelatedFieldMultiSelect and GetQuickSearch in WebApiController - and ORDER BY is a fully
                            //expression-capable position, so it is resolved against entity metadata and emitted quoted. An
                            //unresolvable name is skipped, matching the JSON branch above and the distinct-select pre-pass.
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
                                    //SECURITY C-02 (CWE-200 / CWE-522, OWASP A01:2021 + A02:2021): non-relational read projection
                                    //seam. See RedactEncryptedFieldValue for the full rationale. The redaction here is UNCONDITIONAL
                                    //and deliberately not subject to the credential-read scope that ExtractFieldValue's own gate
                                    //honours. The existing DBNull.Value-to-null normalisation still runs first, so an absent value
                                    //stays null rather than becoming a marker.
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

                        if (relationField.Relation.RelationType == EntityRelationType.OneToOne)
                        {
                            //when the relation is origin -> target entity
                            if (relationField.Relation.OriginEntityId == entity.Id)
                            {

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
                // The trailing "," and the newline AppendLine added must both go so FROM can follow the projection
                // list. The newline is removed by INSPECTING it rather than assuming its width: AppendLine emits
                // Environment.NewLine, one character on Linux and two on Windows, so a fixed count of 3 would remove
                // the closing double quote of the last alias on Linux and PostgreSQL would refuse the statement with
                // 42601. Inspecting also cannot over-trim an empty builder.
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

                                //SECURITY H-09 residual (CWE-89 / OWASP A03:2021). As in the sibling sort construction earlier in
                                //this file: resolve the caller-supplied identifier against entity metadata and emit only the stored
                                //name, quoted. Field not found - skip, exactly as before.
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
                            //SECURITY H-09 residual (CWE-89, OWASP A03:2021 Injection). THE PRIMARY REPORTED SITE. s.FieldName
                            //arrives unresolved from the network and was concatenated here with no metadata check and no
                            //quoting whatsoever, so a value such as "id ASC, (SELECT ...) --" executed verbatim inside ORDER BY
                            //under the application's database role. It is now resolved against entity metadata and emitted
                            //quoted; an unresolvable name is skipped, matching the JSON branch above.
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
                    // CWE-400. Defence in depth behind the complexity bound enforced in GenerateWhereClause: an
                    // ADMISSIBLE pattern is still evaluated once per row, so on a large enough table a legitimate one can
                    // run for a long time. The regex ceiling still leaves ample room for a genuine filter over millions of
                    // rows; non-regex queries keep the ten-minute default exactly, so no existing report or export changes
                    // behaviour.
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

                    //SECURITY CONTRACT. skipClause drops this predicate entirely, so it must only ever be set for a
                    //clause whose ABSENCE is the caller's intent. Exactly one path sets it: ExtractQueryFieldJsonValue,
                    //when an optional query parameter is absent and its declared default is null. A security-sensitive
                    //operand must NEVER reach it - ExtractQueryFieldValue therefore refuses an encrypted credential
                    //filter rather than signalling skipClause, because omitting such a predicate broadens the result set
                    //instead of narrowing it. The relation branch below carries the same contract; keep both in step.
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

                    //SECURITY CONTRACT - the relation-predicate half of the contract documented at the direct-field
                    //branch above. A related entity's encrypted credential field is refused by ExtractQueryFieldValue
                    //rather than dropped here, so a filter across a relation cannot silently widen the join either.
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
                        // CWE-1333 inefficient regular expression complexity / CWE-400 uncontrolled resource consumption,
                        // OWASP A03/A05. The pattern is bound to a parameter below, so this is NOT an injection seam - it is
                        // a COST seam: PostgreSQL evaluates the pattern once per row, so a pattern whose own match cost is
                        // milliseconds becomes minutes across a table scan. Enforced here, where the predicate is generated,
                        // rather than in the calling controller, because there are two entry points and only one is an API
                        // action - the SDK administrative record filter passes a submitted value straight to
                        // EntityQuery.QueryRegex, so a caller-side check alone would leave that path unbounded. Fails hard by
                        // design; the callers' own catch turns it into a generic, non-disclosing failure.
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

						//SECURITY H-09 residual (CWE-89 improper neutralization of special elements used in an SQL command,
						//OWASP A03:2021 Injection). The text-search configuration was written into the statement as SQL
						//TEXT inside hand-written single quotes at both positions below, and QueryObject.FtsLanguage is
						//caller-supplied - EntityQuery.QueryFTS accepts it as a public string parameter - so a value
						//carrying a quote closed that literal and continued the statement.
						//The value is now BOUND ONCE and cast at each use. A text-search configuration is a first-class type
						//in PostgreSQL, so a bound parameter cast to regconfig reaches exactly the same overloads the quoted
						//literal reached - to_tsvector(regconfig, text) and to_tsquery/plainto_tsquery(regconfig, text) -
						//and returns identical rows for every legitimate configuration name; a value naming no configuration
						//is refused by the database instead of being able to alter the statement. The parameter is created
						//ONLY when the statement will reference it, because Npgsql rejects a command carrying a parameter
						//its text never uses. The 'simple' branches still emit a compile-time literal, so the default path
						//is untouched.
						string ftsLanguageCast = null;
						if (!string.IsNullOrWhiteSpace(query.FtsLanguage))
						{
							string ftsLanguageParamName = paramName + "_ftscfg";
							parameters.Add(new NpgsqlParameter(ftsLanguageParamName, query.FtsLanguage));
							ftsLanguageCast = "CAST(" + ftsLanguageParamName + " AS regconfig)";
						}

						if (singleWord)
						{
							parameter.Value = parameter.Value + ":*"; //search for all lexemes starting with this word
							if (ftsLanguageCast == null)
								sql = sql + " to_tsvector( 'simple', " + completeFieldName + ") @@ to_tsquery( 'simple', " + paramName + ") ";
							else
								sql = sql + " to_tsvector( " + ftsLanguageCast + " , " + completeFieldName + ") @@ to_tsquery( " + ftsLanguageCast + " ," + paramName + ") ";

						}
						else
						{
							if (ftsLanguageCast == null)
								sql = sql + " to_tsvector( 'simple', " + completeFieldName + ") @@ plainto_tsquery( 'simple', " + paramName + ") ";
							else
								sql = sql + " to_tsvector( " + ftsLanguageCast + " , " + completeFieldName + ") @@ plainto_tsquery( " + ftsLanguageCast + " ," + paramName + ") ";
						}
						return;
					}
				case QueryType.RELATED:
                    {
                        //Not supported by this generator. The throw is deliberate: an unsupported predicate must fail
                        //loudly rather than be omitted, because omitting it would BROADEN the result set (see the
                        //skipClause contract above).
                        throw new NotImplementedException();
                    }
                case QueryType.NOTRELATED:
                    {
                        //Not supported by this generator, for the reason given on the RELATED case above.
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

        // SECURITY H-09 (CWE-89 SQL injection / OWASP A03:2021 Injection). Every value in this repository is
        // already bound as a parameter, but PostgreSQL cannot parameterise an IDENTIFIER, so the record table
        // name is necessarily concatenated into SQL text. This method is the single chokepoint through which
        // that name is built for the whole class - roughly sixty call sites reach SQL through it - so
        // validating here closes the identifier injection exposure for all of them at once.
        //
        // DbIdentifier.Validate is used rather than Quote deliberately. Validate returns the identifier
        // BYTE-FOR-BYTE unchanged once it matches the allow-list, and the returned value is not only dropped
        // into FROM and JOIN positions but also builds a textual column prefix (see entityTablePrefix in
        // GenerateWhereClause) and is embedded in REGULAR_FIELD_SELECT. Quoting would alter every one of
        // those strings for no security gain: the allow-list already rejects the double quote, upper case,
        // whitespace, semicolons and comment markers, so injection is impossible by construction.
        //
        // A rejected name throws DbException rather than being sanitised: silently repairing a hostile
        // identifier would leave the vulnerability open while making the finding read as closed.
        private string GetTableNameForEntity(string entityName)
        {
            return DbIdentifier.Validate(RECORD_COLLECTION_PREFIX + entityName);
        }

        /// <summary>
        /// Resolves one caller-supplied sort identifier against the queried entity's own field metadata and
        /// renders it as a qualified, quoted column reference fit for an ORDER BY position. Returns null when
        /// the identifier names no field of this entity, which the callers treat as "skip this sort term".
        /// </summary>
        /// <remarks>
        /// SECURITY H-09 residual (CWE-89 improper neutralization of special elements used in an SQL command,
        /// CWE-20 improper input validation / OWASP A03:2021 Injection).
        /// <para>
        /// Every VALUE here is already bound as a parameter, and both the FROM target and the SELECT list are
        /// already safe - the table name passes through the <see cref="GetTableNameForEntity(string)"/>
        /// allow-list chokepoint, and <see cref="ExtractQueryFieldsMeta(EntityQuery)"/> resolves every
        /// projected column against entity.Fields and THROWS on an unknown token. ORDER BY did neither: the
        /// sort identifier was concatenated exactly as supplied, with no metadata resolution and, at one of
        /// the two sites, no quoting at all - and it is reachable from the network as a bare query-string
        /// parameter (WebApiController's RelatedFieldMultiSelect takes "fieldName", GetQuickSearch takes
        /// "sortField"). ORDER BY is fully expression-capable in PostgreSQL, so this was arbitrary
        /// sub-SELECT execution under the application's own database role, not a sort-order nuisance.
        /// </para>
        /// <para>
        /// WHY RESOLUTION RATHER THAN ESCAPING, and why a shared helper: the identifier is compared for
        /// equality against the entity's declared field names and what reaches SQL is the NAME TAKEN FROM
        /// METADATA, never the caller's text. Escaping would still emit caller-controlled bytes. The same
        /// defect occurred at four sites across two methods, so one reviewable helper serves all four rather
        /// than four patches free to drift apart - the reasoning that also produced Database/DbIdentifier.cs.
        /// </para>
        /// <para>
        /// WHY SKIP RATHER THAN THROW on an unresolved name: it is the semantics this method's own callers
        /// already have - the JSON sort branch at both sites, and the distinct-select pre-pass in
        /// <see cref="Find(EntityQuery)"/>, already resolve against entity.Fields and "continue" when the
        /// lookup fails. Throwing would turn a request that previously returned unsorted rows into a server
        /// error, which the preservation requirement forbids, and nothing legitimate is lost: a
        /// relation-qualified sort name never resolved here either. Both callers already handle every term
        /// being skipped, appending "ORDER BY" only when at least one term survived.
        /// </para>
        /// <para>
        /// The emitted shape is bare validated table plus double-quoted column - rec_user."created_on" -
        /// byte-identical to what the SELECT list construction in <see cref="Find(EntityQuery)"/> writes by
        /// hand and to what the quoted sort site already emitted for a legitimate field. The table is left
        /// bare rather than quoted for the reason set out on <see cref="GetTableNameForEntity(string)"/>.
        /// Quoting is behaviour-preserving for the column because DbIdentifier's allow-list rejects upper
        /// case, so every accepted name is already lower case and folds to itself.
        /// </para>
        /// </remarks>
        /// <param name="entity">The entity being queried, and the sole authority on which names are valid.</param>
        /// <param name="fieldName">The caller-supplied sort identifier. Never trusted.</param>
        /// <returns>A qualified quoted column reference, or null when the name resolves to no field.</returns>
        /// <exception cref="DbException">
        /// Thrown only when a name that IS present in entity metadata fails the identifier allow-list, which
        /// would mean the stored metadata itself is unusable in SQL. A hard fault by design, never sanitised.
        /// </exception>
        private string BuildSortColumnReference(Entity entity, string fieldName)
        {
            // A null, empty or whitespace-only identifier names no field, so it is refused before any lookup or
            // concatenation. Defence in depth: both network-reachable callers reject a blank identifier before
            // constructing a QuerySortObject, and the branch selector in the loops above dereferences FieldName
            // ahead of this call.
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

            Entity entity = entMan.ReadEntity(query.EntityName).Object;
            if (entity == null)
                throw new Exception(string.Format("The entity '{0}' does not exists.", query.EntityName));

            //We check for wildcard symbol and if present include all fields of the queried entity. The wildcard
            //and explicit field names may be mixed, so more than one token is not an error.
            bool wildcardSelectionEnabled = tokens.Any(x => x == WILDCARD_SYMBOL);
            if (wildcardSelectionEnabled)
            {
                result.AddRange(entity.Fields);
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

                    //SECURITY C-03 (CWE-916 / CWE-759, OWASP A02:2021) and the structural consequence of closing it.
                    //This branch is NOT a write path: its return value becomes the NpgsqlParameter of a SQL WHERE-clause
                    //predicate, so hashing here produced "WHERE <table>.password = @param". An unsalted MD5 digest is
                    //deterministic, so that comparison used to work - which is precisely what made it a password
                    //confirmation ORACLE: any caller able to build a filter on the password field could confirm a guess
                    //by observing whether a row came back. A salted, work-factored hash differs on every invocation, so
                    //the predicate can never match and the value must not be bound.
                    //
                    //CWE-1284 (improper validation of a specified quantity) reached through OWASP A01:2021 Broken Access
                    //Control. Signalling skipClause here would be worse than refusing: BOTH GenerateWhereClause call
                    //sites honour skipClause by returning without emitting anything, so the entire predicate silently
                    //disappears and a caller that intended "return the single row whose password matches" receives EVERY
                    //row the remaining predicates allow. Omission is invisible and BROADENS the result set, so the query
                    //is REJECTED instead.
                    //
                    //Rejection rather than an always-false predicate: an always-false predicate would still answer, with
                    //an empty set indistinguishable from "no such credential" - the same confirmation oracle in a
                    //quieter form - and would hide the caller's mistake. A thrown exception is the shape every other
                    //invalid query in this method already takes, so the failure travels the platform's existing error
                    //path: RecordManager.Find catches it and returns Success = false with a generic message and no data.
                    //ValidationException rather than a bare Exception because this IS a validation failure of the
                    //submitted query.
                    //
                    //No functionality is lost: nothing in this repository queries by password value. SecurityManager's
                    //GetUser(email, password) - the only such query that ever existed - resolves by e-mail and verifies
                    //in application code through PasswordUtil.VerifyPassword. It also means the redaction marker can
                    //never reach a predicate, because the query is refused before any value is bound. The
                    //IsNullOrWhiteSpace guard above is deliberately left as it was, so a blank operand still contributes
                    //a NULL parameter rather than an error.
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
                //current_user exposes only the id, so the settings object carries no option to inspect.
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

