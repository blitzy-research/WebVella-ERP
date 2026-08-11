using Newtonsoft.Json.Linq;
using Npgsql;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Database;
using WebVella.Erp.Hooks;

namespace WebVella.Erp.Eql
{
	public class EqlCommand
	{
		/// <summary>
		/// Eql text
		/// </summary>
		public string Text { get; set; }

		/// <summary>
		/// DbConnection object
		/// </summary>
		public DbConnection Connection { get; private set; }

		/// <summary>
		/// NpgsqlConnection object
		/// </summary>
		public NpgsqlConnection NpgConnection { get; private set; }

		/// <summary>
		/// NpgsqlConnection object
		/// </summary>
		public NpgsqlTransaction NpgTransaction { get; private set; }

		/// <summary>
		/// List of EqlParameters
		/// </summary>
		public List<EqlParameter> Parameters { get; private set; } = new List<EqlParameter>();

		/// <summary>
		/// EqlSettings object
		/// </summary>
		public EqlSettings Settings { get; private set; } = new EqlSettings();

		/// <summary>
		/// When true, values of fields carrying the Encrypted flag are projected verbatim instead of
		/// being replaced with <see cref="Api.RecordManager.EncryptedFieldRedactedValue"/>. Defaults
		/// to false, and only in-assembly credential resolution ever sets it.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - finding C-02 / F16, CWE-200 (exposure of sensitive information to an
		/// unauthorized actor) and CWE-522 (insufficiently protected credentials), OWASP A01:2021
		/// Broken Access Control + A02:2021 Cryptographic Failures.
		/// <para>
		/// WHAT WAS WRONG: redaction was applied at the two projection seams inside
		/// DbRecordRepository, but this class carries its OWN private ConvertJObjectToEntityRecord,
		/// which called ExtractFieldValue directly. The query language is a first-class, caller-facing
		/// API - reachable through the api/v3/en_US/eql endpoint, through every database data source,
		/// and through Razor page models that run EQL themselves - so
		/// <c>SELECT id,email,password FROM user</c> returned PBKDF2 hashes to any role holding
		/// entity-level read on the user entity. The entity permission check a few lines below is
		/// exactly that: an ENTITY check, with no notion of a field.
		/// </para>
		/// <para>
		/// WHY A FLAG RATHER THAN UNCONDITIONAL REDACTION: credential verification needs the real
		/// stored value, and in this platform it is obtained through this very class -
		/// SecurityManager resolves users with EQL, not with a repository call. Two call sites need
		/// the true value and no others: GetUser(Guid), whose result feeds both the SaveUser
		/// change-detection comparison and the version-4 migration that revokes the published
		/// default administrator credential, and GetUser(email, password), the platform's single
		/// credential-verification routine.
		/// </para>
		/// <para>
		/// WHY IT IS SAFE TO HAVE AN OPT-OUT AT ALL: the member is <c>internal</c> and
		/// <c>init</c>-only, so it can be set only by code compiled into WebVella.Erp and only in an
		/// object initializer at construction. It is deliberately NOT part of
		/// <see cref="EqlSettings"/>: those settings are public and are attached to stored data
		/// source definitions, so a flag living there could be requested by data rather than by code.
		/// Nothing deserializes an EqlCommand, no route model binds to one, and the default is the
		/// safe value - so every caller that does not explicitly opt in, including every caller
		/// outside this assembly, gets redaction and cannot ask for anything else.
		/// </para>
		/// </remarks>
		internal bool IncludeEncryptedFieldValues { get; init; }

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

		/// <summary>
		/// Creates command
		/// </summary>
		public EqlCommand(string text, params EqlParameter[] parameters)
		{
			Text = text;

			if (string.IsNullOrWhiteSpace(text))
				throw new ArgumentException("Command text cannot be null or empty.");

			NpgConnection = null;

			Connection = null;

			if (parameters != null && parameters.Length > 0)
				Parameters.AddRange(parameters);
		}

		/// <summary>
		/// Creates command
		/// </summary>
		public EqlCommand(string text, EqlSettings settings, params EqlParameter[] parameters) : this(text, parameters)
		{
			if (settings != null)
				Settings = settings;
		}

		/// <summary>
		/// Creates command
		/// </summary>
		public EqlCommand(string text, DbContext currentContext, params EqlParameter[] parameters) : this(text, parameters)
		{
			if (currentContext != null)
				suppliedContext = currentContext;
		}

		/// <summary>
		/// Creates command
		/// </summary>
		public EqlCommand(string text, DbContext currentContext, EqlSettings settings, params EqlParameter[] parameters) : this(text, currentContext, parameters)
		{
			if (settings != null)
				Settings = settings;
		}

		/// <summary>
		/// Creates command
		/// </summary>
		public EqlCommand(string text, List<EqlParameter> parameters = null, DbContext currentContext = null)
		{
			if (currentContext != null)
				suppliedContext = currentContext;
			Text = text;

			if (string.IsNullOrWhiteSpace(text))
				throw new ArgumentException("Command text cannot be null or empty.");

			NpgConnection = null;

			Connection = null;

			if (parameters != null)
				Parameters.AddRange(parameters);
		}

		public EqlCommand(string text, EqlSettings settings, List<EqlParameter> parameters = null, DbContext currentContext = null)
		: this(text, parameters, currentContext)
		{
			if (settings != null)
				Settings = settings;
		}

		/// <summary>
		/// Creates command
		/// </summary>
		/// <param name="text"></param>
		/// <param name="parameters"></param>
		public EqlCommand(string text, DbConnection connection, List<EqlParameter> parameters = null, DbContext currentContext = null)
		{
			if (currentContext != null)
				suppliedContext = currentContext;
			Text = text;

			if (string.IsNullOrWhiteSpace(text))
				throw new ArgumentException("Command text cannot be null or empty.");

			NpgConnection = null;

			Connection = connection;

			if (connection == null)
				throw new ArgumentNullException(nameof(connection));

			if (parameters != null)
				Parameters.AddRange(parameters);
		}

		/// <summary>
		/// Creates command
		/// </summary>
		/// <param name="text"></param>
		/// <param name="parameters"></param>
		public EqlCommand(string text, NpgsqlConnection connection, NpgsqlTransaction transaction = null, List<EqlParameter> parameters = null, DbContext currentContext = null)
		{
			if (currentContext != null)
				suppliedContext = currentContext;

			Text = text;

			if (string.IsNullOrWhiteSpace(text))
				throw new ArgumentException("Command text cannot be null or empty.");

			Connection = null;

			NpgConnection = connection;
			NpgTransaction = transaction;

			if (connection == null)
				throw new ArgumentNullException(nameof(connection));

			if (parameters != null)
				Parameters.AddRange(parameters);
		}

		/// <summary>
		/// Executes the command to database
		/// </summary>
		/// <returns></returns>
		public EntityRecordList Execute()
		{
			EqlBuilder eqlBuilder = new EqlBuilder(Text, CurrentContext, Settings);
			var eqlBuildResult = eqlBuilder.Build(Parameters);

			if (eqlBuildResult.Errors.Count > 0)
				throw new EqlException(eqlBuildResult.Errors);

			if (CurrentContext == null)
				throw new EqlException("DbContext need to be created.");

			EntityRecordList result = new EntityRecordList();

			DataTable dt = new DataTable();
			var npgsParameters = eqlBuildResult.Parameters.Select(x => x.ToNpgsqlParameter()).ToList();
			NpgsqlCommand command = null;

			bool hooksExists = RecordHookManager.ContainsAnyHooksForEntity(eqlBuildResult.FromEntity.Name);

			if (Connection != null)
				command = Connection.CreateCommand(eqlBuildResult.Sql, parameters: npgsParameters);
			else if (NpgConnection != null)
			{
				if (NpgTransaction != null)
					command = new NpgsqlCommand(eqlBuildResult.Sql, NpgConnection, NpgTransaction);
				else
					command = new NpgsqlCommand(eqlBuildResult.Sql, NpgConnection);
				command.Parameters.AddRange(npgsParameters.ToArray());
			}
			else
			{
				if (CurrentContext == null)
					throw new EqlException("DbContext needs to be initialized before using EqlCommand without supplying connection.");

				using (var connection = CurrentContext.CreateConnection())
				{
					command = connection.CreateCommand(eqlBuildResult.Sql, parameters: npgsParameters);
					command.CommandTimeout = 600;
					new NpgsqlDataAdapter(command).Fill(dt);

					foreach (DataRow dr in dt.Rows)
					{
						var jObj = JObject.Parse((string)dr[0]);
						if (result.TotalCount == 0 && jObj.ContainsKey("___total_count___"))
							result.TotalCount = int.Parse(((JValue)jObj["___total_count___"]).ToString());
						result.Add(ConvertJObjectToEntityRecord(jObj, eqlBuildResult.Meta));
					}

					if (hooksExists)
					{
						RecordHookManager.ExecutePostSearchRecordHooks(eqlBuildResult.FromEntity.Name, result);
					}

					return result;
				}
			}

			command.CommandTimeout = 600;
			new NpgsqlDataAdapter(command).Fill(dt);
			foreach (DataRow dr in dt.Rows)
			{
				var jObj = JObject.Parse((string)dr[0]);
				if (result.TotalCount == 0 && jObj.ContainsKey("___total_count___"))
					result.TotalCount = int.Parse(((JValue)jObj["___total_count___"]).ToString());
				result.Add(ConvertJObjectToEntityRecord(jObj, eqlBuildResult.Meta));
			}

			return result;
		}

		/// <summary>
		/// Gets field meta
		/// </summary>
		/// <returns></returns>
		public List<EqlFieldMeta> GetMeta()
		{
			EqlBuilder eqlBuilder = new EqlBuilder(Text, CurrentContext, Settings);
			var eqlBuildResult = eqlBuilder.Build(Parameters);

			if (eqlBuildResult.Errors.Count > 0)
				throw new EqlException(eqlBuildResult.Errors);

			return eqlBuildResult.Meta;
		}

		/// <summary>
		/// Gets sql
		/// </summary>
		/// <returns></returns>
		public string GetSql()
		{
			EqlBuilder eqlBuilder = new EqlBuilder(Text, CurrentContext, Settings);
			var eqlBuildResult = eqlBuilder.Build(Parameters);

			if (eqlBuildResult.Errors.Count > 0)
				throw new EqlException(eqlBuildResult.Errors);

			return eqlBuildResult.Sql;
		}

		private EntityRecord ConvertJObjectToEntityRecord(JObject jObj, List<EqlFieldMeta> fieldMeta)
		{
			EntityManager entMan = new EntityManager();
			EntityRecord record = new EntityRecord();
			foreach (EqlFieldMeta meta in fieldMeta)
			{
				if (meta.Field != null)
				{
					var entity = entMan.ReadEntity(meta.Field.EntityName).Object;
					if(entity == null)
						throw new Exception($"Entity '{meta.Field.Name}' not found");

					bool hasPermisstion = SecurityContext.HasEntityPermission(EntityPermission.Read, entity);
					if (!hasPermisstion)
						throw new Exception($"No access to entity '{meta.Field.EntityName}'");

					//THREAT ADDRESSED - finding C-02 / F16, CWE-200 and CWE-522, OWASP A01 + A02. See
					//IncludeEncryptedFieldValues above for why the flag exists and why it cannot be
					//requested from outside this assembly. Redaction wraps the extraction rather than
					//living inside ExtractFieldValue because that method is also on the WRITE path,
					//where it hashes the incoming value - redacting in there would persist the marker.
					//This single line covers relation projections too: the meta.Relation branch below
					//recurses into this same method, so a nested $relation.password is projected
					//through here as well, with the same flag value threaded down.
					var extractedValue = DbRecordRepository.ExtractFieldValue(jObj[meta.Field.Name], meta.Field);
					record[meta.Field.Name] = IncludeEncryptedFieldValues
						? extractedValue
						: DbRecordRepository.RedactEncryptedFieldValue(extractedValue, meta.Field);
				}
				else if (meta.Relation != null)
				{
					List<EntityRecord> relRecords = new List<EntityRecord>();
					JArray relatedJsonRecords = jObj[meta.Name].Value<JArray>();
					foreach (JObject relatedObj in relatedJsonRecords)
						relRecords.Add(ConvertJObjectToEntityRecord(relatedObj, meta.Children));

					record[meta.Name] = relRecords;
				}
			}
			return record;
		}
	}
}
