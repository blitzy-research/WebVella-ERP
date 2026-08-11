using Newtonsoft.Json;
using Npgsql;
using NpgsqlTypes;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Database.Models;

namespace WebVella.Erp.Database
{
	public class DbEntityRepository
	{
		internal const string RECORD_COLLECTION_PREFIX = "rec_";
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
		public DbEntityRepository(DbContext currentContext)
		{
			suppliedContext = currentContext;
		}

		public bool Create(DbEntity entity, Dictionary<string, Guid> sysldDictionary = null, bool createOnlyIdField = true)
		{
			try
			{
				using (DbConnection con = DbContext.Current.CreateConnection())
				{
					con.BeginTransaction();

					try
					{
						List<DbParameter> parameters = new List<DbParameter>();

						// SECURITY H-10. Serialize side; see the deserialize site below for the retained-type-handling
						// rationale. Attaching the binder here changes nothing that is stored: it overrides BindToType
						// only, so the $type strings written stay byte-identical.
						JsonSerializerSettings settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto, SerializationBinder = ErpSerializationBinder.Instance };

						DbParameter parameterId = new DbParameter();
						parameterId.Name = "id";
						parameterId.Value = entity.Id;
						parameterId.Type = NpgsqlDbType.Uuid;
						parameters.Add(parameterId);

						DbParameter parameterJson = new DbParameter();
						parameterJson.Name = "json";
						parameterJson.Value = JsonConvert.SerializeObject(entity, settings);
						parameterJson.Type = NpgsqlDbType.Json;
						parameters.Add(parameterJson);

						// SECURITY H-09 (CWE-89 SQL injection / OWASP A03:2021 Injection). Concatenated into the CREATE
						// TABLE and CREATE COLUMN statements below. Validate returns a conforming name unchanged, so the
						// emitted DDL is identical for legitimate entities.
						string tableName = DbIdentifier.Validate(RECORD_COLLECTION_PREFIX + entity.Name);

						DbRepository.CreateTable(tableName);
						foreach (var field in entity.Fields)
						{
							bool isPrimaryKey = field.Name.ToLowerInvariant() == "id";
							FieldType fieldType = field.GetFieldType();
							DbRepository.CreateColumn(tableName, field);
						}

						bool result = DbRepository.InsertRecord("entities", parameters);

						if (!result)
							throw new Exception("Entity record was not added!");

						if (entity.Id != SystemIds.UserEntityId && createOnlyIdField == false )
						{
							DbEntity userEntity = Read(SystemIds.UserEntityId);

							DbRelationRepository relRep = new DbRelationRepository(CurrentContext);

							string createdByRelationName = $"user_{entity.Name}_created_by";
							string modifiedByRelationName = $"user_{entity.Name}_modified_by";

							Guid createdByRelationId = Guid.NewGuid();
							if (sysldDictionary != null && sysldDictionary.ContainsKey(createdByRelationName))
								createdByRelationId = sysldDictionary[createdByRelationName];

							Guid modifiedByRelationId = Guid.NewGuid();
							if (sysldDictionary != null && sysldDictionary.ContainsKey(modifiedByRelationName))
								modifiedByRelationId = sysldDictionary[modifiedByRelationName];

							List<DbEntityRelation> relationList = relRep.Read();
							DbEntityRelation tempRel = relationList.FirstOrDefault(r => r.Name == createdByRelationName);
							if (tempRel != null)
							{
								createdByRelationId = tempRel.Id;
								relRep.Delete(createdByRelationId);
							}
							tempRel = relationList.FirstOrDefault(r => r.Name == modifiedByRelationName);
							if (tempRel != null)
							{
								modifiedByRelationId = tempRel.Id;
								relRep.Delete(modifiedByRelationId);
							}

							DbEntityRelation createdByRelation = new DbEntityRelation();
							createdByRelation.Id = createdByRelationId;
							createdByRelation.Name = createdByRelationName;
							createdByRelation.Label = $"user<-[1]:[m]->{entity.Name}.created_by";
							createdByRelation.RelationType = EntityRelationType.OneToMany;
							createdByRelation.OriginEntityId = SystemIds.UserEntityId;
							createdByRelation.OriginFieldId = userEntity.Fields.Single(f => f.Name == "id").Id;
							createdByRelation.TargetEntityId = entity.Id;
							createdByRelation.TargetFieldId = entity.Fields.Single(f => f.Name == "created_by").Id;
							{
								bool res = relRep.Create(createdByRelation);
								if (!res)
									throw new Exception("Creation of relation between User and Area entities failed!");
							}

							DbEntityRelation modifiedByRelation = new DbEntityRelation();
							modifiedByRelation.Id = modifiedByRelationId;
							modifiedByRelation.Name = modifiedByRelationName;
							modifiedByRelation.Label = $"user<-[1]:[m]->{entity.Name}.last_modified_by";
							modifiedByRelation.RelationType = EntityRelationType.OneToMany;
							modifiedByRelation.OriginEntityId = SystemIds.UserEntityId;
							modifiedByRelation.OriginFieldId = userEntity.Fields.Single(f => f.Name == "id").Id;
							modifiedByRelation.TargetEntityId = entity.Id;
							modifiedByRelation.TargetFieldId = entity.Fields.Single(f => f.Name == "last_modified_by").Id;
							{
								bool res = relRep.Create(modifiedByRelation);
								if (!res)
									throw new Exception($"Creation of relation between User and {entity.Name} entities failed!");
							}
						}
						con.CommitTransaction();

						return result;
					}
					catch (Exception)
					{
						con.RollbackTransaction();
					}
				}
				return false;
			}
			finally
			{
				Cache.Clear();
			}
		}

		public bool Update(DbEntity entity)
		{
			try
			{
				using (DbConnection con = DbContext.Current.CreateConnection())
				{
					NpgsqlCommand command = con.CreateCommand("UPDATE entities SET json=@json WHERE id=@id;");

					// SECURITY H-10. Serialize side; see the deserialize site below for the retained-type-handling
					// rationale. Attaching the binder here changes nothing that is stored: it overrides BindToType
					// only, so the $type strings written back stay byte-identical and a document written by this
					// build still loads on one running the previous build.
					JsonSerializerSettings settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto, SerializationBinder = ErpSerializationBinder.Instance };

					var parameter = command.CreateParameter() as NpgsqlParameter;
					parameter.ParameterName = "json";
					parameter.Value = JsonConvert.SerializeObject(entity, settings);
					parameter.NpgsqlDbType = NpgsqlDbType.Json;
					command.Parameters.Add(parameter);

					var parameterId = command.CreateParameter() as NpgsqlParameter;
					parameterId.ParameterName = "id";
					parameterId.Value = entity.Id;
					parameterId.NpgsqlDbType = NpgsqlDbType.Uuid;
					command.Parameters.Add(parameterId);


					return command.ExecuteNonQuery() > 0;
				}
			}
			finally
			{
				Cache.Clear();
			}
		}

		public DbEntity Read(Guid entityId)
		{
			List<DbEntity> entities = Read();
			return entities.FirstOrDefault(e => e.Id == entityId);
		}

		public DbEntity Read(string entityName)
		{
			List<DbEntity> entities = Read();
			return entities.FirstOrDefault(e => e.Name.ToLowerInvariant() == entityName.ToLowerInvariant());
		}

		public List<DbEntity> Read()
		{
			using (DbConnection con = CurrentContext.CreateConnection())
			{
				NpgsqlCommand command = con.CreateCommand("SELECT json FROM entities;");

				using (NpgsqlDataReader reader = command.ExecuteReader())
				{

					// SECURITY H-10 (CWE-502 deserialization of untrusted data / OWASP A08:2021). THE DESERIALIZE
					// SITE - the one place in this file where the binder actually fires. Left unconstrained, automatic
					// type handling resolves whatever $type token the entities table happens to contain into a CLR
					// type, a well-known remote-code-execution primitive. TypeNameHandling is RETAINED because the
					// stored documents cannot be read without it - every already-persisted entity carries
					// discriminators for the DbBaseField hierarchy in DbEntity.Fields, so removing it would stop
					// existing installations loading their own schema - and resolution is constrained instead to the
					// binder's enumerated first-party allow-list, which refuses anything outside it.
					JsonSerializerSettings settings = new JsonSerializerSettings
					{
						TypeNameHandling = TypeNameHandling.Auto,
						SerializationBinder = ErpSerializationBinder.Instance,
						NullValueHandling = NullValueHandling.Ignore,
						MissingMemberHandling = MissingMemberHandling.Ignore,
					};
					settings.Converters.Add(new DecimalToIntFormatConverter());
					List<DbEntity> entities = new List<DbEntity>();
					while (reader.Read())
					{
						DbEntity entity = JsonConvert.DeserializeObject<DbEntity>(reader[0].ToString(), settings);
						entities.Add(entity);
					}



					reader.Close();
					return entities;
				}
			}
		}

		public class DecimalToIntFormatConverter : JsonConverter
		{
			public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
			{
				throw new NotImplementedException();
			}

			public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
			{
				if (objectType == typeof(int))
				{
					return Convert.ToInt32(reader.Value.ToString());
				}

				return reader.Value;
			}

			public override bool CanConvert(Type objectType)
			{
				return objectType == typeof(int);
			}
		}


		public bool Delete(Guid entityId)
		{
			try
			{
				var relRepository = new DbRelationRepository(CurrentContext);
				var relations = relRepository.Read();
				var entityRelations = relations.Where(x => x.TargetEntityId == entityId || x.OriginEntityId == entityId);

				using (DbConnection con = DbContext.Current.CreateConnection())
				{
					try
					{
						con.BeginTransaction();

						foreach (var relation in entityRelations)
							relRepository.Delete(relation.Id);

						var entity = Read(entityId);

						// SECURITY H-09 (CWE-89 SQL injection / OWASP A03:2021 Injection). The entity id is bound as a
						// parameter, but PostgreSQL cannot parameterise the identifier in DROP TABLE. This is the
						// highest-consequence identifier sink in the platform: the statement is already a multi-statement
						// batch, so a name carrying a semicolon would append attacker-chosen DDL to a command running
						// inside a transaction with full schema rights. Quote validates against the allow-list and emits
						// double-quoted, throwing rather than sanitising; quoting is behaviour-preserving because the
						// allow-list admits only lower-case names, which fold to themselves.
						NpgsqlCommand command = con.CreateCommand("DELETE FROM entities WHERE id=@id; DROP TABLE " + DbIdentifier.Quote("rec_" + entity.Name));

						var parameterId = command.CreateParameter() as NpgsqlParameter;
						parameterId.ParameterName = "id";
						parameterId.Value = entityId;
						parameterId.NpgsqlDbType = NpgsqlDbType.Uuid;
						command.Parameters.Add(parameterId);

						var result = command.ExecuteNonQuery() > 0;

						con.CommitTransaction();

						return result;
					}
					catch
					{
						con.RollbackTransaction();
						throw;
					}
				}
			}
			finally
			{
				Cache.Clear();
			}
		}
	}
}
