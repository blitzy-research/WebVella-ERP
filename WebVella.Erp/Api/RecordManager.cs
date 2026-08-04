using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Net;
using System.Threading;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Database;
using WebVella.Erp.Exceptions;
using WebVella.Erp.Hooks;
using WebVella.Erp.Utilities;

namespace WebVella.Erp.Api
{
	public class RecordManager
	{
		private const char RELATION_SEPARATOR = '.';
		private const char RELATION_NAME_RESULT_SEPARATOR = '$';

		// SECURITY C-02 (CWE-200 exposure of sensitive information to an unauthorized actor,
		// CWE-522 insufficiently protected credentials / OWASP A01:2021 Broken Access Control +
		// A02:2021 Cryptographic Failures): single source of truth for the value substituted for
		// encrypted-field content in read projections. WebVella.Erp.Database.DbRecordRepository
		// MUST reference this constant rather than repeat a literal, so the read-side marker and
		// the write-side guard cannot drift apart - a drift would let a round-tripped marker be
		// mistaken for a real password and hashed over the stored credential.
		//
		// The value is deliberately fixed rather than random (a per-request marker could not be
		// recognised by the write-side guard), is deliberately NOT 32 lower-case hexadecimal
		// characters (that shape is the legacy-MD5 discriminator in
		// WebVella.Erp/Utilities/PasswordUtil.cs and a collision would make the marker look like a
		// real stored hash), and is deliberately not a plausible password or a plausible modern
		// hash (a modern value is 84 Base64 characters beginning with "AQAAAAEA").
		//
		// internal, not public: WebVella.Erp.Database.DbRecordRepository is in this same assembly,
		// so no public API surface is added.
		//
		// Deliberately PascalCase per WebVella.Erp/.editorconfig lines 52-59; the two char consts
		// above predate that convention and are left untouched. Do not "correct" this to
		// SCREAMING_SNAKE to match them.
		internal const string EncryptedFieldRedactedValue = "__WV_REDACTED_a7f3c1e9__";

		// SECURITY C-02 (CWE-200 exposure of sensitive information to an unauthorized actor,
		// CWE-522 insufficiently protected credentials / OWASP A01:2021 Broken Access Control +
		// A02:2021 Cryptographic Failures): the ambient opt-in that separates the platform's one
		// internal credential-resolution path from every other record projection.
		//
		// THREAT ADDRESSED: redaction was applied at the manager and repository projection seams
		// only, because WebVella.Erp.Database.DbRecordRepository.ExtractFieldValue is ALSO reached
		// from WebVella.Erp/Eql/EqlCommand.cs, which WebVella.Erp/Api/SecurityManager.cs uses to
		// resolve a credential - and that path needs the REAL stored hash in order to verify a
		// login. The generic EQL surface was therefore left projecting the hash verbatim: it gates
		// on the ENTITY read permission only, the Regular role retains read access to the user
		// entity, and the surface is reachable over HTTP. An authenticated regular user could
		// consequently project user.password.
		//
		// Gating the repository's own read fall-through on this scope closes that surface while
		// leaving credential verification working, which is exactly what the acceptance criterion
		// "no API response and no query projection returns a password hash, for any role"
		// requires. It is the enabling change: without it, redaction inside the shared
		// ExtractFieldValue would hand SecurityManager the marker instead of the hash and every
		// login would fail.
		//
		// DELIBERATE DESIGN DECISIONS, each of which must survive future edits:
		//
		// 1. DENY BY DEFAULT. The flag is false unless a caller has explicitly opened the scope, so
		//    a read path added in future is redacted automatically instead of having to opt in.
		//    Never invert this.
		//
		// 2. AsyncLocal, not [ThreadStatic] and not an instance field. The value must flow across
		//    the awaits of one request without leaking into an unrelated request, and the consumer
		//    (ExtractFieldValue) is static so it has no instance to read from. The same primitive
		//    is already used for ambient security state in WebVella.Erp/Api/SecurityContext.cs, so
		//    no new pattern is introduced.
		//
		// 3. The scope is opened at the CREDENTIAL-RESOLUTION call sites in
		//    WebVella.Erp/Api/SecurityManager.cs and nowhere else. It must never be opened around
		//    a controller action, a hook, a job, a bulk user listing or an import: doing so would
		//    reopen exactly the surface this closes.
		//
		// 4. internal, not public. The only consumers are
		//    WebVella.Erp.Database.DbRecordRepository and WebVella.Erp.Api.SecurityManager, both in
		//    this assembly, so no public API surface is added and the "API contracts and interfaces
		//    are unchanged" preservation requirement holds.
		private static readonly AsyncLocal<bool> credentialReadScope = new AsyncLocal<bool>();

		/// <summary>
		/// True only while a scope opened by <see cref="OpenCredentialReadScope"/> is active on the
		/// current asynchronous flow, meaning the caller is the platform's internal
		/// credential-resolution path and needs the real stored hash rather than
		/// <see cref="EncryptedFieldRedactedValue"/>.
		/// </summary>
		internal static bool IsCredentialReadScopeOpen
		{
			get { return credentialReadScope.Value; }
		}

		/// <summary>
		/// Opens the internal credential-read scope for the current asynchronous flow. Disposing the
		/// returned value restores the previous state, so scopes nest safely and a repeated dispose
		/// is a no-op.
		/// </summary>
		/// <returns>A scope handle that must be disposed, normally through a <c>using</c>.</returns>
		internal static IDisposable OpenCredentialReadScope()
		{
			return new CredentialReadScope();
		}

		/// <summary>
		/// Scope handle for <see cref="OpenCredentialReadScope"/>. Restores the captured previous
		/// value rather than assigning false, so a nested scope cannot close an outer one.
		/// </summary>
		private sealed class CredentialReadScope : IDisposable
		{
			private readonly bool previousValue;
			private bool disposed;

			internal CredentialReadScope()
			{
				previousValue = credentialReadScope.Value;
				credentialReadScope.Value = true;
			}

			public void Dispose()
			{
				Dispose(true);
				GC.SuppressFinalize(this);
			}

			private void Dispose(bool disposing)
			{
				if (disposing && !disposed)
				{
					disposed = true;
					credentialReadScope.Value = previousValue;
				}
			}
		}

		private EntityManager entityManager;
		private EntityRelationManager entityRelationManager;
		private DbRelationRepository relationRepository;
		private List<EntityRelation> relations = null;
		private bool ignoreSecurity = false;
		private bool executeHooks = true;

		private DbContext suppliedContext = null;
		private DbContext CurrentContext
		{
			get
			{
				if (suppliedContext != null)
					return suppliedContext;
				else
					return DbContext.Current;
			}
		}


		public RecordManager(DbContext currentContext = null, bool ignoreSecurity = false, bool executeHooks = true)
		{
			if (currentContext != null)
				suppliedContext = currentContext;
			entityManager = new EntityManager(CurrentContext);
			entityRelationManager = new EntityRelationManager(CurrentContext);
			relationRepository = CurrentContext.RelationRepository;
			this.ignoreSecurity = ignoreSecurity;
			this.executeHooks = executeHooks;
		}

		public QueryResponse CreateRelationManyToManyRecord(Guid relationId, Guid originValue, Guid targetValue)
		{
			QueryResponse response = new QueryResponse();
			response.Object = null;
			response.Success = true;
			response.Timestamp = DateTime.UtcNow;

			try
			{
				var relation = relationRepository.Read(relationId);

				if (relation == null)
					response.Errors.Add(new ErrorModel { Message = "Relation does not exists." });

				if (response.Errors.Count > 0)
				{
					response.Object = null;
					response.Success = false;
					response.Timestamp = DateTime.UtcNow;
					return response;
				}

				bool hooksExists = RecordHookManager.ContainsAnyHooksForRelation(relation.Name);
				if (hooksExists)
				{
					using (var connection = CurrentContext.CreateConnection())
					{
						try
						{
							connection.BeginTransaction();

							List<ErrorModel> errors = new List<ErrorModel>();
							RecordHookManager.ExecutePreCreateManyToManyRelationHook(relation.Name, originValue, targetValue, errors);
							if (errors.Count > 0)
							{
								connection.RollbackTransaction();
								response.Success = false;
								response.Object = null;
								response.Errors = errors;
								response.Timestamp = DateTime.UtcNow;
								return response;
							}

							relationRepository.CreateManyToManyRecord(relationId, originValue, targetValue);
							RecordHookManager.ExecutePostCreateManyToManyRelationHook(relation.Name, originValue, targetValue);

							connection.CommitTransaction();
							return response;
						}
						catch
						{
							connection.RollbackTransaction();
							throw;
						}
					}
				}
				else
				{
					relationRepository.CreateManyToManyRecord(relationId, originValue, targetValue);
					return response;
				}
			}
			catch (Exception e)
			{
				response.Success = false;
				response.Object = null;
				response.Timestamp = DateTime.UtcNow;

				if (ErpSettings.DevelopmentMode)
					response.Message = e.Message + e.StackTrace;
				else
					response.Message = "The entity relation record was not created. An internal error occurred!";

				return response;
			}
		}

		public QueryResponse RemoveRelationManyToManyRecord(Guid relationId, Guid? originValue, Guid? targetValue)
		{
			QueryResponse response = new QueryResponse();
			response.Object = null;
			response.Success = true;
			response.Timestamp = DateTime.UtcNow;

			try
			{
				var relation = relationRepository.Read(relationId);

				if (relation == null)
					response.Errors.Add(new ErrorModel { Message = "Relation does not exists." });

				if (response.Errors.Count > 0)
				{
					response.Object = null;
					response.Success = false;
					response.Timestamp = DateTime.UtcNow;
					return response;
				}


				bool hooksExists = RecordHookManager.ContainsAnyHooksForRelation(relation.Name);
				if (hooksExists)
				{
					using (var connection = CurrentContext.CreateConnection())
					{
						try
						{
							connection.BeginTransaction();

							List<ErrorModel> errors = new List<ErrorModel>();
							RecordHookManager.ExecutePreDeleteManyToManyRelationHook(relation.Name, originValue, targetValue, errors);
							if (errors.Count > 0)
							{
								connection.RollbackTransaction();
								response.Success = false;
								response.Object = null;
								response.Errors = errors;
								response.Timestamp = DateTime.UtcNow;
								return response;
							}

							relationRepository.DeleteManyToManyRecord(relationId, originValue, targetValue);
							RecordHookManager.ExecutePostDeleteManyToManyRelationHook(relation.Name, originValue, targetValue);

							connection.CommitTransaction();
							return response;
						}
						catch
						{
							connection.RollbackTransaction();
							throw;
						}
					}
				}
				else
				{
					relationRepository.DeleteManyToManyRecord(relationId, originValue, targetValue);
					return response;
				}
			}
			catch (Exception e)
			{
				response.Success = false;
				response.Object = null;
				response.Timestamp = DateTime.UtcNow;

				if (ErpSettings.DevelopmentMode)
					response.Message = e.Message + e.StackTrace;
				else
					response.Message = "The entity relation record was not created. An internal error occurred!";

				return response;
			}
		}

		// THREAT ADDRESSED - insecure direct object reference on a file, OWASP A01:2021 Broken Access Control,
		// CWE-639 (authorization bypass through a user-controlled key) with CWE-367 (time-of-check to
		// time-of-use) on the mutation that follows. Both the create and the update paths take the value of a
		// file or image field STRAIGHT FROM THE REQUEST and, when it points into the temporary staging
		// namespace, MOVE the file named by it into the record's folder - the update path with overwrite
		// enabled. Nothing established that the staged file belonged to the caller, so an authenticated caller
		// could name another user's pending upload and have it relocated under a record of their own: the
		// victim's file leaves the path their own client is waiting on, and its bytes become readable through
		// the attacker's record.
		//
		// Both halves of the required control live here so the two call sites cannot drift apart:
		//   NAMESPACE. The source must be inside the staging namespace, tested with the trailing separator.
		//   The previous test omitted it, so "/tmpfoo/..." satisfied a check meant to mean "/tmp/...".
		//   OWNERSHIP. The staged file must be the caller's own. Deny-by-default at every uncertain edge: a
		//   missing file, an unresolvable principal and a staged file with no recorded owner all refuse for a
		//   non-administrator, matching the rule the file move, delete and publication paths apply.
		//
		// The DESTINATION needs no ownership test of its own, and that is a structural guarantee rather than an
		// omission: the caller never supplies it. It is composed here from the entity name and the record's own
		// identifier, and the only caller-influenced part is the trailing file name, which is the LAST segment
		// of the source path and therefore cannot contain a separator or a relative segment. The destination is
		// consequently always inside the folder of the record whose create or update permission has already
		// been checked, so it can never name another record's - or another user's - file.
		//
		// The returned identifier is what makes the authorization atomic with the write: the caller passes it to
		// DbFileRepository.Move as the expected source row, and the repository applies the move only while that
		// row is still the one at that path. A concurrent request that substitutes a different file behind the
		// authorized path is refused by the database rather than moved under an authorization never granted for
		// it.
		//
		// ignoreSecurity is honoured because it is this platform's own marker for a trusted system operation -
		// background jobs, provisioning and internal hooks construct RecordManager with it - so an internal
		// write is not made to fail an ownership test that has no meaning outside a request.
		private Guid AuthorizeStagedFilePromotion(Field field, string sourcePath, DbFileRepository fsRepository)
		{
			var stagedFile = fsRepository.Find(sourcePath);

			if (!ignoreSecurity)
			{
				var currentUser = SecurityContext.CurrentUser;
				var isAuthorized = stagedFile != null
					&& currentUser != null
					&& (currentUser.IsAdmin || (stagedFile.CreatedBy.HasValue && stagedFile.CreatedBy.Value == currentUser.Id));

				if (!isAuthorized)
				{
					//ValidationException is this platform's caller-safe channel for a refused field value: the
					//Razor pages and the API actions surface its message and its per-field errors WITHOUT a
					//stack trace, and it is rethrown rather than swallowed by the record managers' own
					//handlers. The message names the field but never echoes the submitted path, so a refusal
					//cannot be used to confirm which staged paths exist.
					var validationException = new ValidationException();
					validationException.AddError(field.Name, "The file referenced by this field cannot be used.");
					throw validationException;
				}
			}
			else if (stagedFile == null)
			{
				//a trusted internal write still cannot move a file that is not there; failing here rather than
				//inside the repository keeps the error attributable to the field
				var validationException = new ValidationException();
				validationException.AddError(field.Name, "The file referenced by this field cannot be used.");
				throw validationException;
			}

			return stagedFile.Id;
		}

		//Staging namespace prefix, WITH the trailing separator - see AuthorizeStagedFilePromotion for why the
		//separator matters. Kept as a single expression so both file-field call sites test the same thing.
		private static string StagedFileNamespacePrefix
		{
			get { return DbFileRepository.FOLDER_SEPARATOR + DbFileRepository.TMP_FOLDER_NAME + DbFileRepository.FOLDER_SEPARATOR; }
		}

		public QueryResponse CreateRecord(string entityName, EntityRecord record)
		{
			if (string.IsNullOrWhiteSpace(entityName))
			{
				QueryResponse response = new QueryResponse
				{
					Success = false,
					Object = null,
					Timestamp = DateTime.UtcNow
				};
				response.Errors.Add(new ErrorModel { Message = "Invalid entity name." });
				return response;
			}

			Entity entity = GetEntity(entityName);
			if (entity == null)
			{
				QueryResponse response = new QueryResponse
				{
					Success = false,
					Object = null,
					Timestamp = DateTime.UtcNow
				};
				response.Errors.Add(new ErrorModel { Message = "Entity cannot be found." });
				return response;
			}

			return CreateRecord(entity, record);
		}

		public QueryResponse CreateRecord(Guid entityId, EntityRecord record)
		{
			Entity entity = GetEntity(entityId);
			if (entity == null)
			{
				QueryResponse response = new QueryResponse
				{
					Success = false,
					Object = null,
					Timestamp = DateTime.UtcNow
				};
				response.Errors.Add(new ErrorModel { Message = "Entity cannot be found." });
				return response;
			}

			return CreateRecord(entity, record);
		}

		public QueryResponse CreateRecord(Entity entity, EntityRecord record)
		{

			QueryResponse response = new QueryResponse();
			response.Object = null;
			response.Success = true;
			response.Timestamp = DateTime.UtcNow;
			var recRepo = CurrentContext.RecordRepository;

			using (DbConnection connection = CurrentContext.CreateConnection())
			{
				bool isTransactionActive = false;
				try
				{
					if (entity == null)
						response.Errors.Add(new ErrorModel { Message = "Invalid entity name." });

					if (record == null)
						response.Errors.Add(new ErrorModel { Message = "Invalid record. Cannot be null." });

					//SECURITY - finding F25, CWE-521. First of the two write boundaries at which a
					//password can be CHOSEN; see ValidatePasswordFieldPolicy. Placed here so the existing
					//early-return below reports it, before any permission check, hook or connection work.
					ValidatePasswordFieldPolicy(entity, record, response);

					if (response.Errors.Count > 0)
					{
						response.Object = null;
						response.Success = false;
						response.Timestamp = DateTime.UtcNow;
						return response;
					}

					if (!ignoreSecurity)
					{
						bool hasPermisstion = SecurityContext.HasEntityPermission(EntityPermission.Create, entity);
						if (!hasPermisstion)
						{
							response.StatusCode = HttpStatusCode.Forbidden;
							response.Success = false;
							response.Message = "Trying to create record in entity '" + entity.Name + "' with no create access.";
							response.Errors.Add(new ErrorModel { Message = "Access denied." });
							return response;
						}
					}

					bool hooksExists = RecordHookManager.ContainsAnyHooksForEntity(entity.Name);

					if (record.Properties.Any(p => p.Key.StartsWith("$")) || hooksExists)
					{
						connection.BeginTransaction();
						isTransactionActive = true;
					}

					if (hooksExists && executeHooks)
					{
						List<ErrorModel> errors = new List<ErrorModel>();
						RecordHookManager.ExecutePreCreateRecordHooks(entity.Name, record, errors);
						if (errors.Count > 0)
						{
							if (isTransactionActive)
								connection.RollbackTransaction();

							response.Success = false;
							response.Object = null;
							response.Errors = errors;
							response.Timestamp = DateTime.UtcNow;
							return response;
						}
					}

					Guid recordId = Guid.Empty;
					if (!record.Properties.ContainsKey("id"))
						recordId = Guid.NewGuid();
					else
					{
						//fixes issue with ID coming from webapi request 
						if (record["id"] is string)
							recordId = new Guid(record["id"] as string);
						else if (record["id"] is Guid)
							recordId = (Guid)record["id"];
						else
							throw new Exception("Invalid record id");

						if (recordId == Guid.Empty)
							throw new Exception("Guid.Empty value cannot be used as valid value for record id.");
					}


					List<KeyValuePair<string, object>> storageRecordData = new List<KeyValuePair<string, object>>();
					List<dynamic> oneToOneRecordData = new List<dynamic>();
					List<dynamic> oneToManyRecordData = new List<dynamic>();
					List<dynamic> manyToManyRecordData = new List<dynamic>();

					Dictionary<string, EntityRecord> fieldsFromRelationList = new Dictionary<string, EntityRecord>();
					Dictionary<string, EntityRecord> relationFieldMetaList = new Dictionary<string, EntityRecord>();

					var relations = GetRelations();

					foreach (var pair in record.GetProperties())
					{
						try
						{
							if (pair.Key == null)
								continue;

							if (pair.Key.Contains(RELATION_SEPARATOR))
							{
								var relationData = pair.Key.Split(RELATION_SEPARATOR).Select(x => x.Trim()).Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
								if (relationData.Count > 2)
									throw new Exception(string.Format("The specified field name '{0}' is incorrect. Only first level relation can be specified.", pair.Key));

								string relationName = relationData[0];
								string relationFieldName = relationData[1];
								string direction = "origin-target";

								if (string.IsNullOrWhiteSpace(relationName) || relationName == "$" || relationName == "$$")
									throw new Exception(string.Format("Invalid relation '{0}'. The relation name is not specified.", pair.Key));
								else if (!relationName.StartsWith("$"))
									throw new Exception(string.Format("Invalid relation '{0}'. The relation name is not correct.", pair.Key));
								else
									relationName = relationName.Substring(1);

								//check for target priority mark $$
								if (relationName.StartsWith("$"))
								{
									direction = "target-origin";
									relationName = relationName.Substring(1);
								}

								if (string.IsNullOrWhiteSpace(relationFieldName))
									throw new Exception(string.Format("Invalid relation '{0}'. The relation field name is not specified.", pair.Key));

								var relation = relations.SingleOrDefault(x => x.Name == relationName);
								if (relation == null)
									throw new Exception(string.Format("Invalid relation '{0}'. The relation does not exist.", pair.Key));

								if (relation.TargetEntityId != entity.Id && relation.OriginEntityId != entity.Id)
									throw new Exception(string.Format("Invalid relation '{0}'. The relation field belongs to entity that does not relate to current entity.", pair.Key));

								Entity relationEntity = null;
								Field relationField = null;
								Field realtionSearchField;
								Field field = null;

								if (relation.OriginEntityId == relation.TargetEntityId)
								{
									if (direction == "origin-target")
									{
										relationEntity = entity;
										relationField = relationEntity.Fields.FirstOrDefault(f => f.Id == relation.TargetFieldId);
										realtionSearchField = relationEntity.Fields.FirstOrDefault(f => f.Name == relationFieldName);
										field = entity.Fields.FirstOrDefault(f => f.Id == relation.OriginFieldId);
									}
									else
									{
										relationEntity = entity;
										relationField = relationEntity.Fields.FirstOrDefault(f => f.Id == relation.OriginFieldId);
										realtionSearchField = relationEntity.Fields.FirstOrDefault(f => f.Name == relationFieldName);
										field = entity.Fields.FirstOrDefault(f => f.Id == relation.TargetFieldId);
									}
								}
								else if (relation.OriginEntityId == entity.Id)
								{
									//direction doesn't matter
									relationEntity = GetEntity(relation.TargetEntityId);
									relationField = relationEntity.Fields.FirstOrDefault(f => f.Id == relation.TargetFieldId);
									realtionSearchField = relationEntity.Fields.FirstOrDefault(f => f.Name == relationFieldName);
									field = entity.Fields.FirstOrDefault(f => f.Id == relation.OriginFieldId);
								}
								else
								{
									//direction doesn't matter
									relationEntity = GetEntity(relation.OriginEntityId);
									relationField = relationEntity.Fields.FirstOrDefault(f => f.Id == relation.OriginFieldId);
									realtionSearchField = relationEntity.Fields.FirstOrDefault(f => f.Name == relationFieldName);
									field = entity.Fields.FirstOrDefault(f => f.Id == relation.TargetFieldId);
								}

								if (realtionSearchField == null)
									throw new Exception(string.Format("Invalid relation '{0}'. Field does not exist.", pair.Key));

								if (realtionSearchField.GetFieldType() == FieldType.MultiSelectField)
									throw new Exception(string.Format("Invalid relation '{0}'. Fields from Multiselect type can't be used as relation fields.", pair.Key));

								if (relation.RelationType == EntityRelationType.OneToOne &&
									((relation.TargetEntityId == entity.Id && field.Name == "id") || (relation.OriginEntityId == entity.Id && relationField.Name == "id")))
									throw new Exception(string.Format("Invalid relation '{0}'. Can't use relations when relation field is id field.", pair.Key));


								QueryObject filter = null;
								if ((relation.RelationType == EntityRelationType.OneToMany && relation.OriginEntityId == relation.TargetEntityId && direction == "origin-target") ||
									(relation.RelationType == EntityRelationType.OneToMany && relation.OriginEntityId != relation.TargetEntityId && relation.OriginEntityId == entity.Id) ||
									relation.RelationType == EntityRelationType.ManyToMany)
								{
									//expect array of values
									if (!record.Properties.ContainsKey(field.Name) || record[field.Name] == null)
										throw new Exception(string.Format("Invalid relation '{0}'. Relation field does not exist into input record data or its value is null.", pair.Key));

									List<string> values = new List<string>();
									if (pair.Value is JArray)
										values = ((JArray)pair.Value).Select(x => ((JToken)x).Value<string>()).ToList<string>();
									else if (pair.Value is List<Guid>)
										values = ((List<Guid>)pair.Value).Select(x => ((Guid)x).ToString()).ToList<string>();
									else if (pair.Value is List<object>)
										values = ((List<object>)pair.Value).Select(x => ((object)x).ToString()).ToList<string>();
									else if (pair.Value is List<string>)
										values = (List<string>)pair.Value;
									else if (pair.Value != null)
										values.Add(pair.Value.ToString());

									if (values.Count < 1)
										continue;

									List<QueryObject> queries = new List<QueryObject>();
									foreach (var val in values)
									{
										queries.Add(EntityQuery.QueryEQ(realtionSearchField.Name, val));
									}

									filter = EntityQuery.QueryOR(queries.ToArray());
								}
								else if ((relation.RelationType == EntityRelationType.OneToMany && relation.OriginEntityId == relation.TargetEntityId && direction == "target-origin") ||
									(relation.RelationType == EntityRelationType.OneToMany && relation.OriginEntityId != relation.TargetEntityId && relation.OriginEntityId != entity.Id))
								{
									List<string> values = new List<string>();
									if (pair.Value is JArray)
									{
										values = ((JArray)pair.Value).Select(x => ((JToken)x).Value<string>()).ToList<string>();
										if (values.Count > 0)
										{
											var newPair = new KeyValuePair<string, object>(pair.Key, values[0]);
											filter = EntityQuery.QueryEQ(realtionSearchField.Name, ExtractFieldValue(newPair, realtionSearchField, true));
										}
										else
										{
											throw new Exception("Array has not elements");
										}
									}
									else if (pair.Value is List<Guid>)
									{
										values = ((List<Guid>)pair.Value).Select(x => x.ToString()).ToList();
										if (values.Count > 0)
										{
											var newPair = new KeyValuePair<string, object>(pair.Key, values[0]);
											filter = EntityQuery.QueryEQ(realtionSearchField.Name, ExtractFieldValue(newPair, realtionSearchField, true));
										}
										else
										{
											throw new Exception("Array has not elements");
										}
									}
									else
									{
										filter = EntityQuery.QueryEQ(realtionSearchField.Name, ExtractFieldValue(pair, realtionSearchField, true));
									}
								}
								else
								{
									filter = EntityQuery.QueryEQ(realtionSearchField.Name, ExtractFieldValue(pair, realtionSearchField, true));
								}

								EntityRecord relationFieldMeta = new EntityRecord();
								relationFieldMeta["key"] = pair.Key;
								relationFieldMeta["direction"] = direction;
								relationFieldMeta["relationName"] = relationName;
								relationFieldMeta["relationEntity"] = relationEntity;
								relationFieldMeta["relationField"] = relationField;
								relationFieldMeta["realtionSearchField"] = realtionSearchField;
								relationFieldMeta["field"] = field;
								relationFieldMetaList[pair.Key] = relationFieldMeta;

								EntityRecord fieldsFromRelation = new EntityRecord();

								if (fieldsFromRelationList.Any(r => r.Key == relation.Name))
								{
									fieldsFromRelation = fieldsFromRelationList[relationName];
								}
								else
								{
									fieldsFromRelation["queries"] = new List<QueryObject>();
									fieldsFromRelation["direction"] = direction;
									fieldsFromRelation["relationEntityName"] = relationEntity.Name;
								}

								((List<QueryObject>)fieldsFromRelation["queries"]).Add(filter);
								fieldsFromRelationList[relationName] = fieldsFromRelation;
							}
						}
						catch (Exception ex)
						{
							if (pair.Key != null)
								throw new Exception("Error during processing value for field: '" + pair.Key + "'. Invalid value: '" + pair.Value + "'", ex);
						}
					}

					foreach (var fieldsFromRelation in fieldsFromRelationList)
					{
						EntityRecord fieldsFromRelationValue = (EntityRecord)fieldsFromRelation.Value;
						List<QueryObject> queries = (List<QueryObject>)fieldsFromRelationValue["queries"];
						string direction = (string)fieldsFromRelationValue["direction"];
						string relationEntityName = (string)fieldsFromRelationValue["relationEntityName"];
						QueryObject filter = EntityQuery.QueryAND(queries.ToArray());

						var relation = relations.SingleOrDefault(r => r.Name == fieldsFromRelation.Key);

						//get related records
						QueryResponse relatedRecordResponse = Find(new EntityQuery(relationEntityName, "*", filter, null, null, null));

						if (!relatedRecordResponse.Success || relatedRecordResponse.Object.Data.Count < 1)
						{
							throw new Exception(string.Format("Invalid relation '{0}'. The relation record does not exist.", relationEntityName));
						}
						else if (relatedRecordResponse.Object.Data.Count > 1 && ((relation.RelationType == EntityRelationType.OneToMany && relation.OriginEntityId == relation.TargetEntityId && direction == "target-origin") ||
							(relation.RelationType == EntityRelationType.OneToMany && relation.OriginEntityId != relation.TargetEntityId && relation.TargetEntityId == entity.Id) ||
							relation.RelationType == EntityRelationType.OneToOne))
						{
							//there can be no more than 1 records
							throw new Exception(string.Format("Invalid relation '{0}'. There are multiple relation records matching this value.", relationEntityName));
						}

						((EntityRecord)fieldsFromRelationList[fieldsFromRelation.Key])["relatedRecordResponse"] = relatedRecordResponse;
					}
					List<Tuple<Field, string>> fileFields = new List<Tuple<Field, string>>();
					foreach (var pair in record.GetProperties())
					{
						try
						{
							if (pair.Key == null)
								continue;

							if (pair.Key.Contains(RELATION_SEPARATOR))
							{
								EntityRecord relationFieldMeta = relationFieldMetaList.FirstOrDefault(f => f.Key == pair.Key).Value;

								if (relationFieldMeta == null)
									continue;

								string direction = (string)relationFieldMeta["direction"];
								string relationName = (string)relationFieldMeta["relationName"];
								Entity relationEntity = (Entity)relationFieldMeta["relationEntity"];
								Field relationField = (Field)relationFieldMeta["relationField"];
								Field realtionSearchField = (Field)relationFieldMeta["realtionSearchField"];
								Field field = (Field)relationFieldMeta["field"];

								var relation = relations.SingleOrDefault(r => r.Name == relationName);

								QueryResponse relatedRecordResponse = (QueryResponse)((EntityRecord)fieldsFromRelationList[relationName])["relatedRecordResponse"];

								var relatedRecords = relatedRecordResponse.Object.Data;
								List<Guid> relatedRecordValues = new List<Guid>();
								foreach (var relatedRecord in relatedRecords)
								{
									relatedRecordValues.Add((Guid)relatedRecord[relationField.Name]);
								}

								if (relation.RelationType == EntityRelationType.OneToOne &&
									((relation.OriginEntityId == relation.TargetEntityId && direction == "origin-target") || (relation.OriginEntityId != relation.TargetEntityId && relation.OriginEntityId == entity.Id)))
								{
									if (!record.Properties.ContainsKey(field.Name) || record[field.Name] == null)
										throw new Exception(string.Format("Invalid relation '{0}'. Relation field does not exist into input record data or its value is null.", pair.Key));

									var relatedRecord = relatedRecords[0];
									List<KeyValuePair<string, object>> relRecordData = new List<KeyValuePair<string, object>>();
									relRecordData.Add(new KeyValuePair<string, object>("id", relatedRecord["id"]));
									relRecordData.Add(new KeyValuePair<string, object>(relationField.Name, record[field.Name]));

									dynamic ooRelationData = new ExpandoObject();
									ooRelationData.RelationId = relation.Id;
									ooRelationData.RecordData = relRecordData;
									ooRelationData.EntityName = relationEntity.Name;

									oneToOneRecordData.Add(ooRelationData);
								}
								else if (relation.RelationType == EntityRelationType.OneToMany &&
									((relation.OriginEntityId == relation.TargetEntityId && direction == "origin-target") || (relation.OriginEntityId != relation.TargetEntityId && relation.OriginEntityId == entity.Id)))
								{
									if (!record.Properties.ContainsKey(field.Name) || record[field.Name] == null)
										throw new Exception(string.Format("Invalid relation '{0}'. Relation field does not exist into input record data or its value is null.", pair.Key));

									foreach (var data in relatedRecordResponse.Object.Data)
									{
										List<KeyValuePair<string, object>> relRecordData = new List<KeyValuePair<string, object>>();
										relRecordData.Add(new KeyValuePair<string, object>("id", data["id"]));
										relRecordData.Add(new KeyValuePair<string, object>(relationField.Name, record[field.Name]));

										dynamic omRelationData = new ExpandoObject();
										omRelationData.RelationId = relation.Id;
										omRelationData.RecordData = relRecordData;
										omRelationData.EntityName = relationEntity.Name;

										oneToManyRecordData.Add(omRelationData);
									}
								}
								else if (relation.RelationType == EntityRelationType.ManyToMany)
								{
									foreach (Guid relatedRecordIdValue in relatedRecordValues)
									{
										Guid relRecordId = Guid.Empty;
										if (record[field.Name] is string)
											relRecordId = new Guid(record[field.Name] as string);
										else if (record[field.Name] is Guid)
											relRecordId = (Guid)record[field.Name];
										else
											throw new Exception("Invalid record value for field: '" + pair.Key + "'. Invalid value: '" + pair.Value + "'");

										Guid originFieldValue = relRecordId;
										Guid targetFieldValue = relatedRecordIdValue;

										if (relation.TargetEntityId == entity.Id)
										{
											originFieldValue = relatedRecordIdValue;
											targetFieldValue = relRecordId;
										}

										dynamic mmRelationData = new ExpandoObject();
										mmRelationData.RelationId = relation.Id;
										mmRelationData.OriginFieldValue = originFieldValue;
										mmRelationData.TargetFieldValue = targetFieldValue;

										if (!manyToManyRecordData.Any(r => r.RelationId == mmRelationData.RelationId && r.OriginFieldValue == mmRelationData.OriginFieldValue && r.TargetFieldValue == mmRelationData.TargetFieldValue))
											manyToManyRecordData.Add(mmRelationData);
									}
								}
								else
								{
									if (!storageRecordData.Any(r => r.Key == field.Name))
										storageRecordData.Add(new KeyValuePair<string, object>(field.Name, relatedRecordValues[0]));
								}
							}
							else
							{
								//locate the field
								var field = entity.Fields.SingleOrDefault(x => x.Name == pair.Key);

								//THREAT ADDRESSED - finding C-02 guard (DATA-INTEGRITY CRITICAL), CWE-200
								//(exposure of sensitive information to an unauthorized actor) and CWE-522
								//(insufficiently protected credentials), OWASP A01:2021 Broken Access
								//Control + A02:2021 Cryptographic Failures. Companion of the identical
								//guard in the update collector below. A client that read a record through
								//Find(EntityQuery) receives EncryptedFieldRedactedValue in place of the
								//stored hash, so a create built by copying such a record would otherwise
								//carry the marker into the PasswordField branch of ExtractFieldValue. The
								//marker must never become a stored credential - hashing it would mint an
								//account whose password is the published marker string, and persisting the
								//null that the defence-in-depth check there returns would write an empty
								//credential column instead of the field's own default. The field is
								//therefore omitted from storageRecordData altogether and
								//SetRecordRequiredFieldsDefaultData below supplies the declared default,
								//which is exactly the outcome a create with no password supplied produces
								//today. Ordinal comparison only - never culture-sensitive, never
								//case-insensitive: a missed match would persist the marker and a false
								//match would silently drop a real password.
								if (field is PasswordField &&
									string.Equals(pair.Value as string, EncryptedFieldRedactedValue, StringComparison.Ordinal))
									continue;

								if (field is AutoNumberField) //Autonumber Value is always autogenerated, this ignored if provided
									continue;

								if (field is FileField || field is ImageField)
								{
									fileFields.Add(new Tuple<Field, string>(field, pair.Value as string));
								}
								else
								{
									if(field == null)
										throw new Exception("Error during processing value for field: '" + pair.Key + "'. Field not found.");

									if (field.Required && pair.Value == null)
										storageRecordData.Add(new KeyValuePair<string, object>(field.Name, field.GetFieldDefaultValue()));
									else
										storageRecordData.Add(new KeyValuePair<string, object>(field.Name, ExtractFieldValue(pair, field, true)));
								}
							}
						}
						catch (Exception ex)
						{
							if (pair.Key != null)
							{
								var field = entity.Fields.SingleOrDefault(x => x.Name == pair.Key);
								if( field == null )
									throw new Exception("Error during processing value for field: '" + pair.Key + "'. Field not found.");
								else
									//CWE-532 / CWE-209: a credential value must never be interpolated into a
									//message that is returned to the caller and written to system_log. See
									//DescribeRejectedFieldValue.
									//ArgumentException rather than the bare Exception this statement used to
									//raise: the value supplied for a field could not be processed, which is
									//precisely an invalid-argument condition, and the reserved base type carried
									//a CA2201 diagnostic onto a line this fix has to touch. Behaviour is
									//identical - the only handlers between here and the method's outer boundary
									//are catch (ValidationException) at :L1014 and catch (Exception e) at :L1021,
									//so this still lands in the same place with the same message. The sibling
									//throw above is deliberately left alone; it is not part of this fix.
									throw new ArgumentException("Error during processing value for field: '" + pair.Key + "'. Invalid value: '" + DescribeRejectedFieldValue(field, pair.Value) + "'", ex);
							}
						}
					}

					SetRecordRequiredFieldsDefaultData(entity, storageRecordData);



					foreach (var item in fileFields)
					{
						Field field = item.Item1;
						string path = item.Item2;
						if (!string.IsNullOrWhiteSpace(path) && path.StartsWith("/fs/"))
							path = path.Substring(3);

						if (!string.IsNullOrWhiteSpace(path) && path.StartsWith("fs/"))
							path = path.Substring(2);

						DbFileRepository fsRepository = new DbFileRepository();

						if (field.Required && string.IsNullOrWhiteSpace(path))
							storageRecordData.Add(new KeyValuePair<string, object>(field.Name, field.GetFieldDefaultValue()));
						else
						{
							if (!string.IsNullOrWhiteSpace(path) && path.StartsWith(StagedFileNamespacePrefix, StringComparison.Ordinal))
							{
								var fileName = path.Split(new[] { '/' }).Last();
								string source = path;
								string target = $"/{field.EntityName}/{record["id"]}/{fileName}";

								//see AuthorizeStagedFilePromotion - the staged file must be the caller's own,
								//and the identifier it returns pins the move to the row that was authorized
								var authorizedSourceId = AuthorizeStagedFilePromotion(field, source, fsRepository);
								var movedFile = fsRepository.Move(source, target, false, authorizedSourceId);
								if (movedFile == null)
								{
									//the authorized row is no longer the row at this path - a concurrent
									//request substituted it. Refuse rather than record a path whose content
									//was never authorized.
									var raceValidationException = new ValidationException();
									raceValidationException.AddError(field.Name, "The file referenced by this field cannot be used.");
									throw raceValidationException;
								}

								storageRecordData.Add(new KeyValuePair<string, object>(field.Name, target));
							}
							else
							{
								storageRecordData.Add(new KeyValuePair<string, object>(field.Name, path));
							}
						}
					}

					recRepo.Create(entity.Name, storageRecordData);

					var query = EntityQuery.QueryEQ("id", recordId);
					var entityQuery = new EntityQuery(entity.Name, "*", query);

					// when user create record, it is get returned ignoring create permissions
					bool oldIgnoreSecurity = ignoreSecurity;
					response = Find(entityQuery);
					ignoreSecurity = oldIgnoreSecurity;

					//if not created exit immediately
					if (!(response.Object != null && response.Object.Data != null && response.Object.Data.Count > 0))
					{
						if (isTransactionActive)
							connection.RollbackTransaction();

						response.Success = false;
						response.Object = null;
						response.Timestamp = DateTime.UtcNow;
						response.Message = "The entity record was not created. An internal error occurred!";
						return response;
					}

					foreach (var ooRelData in oneToOneRecordData)
					{
						bool ooHooksExists = RecordHookManager.ContainsAnyHooksForEntity(ooRelData.EntityName);

						EntityRecord ooRecord = new EntityRecord();
						if (ooHooksExists && executeHooks)
						{
							//move values from ooRelData.RecordData to entity record
							var data = (IEnumerable<KeyValuePair<string, object>>)ooRelData.RecordData;
							foreach (var obj in data)
								ooRecord[obj.Key] = obj.Value;

							List<ErrorModel> errors = new List<ErrorModel>();
							RecordHookManager.ExecutePreUpdateRecordHooks(ooRelData.EntityName, ooRecord, errors);
							if (errors.Count > 0)
							{
								if (isTransactionActive)
									connection.RollbackTransaction();

								response.Success = false;
								response.Object = null;
								response.Errors = errors;
								response.Timestamp = DateTime.UtcNow;
								return response;
							}
							//move values from entity record to ooRelData.RecordData, because they may be changed in pre hooks
							List<KeyValuePair<string, object>> recordData = new List<KeyValuePair<string, object>>();
							foreach (var property in ooRecord.Properties)
								recordData.Add(new KeyValuePair<string, object>(property.Key, property.Value));

							ooRelData.RecordData = recordData;
						}

						recRepo.Update(ooRelData.EntityName, ooRelData.RecordData);

						if (ooHooksExists && executeHooks)
							RecordHookManager.ExecutePostUpdateRecordHooks(ooRelData.EntityName, ooRecord);
					}

					foreach (var omRelData in oneToManyRecordData)
					{
						bool ooHooksExists = RecordHookManager.ContainsAnyHooksForEntity(omRelData.EntityName);

						EntityRecord ooRecord = new EntityRecord();
						if (ooHooksExists && executeHooks)
						{
							var data = (IEnumerable<KeyValuePair<string, object>>)omRelData.RecordData;
							foreach (var obj in data)
								ooRecord[obj.Key] = obj.Value;

							List<ErrorModel> errors = new List<ErrorModel>();
							RecordHookManager.ExecutePreUpdateRecordHooks(omRelData.EntityName, ooRecord, errors);
							if (errors.Count > 0)
							{
								if (isTransactionActive)
									connection.RollbackTransaction();

								response.Success = false;
								response.Object = null;
								response.Errors = errors;
								response.Timestamp = DateTime.UtcNow;
								return response;
							}

							//move values from entity record to ooRelData.RecordData, because they may be changed in pre hooks
							List<KeyValuePair<string, object>> recordData = new List<KeyValuePair<string, object>>();
							foreach (var property in ooRecord.Properties)
								recordData.Add(new KeyValuePair<string, object>(property.Key, property.Value));

							omRelData.RecordData = recordData;
						}



						recRepo.Update(omRelData.EntityName, omRelData.RecordData);

						if (ooHooksExists && executeHooks)
							RecordHookManager.ExecutePostUpdateRecordHooks(omRelData.EntityName, ooRecord);
					}

					//TODO implement hooks
					foreach (var mmRelData in manyToManyRecordData)
					{
						var mmResponse = CreateRelationManyToManyRecord(mmRelData.RelationId, mmRelData.OriginFieldValue, mmRelData.TargetFieldValue);

						if (!mmResponse.Success)
							throw new Exception(mmResponse.Message);
					}

					//execute hooks after create related records
					if (response.Object != null && response.Object.Data != null && response.Object.Data.Count > 0)
					{
						response.Message = "Record was created successfully";

						if (hooksExists && executeHooks)
							RecordHookManager.ExecutePostCreateRecordHooks(entity.Name, response.Object.Data[0]);
					}

					if (isTransactionActive)
						connection.CommitTransaction();

					return response;
				}
				catch (ValidationException)
				{
					if (isTransactionActive)
						connection.RollbackTransaction();

					throw;
				}
				catch (Exception e)
				{
					if (isTransactionActive)
						connection.RollbackTransaction();

					response.Success = false;
					response.Object = null;
					response.Timestamp = DateTime.UtcNow;

					if (ErpSettings.DevelopmentMode)
						response.Message = e.Message + e.StackTrace;
					else
						response.Message = "The entity record was not created. An internal error occurred!";

					return response;
				}
			}
		}

		public QueryResponse UpdateRecord(string entityName, EntityRecord record)
		{
			if (string.IsNullOrWhiteSpace(entityName))
			{
				QueryResponse response = new QueryResponse
				{
					Success = false,
					Object = null,
					Timestamp = DateTime.UtcNow
				};
				response.Errors.Add(new ErrorModel { Message = "Invalid entity name." });
				return response;
			}

			Entity entity = GetEntity(entityName);
			if (entity == null)
			{
				QueryResponse response = new QueryResponse
				{
					Success = false,
					Object = null,
					Timestamp = DateTime.UtcNow
				};
				response.Errors.Add(new ErrorModel { Message = "Entity cannot be found." });
				return response;
			}

			return UpdateRecord(entity, record);
		}

		public QueryResponse UpdateRecord(Guid entityId, EntityRecord record)
		{
			Entity entity = GetEntity(entityId);
			if (entity == null)
			{
				QueryResponse response = new QueryResponse
				{
					Success = false,
					Object = null,
					Timestamp = DateTime.UtcNow
				};
				response.Errors.Add(new ErrorModel { Message = "Entity cannot be found." });
				return response;
			}

			return UpdateRecord(entity, record);
		}

		public QueryResponse UpdateRecord(Entity entity, EntityRecord record)
		{

			QueryResponse response = new QueryResponse();
			response.Object = null;
			response.Success = true;
			response.Timestamp = DateTime.UtcNow;

			using (DbConnection connection = CurrentContext.CreateConnection())
			{
				bool isTransactionActive = false;

				try
				{
					if (entity == null)
						response.Errors.Add(new ErrorModel { Message = "Invalid entity name." });

					if (record == null)
						response.Errors.Add(new ErrorModel { Message = "Invalid record. Cannot be null." });
					else if (!record.Properties.ContainsKey("id"))
						response.Errors.Add(new ErrorModel { Message = "Invalid record. Missing ID field." });

					//SECURITY - finding F25, CWE-521. Second and last write boundary at which a password
					//can be CHOSEN; see ValidatePasswordFieldPolicy. Placed here so the existing
					//early-return below reports it, before any permission check, hook or connection work.
					ValidatePasswordFieldPolicy(entity, record, response);

					if (response.Errors.Count > 0)
					{
						response.Object = null;
						response.Success = false;
						response.Timestamp = DateTime.UtcNow;
						return response;
					}

					if (!ignoreSecurity)
					{
						bool hasPermisstion = SecurityContext.HasEntityPermission(EntityPermission.Update, entity);
						if (!hasPermisstion)
						{
							response.StatusCode = HttpStatusCode.Forbidden;
							response.Success = false;
							response.Message = "Trying to update record in entity '" + entity.Name + "'  with no update access.";
							response.Errors.Add(new ErrorModel { Message = "Access denied." });
							return response;
						}
					}

					//fixes issue with ID coming from webapi request 
					Guid recordId = Guid.Empty;
					if (record["id"] is string)
						recordId = new Guid(record["id"] as string);
					else if (record["id"] is Guid)
						recordId = (Guid)record["id"];
					else
						throw new Exception("Invalid record id");

					bool hooksExists = RecordHookManager.ContainsAnyHooksForEntity(entity.Name);

					if (record.Properties.Any(p => p.Key.StartsWith("$")) || hooksExists)
					{
						connection.BeginTransaction();
						isTransactionActive = true;
					}

					if (hooksExists && executeHooks)
					{
						List<ErrorModel> errors = new List<ErrorModel>();
						RecordHookManager.ExecutePreUpdateRecordHooks(entity.Name, record, errors);
						if (errors.Count > 0)
						{
							if (isTransactionActive)
								connection.RollbackTransaction();

							response.Success = false;
							response.Object = null;
							response.Errors = errors;
							response.Timestamp = DateTime.UtcNow;
							return response;
						}
					}

					QueryObject filterObj = EntityQuery.QueryEQ("id", recordId);
					var oldRecordResponse = Find(new EntityQuery(entity.Name, "*", filterObj, null, null, null));
					if (!oldRecordResponse.Success)
						throw new Exception(oldRecordResponse.Message);
					else if (oldRecordResponse.Object.Data.Count == 0)
					{
						throw new Exception("Record with such Id is not found");
					}
					var oldRecord = oldRecordResponse.Object.Data[0];

					List<KeyValuePair<string, object>> storageRecordData = new List<KeyValuePair<string, object>>();
					List<dynamic> oneToOneRecordData = new List<dynamic>();
					List<dynamic> oneToManyRecordData = new List<dynamic>();
					List<dynamic> manyToManyRecordData = new List<dynamic>();

					Dictionary<string, EntityRecord> fieldsFromRelationList = new Dictionary<string, EntityRecord>();
					Dictionary<string, EntityRecord> relationFieldMetaList = new Dictionary<string, EntityRecord>();

					foreach (var pair in record.GetProperties())
					{
						try
						{
							if (pair.Key == null)
								continue;

							if (pair.Key.Contains(RELATION_SEPARATOR))
							{
								var relations = GetRelations();

								var relationData = pair.Key.Split(RELATION_SEPARATOR).Select(x => x.Trim()).Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
								if (relationData.Count > 2)
									throw new Exception(string.Format("The specified field name '{0}' is incorrect. Only first level relation can be specified.", pair.Key));

								string relationName = relationData[0];
								string relationFieldName = relationData[1];
								string direction = "origin-target";

								if (string.IsNullOrWhiteSpace(relationName) || relationName == "$" || relationName == "$$")
									throw new Exception(string.Format("Invalid relation '{0}'. The relation name is not specified.", pair.Key));
								else if (!relationName.StartsWith("$"))
									throw new Exception(string.Format("Invalid relation '{0}'. The relation name is not correct.", pair.Key));
								else
									relationName = relationName.Substring(1);

								//check for target priority mark $$
								if (relationName.StartsWith("$"))
								{
									direction = "target-origin";
									relationName = relationName.Substring(1);
								}

								if (string.IsNullOrWhiteSpace(relationFieldName))
									throw new Exception(string.Format("Invalid relation '{0}'. The relation field name is not specified.", pair.Key));

								var relation = relations.SingleOrDefault(x => x.Name == relationName);
								if (relation == null)
									throw new Exception(string.Format("Invalid relation '{0}'. The relation does not exist.", pair.Key));

								if (relation.TargetEntityId != entity.Id && relation.OriginEntityId != entity.Id)
									throw new Exception(string.Format("Invalid relation '{0}'. The relation field belongs to entity that does not relate to current entity.", pair.Key));

								Entity relationEntity = null;
								Field relationField = null;
								Field realtionSearchField;
								Field field = null;

								if (relation.OriginEntityId == relation.TargetEntityId)
								{
									if (direction == "origin-target")
									{
										relationEntity = entity;
										relationField = relationEntity.Fields.FirstOrDefault(f => f.Id == relation.TargetFieldId);
										realtionSearchField = relationEntity.Fields.FirstOrDefault(f => f.Name == relationFieldName);
										field = entity.Fields.FirstOrDefault(f => f.Id == relation.OriginFieldId);
									}
									else
									{
										relationEntity = entity;
										relationField = relationEntity.Fields.FirstOrDefault(f => f.Id == relation.OriginFieldId);
										realtionSearchField = relationEntity.Fields.FirstOrDefault(f => f.Name == relationFieldName);
										field = entity.Fields.FirstOrDefault(f => f.Id == relation.TargetFieldId);
									}
								}
								else if (relation.OriginEntityId == entity.Id)
								{
									//direction doesn't matter
									relationEntity = GetEntity(relation.TargetEntityId);
									relationField = relationEntity.Fields.FirstOrDefault(f => f.Id == relation.TargetFieldId);
									realtionSearchField = relationEntity.Fields.FirstOrDefault(f => f.Name == relationFieldName);
									field = entity.Fields.FirstOrDefault(f => f.Id == relation.OriginFieldId);
								}
								else
								{
									//direction doesn't matter
									relationEntity = GetEntity(relation.OriginEntityId);
									relationField = relationEntity.Fields.FirstOrDefault(f => f.Id == relation.OriginFieldId);
									realtionSearchField = relationEntity.Fields.FirstOrDefault(f => f.Name == relationFieldName);
									field = entity.Fields.FirstOrDefault(f => f.Id == relation.TargetFieldId);
								}

								if (realtionSearchField == null)
									throw new Exception(string.Format("Invalid relation '{0}'. Field does not exist.", pair.Key));

								if (realtionSearchField.GetFieldType() == FieldType.MultiSelectField)
									throw new Exception(string.Format("Invalid relation '{0}'. Fields from Multiselect type can't be used as relation fields.", pair.Key));

								QueryObject filter = null;
								if ((relation.RelationType == EntityRelationType.OneToMany && relation.OriginEntityId == relation.TargetEntityId && direction == "origin-target") ||
									(relation.RelationType == EntityRelationType.OneToMany && relation.OriginEntityId != relation.TargetEntityId && relation.OriginEntityId == entity.Id) ||
									relation.RelationType == EntityRelationType.ManyToMany)
								{
									//expect array of values
									if (!record.Properties.ContainsKey(field.Name) || record[field.Name] == null)
										throw new Exception(string.Format("Invalid relation '{0}'. Relation field does not exist into input record data or its value is null.", pair.Key));

									List<string> values = new List<string>();
									if (pair.Value is JArray)
										values = ((JArray)pair.Value).Select(x => ((JToken)x).Value<string>()).ToList<string>();
									else if (pair.Value is List<object>)
										values = ((List<object>)pair.Value).Select(x => ((object)x).ToString()).ToList<string>();
									else if (pair.Value is List<Guid>)
										values = ((List<Guid>)pair.Value).Select(x => ((Guid)x).ToString()).ToList<string>();
									else if (pair.Value is List<string>)
										values = (List<string>)pair.Value;
									else if (pair.Value != null)
										values.Add(pair.Value.ToString());

									if (relation.RelationType == EntityRelationType.ManyToMany)
									{
										Guid? originFieldOldValue = (Guid)oldRecord[field.Name];
										Guid? targetFieldOldValue = null;
										if (relation.TargetEntityId == entity.Id)
										{
											originFieldOldValue = null;
											targetFieldOldValue = (Guid)oldRecord[field.Name];
										}

										var mmResponse = RemoveRelationManyToManyRecord(relation.Id, originFieldOldValue, targetFieldOldValue);

										if (!mmResponse.Success)
											throw new Exception(mmResponse.Message);
									}

									if (values.Count < 1)
										continue;

									List<QueryObject> queries = new List<QueryObject>();
									foreach (var val in values)
									{
										queries.Add(EntityQuery.QueryEQ(realtionSearchField.Name, val));
									}

									filter = EntityQuery.QueryOR(queries.ToArray());
								}
								else
								{
									filter = EntityQuery.QueryEQ(realtionSearchField.Name, ExtractFieldValue(pair, realtionSearchField, true));
								}

								EntityRecord relationFieldMeta = new EntityRecord();
								relationFieldMeta["key"] = pair.Key;
								relationFieldMeta["direction"] = direction;
								relationFieldMeta["relationName"] = relationName;
								relationFieldMeta["relationEntity"] = relationEntity;
								relationFieldMeta["relationField"] = relationField;
								relationFieldMeta["realtionSearchField"] = realtionSearchField;
								relationFieldMeta["field"] = field;
								relationFieldMetaList[pair.Key] = relationFieldMeta;

								EntityRecord fieldsFromRelation = new EntityRecord();

								if (fieldsFromRelationList.Any(r => r.Key == relation.Name))
								{
									fieldsFromRelation = fieldsFromRelationList[relationName];
								}
								else
								{
									fieldsFromRelation["queries"] = new List<QueryObject>();
									fieldsFromRelation["direction"] = direction;
									fieldsFromRelation["relationEntityName"] = relationEntity.Name;
								}

								((List<QueryObject>)fieldsFromRelation["queries"]).Add(filter);
								fieldsFromRelationList[relationName] = fieldsFromRelation;
							}
						}
						catch (Exception ex)
						{
							if (pair.Key != null)
								throw new Exception("Error during processing value for field: '" + pair.Key + "'. Invalid value: '" + pair.Value + "'", ex);
						}
					}

					foreach (var fieldsFromRelation in fieldsFromRelationList)
					{
						EntityRecord fieldsFromRelationValue = (EntityRecord)fieldsFromRelation.Value;
						List<QueryObject> queries = (List<QueryObject>)fieldsFromRelationValue["queries"];
						string direction = (string)fieldsFromRelationValue["direction"];
						string relationEntityName = (string)fieldsFromRelationValue["relationEntityName"];
						QueryObject filter = EntityQuery.QueryAND(queries.ToArray());

						var relation = relations.SingleOrDefault(r => r.Name == fieldsFromRelation.Key);

						//get related records
						QueryResponse relatedRecordResponse = Find(new EntityQuery(relationEntityName, "*", filter, null, null, null));

						if (!relatedRecordResponse.Success || relatedRecordResponse.Object.Data.Count < 1)
						{
							throw new Exception(string.Format("Invalid relation '{0}'. The relation record does not exist.", relationEntityName));
						}
						else if (relatedRecordResponse.Object.Data.Count > 1 && ((relation.RelationType == EntityRelationType.OneToMany && relation.OriginEntityId == relation.TargetEntityId && direction == "target-origin") ||
							(relation.RelationType == EntityRelationType.OneToMany && relation.OriginEntityId != relation.TargetEntityId && relation.TargetEntityId == entity.Id) ||
							relation.RelationType == EntityRelationType.OneToOne))
						{
							//there can be no more than 1 records
							throw new Exception(string.Format("Invalid relation '{0}'. There are multiple relation records matching this value.", relationEntityName));
						}

						((EntityRecord)fieldsFromRelationList[fieldsFromRelation.Key])["relatedRecordResponse"] = relatedRecordResponse;
					}
					List<Tuple<Field, string>> fileFields = new List<Tuple<Field, string>>();
					foreach (var pair in record.GetProperties())
					{
						try
						{
							if (pair.Key == null)
								continue;

							if (pair.Key.Contains(RELATION_SEPARATOR))
							{
								EntityRecord relationFieldMeta = relationFieldMetaList.FirstOrDefault(f => f.Key == pair.Key).Value;

								if (relationFieldMeta == null)
									continue;

								string direction = (string)relationFieldMeta["direction"];
								string relationName = (string)relationFieldMeta["relationName"];
								Entity relationEntity = (Entity)relationFieldMeta["relationEntity"];
								Field relationField = (Field)relationFieldMeta["relationField"];
								Field realtionSearchField = (Field)relationFieldMeta["realtionSearchField"];
								Field field = (Field)relationFieldMeta["field"];

								var relation = relations.SingleOrDefault(r => r.Name == relationName);

								QueryResponse relatedRecordResponse = (QueryResponse)((EntityRecord)fieldsFromRelationList[relationName])["relatedRecordResponse"];

								var relatedRecords = relatedRecordResponse.Object.Data;
								List<Guid> relatedRecordValues = new List<Guid>();
								foreach (var relatedRecord in relatedRecords)
								{
									relatedRecordValues.Add((Guid)relatedRecord[relationField.Name]);
								}

								if (relation.RelationType == EntityRelationType.OneToOne &&
									((relation.OriginEntityId == relation.TargetEntityId && direction == "origin-target") || relation.OriginEntityId == entity.Id))
								{
									if (!record.Properties.ContainsKey(field.Name) || record[field.Name] == null)
										throw new Exception(string.Format("Invalid relation '{0}'. Relation field does not exist into input record data or its value is null.", pair.Key));

									var relatedRecord = relatedRecords[0];
									List<KeyValuePair<string, object>> relRecordData = new List<KeyValuePair<string, object>>();
									relRecordData.Add(new KeyValuePair<string, object>("id", relatedRecord["id"]));
									relRecordData.Add(new KeyValuePair<string, object>(relationField.Name, record[field.Name]));

									dynamic ooRelationData = new ExpandoObject();
									ooRelationData.RelationId = relation.Id;
									ooRelationData.RecordData = relRecordData;
									ooRelationData.EntityName = relationEntity.Name;

									oneToOneRecordData.Add(ooRelationData);
								}
								else if (relation.RelationType == EntityRelationType.OneToMany &&
									((relation.OriginEntityId == relation.TargetEntityId && direction == "origin-target") || relation.OriginEntityId == entity.Id))
								{
									if (!record.Properties.ContainsKey(field.Name) || record[field.Name] == null)
										throw new Exception(string.Format("Invalid relation '{0}'. Relation field does not exist into input record data or its value is null.", pair.Key));

									foreach (var data in relatedRecordResponse.Object.Data)
									{
										List<KeyValuePair<string, object>> relRecordData = new List<KeyValuePair<string, object>>();
										relRecordData.Add(new KeyValuePair<string, object>("id", data["id"]));
										relRecordData.Add(new KeyValuePair<string, object>(relationField.Name, record[field.Name]));

										dynamic omRelationData = new ExpandoObject();
										omRelationData.RelationId = relation.Id;
										omRelationData.RecordData = relRecordData;
										omRelationData.EntityName = relationEntity.Name;

										oneToManyRecordData.Add(omRelationData);
									}
								}
								else if (relation.RelationType == EntityRelationType.ManyToMany)
								{
									foreach (Guid relatedRecordIdValue in relatedRecordValues)
									{
										Guid relRecordId = Guid.Empty;
										if (record[field.Name] is string)
											relRecordId = new Guid(record[field.Name] as string);
										else if (record[field.Name] is Guid)
											relRecordId = (Guid)record[field.Name];
										else
											throw new Exception("Invalid record value for field: '" + pair.Key + "'. Invalid value: '" + pair.Value + "'");

										Guid originFieldValue = relRecordId;
										Guid targetFieldValue = relatedRecordIdValue;

										if (relation.TargetEntityId == entity.Id)
										{
											originFieldValue = relatedRecordIdValue;
											targetFieldValue = relRecordId;
										}

										dynamic mmRelationData = new ExpandoObject();
										mmRelationData.RelationId = relation.Id;
										mmRelationData.OriginFieldValue = originFieldValue;
										mmRelationData.TargetFieldValue = targetFieldValue;

										if (!manyToManyRecordData.Any(r => r.RelationId == mmRelationData.RelationId && r.OriginFieldValue == mmRelationData.OriginFieldValue && r.TargetFieldValue == mmRelationData.TargetFieldValue))
											manyToManyRecordData.Add(mmRelationData);
									}
								}
								else
								{
									if (!storageRecordData.Any(r => r.Key == field.Name))
										storageRecordData.Add(new KeyValuePair<string, object>(field.Name, relatedRecordValues[0]));
								}
							}
							else
							{
								//locate the field
								var field = entity.Fields.SingleOrDefault(x => x.Name == pair.Key);

								if (field == null)
									continue;

								//THREAT ADDRESSED - finding C-02 guard (DATA-INTEGRITY CRITICAL), CWE-200
								//(exposure of sensitive information to an unauthorized actor) and CWE-522
								//(insufficiently protected credentials), OWASP A01:2021 Broken Access
								//Control + A02:2021 Cryptographic Failures. A client that read this record
								//through a query projection receives EncryptedFieldRedactedValue in place of
								//the stored hash - see DbRecordRepository.RedactEncryptedFieldValue. A
								//full-record round-trip update would otherwise reach the PasswordField
								//branch below and hash that marker, PERMANENTLY DESTROYING the credential,
								//because both MD5 and PBKDF2 are one-way. The marker is therefore skipped
								//exactly as a null value already is: the field is omitted from
								//storageRecordData altogether, so the persisted column is left
								//byte-identical. Skipping is required rather than returning null, because a
								//null reaching storage would itself wipe the column.
								if (field is PasswordField && (pair.Value == null ||
									string.Equals(pair.Value as string, EncryptedFieldRedactedValue, StringComparison.Ordinal)))
									continue;

								if (field is AutoNumberField) //always ignored as it is autogenerated
									continue;

								if (field is FileField || field is ImageField)
								{
									fileFields.Add(new Tuple<Field, string>(field, pair.Value as string));
								}
								else
								{
									if (!storageRecordData.Any(r => r.Key == field.Name))
										storageRecordData.Add(new KeyValuePair<string, object>(field.Name, ExtractFieldValue(pair, field, true)));
								}

							}
						}
						catch (Exception ex)
						{
							if (pair.Key != null)
								//CWE-532 / CWE-209: a credential value must never be interpolated into a
								//message that is returned to the caller and written to system_log. The field
								//is resolved here solely to make that decision; an unresolved name yields a
								//null field, which DescribeRejectedFieldValue treats as "not a password" and
								//so renders exactly as before.
								//ArgumentException rather than the bare Exception this statement used to raise,
								//for the reason given at the create-path twin above. The only handlers between
								//here and the method's outer boundary are catch (ValidationException) at :L1721
								//and catch (Exception e) at :L1728, so behaviour and message are unchanged.
								throw new ArgumentException("Error during processing value for field: '" + pair.Key + "'. Invalid value: '"
									+ DescribeRejectedFieldValue(entity.Fields.SingleOrDefault(x => x.Name == pair.Key), pair.Value) + "'", ex);
						}
					}

					var recRepo = CurrentContext.RecordRepository;



					DbFileRepository fsRepository = new DbFileRepository();
					foreach (var item in fileFields)
					{
						Field field = item.Item1;
						string path = item.Item2;
						var originalRecordResponse = Find(new EntityQuery(field.EntityName, "*", EntityQuery.QueryEQ("id", record["id"])));
						EntityRecord originalRecord = originalRecordResponse.Object.Data[0];
						var originalFieldData = originalRecord.GetProperties().First(f => f.Key == field.Name);

						if (string.IsNullOrWhiteSpace(path))
						{
							//delete file                            
							string pathToDelete = (string)originalFieldData.Value;
							if (!string.IsNullOrWhiteSpace(path))
								fsRepository.Delete(pathToDelete);

							storageRecordData.Add(new KeyValuePair<string, object>(field.Name, field.GetFieldDefaultValue()));
						}
						else
						{   //update file
							if (path.StartsWith("/fs/"))
								path = path.Substring(3);

							if (path.StartsWith("fs/"))
								path = path.Substring(2);

							if (path.StartsWith(StagedFileNamespacePrefix, StringComparison.Ordinal))
							{
								var fileName = path.Split(new[] { '/' }).Last();
								string source = path;
								string target = $"/{field.EntityName}/{record["id"]}/{fileName}";

								//see AuthorizeStagedFilePromotion. This is the more dangerous of the two call
								//sites, because the move below overwrites - so an unauthorized source would
								//both steal the staged file and destroy whatever already sat at the target.
								var authorizedSourceId = AuthorizeStagedFilePromotion(field, source, fsRepository);
								var movedFile = fsRepository.Move(source, target, true, authorizedSourceId);
								if (movedFile == null)
								{
									var raceValidationException = new ValidationException();
									raceValidationException.AddError(field.Name, "The file referenced by this field cannot be used.");
									throw raceValidationException;
								}

								storageRecordData.Add(new KeyValuePair<string, object>(field.Name, target));
							}
							else
							{
								storageRecordData.Add(new KeyValuePair<string, object>(field.Name, path));
							}
						}
					}

					recRepo.Update(entity.Name, storageRecordData);

					var query = EntityQuery.QueryEQ("id", recordId);
					var entityQuery = new EntityQuery(entity.Name, "*", query);

					response = Find(entityQuery);
					if (!(response.Object != null && response.Object.Data.Count > 0))
					{
						if (isTransactionActive)
							connection.RollbackTransaction();
						response.Success = false;
						response.Object = null;
						response.Timestamp = DateTime.UtcNow;
						response.Message = "The entity record was not update. An internal error occurred!";
						return response;
					}

					foreach (var ooRelData in oneToOneRecordData)
					{
						bool ooHooksExists = RecordHookManager.ContainsAnyHooksForEntity(ooRelData.EntityName);

						EntityRecord ooRecord = new EntityRecord();
						if (ooHooksExists && executeHooks)
						{
							var data = (IEnumerable<KeyValuePair<string, object>>)ooRelData.RecordData;
							foreach (var obj in data)
								ooRecord[obj.Key] = obj.Value;

							List<ErrorModel> errors = new List<ErrorModel>();
							RecordHookManager.ExecutePreUpdateRecordHooks(ooRelData.EntityName, ooRecord, errors);
							if (errors.Count > 0)
							{
								if (isTransactionActive)
									connection.RollbackTransaction();

								response.Success = false;
								response.Object = null;
								response.Errors = errors;
								response.Timestamp = DateTime.UtcNow;
								return response;
							}

							//move values from entity record to ooRelData.RecordData, because they may be changed in pre hooks
							List<KeyValuePair<string, object>> recordData = new List<KeyValuePair<string, object>>();
							foreach (var property in ooRecord.Properties)
								recordData.Add(new KeyValuePair<string, object>(property.Key, property.Value));

							ooRelData.RecordData = recordData;
						}


						recRepo.Update(ooRelData.EntityName, ooRelData.RecordData);

						if (ooHooksExists && executeHooks)
							RecordHookManager.ExecutePostUpdateRecordHooks(ooRelData.EntityName, ooRecord);
					}

					foreach (var omRelData in oneToManyRecordData)
					{
						bool ooHooksExists = RecordHookManager.ContainsAnyHooksForEntity(omRelData.EntityName);

						EntityRecord ooRecord = new EntityRecord();
						if (ooHooksExists && executeHooks)
						{
							var data = (IEnumerable<KeyValuePair<string, object>>)omRelData.RecordData;
							foreach (var obj in data)
								ooRecord[obj.Key] = obj.Value;

							List<ErrorModel> errors = new List<ErrorModel>();
							RecordHookManager.ExecutePreUpdateRecordHooks(omRelData.EntityName, ooRecord, errors);
							if (errors.Count > 0)
							{
								if (isTransactionActive)
									connection.RollbackTransaction();

								response.Success = false;
								response.Object = null;
								response.Errors = errors;
								response.Timestamp = DateTime.UtcNow;
								return response;
							}

							//move values from entity record to ooRelData.RecordData, because they may be changed in pre hooks
							List<KeyValuePair<string, object>> recordData = new List<KeyValuePair<string, object>>();
							foreach (var property in ooRecord.Properties)
								recordData.Add(new KeyValuePair<string, object>(property.Key, property.Value));

							omRelData.RecordData = recordData;
						}

						recRepo.Update(omRelData.EntityName, omRelData.RecordData);

						if (ooHooksExists && executeHooks)
							RecordHookManager.ExecutePostUpdateRecordHooks(omRelData.EntityName, ooRecord);
					}

					//TODO implement hooks
					foreach (var mmRelData in manyToManyRecordData)
					{
						var mmResponse = CreateRelationManyToManyRecord(mmRelData.RelationId, mmRelData.OriginFieldValue, mmRelData.TargetFieldValue);

						if (!mmResponse.Success)
							throw new Exception(mmResponse.Message);
					}

					//execute hooks after update related records
					if (response.Object != null && response.Object.Data.Count > 0)
					{
						response.Message = "Record was updated successfully";

						if (hooksExists && executeHooks)
							RecordHookManager.ExecutePostUpdateRecordHooks(entity.Name, response.Object.Data[0]);
					}

					if (isTransactionActive)
						connection.CommitTransaction();

					return response;
				}
				catch (ValidationException)
				{
					if (isTransactionActive)
						connection.RollbackTransaction();

					throw;
				}
				catch (Exception e)
				{
					if (isTransactionActive)
						connection.RollbackTransaction();
					response.Success = false;
					response.Object = null;
					response.Timestamp = DateTime.UtcNow;

					if (ErpSettings.DevelopmentMode)
						response.Message = e.Message + e.StackTrace;
					else
						response.Message = "The entity record was not update. An internal error occurred!";

					return response;
				}
			}
		}

		public QueryResponse DeleteRecord(string entityName, Guid id)
		{
			if (string.IsNullOrWhiteSpace(entityName))
			{
				QueryResponse response = new QueryResponse
				{
					Success = false,
					Object = null,
					Timestamp = DateTime.UtcNow
				};
				response.Errors.Add(new ErrorModel { Message = "Invalid entity name." });
				return response;
			}

			Entity entity = GetEntity(entityName);
			if (entity == null)
			{
				QueryResponse response = new QueryResponse
				{
					Success = false,
					Object = null,
					Timestamp = DateTime.UtcNow
				};
				response.Errors.Add(new ErrorModel { Message = "Entity cannot be found." });
				return response;
			}

			return DeleteRecord(entity, id);
		}

		public QueryResponse DeleteRecord(Guid entityId, Guid id)
		{
			Entity entity = GetEntity(entityId);
			if (entity == null)
			{
				QueryResponse response = new QueryResponse
				{
					Success = false,
					Object = null,
					Timestamp = DateTime.UtcNow
				};
				response.Errors.Add(new ErrorModel { Message = "Entity cannot be found." });
				return response;
			}

			return DeleteRecord(entity, id);
		}

		public QueryResponse DeleteRecord(Entity entity, Guid id)
		{

			QueryResponse response = new QueryResponse();
			response.Object = null;
			response.Success = true;
			response.Timestamp = DateTime.UtcNow;

			try
			{
				if (entity == null)
				{
					response.Errors.Add(new ErrorModel { Message = "Invalid entity name." });
					response.Success = false;
					return response;
				}


				if (!ignoreSecurity)
				{
					bool hasPermisstion = SecurityContext.HasEntityPermission(EntityPermission.Delete, entity);
					if (!hasPermisstion)
					{
						response.StatusCode = HttpStatusCode.Forbidden;
						response.Success = false;
						response.Message = "Trying to delete record in entity '" + entity.Name + "' with no delete access.";
						response.Errors.Add(new ErrorModel { Message = "Access denied." });
						return response;
					}
				}

				List<KeyValuePair<string, object>> storageRecordData = new List<KeyValuePair<string, object>>();

			
				var query = EntityQuery.QueryEQ("id", id);
				var entityQuery = new EntityQuery(entity.Name, "*", query);

				response = Find(entityQuery);
				if (response.Object != null && response.Object.Data.Count == 1)
				{
					bool hooksExists = RecordHookManager.ContainsAnyHooksForEntity(entity.Name);
					if (hooksExists && executeHooks)
					{
						List<ErrorModel> errors = new List<ErrorModel>();
						RecordHookManager.ExecutePreDeleteRecordHooks(entity.Name, response.Object.Data[0], errors);
						if (errors.Count > 0)
						{
							response.Message = errors[0].Message;
							response.Success = false;
							response.Object = null;
							response.Errors = errors;
							response.Timestamp = DateTime.UtcNow;
							return response;
						}
					}

					#region <--- check if entity has any file fields and delete files related to this record --->

					var entityObj = entityManager.ReadEntities().Object.Single(x => x.Name == entity.Name);
					var fileFields = entityObj.Fields.Where(x => x.GetFieldType() == FieldType.FileField).ToList();
					var record = response.Object.Data[0];

					var filesToDelete = new List<string>();
					foreach (var fileField in fileFields)
					{
						if (!string.IsNullOrWhiteSpace((string)record[fileField.Name]))
							filesToDelete.Add((string)record[fileField.Name]);
					}

					if (filesToDelete.Any())
					{
						var dbFileRep = new DbFileRepository();
						foreach (var filepath in filesToDelete)
							dbFileRep.Delete(filepath);
					} 

					#endregion

					CurrentContext.RecordRepository.Delete(entity.Name, id);

					if (hooksExists && executeHooks)
						RecordHookManager.ExecutePostDeleteRecordHooks(entity.Name, response.Object.Data[0]);
				}
				else
				{
					response.Success = false;
					response.Message = "Record was not found.";
					return response;
				}


				return response;
			}
			catch (Exception e)
			{
				response.Success = false;
				response.Object = null;
				response.Timestamp = DateTime.UtcNow;

				if (ErpSettings.DevelopmentMode)
					response.Message = e.Message + e.StackTrace;
				else
					response.Message = "The entity record was not update. An internal error occurred!";

				return response;
			}

		}

		public QueryResponse Find(EntityQuery query)
		{
			QueryResponse response = new QueryResponse
			{
				Success = true,
				Message = "The query was successfully executed.",
				Timestamp = DateTime.UtcNow
			};

			try
			{
				var entity = GetEntity(query.EntityName);
				if (entity == null)
				{
					response.Success = false;
					response.Message = string.Format("The query is incorrect. Specified entity '{0}' does not exist.", query.EntityName);
					response.Object = null;
					response.Errors.Add(new ErrorModel { Message = response.Message });
					response.Timestamp = DateTime.UtcNow;
					return response;
				}


				if (!ignoreSecurity)
				{
					bool hasPermisstion = SecurityContext.HasEntityPermission(EntityPermission.Read, entity);
					if (!hasPermisstion)
					{
						response.StatusCode = HttpStatusCode.Forbidden;
						response.Success = false;
						response.Message = "Trying to read records from entity '" + entity.Name + "'  with no read access.";
						response.Errors.Add(new ErrorModel { Message = "Access denied." });
						return response;
					}
				}

				//try
				//{
				//	if (query.Query != null)
				//		ProcessQueryObject(entity, query.Query);
				//}
				//catch (Exception ex)
				//{
				//	response.Success = false;
				//	response.Message = "The query is incorrect and cannot be executed.";
				//	response.Object = null;
				//	response.Errors.Add(new ErrorModel { Message = ex.Message });
				//	response.Timestamp = DateTime.UtcNow;
				//	return response;
				//}

				var fields = CurrentContext.RecordRepository.ExtractQueryFieldsMeta(query);
				var data = CurrentContext.RecordRepository.Find(query);

				//THREAT ADDRESSED - finding C-02, CWE-200 (exposure of sensitive information to an
				//unauthorized actor) and CWE-522 (insufficiently protected credentials), OWASP
				//A01:2021 Broken Access Control + A02:2021 Cryptographic Failures. The gate above
				//authorises the ENTITY, not the FIELD: there is no field-level check anywhere in
				//this data layer, so a stored credential hash was returned verbatim by every record
				//query to every caller that could read the entity at all. Field permissions are
				//enforced ONLY in the presentation layer - PcFieldBase gates the whole
				//field-permission evaluation behind "if (entityField.EnableSecurity)" and
				//EnableSecurity is a plain bool defaulting to false in
				//WebVella.Erp/Api/Models/FieldTypes/BaseField.cs - and the mandated Authorization
				//Enforcement standard requires authorization to be validated "on every request, not
				//just in the UI". The value is therefore replaced here, server-side, at the manager
				//projection seam, so a hash never leaves the server for ANY role.
				RedactEncryptedFieldValues(fields, data);

				response.Object = new QueryResult { FieldsMeta = fields, Data = data };
			}
			catch (Exception ex)
			{
				response.Success = false;
				response.Message = "The query is incorrect and cannot be executed";
				response.Object = null;
				// THREAT ADDRESSED - finding F26, CWE-209 (generation of an error message containing
				// sensitive information), OWASP A05. The error entry beside the fixed message above copied the
				// raw exception message, so an authenticated caller able to provoke a fault here still received
				// internal detail - which is the same disclosure the API-surface remediation closed one layer
				// up, reached by a path that never enters the controller's own catch. Guarded exactly as this
				// file's own write paths already are, so a developer keeps the detail and a caller does not.
				// Deliberately NOT logged here: this method runs on every list and count render, so a log
				// write on its failure path would be the unbounded-logging vector finding F9 exists to close.
				response.Errors.Add(new ErrorModel { Message = ErpSettings.DevelopmentMode ? ex.Message : "An internal error occurred!" });
				response.Timestamp = DateTime.UtcNow;
				return response;
			}

			return response;
		}

		public QueryCountResponse Count(EntityQuery query)
		{
			QueryCountResponse response = new QueryCountResponse
			{
				Success = true,
				Message = "The query was successfully executed.",
				Timestamp = DateTime.UtcNow
			};

			try
			{
				var entity = GetEntity(query.EntityName);
				if (entity == null)
				{
					response.Success = false;
					response.Message = string.Format("The query is incorrect. Specified entity '{0}' does not exist.", query.EntityName);
					response.Object = 0;
					response.Errors.Add(new ErrorModel { Message = response.Message });
					response.Timestamp = DateTime.UtcNow;
					return response;
				}

				//try
				//{
				//	if (query.Query != null)
				//		ProcessQueryObject(entity, query.Query);
				//}
				//catch (Exception ex)
				//{
				//	response.Success = false;
				//	response.Message = "The query is incorrect and cannot be executed";
				//	response.Object = 0;
				//	response.Errors.Add(new ErrorModel { Message = ex.Message });
				//	response.Timestamp = DateTime.UtcNow;
				//	return response;
				//}

				List<Field> fields = CurrentContext.RecordRepository.ExtractQueryFieldsMeta(query);
				response.Object = CurrentContext.RecordRepository.Count(query);
			}
			catch (Exception ex)
			{
				response.Success = false;
				response.Message = "The query is incorrect and cannot be executed";
				response.Object = 0;
				// THREAT ADDRESSED - finding F26, CWE-209. Same guard and same reasoning as Find above.
				response.Errors.Add(new ErrorModel { Message = ErpSettings.DevelopmentMode ? ex.Message : "An internal error occurred!" });
				response.Timestamp = DateTime.UtcNow;
				return response;
			}

			return response;
		}

		//SECURITY C-02 (CWE-200 exposure of sensitive information to an unauthorized actor,
		//CWE-522 insufficiently protected credentials / OWASP A01:2021 Broken Access Control +
		//A02:2021 Cryptographic Failures): replaces the value of every encrypted PasswordField in a
		//query projection with EncryptedFieldRedactedValue, so a stored credential hash never
		//leaves the server. Called from Find(EntityQuery) only, and recursively for the related
		//records projected under a relation token, whose keys carry the
		//RELATION_NAME_RESULT_SEPARATOR prefix and whose values are List<EntityRecord>.
		//
		//DELIBERATE DESIGN DECISIONS, each of which must survive future edits:
		//
		//1. Keyed on the EXISTING PasswordField.Encrypted flag and on nothing else. Encrypted is
		//   bool?, so the test is written "== true" on purpose: that treats null as "not
		//   encrypted", which is the semantics every other PasswordField test in this class
		//   already has. Never write a bare truthiness test and never write "!= false".
		//
		//2. UNCONDITIONAL with respect to role, including administrators. The acceptance criterion
		//   is "no API response and no query projection returns a password hash, for any role", so
		//   this is deliberately NOT conditional on the ignoreSecurity field, on
		//   SecurityContext.CurrentUser or on role membership. A role-conditional projection would
		//   leave the hash reachable and would add exactly the complexity the Minimal Change
		//   Clause forbids.
		//
		//3. Blanket field-permission enforcement is explicitly OUT OF SCOPE and must not be added
		//   here: porting Field.Permissions.CanRead across all field types and every projection
		//   would ripple through the whole read path, and because the presentation layer treats an
		//   empty read permission as denial it would hide fields wholesale. The residual general
		//   gap is recorded in docs/security/risk-register.md rather than fixed.
		//
		//4. Applied at the MANAGER seam, after the repository has produced the records, and
		//   UNCONDITIONALLY - this call is deliberately not subject to the credential-read scope.
		//   The repository carries its own companion redaction at its two record-projection
		//   seams, also unconditionally, so this is defence in depth at a second, independent
		//   layer - which is what closes C-02 even if one layer is later bypassed. Redaction is
		//   idempotent, so a value the repository already replaced is simply replaced again with
		//   the same constant.
		//
		//   The generic EQL surface is a separate path that bypasses this manager and both
		//   repository Find seams entirely - which is how the credential hash remained
		//   projectable over the api/v3/en_US/eql, eql-ds and eql-ds-select2 endpoints after the
		//   first pass at C-02 - and it is gated TWICE, both times deny-by-default:
		//     DbRecordRepository.ExtractFieldValue guards its read fall-through, suppressed only
		//     inside RecordManager.OpenCredentialReadScope;
		//     EqlCommand.ConvertJObjectToEntityRecord redacts unless the internal, init-only
		//     EqlCommand.IncludeEncryptedFieldValues flag is set on the command (the opt-in lives
		//     on the COMMAND, never on the public EqlSettings built from stored data sources).
		//   Both gates must be satisfied before a real hash is projected, and the only place in
		//   the platform that satisfies both is SecurityManager's credential resolution:
		//   GetUser(Guid), which SaveUser and the schema-version-4 migration read through, and
		//   GetUser(email, password). That is what lets a login verify while the EQL and
		//   data-source endpoints keep disclosing nothing.
		//
		//5. A null value stays null. Inventing a marker where there was no value would change
		//   observable behaviour, and the write-side guards in the create and update collectors key
		//   on the marker rather than on null.
		//
		//6. FieldsMeta is deliberately left untouched: metadata is not the hash, and rewriting it
		//   would change the response contract.
		private static void RedactEncryptedFieldValues(List<Field> fields, List<EntityRecord> records)
		{
			if (fields == null || records == null || records.Count == 0)
				return;

			//Single metadata scan, before any record is inspected. A projection that carries no
			//encrypted password field - which is every query in this platform except the handful
			//that touch the user entity - allocates nothing and returns after one type test per
			//projected field, so the cost on an ordinary query is not measurable.
			List<string> encryptedFieldNames = null;
			List<RelationFieldMeta> relationFields = null;

			foreach (var field in fields)
			{
				if (field is RelationFieldMeta)
				{
					var relationField = (RelationFieldMeta)field;

					//Only descend into a relation whose own projection actually carries an
					//encrypted password field, so an unrelated relation projection costs one
					//metadata scan rather than a walk of every related record.
					if (!ContainsEncryptedPasswordField(relationField.Fields))
						continue;

					if (relationFields == null)
						relationFields = new List<RelationFieldMeta>();

					relationFields.Add(relationField);
				}
				else if (field is PasswordField && ((PasswordField)field).Encrypted == true)
				{
					if (encryptedFieldNames == null)
						encryptedFieldNames = new List<string>();

					encryptedFieldNames.Add(field.Name);
				}
			}

			if (encryptedFieldNames == null && relationFields == null)
				return;

			foreach (var record in records)
			{
				if (record == null)
					continue;

				if (encryptedFieldNames != null)
				{
					foreach (var fieldName in encryptedFieldNames)
					{
						//Existence is tested on Properties first because the Expando indexer
						//throws for an absent key - this is the same idiom the record collectors
						//in this class already use. A projection need not contain every field of
						//the entity, and a null value is left as null (decision 5 above).
						if (!record.Properties.ContainsKey(fieldName) || record[fieldName] == null)
							continue;

						record[fieldName] = EncryptedFieldRedactedValue;
					}
				}

				if (relationFields != null)
				{
					foreach (var relationField in relationFields)
					{
						if (!record.Properties.ContainsKey(relationField.Name))
							continue;

						//The related records are projected as a List<EntityRecord> under the
						//relation key. "as" rather than a cast: an unexpected shape must leave the
						//value untouched rather than throw and fail the whole query, and the
						//recursive call returns immediately for a null list.
						RedactEncryptedFieldValues(relationField.Fields, record[relationField.Name] as List<EntityRecord>);
					}
				}
			}
		}

		//SECURITY C-02 support (see RedactEncryptedFieldValues): reports whether a projected field
		//set contains an encrypted PasswordField, directly or through a relation projection. This
		//is the cheap pre-check that keeps redaction off the cost path of every query that cannot
		//expose a credential. Relation projections are limited to one level by
		//DbRecordRepository.ExtractQueryFieldsMeta, but the walk is written recursively so a
		//deeper projection could never silently escape redaction.
		private static bool ContainsEncryptedPasswordField(List<Field> fields)
		{
			if (fields == null)
				return false;

			foreach (var field in fields)
			{
				if (field is PasswordField && ((PasswordField)field).Encrypted == true)
					return true;

				if (field is RelationFieldMeta && ContainsEncryptedPasswordField(((RelationFieldMeta)field).Fields))
					return true;
			}

			return false;
		}

		/// <summary>
		/// Renders a rejected field value for inclusion in a record-write error message, replacing
		/// the value of a credential field with a fixed placeholder.
		/// </summary>
		/// <param name="field">
		/// The field the value belongs to, or <c>null</c> when it could not be resolved.
		/// </param>
		/// <param name="value">The value the write was rejected for.</param>
		/// <returns>The value's text, or a fixed placeholder for a password field.</returns>
		/// <remarks>
		/// Threat addressed - CWE-532 (insertion of sensitive information into log file), CWE-209
		/// (generation of error message containing sensitive information), OWASP A09:2021.
		/// <para>
		/// The record-write collectors report a rejected value by interpolating it into an exception
		/// message. That message is returned to the caller AND persisted to the system_log table, so for a
		/// password field it publishes the submitted PLAINTEXT into durable storage readable by every
		/// account holding log access - a worse disclosure than the stored-hash exposure this engagement
		/// set out to close, because a hash is one-way and this is not. Enforcing the M-13 password bounds
		/// at this write seam makes it far easier to reach, a refused password being an ordinary
		/// user-triggered outcome rather than an internal fault. Redaction is therefore UNCONDITIONAL
		/// rather than limited to the policy failure, so no other exception on this path can leak the
		/// value either.
		/// </para>
		/// <para>
		/// A fixed placeholder is returned rather than the length, a prefix, or a digest: each of
		/// those is a usable oracle against a credential, and none of them helps diagnose a write.
		/// The field NAME is still reported by the callers, which is what an operator needs.
		/// </para>
		/// </remarks>
		private static string DescribeRejectedFieldValue(Field field, object value)
		{
			if (field is PasswordField)
				return RedactedFieldValueForErrorMessage;

			return value?.ToString();
		}

		/// <summary>
		/// The fixed text substituted for a credential value in a record-write error message. It is
		/// intentionally distinct from <see cref="EncryptedFieldRedactedValue"/>, which is a wire
		/// sentinel the write path must recognise and refuse; this one is human-facing message text
		/// and must never be treated as a value.
		/// </summary>
		private const string RedactedFieldValueForErrorMessage = "[redacted]";

		/// <summary>
		/// Applies the platform password policy to every encrypted password field a record carries
		/// on its way into storage, adding one field-level error per offending value.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - finding F25 / M-13, CWE-521 (weak password requirements) and CWE-20
		/// (improper input validation), OWASP A07:2021 Identification and Authentication Failures.
		/// The 12-128 range is published as user-entity field metadata and was enforced nowhere:
		/// every read of MinLength and MaxLength in Api/EntityManager.cs is commented out. Closing
		/// Api/SecurityManager.SaveUser and provisioning alone would have left this door wide open,
		/// because CreateRecord and UpdateRecord below are reached directly from
		/// POST api/v3/en_US/record/{entityName} and from the SDK generic data-create and
		/// data-manage forms, so a principal holding create or update permission on the entity that
		/// owns a credential could still store a one-character administrator password. This is the
		/// same single validator SaveUser uses - PasswordUtil.ValidatePasswordPolicy is the one gate
		/// for that policy platform-wide - applied at the second and last write boundary.
		///
		/// It reports through response.Errors rather than by throwing, deliberately. The per-field
		/// catch inside both collectors re-wraps any exception as "Invalid value: '&lt;value&gt;'", which
		/// for a password field would put the plaintext credential into an API message and into the
		/// server log - a CWE-532 disclosure created by the very fix meant to strengthen the
		/// credential. Running as a pre-pass, before any connection work, avoids that entirely,
		/// uses these methods' own established error mechanism, and leaves nothing half-written.
		/// ErrorModel.Value is left unset for the same reason: it serialises into the response.
		///
		/// Two values are deliberately exempt, and both exemptions are load-bearing:
		/// blank, because both collectors already read it as "leave the stored value alone" or "use
		/// the declared default" rather than as a chosen password; and the redaction marker, because
		/// it is a read artefact being round-tripped by a client that never saw the real hash, and
		/// refusing it would break every record update that simply carries a previously read record
		/// back. Both are dropped by the collectors before hashing, so neither can become a stored
		/// credential in any case.
		///
		/// The legacy rehash-on-login migration cannot reach this method:
		/// SecurityManager.UpgradeStoredPasswordHash hashes in place and writes the one column
		/// through DbRepository.UpdateRecord, never through RecordManager. That is what allows an
		/// account whose password predates this policy to keep authenticating and still be upgraded.
		/// </remarks>
		private static void ValidatePasswordFieldPolicy(Entity entity, EntityRecord record, QueryResponse response)
		{
			if (entity == null || entity.Fields == null || record == null)
				return;

			foreach (var field in entity.Fields)
			{
				//only an encrypted password field is a credential: that is the exact condition under
				//which ExtractFieldValue below one-way hashes the value
				if (!(field is PasswordField) || ((PasswordField)field).Encrypted != true)
					continue;

				if (!record.Properties.ContainsKey(field.Name))
					continue;

				string candidate = record[field.Name] as string;

				if (string.IsNullOrWhiteSpace(candidate))
					continue;

				//Ordinal only - never culture-sensitive, never case-insensitive. A missed match here
				//would refuse a legitimate round-trip update.
				if (string.Equals(candidate, EncryptedFieldRedactedValue, StringComparison.Ordinal))
					continue;

				string policyError = PasswordUtil.ValidatePasswordPolicy(candidate);
				if (policyError != null)
					response.Errors.Add(new ErrorModel { Key = field.Name, Message = policyError });
			}
		}

		private object ExtractFieldValue(KeyValuePair<string, object>? fieldValue, Field field, bool encryptPasswordFields = false)
		{
			if (fieldValue != null && fieldValue.Value.Key != null)
			{
				var pair = fieldValue.Value;
				if (pair.Value == DBNull.Value)
				{
					pair = new KeyValuePair<string, object>(pair.Key, null);
				}

				if (field is AutoNumberField)
				{
					if (pair.Value == null)
						return null;
					if (pair.Value is string)
						return (int)decimal.Parse(pair.Value as string);

					return Convert.ToDecimal(pair.Value);
				}
				else if (field is CheckboxField)
				{
					if (pair.Value is string)
						return Convert.ToBoolean(pair.Value as string);
					return pair.Value as bool?;
				}
				else if (field is CurrencyField)
				{
					if (pair.Value == null)
						return null;

					decimal decimalValue;
					if (pair.Value is string)
						decimalValue = decimal.Parse(pair.Value as string);
					else
						decimalValue = Convert.ToDecimal(Convert.ToString(pair.Value));

					return decimal.Round(decimalValue, ((CurrencyField)field).Currency.DecimalDigits, MidpointRounding.AwayFromZero);
				}
				else if (field is DateField)
				{
					if (pair.Value == null)
						return null;

					DateTime? date = null;
					if (pair.Value is string)
					{
						if (string.IsNullOrWhiteSpace(pair.Value as string))
							return null;
						date = DateTime.Parse(pair.Value as string);
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
						date = pair.Value as DateTime?;
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
					if (pair.Value == null)
						return null;

					DateTime? date = null;
					if (pair.Value is string)
					{
						if (string.IsNullOrWhiteSpace(pair.Value as string))
							return null;
						date = DateTime.Parse(pair.Value as string);
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
						date = pair.Value as DateTime?;

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
					return pair.Value as string;
				else if (field is FileField)
					//TODO convert file path to url path
					return pair.Value as string;
				else if (field is ImageField)
					//TODO convert image path to url path
					return pair.Value as string;
				else if (field is HtmlField)
					return pair.Value as string;
				else if (field is MultiLineTextField)
					return pair.Value as string;
				else if (field is GeographyField)
					return pair.Value as string;
				else if (field is MultiSelectField)
				{
					if (pair.Value == null)
						return null;
					else if (pair.Value is JArray)
						return ((JArray)pair.Value).Select(x => ((JToken)x).Value<string>()).ToList<string>();
					else if (pair.Value is List<object>)
						return ((List<object>)pair.Value).Select(x => ((object)x).ToString()).ToList<string>();
					else
						return pair.Value as IEnumerable<string>;
				}
				else if (field is NumberField)
				{
					if (pair.Value == null)
						return null;
					if (pair.Value is string)
						return decimal.Parse(pair.Value as string);

					return Convert.ToDecimal(pair.Value);
				}
				else if (field is PasswordField)
				{
					if (encryptPasswordFields)
					{
						if (((PasswordField)field).Encrypted == true)
						{
							if (string.IsNullOrWhiteSpace(pair.Value as string))
								return null;

							//THREAT ADDRESSED - finding C-02 guard (DATA-INTEGRITY CRITICAL), CWE-200 and
							//CWE-522, OWASP A01:2021 + A02:2021. Defence in depth behind the collector skip
							//in the update path: the redaction marker must never be hashed and persisted,
							//because that would permanently destroy the credential. Mirrors the identical
							//guard in WebVella.Erp/Database/DbRecordRepository.cs. Ordinal comparison only -
							//never culture-sensitive, never case-insensitive.
							if (string.Equals(pair.Value as string, EncryptedFieldRedactedValue, StringComparison.Ordinal))
								return null;

							//THREAT ADDRESSED - finding M-13, CWE-521 (weak password requirements),
							//OWASP A07:2021, and the mandated Authentication Hardening standard
							//"minimum password complexity: 12+ characters".
							//This is the platform's ONE plaintext-to-hash write seam for records, so it
							//is the only place a length policy can actually be enforced. The 12-to-128
							//bound previously existed solely as field METADATA on the password field,
							//which this platform treats as presentation state and never consults on the
							//write path - so any API caller, import, or provisioning value could store a
							//two-character password while the user interface advertised a twelve
							//character minimum. Enforcing it here also removes a silent data-loss edge:
							//HashPassword answers an over-length value with string.Empty by design
							//(fail-closed), which persisted as an empty credential and left the account
							//unable to authenticate at all, with no error raised to say so. Refusing the
							//write is strictly better than silently storing a value that cannot verify.
							//The reason text is deliberately value-free - never the plaintext, never its
							//length - because it travels into an exception message that is both returned
							//to the caller and persisted to the system log (CWE-532). ArgumentException
							//rather than Exception so the refusal is a typed validation failure.
							string passwordPolicyFailure = PasswordUtil.ValidatePasswordPolicy(pair.Value as string);
							if (passwordPolicyFailure != null)
								throw new ArgumentException("The supplied password does not meet the password policy: "
									+ passwordPolicyFailure + ".");

							//THREAT ADDRESSED - finding C-03, CWE-916 (password hash with insufficient
							//computational effort) and CWE-759 (one-way hash without a salt), OWASP
							//A02:2021. This wrote an unsalted, single-pass MD5 digest, so a leaked
							//password column was recoverable wholesale from precomputed tables and
							//identical passwords produced identical stored values. HashPassword derives
							//a salted, work-factored PBKDF2-HMAC-SHA-256 value instead. The stored
							//shape changes but the column does not: it is varchar(500) and the encoded
							//value is 84 characters, so no schema change is required.
							return PasswordUtil.HashPassword(pair.Value as string);
						}
					}
					return pair.Value;
				}
				else if (field is PercentField)
				{
					if (pair.Value == null)
						return null;
					if (pair.Value is string)
						return decimal.Parse(pair.Value as string);

					return Convert.ToDecimal(pair.Value);
				}
				else if (field is PhoneField)
					return pair.Value as string;
				else if (field is GuidField)
				{
					if (pair.Value is string)
					{
						if (string.IsNullOrWhiteSpace(pair.Value as string))
							return null;

						return new Guid(pair.Value as string);
					}

					if (pair.Value is Guid)
						return (Guid?)pair.Value;

					if (pair.Value == null)
						return (Guid?)null;

					throw new Exception("Invalid Guid field value.");
				}
				else if (field is SelectField)
					return pair.Value as string;
				else if (field is TextField)
					return pair.Value as string;
				else if (field is UrlField)
					return pair.Value as string;
			}
			else
			{
				return field.GetFieldDefaultValue();
			}

			throw new Exception("System Error. A field type is not supported in field value extraction process.");
		}

		private Entity GetEntity(string entityName)
		{
			return entityManager.ReadEntity(entityName).Object;
		}

		private Entity GetEntity(Guid entityId)
		{
			return entityManager.ReadEntity(entityId).Object;
		}

		private List<EntityRelation> GetRelations()
		{
			if (relations == null)
				relations = entityRelationManager.Read().Object;

			if (relations == null)
				return new List<EntityRelation>();

			return relations;
		}

		private void SetRecordRequiredFieldsDefaultData(Entity entity, List<KeyValuePair<string, object>> recordData)
		{
			if (recordData == null)
				return;

			if (entity == null)
				return;

			foreach (var field in entity.Fields)
			{
				if (field.Required && !recordData.Any(p => p.Key == field.Name)
					&& field.GetFieldType() != FieldType.AutoNumberField
					&& field.GetFieldType() != FieldType.FileField
					&& field.GetFieldType() != FieldType.ImageField)
				{
					var defaultValue = field.GetFieldDefaultValue();

					recordData.Add(new KeyValuePair<string, object>(field.Name, defaultValue));
				}
			}
		}
	}
}
