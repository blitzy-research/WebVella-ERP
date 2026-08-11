using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Threading;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Database;
using WebVella.Erp.Diagnostics;
using WebVella.Erp.Exceptions;
using WebVella.Erp.Hooks;
using WebVella.Erp.Utilities;

namespace WebVella.Erp.Api
{
	public class RecordManager
	{
		private const char RELATION_SEPARATOR = '.';
		private const char RELATION_NAME_RESULT_SEPARATOR = '$';

		// SECURITY C-02 (CWE-200 exposure of sensitive information, CWE-522 insufficiently protected
		// credentials / OWASP A01:2021 + A02:2021): single source of truth for the value substituted for
		// encrypted-field content in read projections. DbRecordRepository MUST reference this constant rather
		// than repeat a literal, because a drift between the read-side marker and the write-side guard would
		// let a round-tripped marker be mistaken for a real password and hashed over the stored credential.
		// Fixed rather than random, because a per-request marker could not be recognised by that guard; and
		// deliberately neither 32 lower-case hexadecimal characters (the legacy-MD5 discriminator in
		// PasswordUtil) nor a plausible modern hash (84 Base64 characters beginning "AQAAAAEA"), so it can
		// never be mistaken for a stored value. internal, so no public API surface is added; PascalCase per
		// the .editorconfig convention, unlike the two char consts above, which predate it.
		internal const string EncryptedFieldRedactedValue = "__WV_REDACTED_a7f3c1e9__";

		// SECURITY C-02 (CWE-200, CWE-522 / OWASP A01:2021 + A02:2021): the ambient opt-in that separates the
		// platform's one internal credential-resolution path from every other record projection.
		//
		// THREAT ADDRESSED: redaction applied at the manager and repository seams only left the generic EQL
		// surface projecting the hash verbatim, because DbRecordRepository.ExtractFieldValue is ALSO reached
		// from EqlCommand, which SecurityManager uses to verify a login. That surface gates on the ENTITY read
		// permission alone, the Regular role retains read access to the user entity, and it is reachable over
		// HTTP - so an authenticated regular user could project user.password. Gating the repository's read
		// fall-through on this scope closes it while leaving verification working: it is the enabling change,
		// because redaction inside the shared ExtractFieldValue would otherwise hand SecurityManager the marker.
		//
		// FOUR DECISIONS THAT MUST SURVIVE FUTURE EDITS. It is DENY BY DEFAULT, false unless a caller opens the
		// scope, so a read path added later is redacted automatically - never invert this. It is AsyncLocal, not
		// [ThreadStatic] and not an instance field, because the value must flow across one request's awaits
		// without leaking into another and the consumer is static; SecurityContext already uses the same
		// primitive. It is opened at the credential-resolution call sites in SecurityManager AND NOWHERE ELSE:
		// opening it around a controller action, hook, job, bulk listing or import would reopen the surface it
		// closes. And it is internal, because both consumers are in this assembly.
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

		#region << Protected relation authorization >>

		//THREAT ADDRESSED - privilege escalation to administrator: CWE-269 improper privilege management, with
		//CWE-862 missing authorization and CWE-639 authorization bypass through a user-controlled key; OWASP
		//A01:2021 Broken Access Control.
		//THE ATTACK. Role membership is a row in the many-to-many relation user_role, and nothing in this class
		//asked who was attaching it. The seed grants Regular CanRead on both the user and role entities, so an
		//authenticated regular user could read the administrator role's identifier and their own, post both at
		//the generic relation endpoint, and attach their own account to the administrator role - taking effect
		//on the next request, because SecurityManager reloads a principal's roles from rel_user_role.
		//WHY THE INVARIANT LIVES HERE. These two methods are the ONLY route to a relation row in the platform:
		//DbRelationRepository's many-to-many create and delete are called from nowhere else, and the
		//$relation.field branches of CreateRecord and UpdateRecord funnel back through here. A check at the
		//endpoint would leave every other present and future caller able to reach the same row.
		//WHY ONLY user_role. Requiring administrator rights for EVERY relation would refuse the platform's own
		//working flows - task watchers, project membership, comment subscriptions - so the residual general gap
		//in relation-level authorization is recorded in docs/security/risk-register.md instead. ignoreSecurity
		//is the only bypass because it is constructed at exactly one site, which owns the seed and the migration
		//and cannot be reached from a request; an anonymous caller is refused, which is deny-by-default at the
		//one edge where a missing context would otherwise read as "no restriction applies".
		private static readonly Guid[] AdministratorOnlyRelationIds = new Guid[] { SystemIds.UserRoleRelationId };

		//Source name for the refusal records below. A single const so the audit trail can be queried
		//on one exact value rather than on a family of near-identical strings.
		private const string ProtectedRelationLogSource = "RecordManager.ProtectedRelationAuthorization";

		//Count of refusal records that could not be persisted, carried into the next one that can, so
		//a gap in the trail is visible IN the trail rather than only as an absence of rows (CWE-778).
		private static int protectedRelationReportFailures;

		/// <summary>
		/// Decides whether a many-to-many mutation of an administrator-only relation must be refused,
		/// and records the refusal when it must.
		/// </summary>
		/// <remarks>
		/// SECURITY - privilege escalation to administrator. See the block comment above for the threat and
		/// for why the invariant is enforced at this choke point. Returns true when the caller may NOT proceed.
		/// </remarks>
		private bool IsProtectedRelationMutationRefused(Guid relationId, string operation, Guid? originValue, Guid? targetValue)
		{
			if (!AdministratorOnlyRelationIds.Contains(relationId))
				return false;

			//The platform's own trusted-system marker - see above for why it is safe as a bypass.
			if (ignoreSecurity)
				return false;

			ErpUser currentUser = SecurityContext.CurrentUser;

			//The system principal covers background jobs, provisioning and internal hooks, which open
			//a system scope rather than constructing a manager with ignoreSecurity.
			if (currentUser != null && currentUser.Id == SystemIds.SystemUserId)
				return false;

			if (currentUser != null && currentUser.IsAdmin)
				return false;

			ReportProtectedRelationRefusal(relationId, operation, currentUser, originValue, targetValue);
			return true;
		}

		/// <summary>
		/// Records an authorization refusal for an administrator-only relation.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - CWE-778 insufficient logging, and the requirement that authorization failures be
		/// logged. This method CANNOT throw and CANNOT change the outcome it records: an audit fault must never
		/// turn a clean refusal into a server error, nor unwind the refusal. It writes through the core
		/// <c>Diagnostics.Log</c> deliberately, because that writer executes one parameterised INSERT with no
		/// mail branch, so a caller who can repeat this refusal cannot drive it into an outbound mail flood.
		/// Every interpolated value is a platform identifier or a GUID, so CWE-117 log forging has no operand.
		/// </remarks>
		private static void ReportProtectedRelationRefusal(Guid relationId, string operation, ErpUser currentUser, Guid? originValue, Guid? targetValue)
		{
			try
			{
				int unreported = Volatile.Read(ref protectedRelationReportFailures);

				string details = "relation_id: " + relationId.ToString()
					+ "; operation: " + (operation ?? string.Empty)
					+ "; user_id: " + (currentUser == null ? "anonymous" : currentUser.Id.ToString())
					+ "; origin_id: " + (originValue.HasValue ? originValue.Value.ToString() : "none")
					+ "; target_id: " + (targetValue.HasValue ? targetValue.Value.ToString() : "none");

				string message = "Refused a many-to-many mutation of an administrator-only relation.";
				if (unreported > 0)
				{
					message = message + " | " + unreported.ToString(CultureInfo.InvariantCulture)
						+ " earlier refusal record(s) could not be persisted and are unrecorded.";
				}

				//LogType.Error matches the level the web layer already uses for an authorization or
				//credential denial, so refusals from both layers surface in one query rather than two.
				//DoNotNotify is explicit rather than defaulted: the default is NotNotified, which is what
				//makes Web/Services/LogService.cs mail a record, and this refusal is repeatable at will.
				new Log().Create(LogType.Error, ProtectedRelationLogSource, message, details, LogNotificationStatus.DoNotNotify);

				if (unreported > 0)
					Interlocked.Add(ref protectedRelationReportFailures, -unreported);
			}
			catch (Exception reportFailure)
			{
				//Counted BEFORE the fallback is attempted, so the loss is recorded even if the fallback
				//also fails. Absorbed here, and only here, because the alternative - propagating - would
				//turn a correct refusal into a server error.
				Interlocked.Increment(ref protectedRelationReportFailures);

				try
				{
					Console.Error.WriteLine("[WebVella.Erp] " + ProtectedRelationLogSource
						+ ": a relation authorization refusal could not be persisted ("
						+ reportFailure.GetType().Name + "). relation_id: " + relationId.ToString());
				}
				catch (Exception)
				{
					//No usable error stream is left - redirected, closed or disposed. The increment above
					//is then the only surviving record of the loss, and the next report that reaches the
					//log carries it. Nothing further can be done without risking the refusal itself.
				}
			}
		}

		/// <summary>
		/// Message returned to a caller whose relation mutation was refused. Deliberately generic and identical
		/// for every reason: naming the relation, the role required or the identifiers involved would let an
		/// unprivileged caller map the platform's privilege model by probing.
		/// </summary>
		internal const string ProtectedRelationRefusalMessage = "This relation cannot be modified by the current user.";

		#endregion

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

				//SECURITY - privilege escalation to administrator. Checked AFTER the relation is known to exist so a
				//refusal cannot be told apart from a bad relation identifier by response shape, and
				//BEFORE any hook runs or any row is written, so no side effect of an unauthorized
				//mutation is observable.
				if (IsProtectedRelationMutationRefused(relationId, "create", originValue, targetValue))
				{
					response.Object = null;
					response.Success = false;
					response.Timestamp = DateTime.UtcNow;
					response.StatusCode = HttpStatusCode.Forbidden;
					response.Message = ProtectedRelationRefusalMessage;
					response.Errors.Add(new ErrorModel { Message = ProtectedRelationRefusalMessage });
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

				//SECURITY - privilege escalation to administrator. The REMOVE half matters as much as the create half:
				//without it an unprivileged caller could strip the administrator role from every
				//administrator and lock the installation out of its own administration, which is a
				//denial of service reached through the same missing authorization.
				if (IsProtectedRelationMutationRefused(relationId, "remove", originValue, targetValue))
				{
					response.Object = null;
					response.Success = false;
					response.Timestamp = DateTime.UtcNow;
					response.StatusCode = HttpStatusCode.Forbidden;
					response.Message = ProtectedRelationRefusalMessage;
					response.Errors.Add(new ErrorModel { Message = ProtectedRelationRefusalMessage });
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

		// THREAT ADDRESSED - insecure direct object reference on a file, OWASP A01:2021, CWE-639 (authorization
		// bypass through a user-controlled key) with CWE-367 (time-of-check to time-of-use) on the mutation that
		// follows. Both the create and the update paths take a file or image field value STRAIGHT FROM THE
		// REQUEST and, when it points into the temporary staging namespace, MOVE the named file into the
		// record's folder - the update path with overwrite enabled - without establishing that the staged file
		// belonged to the caller.
		// Both halves of the control live here so the two call sites cannot drift apart. NAMESPACE: the source
		// must be inside the staging namespace, tested WITH the trailing separator, which the previous test
		// omitted so that "/tmpfoo/..." satisfied a check meant to mean "/tmp/...". OWNERSHIP: the staged file
		// must be the caller's own, and a missing file, an unresolvable principal or a staged file with no
		// recorded owner all refuse for a non-administrator.
		// The DESTINATION needs no ownership test, structurally: the caller never supplies it, it is composed
		// from the entity name and the record's own identifier, and the only caller-influenced part is the last
		// path segment, which cannot contain a separator. The returned identifier is what makes authorization
		// atomic with the write - DbFileRepository.Move applies the move only while that row is still at that
		// path, so a concurrent substitution is refused by the database. ignoreSecurity is honoured because it
		// marks a trusted system operation, which has no meaning outside a request.
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

					//SECURITY - M-13, CWE-521. First of the two write boundaries at which a
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

								//THREAT ADDRESSED - C-02 guard, DATA-INTEGRITY CRITICAL (CWE-200, CWE-522 / OWASP A01:2021 +
								//A02:2021). Companion of the identical guard in the update collector below. A client that read a
								//record through Find(EntityQuery) receives EncryptedFieldRedactedValue in place of the stored
								//hash, so a create built by copying such a record would carry the marker into the PasswordField
								//branch of ExtractFieldValue: hashing it would mint an account whose password is the published
								//marker. The field is omitted from storageRecordData altogether and the declared default is
								//supplied instead, which is exactly what a create with no password produces. Ordinal comparison
								//only - a missed match would persist the marker and a false match would drop a real password.
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
									//CWE-532 / CWE-209: a credential value must never be interpolated into a message that is
									//returned to the caller and written to system_log - see DescribeRejectedFieldValue.
									//ArgumentException rather than the reserved base type, which carried a CA2201 diagnostic; the
									//only handlers before this method's boundary catch ValidationException and Exception, so
									//behaviour and message are unchanged.
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

					//many-to-many relation rows carry no post-create hook invocation
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

					//SECURITY - M-13, CWE-521. Second and last write boundary at which a password
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

								//THREAT ADDRESSED - C-02 guard, DATA-INTEGRITY CRITICAL (CWE-200, CWE-522 / OWASP A01:2021 +
								//A02:2021). A client that read this record through a query projection receives
								//EncryptedFieldRedactedValue in place of the stored hash, so a full-record round-trip update
								//would otherwise reach the PasswordField branch below and hash the marker, PERMANENTLY
								//DESTROYING the credential, because both MD5 and PBKDF2 are one-way. The field is skipped
								//exactly as a null already is - omitted from storageRecordData, leaving the column
								//byte-identical - because a null reaching storage would itself wipe it.
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
								//CWE-532 / CWE-209: a credential value must never be interpolated into a message that is
								//returned to the caller and written to system_log. The field is resolved here solely to make
								//that decision, and an unresolved name yields null, which DescribeRejectedFieldValue treats as
								//"not a password". ArgumentException for the reason given at the create-path twin above.
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

					//many-to-many relation rows carry no post-create hook invocation
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


				var fields = CurrentContext.RecordRepository.ExtractQueryFieldsMeta(query);
				var data = CurrentContext.RecordRepository.Find(query);

				//THREAT ADDRESSED - C-02, CWE-200 / CWE-522, OWASP A01:2021 + A02:2021. The gate above authorises
				//the ENTITY, not the FIELD: there is no field-level check anywhere in this data layer, so a stored
				//credential hash was returned verbatim by every record query to every caller that could read the
				//entity at all. Field permissions are enforced ONLY in the presentation layer - PcFieldBase gates
				//the whole evaluation behind EnableSecurity, a bool defaulting to false - and the mandated
				//Authorization Enforcement standard requires authorization on every request, not just in the UI.
				RedactEncryptedFieldValues(fields, data);

				response.Object = new QueryResult { FieldsMeta = fields, Data = data };
			}
			catch (Exception ex)
			{
				response.Success = false;
				response.Message = "The query is incorrect and cannot be executed";
				response.Object = null;
				// THREAT ADDRESSED - CWE-209 (generation of an error message containing sensitive information),
				// OWASP A05. The error entry beside the fixed message above copied the raw exception message, so a
				// caller able to provoke a fault here received internal detail by a path that never enters the
				// controller's own catch. Guarded as this file's write paths already are. Deliberately NOT logged:
				// this method runs on every list and count render, so that would be an unbounded-logging vector.
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


				List<Field> fields = CurrentContext.RecordRepository.ExtractQueryFieldsMeta(query);
				response.Object = CurrentContext.RecordRepository.Count(query);
			}
			catch (Exception ex)
			{
				response.Success = false;
				response.Message = "The query is incorrect and cannot be executed";
				response.Object = 0;
				// THREAT ADDRESSED - CWE-209 (error message containing sensitive information). Same guard as Find.
				response.Errors.Add(new ErrorModel { Message = ErpSettings.DevelopmentMode ? ex.Message : "An internal error occurred!" });
				response.Timestamp = DateTime.UtcNow;
				return response;
			}

			return response;
		}

		//SECURITY C-02 (CWE-200, CWE-522 / OWASP A01:2021 + A02:2021): replaces the value of every encrypted
		//PasswordField in a query projection with EncryptedFieldRedactedValue, so a stored credential hash
		//never leaves the server. Called from Find(EntityQuery), and recursively for the related records
		//projected under a relation token, whose keys carry the RELATION_NAME_RESULT_SEPARATOR prefix.
		//
		//SIX DECISIONS THAT MUST SURVIVE FUTURE EDITS.
		//1. Keyed on the existing PasswordField.Encrypted flag and nothing else. Encrypted is bool?, so the
		//   test is written "== true" on purpose, treating null as "not encrypted" exactly as every other
		//   PasswordField test here does. Never a bare truthiness test and never "!= false".
		//2. UNCONDITIONAL with respect to role, including administrators, because the acceptance criterion is
		//   that no projection returns a hash for ANY role. A role-conditional projection would leave the hash
		//   reachable and add exactly the complexity the Minimal Change Clause forbids.
		//3. Blanket field-permission enforcement is OUT OF SCOPE and must not be added here: porting
		//   Field.Permissions.CanRead across all field types and projections would ripple through the whole
		//   read path and, because the presentation layer treats an empty read permission as denial, would hide
		//   fields wholesale. The residual gap is recorded in docs/security/risk-register.md.
		//4. Applied at the MANAGER seam and deliberately not subject to the credential-read scope. The
		//   repository carries its own companion redaction at its two record-projection seams, so this is
		//   defence in depth at a second independent layer, and redaction is idempotent. The generic EQL
		//   surface bypasses both and is gated TWICE, both deny-by-default: ExtractFieldValue guards its read
		//   fall-through unless OpenCredentialReadScope is active, and EqlCommand redacts unless its internal,
		//   init-only IncludeEncryptedFieldValues flag is set on the COMMAND - never on the public EqlSettings
		//   built from stored data sources. Only SecurityManager's credential resolution satisfies both.
		//5. A null value stays null: inventing a marker where there was no value would change observable
		//   behaviour, and the write-side guards key on the marker rather than on null.
		//6. FieldsMeta is left untouched, because metadata is not the hash and rewriting it would change the
		//   response contract.
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

		//SECURITY C-02 support (see RedactEncryptedFieldValues): reports whether a projected field set contains
		//an encrypted PasswordField, directly or through a relation projection - the cheap pre-check that keeps
		//redaction off the cost path of queries that cannot expose a credential. Relation projections are one
		//level deep today, but the walk is recursive so a deeper one could never silently escape redaction.
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
		/// Renders a rejected field value for a record-write error message, replacing a credential field's value
		/// with a fixed placeholder.
		/// </summary>
		/// <param name="field">The field the value belongs to, or <c>null</c> when it could not be resolved.</param>
		/// <param name="value">The value the write was rejected for.</param>
		/// <returns>The value's text, or a fixed placeholder for a password field.</returns>
		/// <remarks>
		/// Threat addressed - CWE-532 (insertion of sensitive information into a log file) and CWE-209
		/// (generation of an error message containing sensitive information), OWASP A09:2021. The record-write
		/// collectors report a rejected value by interpolating it into an exception message that is BOTH returned
		/// to the caller and persisted to system_log, so for a password field that publishes the submitted
		/// PLAINTEXT into durable storage - a worse disclosure than the stored hash, because a hash is one-way.
		/// Redaction is UNCONDITIONAL rather than limited to the policy failure, so no other exception on this
		/// path can leak the value either, and a fixed placeholder is returned rather than the length, a prefix
		/// or a digest, each of which is a usable oracle. The field NAME is still reported by the callers.
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
		/// Applies the platform password policy to every encrypted password field a record carries on its way
		/// into storage, adding one field-level error per offending value.
		/// </summary>
		/// <remarks>
		/// THREAT ADDRESSED - M-13, CWE-521 (weak password requirements) and CWE-20 (improper input validation),
		/// OWASP A07:2021. The 12-128 range is published as user-entity field metadata and was enforced nowhere,
		/// every read of MinLength and MaxLength in Api/EntityManager.cs being commented out. Closing SaveUser
		/// and provisioning alone would have left this open, because CreateRecord and UpdateRecord are reached
		/// directly from POST api/v3/en_US/record/{entityName} and from the SDK generic data forms, so a
		/// principal holding create or update permission on the entity owning a credential could still store a
		/// one-character administrator password. It calls the same single validator SaveUser uses.
		/// <para>
		/// It reports through response.Errors rather than by throwing, deliberately: the per-field catch inside
		/// both collectors re-wraps any exception as "Invalid value: '&lt;value&gt;'", which for a password field
		/// would put the plaintext into an API message and the server log (CWE-532). Running as a pre-pass
		/// avoids that, uses the established error mechanism and leaves nothing half-written; ErrorModel.Value
		/// is left unset for the same reason. Two exemptions are load-bearing: blank, which both collectors
		/// already read as "leave the stored value alone", and the redaction marker, which is a read artefact
		/// being round-tripped by a client that never saw the real hash. Both are dropped before hashing. The
		/// rehash-on-login migration cannot reach this method, because UpgradeStoredPasswordHash writes the one
		/// column through DbRepository directly - which is what lets an older password keep authenticating.
		/// </para>
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
					return pair.Value as string;
				else if (field is ImageField)
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

							//THREAT ADDRESSED - C-02 guard, DATA-INTEGRITY CRITICAL (CWE-200, CWE-522 / OWASP A01:2021 +
							//A02:2021). Defence in depth behind the collector skip in the update path: the redaction marker
							//must never be hashed and persisted, because that would permanently destroy the credential.
							//Mirrors the identical guard in DbRecordRepository. Ordinal comparison only.
							if (string.Equals(pair.Value as string, EncryptedFieldRedactedValue, StringComparison.Ordinal))
								return null;

							//THREAT ADDRESSED - M-13, CWE-521 (weak password requirements), OWASP A07:2021, and the mandated
							//"minimum password complexity: 12+ characters". This is the platform's ONE plaintext-to-hash write
							//seam for records, so it is the only place a length policy can be enforced: the 12-to-128 bound
							//previously existed solely as field METADATA, which this platform treats as presentation state and
							//never consults on the write path, so any API caller, import or provisioning value could store a
							//two-character password. It also refuses an over-length value HERE, where the failure names the
							//field, rather than letting PasswordUtil.HashPassword throw ArgumentOutOfRangeException from inside
							//the collector. The reason text is value-free - never the plaintext, never its length - because it
							//travels into an exception message that is returned to the caller and persisted (CWE-532).
							string passwordPolicyFailure = PasswordUtil.ValidatePasswordPolicy(pair.Value as string);
							if (passwordPolicyFailure != null)
								throw new ArgumentException("The supplied password does not meet the password policy: "
									+ passwordPolicyFailure + ".");

							//THREAT ADDRESSED - C-03, CWE-916 (password hash with insufficient computational effort) and CWE-759
							//(one-way hash without a salt), OWASP A02:2021. This wrote an unsalted single-pass MD5 digest, so a
							//leaked password column was recoverable wholesale from precomputed tables and identical passwords
							//produced identical stored values. HashPassword derives a salted, work-factored PBKDF2-HMAC-SHA-256
							//value instead; the stored shape changes but varchar(500) already accommodates its 84 characters.
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
