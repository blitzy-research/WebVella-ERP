using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Database;
using WebVella.Erp.Fts;

namespace WebVella.Erp.Eql
{
	public partial class EqlBuilder
	{
		private EntityManager entMan;
		private EntityRelationManager relMan ;

		private Entity fromEntity = null;

		#region <--- constants --->
		const string RECORD_COLLECTION_PREFIX = "rec_";

		#region SECURITY H-09 identifier chokepoints

		// SECURITY H-09 (CWE-89 SQL injection / OWASP A03:2021 Injection). The EQL compiler emits
		// parameterised SQL for every VALUE, but a table name is an identifier and PostgreSQL cannot
		// bind an identifier as a parameter, so entity and relation table names are necessarily
		// concatenated into the generated statement - in FROM, JOIN, ORDER BY, SELECT and operand
		// positions, at roughly thirty-seven sites in this file.
		//
		// Rather than validate at each of those sites, all of them are routed through these two
		// helpers, so the allow-list is applied exactly once per name and cannot be forgotten when a
		// new emit site is added. The names originate in entity metadata and in parsed EQL text, so
		// they are attacker-influenceable wherever a caller can create an entity or relation, or
		// where stored metadata has been tampered with.
		//
		// DbIdentifier.Validate is used rather than DbIdentifier.Quote because Validate returns the
		// identifier unchanged once it matches the allow-list. That keeps the generated SQL
		// byte-identical to what this builder produced before, which matters here because these
		// values are not only emitted as identifiers but are also used as JOIN ALIASES and are
		// concatenated into textual column prefixes such as rec_x."field". Quoting would change all
		// of those strings for no security gain: the allow-list already rejects the double quote,
		// whitespace, semicolons, comment markers and upper case, which makes injection impossible
		// by construction. A non-conforming name throws DbException instead of being sanitised.

		private static string RecordTable(string entityName)
		{
			return DbIdentifier.Validate("rec_" + entityName);
		}

		private static string RelationTable(string relationName)
		{
			return DbIdentifier.Validate("rel_" + relationName);
		}

		#endregion
		const string BEGIN_OUTER_SELECT = @"SELECT row_to_json( X ) FROM (";
		const string BEGIN_SELECT = @"SELECT ";
		const string REGULAR_FIELD_SELECT = @" {1}.""{0}"" AS ""{0}"",";
		const string GEOGRAPHY_FIELD_SELECT = @" ST_As{2}({1}.""{0}"") AS ""{0}"",";
		const string END_SELECT = @"";
		const string BEGIN_SELECT_DISTINCT = @"SELECT DISTINCT ";
		const string END_OUTER_SELECT = @") X";
		const string FROM = @"FROM {0}";

		const string OTM_RELATION_TEMPLATE =
@"$$$TABS$$$(SELECT  COALESCE( array_to_json( array_agg( row_to_json(d) )), '[]') FROM (
$$$TABS$$$ SELECT {1}
$$$TABS$$$ FROM {2} {3}
$$$TABS$$$ WHERE {3}.{4} = {5}.{6} ) d )::jsonb AS ""{0}"",";

		const string MTM_RELATION_TEMPLATE =
@"$$$TABS$$$(SELECT  COALESCE(  array_to_json(array_agg( row_to_json(d))), '[]') FROM (
$$$TABS$$$ SELECT {1}
$$$TABS$$$ FROM {2} {3}
$$$TABS$$$ LEFT JOIN  {4} {5} ON {6}.{7} = {8}.{9}
$$$TABS$$$ WHERE {10}.{11} = {12}.{13} )d  )::jsonb AS ""{0}"",";

		const string FILTER_JOIN = @"
LEFT OUTER JOIN  {0} {1} ON {2}.{3} = {4}.{5}";

		#endregion

		private class SelectInfoWrapper
		{
			public Entity Entity { get; set; }

			public List<Field> Fields { get; private set; } = new List<Field>();

			public EntityRelation Relation { get; set; } = null;

			public EqlRelationInfo RelationInfo { get; set; } = null;

			public List<SelectInfoWrapper> Children { get; private set; } = new List<SelectInfoWrapper>();

			public SelectInfoWrapper Parent { get; set; } = null;
		}

		private string BuildSql(EqlAbstractTree tree, List<EqlError> errors, List<EqlFieldMeta> fieldsMeta, EqlSettings settings, out Entity fromEntity )
		{
			if (errors == null)
				errors = new List<EqlError>();

			EqlSelectNode selectNode = ((EqlSelectNode)tree.RootNode);
			var entities = entMan.ReadEntities().Object;
			fromEntity = entities.SingleOrDefault(x => x.Name == selectNode.From.EntityName);
			this.fromEntity = fromEntity;
			if (fromEntity == null)
			{
				errors.Add(new EqlError { Message = $"Entity '{selectNode.From.EntityName}' specified in FROM clause not found." });
				return string.Empty;
			}

			SelectInfoWrapper rootInfo = ProcessEntity(fromEntity, selectNode.Fields);
			StringBuilder sql = new StringBuilder();
			sql.AppendLine(BEGIN_OUTER_SELECT);
			if(settings.Distinct )
				sql.AppendLine(BEGIN_SELECT_DISTINCT);
			else
				sql.AppendLine(BEGIN_SELECT);
			var fieldsSql = BuildFieldsSql(rootInfo, 1, fieldsMeta);
			sql.Append(fieldsSql);
			sql.AppendLine(END_SELECT);
			sql.AppendLine(string.Format(FROM, RecordTable(rootInfo.Entity.Name)));

			//WHERE
			List<EqlRelationFieldNode> relationsUsedInWhere = new List<EqlRelationFieldNode>();
			if (selectNode.Where != null && selectNode.Where.RootExpressionNode != null)
			{
				string whereExpressionSql = ProcessExpressionNode(selectNode.Where.RootExpressionNode, fromEntity.Name, relationsUsedInWhere);
				if (!string.IsNullOrWhiteSpace(whereExpressionSql))
				{
					if (relationsUsedInWhere.Any())
					{
						string joinSql = ProcessWhereJoins(relationsUsedInWhere, fromEntity);
						sql.AppendLine(joinSql);
					}

					sql.AppendLine("WHERE " + whereExpressionSql);
				}
			}

			//ORDER BY
			if (selectNode.OrderBy != null && selectNode.OrderBy.Fields.Count > 0)
			{
				sql.Append("ORDER BY ");
				foreach (var field in selectNode.OrderBy.Fields)
				{
					//THREAT ADDRESSED - CWE-89 (improper neutralization of special elements used in an SQL
					//command), OWASP A03 Injection. An ORDER BY field name can arrive from an EQL parameter
					//(BuildOrderByNode reads it straight out of EqlParameter.Value), so it is a caller-supplied
					//string, and it used to be concatenated into the statement inside hand-written quotes. The
					//membership test below is a genuine allow-list and did already stop a crafted name reaching
					//the statement, but the emission is now made canonical as well, exactly as the four sort
					//emissions in DbRecordRepository were: the identifier written out is the MATCHED METADATA
					//field's own name, quoted through DbIdentifier rather than by string concatenation. The
					//invariant is then uniform and checkable - no caller-supplied string reaches an identifier
					//position anywhere in this builder. field.Direction needs no such treatment: the grammar
					//admits only the ASC and DESC terms there, and the parameter form is checked against those
					//two values in BuildOrderByNode before it ever gets here.
					var orderByFieldMeta = fromEntity.Fields.FirstOrDefault(x => x.Name == field.FieldName);
					if (orderByFieldMeta == null)
					{
						errors.Add(new EqlError { Message = $"Order field '{field.FieldName}' is not found in entity '{fromEntity.Name}'" });
						return string.Empty;
					}

					sql.Append(RecordTable(fromEntity.Name) + "." + DbIdentifier.Quote(orderByFieldMeta.Name) + " " + field.Direction);
					if (selectNode.OrderBy.Fields.Last() != field )
						sql.Append(" , ");

				}
				sql.AppendLine();
			}

			//PAGING
			int? pageSize = (selectNode.PageSize != null && selectNode.PageSize.Number.HasValue) ? (int)selectNode.PageSize.Number : (int?)null;
			int? page = (selectNode.Page != null && selectNode.Page.Number.HasValue) ? (int)selectNode.Page.Number : (int?)null;
			if ((page != null && pageSize == null) || (page == null && pageSize != null))
			{
				errors.Add(new EqlError { Message = $"When PAGE or PAGESIZE commands are used, both of them should be used together." });
				return string.Empty;
			}
			else if (page != null && pageSize != null)
			{
				if (page.Value <= 0)
				{
					errors.Add(new EqlError { Message = $"PAGE should be positive number" });
					return string.Empty;
				}
				if (pageSize.Value <= 0)
				{
					errors.Add(new EqlError { Message = $"PAGESIZE should be positive number" });
					return string.Empty;
				}

				sql.AppendLine($"LIMIT {pageSize.Value}");
				sql.AppendLine($"OFFSET {(page.Value - 1) * pageSize.Value}");
			}

			sql.AppendLine(END_OUTER_SELECT);

			return sql.ToString();
		}

		private SelectInfoWrapper ProcessEntity(Entity entity, List<EqlFieldNode> fieldNodes)
		{
			SelectInfoWrapper info = new SelectInfoWrapper();
			info.Entity = entity;

			foreach (var fieldNode in fieldNodes)
			{
				switch (fieldNode.Type)
				{
					case EqlNodeType.Field:
						{
							var field = entity.Fields.SingleOrDefault(x => x.Name == fieldNode.FieldName);
							if (field == null)
								throw new EqlException($"Field '{fieldNode.FieldName}' not found.");

							if (!info.Fields.Any(f => f.Id == field.Id))
								info.Fields.Add(field);
						}
						break;
					case EqlNodeType.WildcardField:
						{
							foreach (var field in entity.Fields)
							{
								if (!info.Fields.Any(f => f.Id == field.Id))
									info.Fields.Add(field);
							}
						}
						break;
					case EqlNodeType.RelationField:
					case EqlNodeType.RelationWildcardField:
						ProcessRelationField(info, (EqlRelationFieldNode)fieldNode);
						break;
				}
			}

			return info;
		}

		private void ProcessRelationField(SelectInfoWrapper parent, EqlRelationFieldNode relationFieldNode)
		{
			var relations = relMan.Read().Object;
			var entities = entMan.ReadEntities().Object;
			SelectInfoWrapper parentInfo = parent;

			var relCount = relationFieldNode.Relations.Count;
			for (int i = 0; i < relCount; i++)
			{
				var relInfo = relationFieldNode.Relations[i];
				var relation = relations.SingleOrDefault(r => r.Name == relInfo.Name);
				if (relation == null)
					throw new EqlException($"Relation '{relInfo.Name}' not found.");

				bool isLast = (i == (relCount - 1));
				if (isLast)
				{
					// if relation origin entity is parent entity
					// then we use target entity as next to go
					// else we use origin as next to go
					// direction doesn't matter here, it will be taken in consideration when sql is generated
					Entity currentEntity = null;
					if (relation.OriginEntityId == parentInfo.Entity.Id)
						currentEntity = entities.Single(x => x.Id == relation.TargetEntityId);
					else
						currentEntity = entities.Single(x => x.Id == relation.OriginEntityId);

					SelectInfoWrapper currentInfo = parentInfo.Children.SingleOrDefault(x => x.Relation.Id == relation.Id);
					//if the relation is not processed yet, we create and add new object,
					//otherwise we ignore, because the object exists and id field is already inside
					if (currentInfo == null)
					{
						currentInfo = new SelectInfoWrapper();
						currentInfo.Entity = currentEntity;
						currentInfo.Relation = relation;
						currentInfo.RelationInfo = relInfo;
						currentInfo.Fields.Add(currentEntity.Fields.Single(x => x.Name == "id"));
						currentInfo.Parent = parentInfo;
						parentInfo.Children.Add(currentInfo);
						parentInfo = currentInfo;
					}

					if (relationFieldNode.Type == EqlNodeType.RelationField)
					{
						var field = currentEntity.Fields.SingleOrDefault(x => x.Name == relationFieldNode.FieldName);
						if (field == null)
							throw new EqlException($"Field '{relationFieldNode.FieldName}' not found in entity '{currentEntity.Name}' for relation '{relInfo.Name}'.");

						if (!currentInfo.Fields.Any(x => x.Id == field.Id))
							currentInfo.Fields.Add(field);

						//always add id field if not in the list
						if (!currentInfo.Fields.Any(x => x.Name == "id"))
							currentInfo.Fields.Add(currentEntity.Fields.Single(x => x.Name == "id"));
					}
					else //wildcard field
					{
						//add all fields, not already added
						foreach (var field in currentEntity.Fields)
						{
							if (!currentInfo.Fields.Any(x => x.Id == field.Id))
								currentInfo.Fields.Add(field);
						}
					}
				}
				else
				{
					// if relation origin entity is parent entity
					// then we use target entity as next to go
					// else we use origin as next to go
					// direction doesn't matter here, it will be taken in consideration when sql is generated
					Entity currentEntity = null;
					if (relation.OriginEntityId == parentInfo.Entity.Id)
						currentEntity = entities.Single(x => x.Id == relation.TargetEntityId);
					else
						currentEntity = entities.Single(x => x.Id == relation.OriginEntityId);

					SelectInfoWrapper currentInfo = parentInfo.Children.SingleOrDefault(x => x.Relation.Id == relation.Id);
					//if the relation is not processed yet, we create and add new object,
					//otherwise we ignore, because the object exists and id field is already inside
					if (currentInfo == null)
					{
						currentInfo = new SelectInfoWrapper();
						currentInfo.Entity = currentEntity;
						currentInfo.Relation = relation;
						currentInfo.RelationInfo = relInfo;
						currentInfo.Fields.Add(currentEntity.Fields.Single(x => x.Name == "id"));
						currentInfo.Parent = parentInfo;
						parentInfo.Children.Add(currentInfo);
						parentInfo = currentInfo;
					}
					parentInfo = currentInfo;
				}
			}
		}

		private string BuildFieldsSql(SelectInfoWrapper rootInfo, int depth = 1, List<EqlFieldMeta> fieldsMeta = null)
		{
			StringBuilder sb = new StringBuilder();
			foreach (var field in rootInfo.Fields)
			{
				if (fieldsMeta != null)
					fieldsMeta.Add(new EqlFieldMeta { Name = field.Name, Field = field });
				if (rootInfo.Relation != null)
					AppendToStringBuilder(sb, depth, true, string.Format(REGULAR_FIELD_SELECT, field.Name, rootInfo.Relation.Name));
				else if (field.GetFieldType() == FieldType.GeographyField)
				{
					// 628426 6 Sep 2020, Geography Support
					// returns either GeoJSON or Text
					// intended to generate ST_AsGeoJson(...) or ST_AsText(...)
					string format = (field as GeographyField).Format.ToString();

					AppendToStringBuilder(sb, depth, true, string.Format(GEOGRAPHY_FIELD_SELECT, field.Name, RecordTable(rootInfo.Entity.Name), format));
				}
				else
					AppendToStringBuilder(sb, depth, true, string.Format(REGULAR_FIELD_SELECT, field.Name, RecordTable(rootInfo.Entity.Name)));
			}

			//append total count column
			if (depth == 1)
			{
				if(Settings.IncludeTotal)
					AppendToStringBuilder(sb, depth, true, " COUNT(*) OVER() AS ___total_count___,");
			}

			bool trimed = false;
			if (rootInfo.Children.Count == 0)
			{
				trimed = true;
				sb.Remove(sb.Length - (Environment.NewLine.Length + 1), Environment.NewLine.Length + 1); //remove newline and comma;
			}

			foreach (var info in rootInfo.Children)
			{
				List<EqlFieldMeta> childFieldsMeta = null;
				if (fieldsMeta != null)
					childFieldsMeta = new List<EqlFieldMeta>();

				var fieldsSql = Environment.NewLine + BuildFieldsSql(info, depth + 1, childFieldsMeta);

				AppendToStringBuilder(sb, depth, true, $"------->: ${info.Relation.Name}");

				if (fieldsMeta != null)
				{
					var meta = new EqlFieldMeta { Name = $"${info.Relation.Name}", Relation = info.Relation };
					meta.Children.AddRange(childFieldsMeta);
					fieldsMeta.Add(meta);
				}

				if (info.Relation.RelationType == EntityRelationType.OneToOne)
				{
					if (info.Relation.OriginEntityId == info.Entity.Id)
					{
						string alias = RecordTable(info.Relation.OriginEntityName);
						if (info.Parent != null && info.Parent.Relation != null)
							alias = info.Parent.Relation.Name;


						AppendToStringBuilder(sb, depth, true, string.Format(OTM_RELATION_TEMPLATE,
							$"${info.Relation.Name}",
							fieldsSql.ToString(),
							RecordTable(info.Relation.TargetEntityName),
							info.Relation.Name,
							info.Relation.TargetFieldName,
							alias,
							info.Relation.OriginFieldName));
					}
					else //when the relation is target -> origin, we have to query origin entity
					{
						string alias = RecordTable(info.Relation.TargetEntityName);
						if (info.Parent != null && info.Parent.Relation != null)
							alias = info.Parent.Relation.Name;

						AppendToStringBuilder(sb, depth, true, string.Format(OTM_RELATION_TEMPLATE,
								$"${info.Relation.Name}",
								fieldsSql.ToString(),
								RecordTable(info.Relation.OriginEntityName),
								info.Relation.Name,
								info.Relation.OriginFieldName,
								alias,
								info.Relation.TargetFieldName));
					}
				}
				else if (info.Relation.RelationType == EntityRelationType.OneToMany)
				{
					if (info.Relation.OriginEntityId != info.Relation.TargetEntityId)
					{
						if (info.Relation.OriginEntityId != info.Entity.Id)
						{
							string alias = RecordTable(info.Relation.OriginEntityName);
							if (info.Parent != null && info.Parent.Relation != null)
								alias = info.Parent.Relation.Name;

							AppendToStringBuilder(sb, depth, true, string.Format(OTM_RELATION_TEMPLATE,
								$"${info.Relation.Name}",
								fieldsSql.ToString(),
								RecordTable(info.Relation.TargetEntityName),
								info.Relation.Name,
								info.Relation.TargetFieldName,
								alias,
								info.Relation.OriginFieldName));
						}
						else //when the relation is target -> origin, we have to query origin entity
						{
							string alias = RecordTable(info.Relation.TargetEntityName);
							if (info.Parent != null && info.Parent.Relation != null)
								alias = info.Parent.Relation.Name;

							AppendToStringBuilder(sb, depth, true, string.Format(OTM_RELATION_TEMPLATE,
									$"${info.Relation.Name}",
									fieldsSql.ToString(),
									RecordTable(info.Relation.OriginEntityName),
									info.Relation.Name,
									info.Relation.OriginFieldName,
									alias,
									info.Relation.TargetFieldName));
						}
					}
					else
					{
						if (info.RelationInfo.Direction == EqlRelationDirectionType.OriginTarget)
						{
							string alias = RecordTable(info.Relation.OriginEntityName);
							if (info.Parent != null && info.Parent.Relation != null)
								alias = info.Parent.Relation.Name;

							AppendToStringBuilder(sb, depth, true, string.Format(OTM_RELATION_TEMPLATE,
									$"${info.Relation.Name}",
									fieldsSql.ToString(),
									RecordTable(info.Relation.TargetEntityName),
									info.Relation.Name,
									info.Relation.TargetFieldName,
									alias,
									info.Relation.OriginFieldName));
						}
						else
						{
							string alias = RecordTable(info.Relation.TargetEntityName);
							if (info.Parent != null && info.Parent.Relation != null)
								alias = info.Parent.Relation.Name;

							AppendToStringBuilder(sb, depth, true, string.Format(OTM_RELATION_TEMPLATE,
										$"${info.Relation.Name}",
										fieldsSql.ToString(),
										RecordTable(info.Relation.OriginEntityName),
										info.Relation.Name,
										info.Relation.OriginFieldName,
										alias,
										info.Relation.TargetFieldName));
						}
					}
				}
				else if (info.Relation.RelationType == EntityRelationType.ManyToMany)
				{
					string relationTable = RelationTable(info.Relation.Name);
					string targetJoinAlias = info.Relation.Name + "_target";
					string originJoinAlias = info.Relation.Name + "_origin";

					var direction = info.RelationInfo.Direction;
					if(info.Relation.OriginEntityId != info.Relation.TargetEntityId && info.Parent != null && info.Parent.Entity != null)
					{
						if (info.Parent.Entity.Id == info.Relation.OriginEntityId)
							direction = EqlRelationDirectionType.OriginTarget;
						else
							direction = EqlRelationDirectionType.TargetOrigin;
					}

					if (direction == EqlRelationDirectionType.TargetOrigin)
					{
						string alias = RecordTable(info.Relation.TargetEntityName);
						if (info.Parent != null && info.Parent.Relation != null)
							alias = info.Parent.Relation.Name;

						AppendToStringBuilder(sb, depth, true, string.Format(MTM_RELATION_TEMPLATE,
									$"${info.Relation.Name}",
									fieldsSql.ToString(),
									RecordTable(info.Relation.OriginEntityName),
									info.Relation.Name,
									relationTable,
									targetJoinAlias,
									targetJoinAlias,
									"target_id",
									alias,
									info.Relation.TargetFieldName,
									info.Relation.Name,
									info.Relation.OriginFieldName,
									targetJoinAlias,
									"origin_id"));
					}
					else
					{
						string alias = RecordTable(info.Relation.OriginEntityName);
						if (info.Parent != null && info.Parent.Relation != null)
							alias = info.Parent.Relation.Name;

						AppendToStringBuilder(sb, depth, true, string.Format(MTM_RELATION_TEMPLATE,
									$"${info.Relation.Name}",
									fieldsSql.ToString(),
									RecordTable(info.Relation.TargetEntityName),
									info.Relation.Name,
									relationTable,
									originJoinAlias,
									originJoinAlias,
									"origin_id",
									alias,
									info.Relation.OriginFieldName,
									info.Relation.Name,
									info.Relation.TargetFieldName,
									originJoinAlias,
									"target_id"));
					}
				}

				if (info == rootInfo.Children.Last())
				{
					if (!trimed)
						sb.Remove(sb.Length - (Environment.NewLine.Length + 1), Environment.NewLine.Length + 1); //remove newline and comma;
				}


				if(!sb.ToString().EndsWith(Environment.NewLine))
					AppendToStringBuilder(sb, depth, true, "");

				AppendToStringBuilder(sb, depth, true, $"-------< ${info.Relation.Name}");
			}


			return sb.ToString();
		}

		private void AppendToStringBuilder(StringBuilder sb, int depth, bool line, string text)
		{
			var tabs = "";
			for (int i = 0; i < depth; i++)
				tabs = tabs + "\t";

			if (text.Contains("$$$TABS$$$"))
			{
				var processedText = text.Replace("$$$TABS$$$", tabs);
				if (line)
					sb.AppendLine(processedText);
				else
					sb.Append(processedText);

			}
			else
			{
				sb.Append(tabs);
				if (line)
					sb.AppendLine(text);
				else
					sb.Append(text);
			}
		}

		// THREAT ADDRESSED - CWE-89 (improper neutralization of special elements used in an SQL command),
		// OWASP A03 Injection. Emits an EQL text literal as a PostgreSQL string literal that the server's
		// lexer cannot be talked out of, whatever the literal contains.
		//
		// WHAT WAS WRONG: the TextValue operand below re-wrapped the PARSED literal in quotes with no
		// escaping at all. The grammar declares its string terminal as
		// new StringLiteral("STRING", "'", StringOptions.AllowsDoubledQuote) (EqlGrammar.cs:15), so Irony
		// DECODES a doubled quote in the source down to a single quote in Token.ValueString. The EQL fragment
		// WHERE x = 'a'' OR 1=1 --'  therefore arrived here as the text  a' OR 1=1 --  and was emitted back
		// into the statement as  'a' OR 1=1 --'  - the literal closed early and the remainder became SQL.
		//
		// WHY ESCAPING RATHER THAN A BOUND PARAMETER: parameterizing the literal was considered first and
		// rejected because it silently widens two existing guards. ProcessExpressionNode classifies operands
		// by the SHAPE of the string emitted here - a leading '@' means "parameter" - so a literal rendered as
		// a placeholder would slip past the "first operand must be an entity field name" check in that method,
		// and the CONTAINS and STARTSWITH branches, which today reject a literal second operand outright with
		// "Parameter not found", would begin accepting one. Both are behaviour changes, and a bound parameter
		// would additionally have to be appended to the Parameters list, which Build aliases from the caller's
		// own list - so a second Execute on the same command would accumulate duplicates. One audited quoting
		// function closes the injection while leaving operand classification, error semantics and the
		// parameter collection all exactly as they were.
		//
		// WHY TWO FORMS: inside a plain '...' literal PostgreSQL treats a doubled quote as the only escape and
		// a backslash as ordinary data, so doubling the quote is exact and complete. That holds only while
		// standard_conforming_strings is on. It is on by default from PostgreSQL 9.1 and Npgsql never changes
		// it, but a server or session that turned it off would start reading a backslash as an escape
		// introducer, and  \'  would then close a literal that quote-doubling alone had left safe. Rather than
		// rest on a server setting, a value containing a backslash is emitted in the E'...' form, whose escape
		// processing is fixed and identical under both settings, with the backslash and the quote both
		// escaped. Neither form can be terminated from inside, and both reproduce the input text character for
		// character, so no stored or searched value changes meaning.
		private static string QuoteSqlTextLiteral(string text)
		{
			if (text == null)
			{
				text = string.Empty;
			}

			//PostgreSQL cannot represent U+0000 in a text value at all, so it is refused here as an EQL error
			//rather than handed to the driver to fail on obscurely part way through executing a statement.
			//The char overloads of Contains are used throughout: they are ordinal by definition, so no
			//culture can make a quote or a backslash go unnoticed.
			if (text.Contains('\0'))
			{
				throw new EqlException("WHERE CLAUSE: a text value may not contain a null character.");
			}

			if (!text.Contains('\\'))
			{
				return "'" + text.Replace("'", "''", StringComparison.Ordinal) + "'";
			}

			//Order matters: the backslash is escaped first, so the backslashes introduced when escaping the
			//quote are not themselves doubled a second time.
			return "E'" + text.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("'", "\\'", StringComparison.Ordinal) + "'";
		}

		// textLiteralValue carries the RAW, unescaped text of a string-literal operand out to the caller and is
		// null for every other operand kind. It exists because the full-text-search branch in
		// ProcessExpressionNode used to recover a literal's value by trimming the first and last character off
		// the emitted SQL, which no longer round-trips once the value is escaped - and which was itself the
		// second half of the same injection, since the recovered text was interpolated straight back into a
		// quoted literal.
		private string ProcessExpressionOperandNode(EqlNode operandNode, string entityName, List<EqlRelationFieldNode> relationsUsedInWhere, out Field field, out string textLiteralValue)
		{
			field = null;
			textLiteralValue = null;
			string operandString = string.Empty;
			switch (operandNode.Type)
			{
				case EqlNodeType.Field:
					{
						var entities = entMan.ReadEntities().Object;
						var fieldName = ((EqlFieldNode)operandNode).FieldName;

						Entity entity = entities.Single(x => x.Name == entityName);
						field = entity.Fields.SingleOrDefault(x => x.Name == ((EqlFieldNode)operandNode).FieldName);
						if (field == null)
							throw new EqlException($"WHERE CLAUSE: Field '{fieldName}' not found in entity {entityName}");

						operandString = RecordTable(entityName) + ".\"" + fieldName + "\"";
					}
					break;
				case EqlNodeType.BinaryExpression:
					operandString = ProcessExpressionNode((EqlBinaryExpressionNode)operandNode, entityName, relationsUsedInWhere);
					break;
				case EqlNodeType.ArgumentValue:
					operandString = $"@{((EqlArgumentValueNode)operandNode).ArgumentName}";
					if (!ExpectedParameters.Contains(operandString))
						ExpectedParameters.Add(operandString);
					break;
				case EqlNodeType.NumberValue:
					operandString = $"'{((EqlNumberValueNode)operandNode).Number.ToString()}'";
					break;
				case EqlNodeType.TextValue:
					//THREAT ADDRESSED - CWE-89, OWASP A03. See QuoteSqlTextLiteral above: this line used to be
					//$"'{...Text}'" and the parsed text reached the statement unescaped.
					textLiteralValue = ((EqlTextValueNode)operandNode).Text ?? string.Empty;
					operandString = QuoteSqlTextLiteral(textLiteralValue);
					break;
				case EqlNodeType.Keyword:
					if (((EqlKeywordNode)operandNode).Keyword == "null")
						operandString = $"NULL";
					else if (((EqlKeywordNode)operandNode).Keyword == "true")
						operandString = $"TRUE";
					else if (((EqlKeywordNode)operandNode).Keyword == "false")
						operandString = $"FALSE";
					else
						throw new EqlException($"WHERE CLAUSE: Unknown term '{((EqlKeywordNode)operandNode).Keyword}' used as keyword.");
					break;
				case EqlNodeType.RelationField:
					{
						EqlRelationFieldNode relON = ((EqlRelationFieldNode)operandNode);
						if (relON.Relations.Count != 1)
							throw new EqlException($"WHERE CLAUSE: Only first level relation fields can be used in WHERE clause.");

						if (!relationsUsedInWhere.Any(x => x.Relations[0].Name == relON.Relations[0].Name))
							relationsUsedInWhere.Add(relON);

						var entities = entMan.ReadEntities().Object;
						var relations = relMan.Read().Object;

						var relation = relations.SingleOrDefault(x => x.Name == relON.Relations[0].Name);
						if (relation == null)
							throw new EqlException($"WHERE CLAUSE: Relation '{relON.Relations[0].Name}' not found.");

						var originEntity = entities.Single(x => x.Id == relation.OriginEntityId);
						var targetEntity = entities.Single(x => x.Id == relation.TargetEntityId);

						var relatedEntity = targetEntity;
						var suffix = "_org_tar";
						if ( this.fromEntity.Id != originEntity.Id )
						{
							suffix = "_tar_org";
							relatedEntity = originEntity;
						}

						field = relatedEntity.Fields.SingleOrDefault(x => x.Name == relON.FieldName);
						if (field == null)
							throw new EqlException($"WHERE CLAUSE: Field '{relON.FieldName}' not found in entity '{relatedEntity.Name}' from '{relON.Relations[0].Name}'.");

						operandString = relON.Relations[0].Name + suffix + ".\"" + relON.FieldName + "\"";
					}
					break;
			}
			return operandString;
		}

		private string ProcessExpressionNode(EqlBinaryExpressionNode expNode, string entityName, List<EqlRelationFieldNode> relationsUsedInWhere)
		{
			if (expNode == null)
				return null;

			Field firstOperandField, secondOperandField;
			//The first operand's raw literal text is discarded deliberately: no branch below needs it, because
			//a literal is never a legal first operand - the guard immediately after this rejects it.
			string firstOperandString = ProcessExpressionOperandNode(expNode.FirstOperand, entityName, relationsUsedInWhere, out firstOperandField, out _);
			string secondOperandString = ProcessExpressionOperandNode(expNode.SecondOperand, entityName, relationsUsedInWhere, out secondOperandField, out string secondOperandTextLiteral);

			if (!( firstOperandString.StartsWith(" (") || firstOperandString.StartsWith(" to_tsvector") || firstOperandString.StartsWith("@") ) && firstOperandField == null)
				throw new EqlException($"WHERE: First operand in where expressions should always be an entity field name . '{firstOperandString}' is not a field name.");

			if ((firstOperandString == "NULL" || secondOperandString == "NULL") && (expNode.Operator != "=" && expNode.Operator != "<>" && expNode.Operator != "!="))
				throw new EqlException($"WHERE: NULL can be used only with '=' and '<>' comparison.");

			switch (expNode.Operator)
			{
				case "=":
					if (firstOperandString == "NULL") //keyword NULL
						return $" ( {secondOperandString} IS NULL ) ";
					if (secondOperandString == "NULL") //keyword NULL
						return $" ( {firstOperandString} IS NULL ) ";

					if (firstOperandString.StartsWith("@")) //parameter
					{
						string paramName = firstOperandString;
						var param = Parameters.SingleOrDefault(x => x.ParameterName == paramName);
						if (param == null)
							throw new EqlException($"WHERE: Parameter '{paramName}' not found.");

						if (param.Value == null || param.Value == DBNull.Value)
							return $" ( {secondOperandString} IS NULL ) ";
					}
					if (secondOperandString.StartsWith("@")) //parameter
					{
						string paramName = secondOperandString;
						var param = Parameters.SingleOrDefault(x => x.ParameterName == paramName);
						if (param == null)
							throw new EqlException($"WHERE: Parameter '{paramName}' not found.");

						if (param.Value == null || param.Value == DBNull.Value)
							return $" ( {firstOperandString} IS NULL ) ";
					}
					return $" ( {firstOperandString} {expNode.Operator} {secondOperandString} ) ";
				case "!=":
				case "<>":
					if (secondOperandString == "NULL") //keyword NULL
						return $" ( {firstOperandString} IS NOT NULL ) ";
					if (secondOperandString.StartsWith("@")) //parameter
					{
						string paramName = secondOperandString;
						var param = Parameters.SingleOrDefault(x => x.ParameterName == paramName);
						if (param == null)
							throw new EqlException($"WHERE: Parameter '{paramName}' not found.");

						if (param.Value == null || param.Value == DBNull.Value)
							return $" ( {firstOperandString} IS NOT NULL ) ";
					}
					return $" ( {firstOperandString} {expNode.Operator} {secondOperandString} ) ";
				case ">":
				case "<":
				case ">=":
				case "<=":
				case "AND":
				case "OR":
				case "~":
				case "~*":
				case "!~":
				case "!~*":
					return $" ( {firstOperandString} {expNode.Operator} {secondOperandString} ) ";
				case "CONTAINS":
					if (firstOperandField != null)
					{
						if (firstOperandField.GetFieldType() == FieldType.MultiSelectField)
						{
							var result =  $" ( {firstOperandString}  @>  {secondOperandString} ) ";
							string paramName = secondOperandString;
							var param = Parameters.SingleOrDefault(x => x.ParameterName == paramName);
							if (param != null && param.Value != null )
							{
								//if parameter is not array or enumerable, we create new parameter 
								//with array type
								if (!typeof(IEnumerable).IsAssignableFrom(param.Value.GetType()) || param.Value.GetType() == typeof(string))
								{
									string newParamName = $"{secondOperandString}_converted_to_array";
									var newParamValue = new List<string> { param.Value.ToString() };
									Parameters.Add(new EqlParameter(newParamName, newParamValue));
									result = $" ( {firstOperandString}  @>  {newParamName} ) ";
								}
							}
							return result;
						}
						else
						{
							string paramName = secondOperandString;
							var param = Parameters.SingleOrDefault(x => x.ParameterName == paramName);
							if (param == null) throw new EqlException($"WHERE: Parameter '{paramName}' not found.");
							//param.Value = "%" + param.Value + "%";

							return $" ( {firstOperandString}  ILIKE  CONCAT ( '%' , {secondOperandString} , '%' ) )";
						}
					}
					else
						throw new EqlException($"WHERE: CONTAINS first operand should be a field name.");
				case "STARTSWITH":
					if (firstOperandField != null)
					{
						string paramName = secondOperandString;
						var param = Parameters.SingleOrDefault(x => x.ParameterName == paramName);
						if (param == null) throw new EqlException($"WHERE: Parameter '{paramName}' not found.");
						//param.Value = param.Value + "%";

						return $" ( {firstOperandString}  ILIKE CONCAT ( {secondOperandString},'%'  ) ) ";
					}
					else
						throw new EqlException($"WHERE: STARTSWITH first operand should be a field name.");

				case "@@":
					if (firstOperandField != null)
					{
						FtsAnalyzer ftsAnalyzer = new FtsAnalyzer();

						if (secondOperandString.StartsWith("@")) //parameter
						{
							string paramName = secondOperandString;
							var param = Parameters.SingleOrDefault(x => x.ParameterName == paramName);
							if (param == null)
								throw new EqlException($"WHERE: Parameter '{paramName}' not found.");

							string text = (string)param.Value;

							bool singleWord = true;
							if (!string.IsNullOrWhiteSpace(text))
							{
								string analizedText = ftsAnalyzer.ProcessText(text);
								param.Value = analizedText;
								singleWord = analizedText.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).Count() == 1;
							}
							else
								singleWord = false; //in case of empty string, we use plainto_tsquery

							//coalesce(string_agg(tag.name, ' '))
							if (singleWord)
							{
								param.Value = param.Value + ":*"; //search for all lexemes starting with this word
								return $" to_tsvector( 'simple', {firstOperandString} ) @@ to_tsquery( 'simple', {paramName} ) ";
							}
							else
								return $" to_tsvector( 'simple', {firstOperandString} ) @@ plainto_tsquery( 'simple', COALESCE( {paramName}, ' ') ) ";

						}
						else if (secondOperandTextLiteral != null) //text
						{
							//THREAT ADDRESSED - CWE-89, OWASP A03. This branch used to detect a text operand by
							//testing the emitted SQL for a leading quote, then recover its value by trimming the
							//first and last character, then interpolate that value straight back into a quoted
							//literal below - the same unescaped round trip QuoteSqlTextLiteral exists to close.
							//The operand node now hands the raw value back directly, so neither the shape test
							//nor the trimming is needed, and both emissions below are quoted properly.
							var text = secondOperandTextLiteral;

							bool singleWord = true;
							if (!string.IsNullOrWhiteSpace(text))
							{
								text = ftsAnalyzer.ProcessText(text);
								singleWord = text.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).Count() == 1;
							}
							else
								singleWord = false; //in case of empty string, we use plainto_tsquery

							if (singleWord)
							{
								text = text + ":*"; //search for all lexemes starting with this word
								return $" to_tsvector( 'simple', {firstOperandString} ) @@ to_tsquery( 'simple', {QuoteSqlTextLiteral(text)}) ";
							}
							else
								return $" to_tsvector( 'simple', {firstOperandString} ) @@ plainto_tsquery( 'simple', {QuoteSqlTextLiteral(text)}) ";
						}
					}
					else
						throw new EqlException($"WHERE: @@ operator first operand should be a field name.");
					break;
				default:
					throw new EqlException($"WHERE: '{expNode.Operator}' unknown operator");
			}

			return string.Empty;
		}

		private string ProcessWhereJoins(List<EqlRelationFieldNode> relationsUsedInWhere, Entity fromEntity)
		{
			string relationJoinSql = string.Empty;
			List<string> aliases = new List<string>();
			var relations = relMan.Read().Object;
			var entities = entMan.ReadEntities().Object;

			foreach (var relNode in relationsUsedInWhere)
			{
				var relationInfo = relNode.Relations[0];
				var relation = relations.SingleOrDefault(x => x.Name == relationInfo.Name);

				if (relation == null)
					throw new EqlException($"WHERE: Relation with name '{relationInfo.Name}' is not found.");

				var suffix = "_org_tar";
				//if (relNode.Relations[0].Direction == EqlRelationDirectionType.TargetOrigin)
				if (relation.OriginEntityId != fromEntity.Id)
					suffix = "_tar_org";

				var relationAlias = relation.Name + suffix;
				if (aliases.Contains(relationAlias))
					continue;

				aliases.Add(relationAlias);

				if (relation.RelationType == EntityRelationType.OneToOne)
				{
					//when the relation is origin -> target entity
					if (relation.OriginEntityId == fromEntity.Id)
					{
						relationJoinSql += string.Format(FILTER_JOIN,
							RecordTable(relation.TargetEntityName),
							relationAlias,
							relationAlias,
							relation.TargetFieldName,
							RecordTable(relation.OriginEntityName),
							relation.OriginFieldName);
					}
					else //when the relation is target -> origin, we have to query origin entity
					{
						relationJoinSql += string.Format(FILTER_JOIN,
							   RecordTable(relation.OriginEntityName),
							   relationAlias,
							   relationAlias,
							   relation.OriginFieldName,
							   RecordTable(relation.TargetEntityName),
							   relation.TargetFieldName);
					}
				}
				else if (relation.RelationType == EntityRelationType.OneToMany)
				{
					//when origin and target entity are different, then direction don't matter
					if (relation.OriginEntityId != relation.TargetEntityId)
					{
						//when the relation is origin -> target entity
						if (relation.OriginEntityId == fromEntity.Id)
						{
							relationJoinSql += string.Format(FILTER_JOIN,
								RecordTable(relation.TargetEntityName),
								relationAlias,
								relationAlias,
								relation.TargetFieldName,
								 RecordTable(relation.OriginEntityName),
								relation.OriginFieldName);
						}
						else //when the relation is target -> origin, we have to query origin entity
						{
							relationJoinSql += string.Format(FILTER_JOIN,
								 RecordTable(relation.OriginEntityName),
								relationAlias,
								relationAlias,
								relation.OriginFieldName,
								RecordTable(relation.TargetEntityName),
								relation.TargetFieldName);
						}
					}
					else //when the origin entity is same as target entity direction matters
					{
						if (relationInfo.Direction == EqlRelationDirectionType.TargetOrigin)
						{
							relationJoinSql = string.Format(FILTER_JOIN,
								RecordTable(relation.OriginEntityName),
							   relationAlias,
							   relationAlias,
							   relation.OriginFieldName,
							   RecordTable(relation.TargetEntityName),
							   relation.TargetFieldName);
						}
						else
						{
							relationJoinSql += string.Format(FILTER_JOIN,
								RecordTable(relation.TargetEntityName),
								relationAlias,
								relationAlias,
								relation.TargetFieldName,
								 RecordTable(relation.OriginEntityName),
								relation.OriginFieldName);
						}
					}
				}
				else if (relation.RelationType == EntityRelationType.ManyToMany)
				{
					string relationTable = RelationTable(relation.Name);

					string targetJoinTable = RecordTable(relation.TargetEntityName);
					string originJoinTable = RecordTable(relation.OriginEntityName);

					//if target is entity we query
					if (fromEntity.Id == relation.TargetEntityId)
					{
						string targetJoinAlias = relation.Name + "_target";
						string originJoinAlias = relationAlias;

						relationJoinSql += string.Format(FILTER_JOIN,
								 /*LEFT OUTER JOIN*/ relationTable, /* */ targetJoinAlias /*ON*/,
								 targetJoinAlias, /*.*/ "target_id", /* =  */
								 targetJoinTable, /*.*/ relation.TargetFieldName);

						relationJoinSql += Environment.NewLine + string.Format(FILTER_JOIN,
								/*LEFT OUTER JOIN*/ originJoinTable, /* */ originJoinAlias /*ON*/,
								targetJoinAlias, /*.*/ "origin_id", /* =  */
								originJoinAlias, /*.*/ relation.OriginFieldName);
					}
					else // if origin is entity we query
					{
						string targetJoinAlias = relationAlias;
						string originJoinAlias = relation.Name + "_origin";

						relationJoinSql += string.Format(FILTER_JOIN,
								/*LEFT OUTER JOIN*/ relationTable, /* */ originJoinAlias /*ON*/,
								originJoinAlias, /*.*/ "origin_id", /* =  */
								originJoinTable, /*.*/ relation.OriginFieldName);

						relationJoinSql += Environment.NewLine + string.Format(FILTER_JOIN,
								  /*LEFT OUTER JOIN*/ targetJoinTable, /* */ targetJoinAlias /*ON*/,
								originJoinAlias, /*.*/ "target_id", /* =  */
								targetJoinAlias, /*.*/ relation.TargetFieldName);
					}
				}
			}
			return relationJoinSql;

		}
	}
}
