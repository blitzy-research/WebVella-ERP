using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Api.Models.AutoMapper;
using WebVella.Erp.Database;
using WebVella.Erp.Utilities;
using WebVella.Erp.Web.Utils;

namespace WebVella.Erp.Web.Services
{
	public class UserFileService : BaseService
	{
		// THREAT ADDRESSED - insecure direct object reference, CWE-639 (authorization bypass through a
		// user-controlled key), OWASP A01:2021 Broken Access Control. CreateUserFile PROMOTES the file named
		// by a caller-supplied path into the shared media library, and the path was accepted verbatim: any
		// authenticated caller could name a path belonging to somebody else and have that file relocated
		// under a record they own. Two constraints close it, and both are required:
		//   the source must be inside the temporary staging namespace, because promotion is defined as
		//   "publish the upload I just made" and a staged upload is the only legitimate source. This alone
		//   removes every already-published path - record attachments and existing media - from reach;
		//   the staged file must belong to the caller, because staging is per-user.
		// Refusal is reported as UnauthorizedAccessException so the calling action can answer with a generic
		// denial rather than the exception text, which is why a distinct type is used rather than the plain
		// Exception this class throws for genuinely unexpected faults.
		private const string PROMOTION_DENIED_MESSAGE = "The requested file could not be published.";

		// Bound applied to the caller-supplied path before it reaches an audit record. Matches the bound the
		// sibling refusal writers in WebApiController and DbFileRepository apply.
		private const int MAX_LOGGED_PATH_LENGTH = 400;

		/// <summary>
		/// Records one promotion refusal and returns the exception that reports it to the calling action.
		/// </summary>
		/// <param name="requestedPath">The normalised, caller-supplied path the refusal concerns.</param>
		/// <param name="reason">
		/// One of this class's own fixed literals. It is the ONLY place the specific cause of the refusal
		/// survives, and it never leaves the server.
		/// </param>
		/// <param name="recordedByRepository">
		/// True when <see cref="DbFileRepository.Find(string, out bool)"/> has already written this exact
		/// refusal, in which case no second record is written here.
		/// </param>
		/// <remarks>
		/// THREAT ADDRESSED - CWE-200 (exposure of sensitive information to an unauthorized actor) and
		/// CWE-639 (authorization bypass through a user-controlled key), OWASP A01:2021. The five refusal
		/// outcomes of a promotion did not answer identically. Four raised
		/// <see cref="UnauthorizedAccessException"/> and reached the caller as this class's generic denial,
		/// but the fifth - "no row at that staged path" - raised a plain exception, fell through to the
		/// calling action's general fault handler and came back as the platform's INTERNAL error message
		/// instead. Two distinguishable production responses over one caller-supplied path is an ORACLE: a
		/// caller could enumerate which staged paths hold real files belonging to somebody else, which is
		/// precisely the information the ownership rule exists to withhold. Every outcome now produces the
		/// same status, the same envelope and the same text, and the distinction survives only in the
		/// server-side record - which is where a distinction between "absent" and "not yours" is useful and
		/// harmless.
		/// <para>
		/// THREAT ADDRESSED - CWE-779 (logging of excessive data), OWASP A09:2021, and the reason this method
		/// owns the record rather than the calling action. The action wrote a refusal row for every
		/// <see cref="UnauthorizedAccessException"/> it caught, and one of the five outcomes - a staged row
		/// withheld by the ownership rule - had ALREADY been recorded, accurately and with the acting
		/// identity, by the repository at the moment it withheld the row. One probe therefore persisted two
		/// rows, so an attacker's own volume inflated the table that the authentication and authorization
		/// trail shares. Exactly one layer owns each refusal now: the repository owns the withheld case, this
		/// method owns the four it can observe and the repository cannot, and the action writes none.
		/// </para>
		/// <para>
		/// The sink is <see cref="SecurityAuditLog"/> rather than <c>LogService</c>, whose exception overload
		/// sends an outbound SMTP message BEFORE it persists and whose notification parameter defaults to
		/// that mailing path - so a caller probing paths could otherwise generate one e-mail per attempt.
		/// SecurityAuditLog owns that choice centrally, never throws, and counts any record it cannot
		/// persist. The caller-supplied path is bounded, quoted and control-character neutralised by
		/// <see cref="SecurityAuditLog.Field(string, int)"/> (CWE-117) so it can forge neither a field nor a
		/// record; <c>user_id</c> and <c>reason</c> are left unquoted because both are values this code
		/// chooses rather than values the caller supplies.
		/// </para>
		/// </remarks>
		private static UnauthorizedAccessException PromotionRefused(string requestedPath, string reason, bool recordedByRepository = false)
		{
			if (!recordedByRepository)
			{
				var currentUser = SecurityContext.CurrentUser;
				SecurityAuditLog.Write(Diagnostics.LogType.Error, "UserFileService:CreateUserFile",
					"Authorization failure: user file publication refused.",
					"user_id=" + (currentUser == null ? "anonymous" : currentUser.Id.ToString())
						+ "; requested_path=" + SecurityAuditLog.Field(requestedPath, MAX_LOGGED_PATH_LENGTH)
						+ "; reason=" + reason);
			}

			return new UnauthorizedAccessException(PROMOTION_DENIED_MESSAGE);
		}

		public List<UserFile> GetFilesList(string type = "", string search = "",  int sort = 1, int page = 1, int pageSize = 30)
		{
			//sort -> 1(created on), 2(filename alpha)
			//type -> image,document,audio,video
			var skipCount = (page-1)*pageSize;


			var listSorts = new List<QuerySortObject>();
			switch(sort) {
				case 1:
					listSorts.Add(new QuerySortObject("created_on", QuerySortType.Descending));
					break;
				case 2:
					listSorts.Add(new QuerySortObject("name", QuerySortType.Ascending));
					break;
			}

			var filters = new List<QueryObject>();
			if(!String.IsNullOrWhiteSpace(search)) {
				filters.Add(EntityQuery.QueryOR(EntityQuery.QueryContains("name",search),EntityQuery.QueryContains("alt",search),EntityQuery.QueryContains("caption",search)));
			}
			if(!String.IsNullOrWhiteSpace(type)) {
				filters.Add(EntityQuery.QueryContains("type",type));
			}
			var filterQuery = EntityQuery.QueryAND(filters.ToArray());

			EntityQuery query = new EntityQuery("user_file", UserFile.GetQueryColumns(), filterQuery, listSorts.ToArray(),skipCount,pageSize);
			QueryResponse response = RecMan.Find(query);
			if (!response.Success)
				throw new Exception(response.Message);

			var files = response.Object.Data.MapTo<UserFile>();

			return FilterByOwnership(files);
		}

		// THREAT ADDRESSED - insecure direct object reference through list enumeration, CWE-639, OWASP A01:2021
		// Broken Access Control. The user_file entity grants read to the REGULAR role as well as to
		// administrators (verified in the provisioned entity's record permissions), so this listing handed every
		// caller the name, size and STORAGE PATH of every other user's uploaded media. The paths are what make
		// that more than an information leak: they are the input the promotion and mutation paths take.
		//
		// The filter has to be applied here, in application code, rather than as a query predicate, because the
		// owner is recorded on the FILE row and the user_file RECORD table has no owner column at all. Adding one
		// would be a schema change, which this remediation is not permitted to make - so ownership is resolved
		// from the file store in a single bulk round trip instead.
		//
		// A file with NO recorded owner stays visible. That is deliberate and is the same rule the download path
		// applies: an unowned file is a shared platform asset, and every media item stored before uploads began
		// recording their uploader is unowned - hiding them would empty the media library on every existing
		// installation, which is a functionality regression rather than a control. What is closed is the case
		// that actually matters: media OWNED by a different user is no longer listed to a non-administrator.
		//
		// Filtering after paging can return fewer rows than the requested page size. That is unavoidable without
		// an owner column to filter on in SQL, and it is the correct trade: a short page is a cosmetic artefact,
		// whereas leaking another user's storage paths is the finding.
		private List<UserFile> FilterByOwnership(List<UserFile> files)
		{
			if (files == null || files.Count == 0)
				return files;

			//deny-by-default: an unresolvable principal is shown nothing. ErpMiddleware opens a security scope
			//for every authenticated request, so this is null only outside a request scope.
			var currentUser = SecurityContext.CurrentUser;
			if (currentUser == null)
				return new List<UserFile>();

			//administrators manage the whole library, so their view is unchanged
			if (currentUser.IsAdmin)
				return files;

			var owners = Fs.FindOwnersByPaths(files.Select(f => f.Path).Where(p => !string.IsNullOrWhiteSpace(p)).ToList());

			var visible = new List<UserFile>();
			foreach (var file in files)
			{
				if (string.IsNullOrWhiteSpace(file.Path))
					continue;

				var normalizedPath = file.Path.ToLowerInvariant();
				if (!normalizedPath.StartsWith(DbFileRepository.FOLDER_SEPARATOR, StringComparison.Ordinal))
					normalizedPath = DbFileRepository.FOLDER_SEPARATOR + normalizedPath;

				//a record whose file row is missing is a dangling reference - it carries no owner to compare
				//against, and it was already listed before this change, so it stays listed
				if (!owners.TryGetValue(normalizedPath, out Guid? createdBy))
				{
					visible.Add(file);
					continue;
				}

				if (!createdBy.HasValue || createdBy.Value == currentUser.Id)
					visible.Add(file);
			}

			return visible;
		}

		public UserFile CreateUserFile(string path = "", string alt = "",  string caption = "")
		{
			var userFileRecord = new EntityRecord();
			if(path.StartsWith("/fs")) {
				path = path.Substring(3);
			}

			//see PROMOTION_DENIED_MESSAGE above for the threat. The namespace test comes FIRST because it is
			//the cheapest refusal and because it answers without revealing whether the named path exists.
			//The comparison is made on a normalised COPY: `path` itself must keep its original casing, since
			//the file name taken from it below becomes the stored record name and the published path.
			var normalizedSourcePath = (path ?? string.Empty).ToLowerInvariant();
			if (!normalizedSourcePath.StartsWith(DbFileRepository.FOLDER_SEPARATOR, StringComparison.Ordinal))
				normalizedSourcePath = DbFileRepository.FOLDER_SEPARATOR + normalizedSourcePath;

			var temporaryNamespacePrefix = DbFileRepository.FOLDER_SEPARATOR + DbFileRepository.TMP_FOLDER_NAME + DbFileRepository.FOLDER_SEPARATOR;
			if (!normalizedSourcePath.StartsWith(temporaryNamespacePrefix, StringComparison.Ordinal))
				throw PromotionRefused(normalizedSourcePath, "source path is outside the staging namespace");

			//THREAT ADDRESSED - CWE-778 (insufficient logging) and the audit MISCLASSIFICATION it produces,
			//OWASP A09:2021. The ownership guard immediately below was UNREACHABLE for the case it was
			//written for: DbFileRepository.Find withholds a staged row the caller does not own by answering
			//null - deliberately, so a client cannot tell "not yours" from "no such path" - which is
			//indistinguishable from a genuinely missing file at THIS call site, so the plain Exception on the
			//not-found line fired first. The calling action's dedicated UnauthorizedAccessException clause
			//therefore never ran, and a deliberate access-control refusal was filed by the general handler as
			//"Unhandled fault: Exception" - a system fault an operator would triage as a bug, which is
			//exactly the signal the "log authorization failures" requirement exists to produce correctly.
			//
			//The overload reports the withheld case WITHOUT changing the access decision or the response
			//text: a withheld row answers PROMOTION_DENIED_MESSAGE, the SAME message the namespace test above
			//and the pinned-move refusal below return.
			//
			//That alone did NOT close the existence oracle, and an earlier revision of this comment claimed
			//it did. Reclassifying the withheld case left the NOT-FOUND case still raising a plain exception,
			//which the calling action answered with a different production message - so the two remained
			//distinguishable on the wire and the oracle survived where the two lines below now close it.
			var tempFile = Fs.Find(path, out var withheldByStagedOwnership);

			//Ordered BEFORE the not-found test, because a withheld row is an authorization outcome and must
			//be classified as one server-side. recordedByRepository suppresses a SECOND audit row here: the
			//repository wrote this exact refusal, with the acting identity and the neutralised path, at the
			//moment it withheld the row - see the PromotionRefused remarks at the top of this class.
			if (withheldByStagedOwnership)
				throw PromotionRefused(normalizedSourcePath, "staged file withheld by the ownership rule", recordedByRepository: true);

			//THREAT ADDRESSED - CWE-200, OWASP A01:2021. This raised a plain Exception, which the calling
			//action's general fault handler answered with the platform's INTERNAL error message while every
			//other refusal here answered with the generic denial - so the two were distinguishable and a
			//caller could use the difference to learn whether a staged path it did not own actually existed.
			//It now answers exactly as the other four do, and only the server-side record says which it was.
			if(tempFile == null) {
				throw PromotionRefused(normalizedSourcePath, "no file exists at the staged path");
			}

			//the staged file must be the caller's own. Deny-by-default at every uncertain edge: an
			//unresolvable principal and a staged file with no recorded owner both refuse for a
			//non-administrator, which matches the rule the file move and delete paths already apply. The
			//uploader is recorded at every upload site, so a file staged through the platform's own upload
			//endpoints always satisfies this for the user who staged it.
			var currentUser = SecurityContext.CurrentUser;
			var isPromotionAuthorized = currentUser != null
				&& (currentUser.IsAdmin || (tempFile.CreatedBy.HasValue && tempFile.CreatedBy.Value == currentUser.Id));

			if (!isPromotionAuthorized)
			{
				//The three reasons are the same three the repository's staged-refusal writer records, so the
				//two audit trails describe the same decision in the same vocabulary. Each is a fixed literal
				//chosen here rather than any caller-supplied value.
				var refusalReason = currentUser == null
					? "unresolved principal"
					: (tempFile.CreatedBy.HasValue ? "caller is not the owner of the staged file" : "staged file has no recorded owner");

				throw PromotionRefused(normalizedSourcePath, refusalReason);
			}

			var newFileId = Guid.NewGuid();
			userFileRecord["id"] = newFileId;
			userFileRecord["alt"] = alt;
			userFileRecord["caption"] = caption;
			var fileKilobytes = Math.Round(((decimal)tempFile.GetBytes().Length / 1024),2);
			userFileRecord["size"] = fileKilobytes;
			userFileRecord["name"] = Path.GetFileName(path);
			var fileExtension = Path.GetExtension(path);
            var mimeType = MimeMapping.MimeUtility.GetMimeMapping(path);
			//THREAT ADDRESSED - review finding M-08 (CWE-400 uncontrolled resource consumption / CWE-1188
			//reliance on platform behaviour this platform does not provide). Helpers.GetImageDimension now
			//reads the dimensions from the image header instead of decoding the image, and returns NULL when
			//the header cannot be read. This site dereferenced the result unconditionally, so on Linux the
			//Windows-only GDI+ facade it previously used threw TypeInitializationException and promoting ANY
			//staged image to a user file failed. Dimensions are metadata rather than a security property, so
			//"unknown" omits the two fields exactly as a non-image file does and the promotion still succeeds.
            if (mimeType.StartsWith("image")) {
				var dimensionsRecord = Helpers.GetImageDimension(tempFile.GetBytes());
				if (dimensionsRecord != null) {
					userFileRecord["width"] = (decimal)dimensionsRecord["width"];
					userFileRecord["height"] = (decimal)dimensionsRecord["height"];
				}
				userFileRecord["type"] = "image";
			}
			else if(mimeType.StartsWith("video")) {
				userFileRecord["type"] = "video";
			}
			else if(mimeType.StartsWith("audio")) {
				userFileRecord["type"] = "audio";
			}
			else if(fileExtension == ".doc" || fileExtension == ".docx"  || fileExtension == ".odt"  || fileExtension == ".rtf"
			 || fileExtension == ".txt"  || fileExtension == ".pdf"  || fileExtension == ".html"  || fileExtension == ".htm"  || fileExtension == ".ppt"
			  || fileExtension == ".pptx"  || fileExtension == ".xls"  || fileExtension == ".xlsx"  || fileExtension == ".ods"  || fileExtension == ".odp" ) {
				userFileRecord["type"] = "document";
			}
			else {
				userFileRecord["type"] = "other";
			}

			var newFilePath = $"/file/{newFileId}/{Path.GetFileName(path)}";

			using (DbConnection con = DbContext.Current.CreateConnection())
			{
				con.BeginTransaction();
				try
				{
					//the identifier resolved during the authorization check above is pinned onto the move, so
					//the row that is relocated is provably the row that was authorized. Without it the check
					//and the mutation are two independent statements against a caller-supplied path, and a
					//substitution landing between them would relocate a row nobody authorized. Move answers
					//null when the pinned row is no longer at that path, which is refused as a denial rather
					//than reported as a failure.
					var file = Fs.Move(path,newFilePath,false,tempFile.Id);
					if(file == null) {
						throw PromotionRefused(normalizedSourcePath, "the authorized staged row is no longer at that path");
					}

					userFileRecord["path"] = newFilePath;
					var response = RecMan.CreateRecord("user_file",userFileRecord);
					if(!response.Success)
						throw new Exception(response.Message);

					userFileRecord = response.Object.Data.First();
					con.CommitTransaction();
				}
				catch (Exception)
				{
					con.RollbackTransaction();
					throw;
				}
			}
			return userFileRecord.MapTo<UserFile>();
		}

	}
}
