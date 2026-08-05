using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using WebVella.Erp.Api;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Api.Models.AutoMapper;
using WebVella.Erp.Database;
using WebVella.Erp.Utilities;

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
		// Exception this class throws for a missing file.
		private const string PROMOTION_DENIED_MESSAGE = "The requested file could not be published.";

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
				throw new UnauthorizedAccessException(PROMOTION_DENIED_MESSAGE);

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
			//text: both outcomes still answer the caller with a generic denial, so no existence oracle is
			//created - a withheld row now answers PROMOTION_DENIED_MESSAGE, which is the SAME message this
			//method already returns for the namespace test above and for the pinned-move refusal below.
			var tempFile = Fs.Find(path, out var withheldByStagedOwnership);

			//Ordered BEFORE the not-found test, because a withheld row is an authorization outcome and must
			//be reported as one. The distinct exception type is what the calling action switches on - see the
			//PROMOTION_DENIED_MESSAGE remarks at the top of this class for why refusals use a type of their
			//own rather than the plain Exception a missing file raises.
			if (withheldByStagedOwnership)
				throw new UnauthorizedAccessException(PROMOTION_DENIED_MESSAGE);

			if(tempFile == null) {
				throw new Exception("File not found on that path");
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
				throw new UnauthorizedAccessException(PROMOTION_DENIED_MESSAGE);
			var newFileId = Guid.NewGuid();
			userFileRecord["id"] = newFileId;
			userFileRecord["alt"] = alt;
			userFileRecord["caption"] = caption;
			var fileKilobytes = Math.Round(((decimal)tempFile.GetBytes().Length / 1024),2);
			userFileRecord["size"] = fileKilobytes;
			userFileRecord["name"] = Path.GetFileName(path);
			var fileExtension = Path.GetExtension(path);
            var mimeType = MimeMapping.MimeUtility.GetMimeMapping(path);
            if (mimeType.StartsWith("image")) {
				var dimensionsRecord = Helpers.GetImageDimension(tempFile.GetBytes());
				userFileRecord["width"] = (decimal)dimensionsRecord["width"];
				userFileRecord["height"] = (decimal)dimensionsRecord["height"];
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
						throw new UnauthorizedAccessException(PROMOTION_DENIED_MESSAGE);
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
