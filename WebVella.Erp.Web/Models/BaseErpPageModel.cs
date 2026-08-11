using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Encodings.Web;
using System.Web;
using WebVella.Erp.Api.Models;
using WebVella.Erp.Exceptions;
using WebVella.Erp.Web.Services;
using WebVella.Erp.Web.Utils;

namespace WebVella.Erp.Web.Models
{
	[Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
	public class BaseErpPageModel : PageModel
	{
		private ErpUser currentUser = null;
		public ErpUser CurrentUser
		{
			get
			{
				if (currentUser == null)
					currentUser = AuthService.GetUser(User);

				return currentUser;
			}
		}

		[BindProperty(SupportsGet = true)]
		public string AppName { get; set; } = "";

		[BindProperty(SupportsGet = true)]
		public string AreaName { get; set; } = "";

		[BindProperty(SupportsGet = true)]
		public string NodeName { get; set; } = "";

		[BindProperty(SupportsGet = true)]
		public string PageName { get; set; } = "";

		[BindProperty(SupportsGet = true)]
		public Guid? RecordId { get; set; } = null;

		[BindProperty(SupportsGet = true)]
		public Guid? RelationId { get; set; } = null;

		[BindProperty(SupportsGet = true)]
		public Guid? ParentRecordId { get; set; } = null;

		public PageDataModel DataModel { get; protected set; } = null;

		public ErpRequestContext ErpRequestContext { get; protected set; }

		public ErpAppContext ErpAppContext { get; protected set; }

		//public List<string> HeaderActions { get; private set; } = new List<string>(); //Convenience property only

		public List<MenuItem> ToolbarMenu { get; private set; } = new List<MenuItem>();

		public List<MenuItem> SidebarMenu { get; private set; } = new List<MenuItem>();

		public List<MenuItem> SiteMenu { get; private set; } = new List<MenuItem>();

		public List<MenuItem> ApplicationMenu { get; private set; } = new List<MenuItem>();

		public List<MenuItem> UserMenu { get; private set; } = new List<MenuItem>();

		public ValidationException Validation { get; private set; } = new ValidationException();

		private string returnUrl = "";

		/// <summary>
		/// The caller-supplied URL a page returns to when the user cancels or completes an edit.
		/// Always a safe, application-local URL: the setter rejects anything else.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding H-1, CWE-601 (URL redirection to untrusted site / open redirect) and
		/// CWE-79 (cross-site scripting via a dangerous URI scheme), OWASP A03 Injection / A01.
		///
		/// THREAT: this value arrives entirely from the request - by model binding from the query string
		/// or form, and again in Init below from Request.Query - and it reaches two kinds of sink:
		///   * it is emitted as a whole href, so "javascript:alert(document.domain)" executed as script on
		///     this application's own origin the moment a user clicked Cancel; and
		///   * it is passed to Redirect(...), so "//attacker.example/path" sent the user off-site while the
		///     URL bar still showed this application's domain - a credential-phishing redirect.
		/// Razor's automatic HTML encoding, applied earlier in this remediation, closed the ATTRIBUTE
		/// BREAKOUT half of the problem, but encoding cannot make a hostile URL safe: "javascript:..." and
		/// "//attacker.example" contain no characters that HTML encoding alters, so both survived intact.
		/// Validating the SCHEME AND LOCALITY is the only fix, and it has to happen before the value is
		/// stored rather than at each sink.
		///
		/// WHY THE SETTER: sanitizing here makes this property the single chokepoint. Model binding, the
		/// explicit assignment in Init, and any future assignment all pass through it, so every consumer
		/// is covered by construction - 48 Razor views that render this value and 17 call sites that pass
		/// it to Redirect(...), across this assembly and the SDK plugin. Fixing the three views the review
		/// sampled would have left the other 45 and every redirect sink exposed; fixing each sink instead
		/// would mean 65 edits that a 66th consumer could silently miss.
		///
		/// It also removes a latent fault: login.cshtml.cs passes this value to LocalRedirectResult, which
		/// THROWS InvalidOperationException on a non-local URL. A crafted returnUrl therefore turned a
		/// *successful* sign-in into an unhandled exception - a 500 carrying a stack trace to an anonymous
		/// caller. That throw is unreachable now that the value cannot be non-local. (logout.cshtml.cs
		/// reaches LocalRedirectResult too, but passes the constant "/" and was never exposed.)
		///
		/// A derived page model MUST NOT re-declare this property with the "new" modifier. Model binding
		/// targets the most-derived declaration, so a shadowing property silently bypasses this setter and
		/// reintroduces the vulnerability. login.cshtml.cs did exactly that and has been corrected; it is
		/// the reason this warning is recorded here rather than left implicit.
		/// </remarks>
		[BindProperty(Name = "returnUrl", SupportsGet = true)]
		public string ReturnUrl
		{
			get { return returnUrl; }
			set { returnUrl = SanitizeReturnUrl(value); }
		}

		/// <summary>
		/// Reduces a caller-supplied return URL to one that is guaranteed safe to emit as an href and to
		/// pass to a redirect: an application-local, scheme-less path.
		/// </summary>
		/// <remarks>
		/// Applies the same rule as IUrlHelper.IsLocalUrl, implemented directly so that it is a pure
		/// function - it needs no IUrlHelper, no PageContext and no HTTP context, so it is valid during
		/// model binding (before PageContext is assigned) and is unit-testable in isolation. The rule:
		/// a URL is local when it starts with a single '/' not followed by '/' or '\', or with "~/".
		/// Everything else - absolute URLs, protocol-relative "//host", backslash variants, and every
		/// scheme including javascript:, data: and vbscript: - is rejected.
		///
		/// An empty or absent value is preserved as empty rather than rewritten to the fallback, because
		/// most pages are reached with no returnUrl at all and render this value directly into a
		/// return-url attribute; substituting "/" there would change what every one of those pages emits.
		/// A value that is PRESENT but unsafe is replaced with the site root, which is the "fall back to a
		/// safe local route" behaviour, so a hostile link degrades to a harmless one instead of failing.
		/// </remarks>
		internal static string SanitizeReturnUrl(string candidate)
		{
			// Absent means absent: preserve it so pages with no returnUrl render exactly as before.
			if (string.IsNullOrEmpty(candidate))
				return "";

			// Browsers ignore leading and trailing whitespace in a URL, so a validator that does not
			// would accept " javascript:..." and hand the browser something it treats as a scheme.
			var url = candidate.Trim();
			if (url.Length == 0)
				return "";

			// Browsers also strip TAB, CR and LF from WITHIN a scheme, so "java\tscript:alert(1)" is
			// treated as "javascript:". Normalising those away is guesswork; rejecting any value that
			// contains a control character is not, and no legitimate return URL contains one.
			foreach (var character in url)
			{
				if (character < ' ' || character == '\u007f')
					return SafeReturnUrlFallback;
			}

			if (url[0] == '/')
			{
				// "/" alone is the site root and is local.
				if (url.Length == 1)
					return url;

				// "//host" is protocol-relative and "/\host" is the backslash equivalent; both leave the
				// origin, which is precisely the open-redirect vector.
				if (url[1] != '/' && url[1] != '\\')
					return url;

				return SafeReturnUrlFallback;
			}

			// "~/path" is the app-relative form Razor understands.
			if (url.Length > 1 && url[0] == '~' && url[1] == '/')
				return url;

			// Anything else carries a scheme or an authority: not local.
			return SafeReturnUrlFallback;
		}

		/// <summary>
		/// The safe local route an unsafe return URL degrades to.
		/// </summary>
		private const string SafeReturnUrlFallback = "/";

		/// <summary>
		/// HTML-encodes a database-sourced value that is about to be interpolated into the
		/// server-built navigation markup carried by <see cref="MenuItem.Content"/>.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding H-06 (CWE-79 cross-site scripting, OWASP A03:2021 Injection), stored variant.
		/// <para>
		/// THREAT: MenuItem.Content is a markup string composed here and emitted with Html.Raw by
		/// Pages/Shared/NavMenu.cshtml, Pages/Shared/NavItem.cshtml and Components/SiteMenu/SiteMenu.cshtml,
		/// which render on every page of every host. The skeleton of that string - the anchor and the icon
		/// span - is authored by this class and must stay raw: NavItem.cshtml rewrites it AS MARKUP to inject
		/// data-toggle='dropdown' by string-replacing the "&lt;a" tag, so encoding the finished string would
		/// print literal HTML in the navigation and stop every dropdown in the product from toggling. What
		/// carried the injection was never the skeleton; it was the administrator-editable database TEXT
		/// interpolated into it. A sitemap area labelled
		/// &lt;/a&gt;&lt;img src=x onerror=alert(document.cookie)&gt; executed for every authenticated user
		/// who loaded any page. Encoding therefore belongs HERE, at the point of composition, where each
		/// value's context is known - and it is applied to every one of the six database-sourced values that
		/// reach the raw sink: area.Label, node.Label, node.Url, node.IconClass, sitePage.Name and
		/// sitePage.Label.
		/// </para>
		/// <para>
		/// HtmlEncoder.Default is the very encoder Razor's own automatic encoding uses, so an encoded value
		/// renders the identical glyphs a plain @value expression would produce: legitimate labels are
		/// unchanged on screen, which is what preserves user-facing behaviour.
		/// </para>
		/// </remarks>
		private static string EncodeMenuText(string value)
		{
			if (String.IsNullOrEmpty(value))
				return "";

			return HtmlEncoder.Default.Encode(value);
		}

		/// <summary>
		/// Validates a database-sourced menu URL against an allow-list and returns it HTML-encoded for
		/// emission into an href attribute. Returns false when the value must not be emitted at all.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding H-06 (CWE-79, OWASP A03:2021).
		/// <para>
		/// An href is a URL context, and HTML encoding does not neutralise it: "javascript:alert(1)" survives
		/// encoding completely intact, renders as a working link, and executes in the application's own
		/// authenticated origin the moment it is clicked. Only validation closes that, which is why this
		/// method exists in addition to <see cref="EncodeMenuText"/>.
		/// </para>
		/// <para>
		/// ALLOW-LIST - accepted: an application-local path ("/", "/path", but not the protocol-relative
		/// "//host" nor its backslash variant "/\host"), the framework's "~/path" form, a same-page fragment
		/// ("#" or "#anchor"), and an explicit "http://" or "https://" absolute URL, because a sitemap node of
		/// type Url legitimately links off-site. REJECTED: every other scheme - javascript:, data:, vbscript:,
		/// file: and any future one - and any value containing a control character, because browsers ignore
		/// TAB, CR and LF inside a scheme and would treat "java&#9;script:" as active. The rule mirrors the
		/// local-URL test already used for return URLs in this class, extended by the two web schemes.
		/// </para>
		/// <para>
		/// A rejected value degrades to the inert href="#" onclick="return false" anchor this builder already
		/// emits for a node that has no URL at all, so the menu entry stays visible and clicking it does
		/// nothing - an existing, safe rendering rather than an invented one.
		/// </para>
		/// </remarks>
		private static bool TryEncodeMenuUrl(string value, out string encodedUrl)
		{
			encodedUrl = "";

			if (String.IsNullOrWhiteSpace(value))
				return false;

			//Browsers ignore whitespace surrounding a URL, so a validator that does not would accept
			//" javascript:..." and hand the browser something it treats as a scheme.
			var candidate = value.Trim();

			foreach (var character in candidate)
			{
				if (Char.IsControl(character))
					return false;
			}

			var isLocal = (candidate[0] == '/' && (candidate.Length == 1 || (candidate[1] != '/' && candidate[1] != '\\')))
				|| (candidate.Length > 1 && candidate[0] == '~' && candidate[1] == '/')
				|| candidate[0] == '#';

			var isWebScheme = candidate.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
				|| candidate.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

			if (!isLocal && !isWebScheme)
				return false;

			encodedUrl = HtmlEncoder.Default.Encode(candidate);
			return true;
		}

		/// <summary>
		/// Reduces a database-sourced icon class to the character vocabulary a CSS class list may contain,
		/// returning an empty string when the value is anything else.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding H-06 (CWE-79, OWASP A03:2021). node.IconClass is interpolated into a class
		/// attribute inside the raw-rendered menu markup. Encoding alone stops the attribute being closed,
		/// but a class attribute is still no place for arbitrary stored text: the platform's own stylesheets
		/// would honour whatever classes it named, which is a user-interface redressing primitive. An
		/// allow-list of letters, digits, space, hyphen and underscore accepts the entire Font Awesome and
		/// Bootstrap vocabulary these values actually use, and rejects everything else outright. A rejected
		/// value yields an empty class, which is exactly what a sitemap node with no icon configured already
		/// renders today, so the fallback is an existing state rather than a new one. The result is still
		/// encoded, so a non-ASCII letter that passes the allow-list cannot alter the attribute either.
		/// </remarks>
		private static string EncodeMenuIconClass(string value)
		{
			if (String.IsNullOrWhiteSpace(value))
				return "";

			foreach (var character in value)
			{
				if (Char.IsLetterOrDigit(character) || character == ' ' || character == '-' || character == '_')
					continue;

				return "";
			}

			return HtmlEncoder.Default.Encode(value);
		}

		/// <summary>
		/// Percent-encodes a database-sourced value for use as a single URL path segment and HTML-encodes the
		/// result for emission into an href attribute.
		/// </summary>
		/// <remarks>
		/// SECURITY - finding H-06 (CWE-79, OWASP A03:2021). sitePage.Name is interpolated into the "/s/{name}"
		/// path of the site-menu anchor, so it needs URL-segment escaping first and attribute encoding second;
		/// either one alone leaves a gap. Uri.EscapeDataString leaves the unreserved characters a legitimate
		/// page name is made of (letters, digits, hyphen, underscore, period, tilde) untouched, so every
		/// existing site-menu link resolves to exactly the URL it did before.
		/// </remarks>
		private static string EncodeUrlPathSegment(string value)
		{
			if (String.IsNullOrEmpty(value))
				return "";

			return HtmlEncoder.Default.Encode(Uri.EscapeDataString(value));
		}

		public string CurrentUrl { get; set; } = "";

		public string HookKey
		{
			get
			{
				string hookKey = string.Empty;
				if (PageContext.HttpContext.Request.Query.ContainsKey("hookKey"))
					hookKey = HttpContext.Request.Query["hookKey"].ToString();
				return hookKey;
			}
		}

		public IActionResult Init(string appName = "", string areaName = "", string nodeName = "",
						string pageName = "", Guid? recordId = null, Guid? relationId = null, Guid? parentRecordId = null)
		{
			//Stopwatch sw = new Stopwatch();
			//sw.Start();

			if (String.IsNullOrWhiteSpace(appName)) appName = AppName;
			if (String.IsNullOrWhiteSpace(areaName)) areaName = AreaName;
			if (String.IsNullOrWhiteSpace(nodeName)) nodeName = NodeName;
			if (String.IsNullOrWhiteSpace(pageName)) pageName = PageName;
			if (recordId == null) recordId = RecordId;
			if (relationId == null) relationId = RelationId;
			if (parentRecordId == null) parentRecordId = ParentRecordId;

			var urlInfo = new PageService().GetInfoFromPath(HttpContext.Request.Path);
			if (String.IsNullOrWhiteSpace(appName))
			{
				appName = urlInfo.AppName;
				if (AppName != appName)
					AppName = appName; //When dealing with non standard routing in pages
			}
			if (String.IsNullOrWhiteSpace(areaName))
			{
				areaName = urlInfo.AreaName;
				if (AreaName != areaName)
					AreaName = areaName; //When dealing with non standard routing in pages
			}
			if (String.IsNullOrWhiteSpace(nodeName))
			{
				nodeName = urlInfo.NodeName;
				if (NodeName != nodeName)
					NodeName = nodeName; //When dealing with non standard routing in pages
			}
			if (String.IsNullOrWhiteSpace(pageName))
			{
				pageName = urlInfo.PageName;
				if (PageName != pageName)
					PageName = pageName; //When dealing with non standard routing in pages
			}
			if (recordId == null)
			{
				recordId = urlInfo.RecordId;
				if (RecordId != recordId)
					RecordId = recordId; //When dealing with non standard routing in pages
			}
			if (relationId == null)
			{
				relationId = urlInfo.RelationId;
				if (RelationId != relationId)
					RelationId = relationId; //When dealing with non standard routing in pages
			}
			if (parentRecordId == null)
			{
				parentRecordId = urlInfo.ParentRecordId;
				if (ParentRecordId != parentRecordId)
					ParentRecordId = parentRecordId; //When dealing with non standard routing in pages
			}


			ErpRequestContext.SetCurrentApp(appName, areaName, nodeName);
			ErpRequestContext.SetCurrentPage(PageContext, pageName, appName, areaName, nodeName, recordId, relationId, parentRecordId);

			List<Guid> currentUserRoles = new List<Guid>();
			if (CurrentUser != null)
				currentUserRoles.AddRange(CurrentUser.Roles.Select(x => x.Id));

			if (ErpRequestContext.App != null)
			{
				if (ErpRequestContext.App.Access == null || ErpRequestContext.App.Access.Count == 0)
					return new LocalRedirectResult("/error?401");

				IEnumerable<Guid> rolesWithAccess = ErpRequestContext.App.Access.Intersect(currentUserRoles);
				if (!rolesWithAccess.Any())
					return new LocalRedirectResult("/error?401");
			}
			else if (!currentUserRoles.Contains(WebVella.Erp.Api.SystemIds.AdministratorRoleId) && urlInfo.PageType != PageType.Home && urlInfo.PageType != PageType.Site)
			{
				return new LocalRedirectResult("/error?401");
			}

			ErpRequestContext.RecordId = recordId;
			ErpRequestContext.RelationId = relationId;
			ErpRequestContext.ParentRecordId = parentRecordId;
			ErpRequestContext.PageContext = PageContext;



			if (PageContext.HttpContext.Request.Query.ContainsKey("returnUrl"))
			{
				ReturnUrl = HttpUtility.UrlDecode(PageContext.HttpContext.Request.Query["returnUrl"].ToString());
			}
			//SECURITY (CWE-79 reflected XSS / CWE-601 open redirect / OWASP A03:2021 Injection):
			//ReturnUrl is attacker-supplied, URL-DECODED request input - it arrives either through the
			//[BindProperty(Name = "returnUrl", SupportsGet = true)] binder declared above or through the
			//explicit UrlDecode immediately above - and it then flows unchanged into anchor href values,
			//into the return-url attribute of the page-header tag helper, and into Redirect(ReturnUrl)
			//after POST. HTML-encoding those sinks stops a crafted value from breaking out of the
			//surrounding attribute, but it does NOT constrain the value as a URL: "javascript:alert(1)"
			//passes through encoding untouched and executes in this application's authenticated origin
			//when the link is clicked, while "https://evil.example" or "//evil.example" turns the
			//platform into an open redirector. Validation is the only control that closes those, so it
			//is applied HERE, at the single point where ReturnUrl is resolved, rather than at each of
			//the sinks - one check covers every consumer and none can be forgotten.
			//The call is unconditional on purpose so that it also covers the model-binder path, which
			//the surrounding query-string test above does not reach.
			//A rejected value degrades to an empty string, which is exactly what every page model
			//already treats as "no return URL supplied" and answers with its own server-authored local
			//default - so existing navigation behaviour is preserved rather than broken.
			ReturnUrl = PageUtils.GetSafeReturnUrl(ReturnUrl);
			ErpAppContext = ErpAppContext.Current;
			CurrentUrl = PageUtils.GetCurrentUrl(PageContext.HttpContext);

			#region << Init Navigation >>
			//Application navigation
			if (ErpRequestContext.App != null)
			{
				var sitemap = ErpRequestContext.App.Sitemap;
				var appPages = new PageService().GetAppControlledPages(ErpRequestContext.App.Id);
				//Calculate node Urls
				foreach (var area in sitemap.Areas)
				{
					foreach (var currentNode in area.Nodes)
					{
						switch (currentNode.Type)
						{
							case SitemapNodeType.ApplicationPage:
								var nodePages = appPages.FindAll(x => x.NodeId == currentNode.Id).ToList();
								//Case 1: Node has attached pages
								if (nodePages.Count > 0)
								{
									nodePages = nodePages.OrderBy(x => x.Weight).ToList();
									currentNode.Url = $"/{ErpRequestContext.App.Name}/{area.Name}/{currentNode.Name}/a/{nodePages[0].Name}";
								}
								else
								{
									var firstAppPage = appPages.FindAll(x => x.Type == PageType.Application).OrderBy(x => x.Weight).FirstOrDefault();
									if (firstAppPage == null)
										currentNode.Url = $"/{ErpRequestContext.App.Name}/{area.Name}/{currentNode.Name}/a/";
									else
										currentNode.Url = $"/{ErpRequestContext.App.Name}/{area.Name}/{currentNode.Name}/a/{firstAppPage.Name}";
								}
								break;
							case SitemapNodeType.EntityList:
								var firstListPage = appPages.FindAll(x => x.Type == PageType.RecordList && x.EntityId == currentNode.EntityId).OrderBy(x => x.Weight).FirstOrDefault();
								if (firstListPage == null)
									currentNode.Url = $"/{ErpRequestContext.App.Name}/{area.Name}/{currentNode.Name}/l/";
								else
									currentNode.Url = $"/{ErpRequestContext.App.Name}/{area.Name}/{currentNode.Name}/l/{firstListPage.Name}";
								break;
							case SitemapNodeType.Url:
								//Do nothing
								break;
							default:
								throw new Exception("Type not found");
						}
						continue;
					}
				}
				//Convert to MenuItem
				foreach (var area in sitemap.Areas)
				{
					if (area.Nodes.Count == 0)
						continue;

					var areaMenuItem = new MenuItem();
					if (area.Nodes.Count > 1)
					{
						//SECURITY - H-06 (CWE-79, OWASP A03): area.Label is administrator-editable database
						//text interpolated into markup that NavMenu/NavItem emit with Html.Raw on every page
						//of every host. The markup skeleton stays server-authored and raw; the value is
						//encoded here, at the point of composition. See EncodeMenuText.
						var areaLabel = EncodeMenuText(area.Label);
						var areaLink = $"<a href=\"javascript: void(0)\" title=\"{areaLabel}\" data-navclick-handler>";
						areaLink += $"<span class=\"menu-label\">{areaLabel}</span>";
						areaLink += $"<span class=\"menu-nav-icon fa fa-angle-down nav-caret\"></span>";
						areaLink += $"</a>";
						areaMenuItem = new MenuItem()
						{
							Id = area.Id,
							Content = areaLink
						};

						foreach (var node in area.Nodes)
						{
							var nodeLink = "";
							//SECURITY - H-06 (CWE-79, OWASP A03): node.Label, node.IconClass and node.Url are
							//database text reaching the raw menu sink. Text and attribute values are encoded;
							//the URL is additionally allow-listed, because encoding does not neutralise a
							//"javascript:" href - it renders as a working link and executes on click. A URL
							//that is absent OR rejected takes the inert anchor below, which is the same
							//rendering a node without a URL already produced.
							var nodeLabel = EncodeMenuText(node.Label);
							var nodeIconClass = EncodeMenuIconClass(node.IconClass);
							if (TryEncodeMenuUrl(node.Url, out string nodeUrl))
							{
								nodeLink = $"<a class=\"dropdown-item\" href=\"{nodeUrl}\" title=\"{nodeLabel}\"><span class=\"{nodeIconClass} icon fa-fw\"></span>{nodeLabel}</a>";
							}
							else
							{
								nodeLink = $"<a class=\"dropdown-item\" href=\"#\" onclick=\"return false\" title=\"{nodeLabel}\"><span class=\"{nodeIconClass} icon fa-fw\"></span>{nodeLabel}</a>";
							}
							areaMenuItem.Nodes.Add(new MenuItem()
							{
								Content = nodeLink,
								Id = node.Id,
								ParentId = node.ParentId,
								SortOrder = node.Weight
							});
						}
					}
					else if (area.Nodes.Count == 1)
					{
						//SECURITY - H-06 (CWE-79, OWASP A03): same treatment as the multi-node branch above.
						//The label is encoded and the single node's URL allow-listed. An ABSENT URL keeps
						//emitting an empty href exactly as before, so that existing rendering is untouched;
						//only a URL that fails the allow-list degrades to the inert "#".
						var areaLabel = EncodeMenuText(area.Label);
						var areaNodeUrl = "";
						if (!String.IsNullOrWhiteSpace(area.Nodes[0].Url))
						{
							if (!TryEncodeMenuUrl(area.Nodes[0].Url, out areaNodeUrl))
								areaNodeUrl = "#";
						}
						var areaLink = $"<a href=\"{areaNodeUrl}\" title=\"{areaLabel}\">";
						areaLink += $"<span class=\"menu-label\">{areaLabel}</span>";
						areaLink += $"</a>";
						areaMenuItem = new MenuItem()
						{
							Content = areaLink,
							Id = area.Nodes[0].Id,
							ParentId = area.Nodes[0].ParentId,
							SortOrder = area.Nodes[0].Weight
						};
					}

					if (ErpRequestContext.SitemapArea == null && ErpRequestContext.Page != null && ErpRequestContext.Page.Type != PageType.Application)
					{
						Debug.WriteLine("<><><><> ERP results in page not found");
						return new NotFoundResult();
					}

					if (ErpRequestContext.SitemapArea != null && area.Id == ErpRequestContext.SitemapArea.Id)
						areaMenuItem.Class = "current";

					//Process the an unusual case when the area has a node type URL which has a link to an app Page or a site page.
					//Then there is no SitemapArea in the ErpRequest as the URL does not has the information about one but still it needs to be 
					//marked as current
					if (ErpRequestContext.SitemapArea == null)
					{
						var urlNodes = area.Nodes.FindAll(x => x.Type == SitemapNodeType.Url);
						var path = HttpContext.Request.Path;
						foreach (var urlNode in urlNodes)
						{
							if (path == urlNode.Url)
							{
								areaMenuItem.Class = "current";
							}
						}
					}

					ApplicationMenu.Add(areaMenuItem);
				}
			}

			//Site menu
			var pageSrv = new PageService();
			var sitePages = pageSrv.GetSitePages();
			foreach (var sitePage in sitePages)
			{
				if (sitePage.Weight < 1000)
				{
					//SECURITY - H-06 (CWE-79, OWASP A03): sitePage.Name lands in a URL path segment and
					//sitePage.Label in element text, both inside markup SiteMenu.cshtml emits with Html.Raw.
					//The name is percent-encoded for the path then attribute-encoded; the label is HTML-encoded.
					SiteMenu.Add(new MenuItem()
					{
						Content = $"<a class=\"dropdown-item\" href=\"/s/{EncodeUrlPathSegment(sitePage.Name)}\">{EncodeMenuText(sitePage.Label)}</a>"
					});
				}
			}


			#endregion


			DataModel = new PageDataModel(this);

			//Debug.WriteLine(">>>>>>>>>>>>>>>>>>>>>>>>>> Base page init: " + sw.ElapsedMilliseconds);
			return null;
		}

		protected bool RecordsExists()
		{
			if (RecordId.HasValue && DataModel.GetProperty("Record") == null)
				return false;
			if (ParentRecordId.HasValue && DataModel.GetProperty("ParentRecord") == null)
				return false;

			return true;
		}

		protected void ValidateRecordSubmission(EntityRecord postObject, Entity entity, ValidationException validation)
		{
			if (entity == null || postObject == null || postObject.Properties.Count == 0 || validation == null)
				return;

			foreach (var property in postObject.Properties)
			{
				//TODO relations validation
				if (property.Key.StartsWith("$"))
					continue;

				Field fieldMeta = entity.Fields.FirstOrDefault(x => x.Name == property.Key);
				if (fieldMeta != null)
				{
					switch (fieldMeta.GetFieldType())
					{
						//case FieldType.AutoNumberField:
						//	if (property.Value != null && !String.IsNullOrWhiteSpace(property.Value.ToString()))
						//	{
						//		validation.Errors.Add(new ValidationError(property.Key, "Autonumber field value should be null or empty string"));
						//	}
						//	break;
						default:
							if (fieldMeta.Required &&
								(property.Value == null || String.IsNullOrWhiteSpace(property.Value.ToString())))
							{
								validation.Errors.Add(new ValidationError(property.Key, "Required"));
							}
							break;
					}
				}
			}
		}

		public object TryGetDataSourceProperty(string propertyName)
		{
			if (DataModel == null)
				return null;

			var dataSource = DataModel.GetProperty(propertyName);
			if (dataSource != null)
				return dataSource;

			return null;
		}

		public T TryGetDataSourceProperty<T>(string propertyName)
		{
			if (DataModel == null)
				return default(T);

			var dataSource = DataModel.GetProperty(propertyName);
			if (dataSource != null && dataSource is T)
				return (T)dataSource;

			return default(T);
		}

		public static BaseErpPageModel CreatePageModelSimulation(
			ErpRequestContext erpRequestContext,
			ErpUser currentUser
		)
		{
			var pageModel = new BaseErpPageModel();
			pageModel.ErpRequestContext = erpRequestContext;
			pageModel.currentUser = currentUser;
			pageModel.AppName = erpRequestContext.App != null ? erpRequestContext.App.Name : "";
			pageModel.AreaName = erpRequestContext.SitemapArea != null ? erpRequestContext.SitemapArea.Name : "";
			pageModel.NodeName = erpRequestContext.SitemapNode != null ? erpRequestContext.SitemapNode.Name : "";
			pageModel.PageName = erpRequestContext.Page != null ? erpRequestContext.Page.Name : "";
			pageModel.RecordId = erpRequestContext.RecordId;
			pageModel.DataModel = new PageDataModel(pageModel);
			return pageModel;
		}

		public void AddUserMenu(MenuItem menu)
		{
			UserMenu.Add(menu);
			UserMenu = UserMenu.OrderBy(x => x.SortOrder).ToList();
		}

		public void BeforeRender()
		{

			#region << Set BodyClass >>
			ViewData["BodyBorderColor"] = "#555";
			if (ErpRequestContext.App != null && !String.IsNullOrWhiteSpace(ErpRequestContext.App.Color))
			{
				ViewData["BodyBorderColor"] = ErpRequestContext.App.Color;
			}
			if (ToolbarMenu.Count > 0)
			{
				var bodyClass = ViewData.ContainsKey("BodyClass") ? ViewData["BodyClass"].ToString().ToLowerInvariant() : "";
				if (!bodyClass.Contains("has-toolbar"))
				{
					ViewData["BodyClass"] = bodyClass + " has-toolbar ";
				}
			}
			if (SidebarMenu.Count > 0)
			{
				var bodyClass = ViewData.ContainsKey("BodyClass") ? ViewData["BodyClass"].ToString().ToLowerInvariant() : "";
				var classAddon = "";
				if (!bodyClass.Contains("sidebar-"))
				{
					if (CurrentUser != null && !String.IsNullOrWhiteSpace(CurrentUser.Preferences.SidebarSize))
					{
						if (CurrentUser.Preferences.SidebarSize != "lg")
							CurrentUser.Preferences.SidebarSize = "sm";

						classAddon = $" sidebar-{CurrentUser.Preferences.SidebarSize} ";
					}
					else
					{
						classAddon = " sidebar-sm ";
					}
					ViewData["BodyClass"] = bodyClass + classAddon;
				}
			}
			ViewData["AppName"] = ErpSettings.AppName;
			ViewData["SystemMasterBodyStyle"] = "";
			if (!String.IsNullOrWhiteSpace(ErpSettings.SystemMasterBackgroundImageUrl))
			{
				ViewData["SystemMasterBodyStyle"] = "background-image: url('" + ErpSettings.SystemMasterBackgroundImageUrl + "');background-position: top center;background-repeat: repeat;min-height: 100vh; ";
			}
			#endregion
		}

	}
}
