=========================================================================
1. add to web site project 
<PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="10.0.1" />


=========================================================================
2. Config.json   (that exact spelling - see the note at the end of this file)

add in settings section

"Jwt": {
	"Key": "",
	"Issuer": "webvella-erp",
	"Audience": "webvella-erp"
}

SECURITY - findings H-04 (High, weak bearer-token signing key) and H-05; CWE-798 use of
hard-coded credentials, CWE-321 use of a hard-coded cryptographic key; OWASP A02:2021
Cryptographic Failures.
THREAT: earlier revisions of this note published a literal signing key, and the very same
literal shipped inside Config.json. Anyone who could read this public repository could mint a
valid bearer token for any user of any deployment that had not replaced it, and the key could
be neither rotated nor revoked because it was identical everywhere.
INVARIANT: the Key entry stays EMPTY in every tracked file. The value is supplied per deployment,
out of band, and never through this file or any other tracked file.

TWO SPELLINGS OF ONE SETTING - do not mix them up. Settings:Jwt:Key, with single colons, is the
configuration key path: it is the form used in code (Configuration["Settings:Jwt:Key"], step 3
below) and the form the dotnet user-secrets CLI takes. Settings__Jwt__Key, with double
underscores, is the environment-variable name and nothing else - a double underscore is simply
how an environment variable spells the ':' section separator, so both name the same setting.

RESOLUTION ORDER: Config.json is read first, then environment variables override it, then in
Development only, user secrets override those. The empty entry above is therefore a placeholder
that the environment fills in at run time, not a default anyone has to edit in place.

GENERATE the value with a cryptographically secure random generator - never a passphrase, a
dictionary word, or a literal reused across deployments:

	Settings__Jwt__Key=$(openssl rand -base64 48)

HS256 signs with HMAC-SHA-256, so RFC 7518 section 3.2 requires a key at least as long as the
hash it feeds: 256 bits, i.e. 32 bytes. Anything shorter is refused outright. 48 random bytes is
384 bits, which clears that floor with margin. On Windows, one line of PowerShell does the same:
[Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(48))

IN DEVELOPMENT the value may instead go into user secrets, which live outside the repository.
Run this from the WebVella.Erp.Site project directory - it is the only project in this solution
that declares a user secrets identifier:

	dotnet user-secrets set "Settings:Jwt:Key" "<value generated as above>"

ROTATION IS MANDATORY, NOT OPTIONAL. The literal this note used to publish is permanently
compromised for anyone who has ever had access to this repository or its history, and blanking
the working tree does not undo that. Every deployment that ever ran with the shipped default
MUST be issued a new key. Startup screens the old published value by digest and refuses it, so
copying it back out of the git history will not work either. Rotating the key invalidates every
bearer token already issued, and clients must authenticate again: intended, and acceptable.

NO INSECURE FALLBACK REMAINS. The compiled-in default signing key was deleted, so nothing is
substituted when the value is missing. Settings:ConnectionString and Settings:EncryptionKey are
required by every host, and their absence aborts startup with a message naming each one. This
key is conditional instead, because five of the seven hosts serve no tokens at all: while it is
absent, too short, or the published default, the token issue and refresh routes disable
themselves rather than sign forgeable tokens and every presented bearer token is refused, while
cookie login keeps working. Read either outcome as "supply the secret", not as a defect.

The companion secrets follow the same double-underscore convention: Settings__ConnectionString,
Settings__EncryptionKey and Settings__EmailSMTPPassword. See README.md, section "Configuration:
required secrets", for the short list, and docs/security/secure-configuration.md for the
authoritative per-host list and the rotation procedure.


=========================================================================
3. startup
in ConfigureServices method change auth to be 

 services.AddAuthentication(options =>
{
    options.DefaultScheme = "JWT_OR_COOKIE";
    options.DefaultChallengeScheme = "JWT_OR_COOKIE";
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.ExpireTimeSpan = TimeSpan.FromHours(24);
    options.SlidingExpiration = true;
    options.Cookie.Name = "erp_auth_base";
    options.LoginPath = new PathString("/login");
    options.LogoutPath = new PathString("/logout");
    options.AccessDeniedPath = new PathString("/error?access_denied");
    options.ReturnUrlParameter = "returnUrl";
})
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = Configuration["Settings:Jwt:Issuer"],
            ValidAudience = Configuration["Settings:Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Settings:Jwt:Key"]))
        };
    })
    .AddPolicyScheme("JWT_OR_COOKIE", "JWT_OR_COOKIE", options =>
    {
        options.ForwardDefaultSelector = context =>
        {
            string authorization = context.Request.Headers[HeaderNames.Authorization];
            if (!string.IsNullOrEmpty(authorization) && authorization.StartsWith("Bearer "))
                return JwtBearerDefaults.AuthenticationScheme;

            return CookieAuthenticationDefaults.AuthenticationScheme;
        };
    });

SECURITY - finding H-15 (High); CWE-614 sensitive cookie without the 'Secure' attribute, CWE-319
cleartext transmission of sensitive information; OWASP A02:2021 / A05:2021.
THREAT: this note used to set HttpOnly and stop there. A host built from it let the
authentication cookie travel over plain HTTP, where any intermediary can read it and replay the
session, and the cookie never expired. The four lines added above close that, and two of them are
deliberate choices rather than defaults:
- Lax rather than Strict: Strict drops the cookie on the redirect back out of /login and breaks
  the returnUrl round trip. Lax is the framework's own default posture.
- 24 hours matches the bounded authentication ticket in WebVella.Erp.Web/Services/AuthService.cs
  (1440 minutes). That ticket used to expire 100 years out (finding H-03), so a stolen cookie
  stayed valid forever.
The platform itself now applies all five attributes from one place - the shared cookie helper in
WebVella.Erp.Web/ErpMvcExtensions.cs - so the seven hosts cannot drift apart. Call that helper
rather than copying these lines into a new host.

 in Configure method add 
 
 app.UseJwtMiddleware();

 =========================================================================
 

=========================================================================
4. the configuration file name

SECURITY - finding CFG-03; CWE-178 improper handling of case sensitivity,
CWE-706 use of an incorrectly resolved name or reference.
The file is named Config.json, with a capital C. Use that exact spelling. An
earlier revision of this note wrote it in lower case, and the loader asked for
the lower-case name too, which worked only because Windows and macOS resolve
filenames case-insensitively. On Linux and in containers the requested name did
not exist, so a published host either failed to start or - the worse outcome -
started against an unaudited file that somebody had created to work around the
failure. Both halves are fixed: all four builder sites now request Config.json
by its exact name, resolved from AppContext.BaseDirectory rather than from the
current working directory, so the file is found next to the assembly no matter
where the process was launched from.

Two consequences for anyone following these instructions:

  - Do NOT create a lower-case config.json anywhere. The continuous security
    workflow fails the build if a published artifact carries one, because two
    spellings of the same settings file means the one that is read is decided
    by the filesystem rather than by the deployment.
  - Do NOT add a second copy to the project directory. MSBuild item identity is
    case-insensitive, so Config.json and config.json in the same source folder
    collide and the build stops with NETSDK1022.

See docs/security/secure-configuration.md for the resolved-path details.
=========================================================================
