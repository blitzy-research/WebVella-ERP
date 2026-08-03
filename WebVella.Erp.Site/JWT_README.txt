=========================================================================
1. add to web site project 
<PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="6.0.3" />


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
INVARIANT: the Key entry stays EMPTY in every tracked file. Supply at least 32 bytes of
cryptographically random material per deployment, out of band, and never through this file:

	Settings__Jwt__Key=$(openssl rand -base64 48)

or through user secrets in development. Startup rejects the key this repository once published,
so copying the value out of the git history will not work. While the value is absent the token
issue and refresh routes disable themselves rather than sign forgeable tokens; cookie login is
unaffected. See docs/security/secure-configuration.md for the full list of required settings.


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
