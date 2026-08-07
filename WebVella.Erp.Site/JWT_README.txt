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

	export Settings__Jwt__Key="$(openssl rand -base64 48)"

THE 'export' IS LOAD-BEARING, and an earlier revision of this note omitted it. A bare
NAME=value assignment creates a SHELL variable, not an environment variable: the shell keeps it
to itself, so a host launched afterwards from that same shell inherits nothing and the
environment-variables provider finds no key. The symptom is confusing rather than obvious - the
host starts normally, because this key is not startup-fatal (see NO INSECURE FALLBACK REMAINS
below), and only the token routes stay disabled, so the operator sees a working site with
bearer authentication silently off. Either form below is correct; use whichever suits the
context:

	export Settings__Jwt__Key="$(openssl rand -base64 48)"      # persists for this shell
	Settings__Jwt__Key="$(openssl rand -base64 48)" dotnet run  # one command only

Quote the command substitution. Base64 output contains '+' and '/' and can end in '=', and an
unquoted expansion is subject to word splitting and pathname expansion - so an unquoted value
can be silently truncated or mangled, which then fails the 32-byte floor for a reason that
looks nothing like the cause.

HS256 signs with HMAC-SHA-256, so RFC 7518 section 3.2 requires a key at least as long as the
hash it feeds: 256 bits, i.e. 32 bytes. Anything shorter is refused outright. 48 random bytes is
384 bits, which clears that floor with margin. On Windows, one line of PowerShell does the same:
[Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(48))

IN DEVELOPMENT the value may instead go into user secrets, which live outside the repository.
Run this from the WebVella.Erp.Site project directory:

	dotnet user-secrets set "Settings:Jwt:Key" "<value generated as above>"

SECURITY - review finding HIGH-02; CWE-1059 insufficient technical documentation. An earlier
revision of this note claimed WebVella.Erp.Site was "the only project in this solution that
declares a user secrets identifier". That was false, and the falsehood mattered: a reader
following it would conclude that user secrets were unavailable to the other executables and
would put a real secret into a tracked Config.json instead - reopening the very finding this
note exists to close. ALL EIGHT executables declare a UserSecretsId, each its own store, so a
secret set for one host is NOT visible to another. Measured from the project files:

	WebVella.Erp.Site                3d84b9b1-534b-473b-b0d8-f6b47f33297b
	WebVella.Erp.Site.Crm            7cdbf11d-ae56-5ee3-907d-2a50d47825c9
	WebVella.Erp.Site.Mail           433b5aa4-8f48-5924-b1c5-a2b91b06b85c
	WebVella.Erp.Site.MicrosoftCDM   1f2442e7-e410-5bd1-8ec1-b82f4388f95c
	WebVella.Erp.Site.Next           383b4579-6bb3-55f1-a998-47adfcf25dc6
	WebVella.Erp.Site.Project        921179fc-4177-5603-bbf9-9c8a43db8cc3
	WebVella.Erp.Site.Sdk            e902f2c3-b59e-5aef-b217-6501e03e6a44
	WebVella.Erp.ConsoleApp          9b3e4423-9b40-55c3-9abc-bcd7bcf79685

Only WebVella.Erp.Site and WebVella.Erp.Site.Project read a Settings:Jwt section, so those two
are the only ones for which THIS key is meaningful; the remaining six still need their own
Settings:ConnectionString and Settings:EncryptionKey, set from each project's own directory.
User secrets resolve only outside a Production environment, so they are a development channel
only - a deployed host must use environment variables or another configuration provider.

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
Settings__EncryptionKey and Settings__EmailSMTPPassword. Those three are the SECRET-BEARING ones and
are all this note undertakes to list - it is not an inventory, and should not be read as one. The
platform reads 41 configuration keys in total. See README.md, section "Configuration: required
secrets", for the short list; docs/security/secure-configuration.md section "The complete inventory
of every configuration key the platform reads" is the exhaustive one, with each key's default and
applicability, and it also carries the rotation procedure.

Of those three, only Settings__ConnectionString and Settings__EncryptionKey abort startup when
absent. Settings__EmailSMTPPassword is needed only when e-mail is enabled and the relay
authenticates, and Settings__Jwt__Key - the subject of this note - is not startup-fatal either, as
set out above.


=========================================================================
3. startup

SECURITY - review finding HIGH-02 (High); CWE-1059 insufficient technical documentation, with
CWE-613 insufficient session expiration, CWE-347 improper verification of a cryptographic
signature and CWE-178 improper handling of case sensitivity as the concrete consequences.

THIS SECTION NO LONGER PUBLISHES A COPYABLE AUTHENTICATION SETUP, AND THAT IS THE FIX.
It used to carry a ~40-line services.AddAuthentication(...) sample. Every line of it was correct
when written, and the platform's own wiring then moved on while the sample did not. By the time
this note was reviewed the sample had drifted from the shipping code in FOUR security-relevant
ways, and a reader who pasted it into a new host would have built a measurably weaker one:

  - NO ClockSkew. The sample set none, so IdentityModel's default of FIVE MINUTES applied and
    every token stayed acceptable for five minutes past its stated expiry. The platform pins the
    skew explicitly instead (see AuthService.JwtClockSkew).
  - NO revocation hook. The sample validated the signature and stopped. A token issued before a
    logout, a password rotation or an administrative disable therefore kept working until it
    expired. The platform hooks OnTokenValidated and consults the session-revocation service, so
    a revoked principal is refused on its next request.
  - NO screening of the signing key. The sample fed Configuration["Settings:Jwt:Key"] straight
    into a SymmetricSecurityKey. A host configured with a null, too-short or previously-published
    key would therefore either throw at startup or, worse, sign and accept forgeable tokens. The
    platform resolves acceptability ONCE at startup by the same rule the issue and refresh routes
    apply, so the handler and the routes can never disagree about whether tokens are trustworthy.
  - CASE-SENSITIVE scheme dispatch. The sample tested authorization.StartsWith("Bearer "). The
    Authorization scheme token is case-INSENSITIVE per RFC 7235, and the platform's own
    JwtMiddleware compares it with StringComparison.OrdinalIgnoreCase, so a client sending
    "bearer " was routed to the COOKIE scheme by the sample while the middleware treated it as a
    bearer request - the two disagreed about which scheme was in play. The platform compares
    case-insensitively in both places.

A second copy of security-critical wiring is a liability, not a convenience: it cannot be
compiled, cannot be analyzed, and drifts silently. Review finding MAJ-12 makes the same point
about duplicated normative content across this document set. So this note now names the ONE
canonical implementation and stops describing it:

  AUTHENTICATION AND BEARER VALIDATION
	WebVella.Erp.Site/Startup.cs, ConfigureServices - the authentication builder, the bearer
	token validation parameters, the pinned clock skew, the signing-key acceptability check,
	the OnTokenValidated revocation hook and the case-insensitive JWT_OR_COOKIE selector.

  COOKIE ATTRIBUTES, SHARED BY ALL SEVEN HOSTS
	WebVella.Erp.Web/ErpMvcExtensions.cs - the shared cookie helper. Call it from a new host
	rather than restating attributes, so the hosts cannot drift apart.

  MIDDLEWARE REGISTRATION
	The Configure method calls app.UseJwtMiddleware(). That one line is the whole of the
	pipeline change and is stated here because it is the only part a new host must add itself.

Read those two files for the current contract. If they and this note ever disagree, THE CODE IS
AUTHORITATIVE - this note is a setup guide, not a specification.

TWO COOKIE CHOICES ARE DELIBERATE, and are recorded here because the reason is not visible from
the code alone (SECURITY - finding H-15; CWE-614 sensitive cookie without the 'Secure' attribute,
CWE-319 cleartext transmission of sensitive information; OWASP A02:2021 / A05:2021 - the helper
sets HttpOnly, Secure, SameSite, a bounded lifetime and sliding expiration, where this note once
set HttpOnly and stopped, leaving the cookie replayable over plain HTTP and never expiring):
- SameSite Lax rather than Strict: Strict drops the cookie on the redirect back out of /login and
  breaks the returnUrl round trip. Lax is the framework's own default posture.
- A 24-hour lifetime, matching the bounded authentication ticket in
  WebVella.Erp.Web/Services/AuthService.cs (1440 minutes). That ticket used to expire 100 years
  out (finding H-03), so a stolen cookie stayed valid forever.

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
