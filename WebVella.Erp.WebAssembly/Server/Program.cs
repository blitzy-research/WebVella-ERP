using Microsoft.AspNetCore.ResponseCompression;
using WebVella.Erp.Web.Middleware;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

// SECURITY M-01 / H-15 (OWASP A05 security misconfiguration, CWE-319 cleartext transmission), QA finding
// P6-04. This host emitted NONE of the seven mandated response headers - measured at 0 of 7 on the document,
// a .js, the .wasm, a .json, a 404 and the plain-HTTP redirect - while the seven Razor hosts emitted all of
// them. The cause was structural rather than an oversight in ordering: this project references only Client
// and Shared, never WebVella.Erp.Web, so the platform's SecurityHeadersMiddleware was never in its build.
//
// WHY AddHsts IS HERE AND NOT LEFT AT THE FRAMEWORK DEFAULT. HstsMiddleware, which app.UseHsts() below
// installs, assigns Strict-Transport-Security by indexer and runs LATER than the headers middleware, so it
// decides the value on any host it is not excluded from. At framework-default HstsOptions that value is
// "max-age=2592000" - thirty days, no includeSubDomains - which would silently replace the mandated
// one-year subdomain-inclusive string. Pinning the framework's own options makes both writers emit the
// identical value, so the overwrite is a no-op in either order. This mirrors ErpMvcExtensions.AddErp
// exactly, including Preload = false: preload is not part of the mandated value and submission to the
// browser preload list is effectively irreversible.
builder.Services.AddHsts(hstsOptions =>
{
	hstsOptions.MaxAge = TimeSpan.FromDays(365);
	hstsOptions.IncludeSubDomains = true;
	hstsOptions.Preload = false;
});

var app = builder.Build();

// Ordered FIRST, outermost, and that position is load-bearing: UseBlazorFrameworkFiles and UseStaticFiles
// below TERMINATE the pipeline for a matched asset, so anything registered after them never runs for the
// .wasm, the framework .js, appsettings.json or any other static response - which is exactly the set QA
// measured bare. Registered ahead of UseHttpsRedirection too, so the plaintext 307 carries the headers as
// well. This is the same placement every Razor host uses (see WebVella.Erp.Site/Startup.cs, where
// app.UseSecurityHeaders() precedes response compression and both UseStaticFiles calls).
app.UseSecurityHeaders();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
}
else
{
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseBlazorFrameworkFiles();
app.UseStaticFiles();

app.UseRouting();

app.MapRazorPages();
app.MapControllers();
app.MapFallbackToFile("index.html");

app.Run();
