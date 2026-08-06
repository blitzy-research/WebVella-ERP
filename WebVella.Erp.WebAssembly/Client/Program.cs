using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using WebVella.Erp.WebAssembly;
using WebVella.Erp.WebAssembly.ApiService;

var builder = WebAssemblyHostBuilder.CreateDefault(args);


builder.Configuration
	.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
	.AddJsonFile($"appsettings.{Environment.MachineName}.json", optional: true, reloadOnChange: true);

var config = builder.Configuration.Build();

// THREAT ADDRESSED - CWE-319 cleartext transmission of a credential, and the mixed-content failure that
// masked it. Review finding C-03. "serverUrl" shipped as "http://localhost:5000/", while the host that
// serves this client redirects to HTTPS - so the page loads over HTTPS and every API call is an active
// mixed-content request that the browser blocks outright, which is why the client could not start. The
// dangerous variant is the one that DOES work: served over plain HTTP, the same setting sends the bearer
// token in cleartext on every request. Defaulting to the ORIGIN THIS CLIENT WAS SERVED FROM removes the
// setting from the trusted path entirely - same-origin inherits the page's own scheme, so it can never be
// weaker than the page - and an explicit override is still honoured for a genuinely separate API host.
// Downgrading from a secure page is refused rather than attempted, because the alternatives are a blocked
// request or a leaked token and neither should be reached silently.
var apiUrl = ResolveApiBaseAddress(builder.HostEnvironment.BaseAddress, config["serverUrl"]);

static string ResolveApiBaseAddress(string hostBaseAddress, string configuredServerUrl)
{
    const string apiSegment = "api/";

    // No override configured: use the origin that served this client.
    if (string.IsNullOrWhiteSpace(configuredServerUrl))
        return new Uri(new Uri(hostBaseAddress, UriKind.Absolute), apiSegment).ToString();

    // A relative override is resolved against the serving origin and so is scheme-safe by construction.
    if (!Uri.TryCreate(configuredServerUrl, UriKind.Absolute, out var configuredUri))
        return new Uri(new Uri(hostBaseAddress, UriKind.Absolute), EnsureTrailingSlash(configuredServerUrl) + apiSegment).ToString();

    var hostUri = new Uri(hostBaseAddress, UriKind.Absolute);
    var pageIsSecure = string.Equals(hostUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
    var apiIsSecure = string.Equals(configuredUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

    if (pageIsSecure && !apiIsSecure)
        throw new InvalidOperationException(
            $"Insecure API base address '{configuredServerUrl}' cannot be used from the secure origin '{hostBaseAddress}'. " +
            "The browser blocks such requests as active mixed content, and any that succeeded would transmit the " +
            "bearer token in cleartext. Configure 'serverUrl' with an https scheme, or leave it empty to use the " +
            "origin serving this application.");

    // A base address must end in '/' or Uri resolution discards its last segment.
    var normalizedBase = new Uri(EnsureTrailingSlash(configuredUri.ToString()), UriKind.Absolute);
    return new Uri(normalizedBase, apiSegment).ToString();
}

static string EnsureTrailingSlash(string value) => value.EndsWith('/') ? value : value + "/";

builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(apiUrl) });
builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthenticationProvider>();
builder.Services.AddAuthorizationCore();
builder.Services.AddBlazoredLocalStorage();
builder.Services.AddSingleton<IConfigurationService, ConfigurationService>();
builder.Services.AddScoped<ITokenManagerService, TokenManagerService>();
builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
builder.Services.AddScoped<IApiService, ApiService>();

await builder.Build().RunAsync();
