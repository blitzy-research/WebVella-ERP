using Microsoft.AspNetCore.Components;
using WebVella.Erp.WebAssembly.ApiService;

namespace WebVella.Erp.WebAssembly.Pages;

public partial class Index : ComponentBase
{

    [Inject] private IAuthenticationService _authService { get; set; }
    [Inject] private IApiService _apiService { get; set; }
    [Inject] private NavigationManager _navigator { get; set; }

    //THREAT ADDRESSED - finding F-09, CWE-798 (use of hard-coded credentials), OWASP A07:2021.
    //Needed so the Login button can hand the user to the real /login page instead of
    //authenticating with a credential compiled into the shipped WebAssembly payload. Injected the
    //same way as the two services above; WvBaseComponent injects NavigationManager under this
    //exact name, so /login and this page name it identically.
    [Inject] private NavigationManager Navigator { get; set; }

    private bool _isAuthenticated = false;
    private WvUser _user = null;
    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (firstRender)
        {
            _isAuthenticated = await _authService.HasTokenAsync();
            _user = await _apiService.GetCurrentUserAsync();
            await InvokeAsync(StateHasChanged);
        }
    }
    //THREAT ADDRESSED - finding F-09, CWE-798 (use of hard-coded credentials), OWASP A07:2021
    //Identification and Authentication Failures. This method called LoginAsync with a literal
    //e-mail and password. Those literals were not test scaffolding: this is /, the client's entry
    //page, the button that reaches them ships in the rendered markup, and a Blazor WebAssembly
    //assembly is downloaded to and readable by every visitor - so the credential was published to
    //anyone who asked for the page, and any deployment that still had that account authenticated
    //an anonymous visitor as it with one click.
    //
    //The button now hands the user to the application's real login page, which already exists
    //at /login (LoginPage.razor -> WvLogin) with a form, error reporting and returnUrl handling.
    //No replacement credential is introduced and none is read from configuration: a browser-
    //delivered client cannot hold a secret at all, so the only correct destination is the form.
    //The returnUrl is the query parameter WvLogin itself reads, so a successful login returns here.
    private void _login()
    {
        Navigator.NavigateTo($"/login?{WasmConstants.ReturnUrlQuery}=/");
    }
    private async Task _logout()
    {
        await _authService.LogoutAsync();
        _isAuthenticated = false;
    }
}
