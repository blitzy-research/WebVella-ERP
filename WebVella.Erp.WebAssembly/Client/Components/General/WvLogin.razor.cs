namespace WebVella.Erp.WebAssembly.Components;

public partial class WvLogin : WvBaseComponent
{
    public LoginModel _form = new();
    private string _error = "";
    //private Dictionary<string, List<string>> _errorDictionary = null;
    private string _returnUrl = "";

    protected override void OnInitialized()
    {
        base.OnInitialized();
        //Review finding M-02, CWE-601. The value is read through the local-only policy, so a crafted
        //absolute or scheme-relative returnUrl cannot become a post-authentication navigation off this
        //origin. A refused value reads as absent, which the branches below already handle by going to "/".
        _returnUrl = NavigatorExt.GetLocalReturnUrlFromQuery(Navigator, WasmConstants.ReturnUrlQuery);
        State = ComponentState.Content;
    }

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (firstRender)
        {
            if (await ApiService.HasTokenAsync())
            {
                //Review finding M-02, CWE-601. The already-signed-in path is the SAME sink as the post-login
                //path below and needed the same policy - an attacker who can get a signed-in user to open the
                //login route with a crafted returnUrl needs no credential at all for the redirect to fire.
                var returnUrl = NavigatorExt.GetLocalReturnUrlFromQuery(Navigator, WasmConstants.ReturnUrlQuery, null);
                if (returnUrl is not null) Navigator.NavigateTo(returnUrl);
                else Navigator.NavigateTo("/");
            }

            await InvokeAsync(StateHasChanged);
        }
    }

    public async Task _loginBtnClick()
    {
        try
        {
            _error = "";
            //_errorDictionary = null;

            var result = await ApiService.LoginAsync(new LoginModel { Email = _form.Email, Password = _form.Password });

            if (!result)
                throw new ValidationException("Грешно потребителско име или парола");

           // var user = await ApiService.GetCurrentUserAsync();

            if (!String.IsNullOrWhiteSpace(_returnUrl))
                Navigator.NavigateTo(_returnUrl);
            else
                Navigator.NavigateTo("/");
        }
        catch (Exception ex)
        {
            _error = "Невалидни данни";
            //_errorDictionary = await ExceptionExt.Notify(ex, "_onSubmitHandler", this.GetType().Name,
            //    NotificationService, ApiService, null, "", true);
        }
    }

}

