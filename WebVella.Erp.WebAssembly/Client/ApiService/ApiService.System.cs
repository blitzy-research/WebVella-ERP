using Blazored.LocalStorage;

namespace WebVella.Erp.WebAssembly.ApiService;

public partial interface IApiService
{
    ValueTask<HttpClient> GetAuthorizedHttpClientAsync();
    HttpClient GetNotAuthorizedHttpClientAsync();
}

public partial class ApiService : IApiService
{
    public async ValueTask<HttpClient> GetAuthorizedHttpClientAsync()
    {
        string token = await _tokenManagerService.GetTokenAsync();
        if (String.IsNullOrWhiteSpace(token))
        {
            //THREAT ADDRESSED - CWE-476 null dereference on a security decision path. Review finding C-02.
            //Returning null after starting a navigation did not stop the caller: NavigateTo does not abort
            //the current method, so execution continued and every caller dereferenced the null immediately -
            //ApiService.Project.GetCurrentUserAsync did so on its very next statement. The observable result
            //of "not signed in" was therefore an unhandled NullReferenceException racing a redirect, instead
            //of a handled sign-in. Throwing the exception type this file already named in the comment below
            //makes the outcome explicit and unmissable, and keeps the navigation.
            _navManager.NavigateTo("/login");
            throw new ApiTokenException("Token not found");
        }

        //THREAT ADDRESSED - CWE-178. Review finding C-02. The scheme is emitted in its canonical "Bearer"
        //spelling. RFC 7235 makes the token case-insensitive so a correct server accepts either, but the
        //platform's own policy-scheme selector compared it literally, so the lower-case spelling silently
        //routed authenticated API calls to the cookie handler and they came back anonymous. The server side
        //is fixed to compare case-insensitively; emitting the canonical form as well means neither half has
        //to rely on the other's leniency.
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return _httpClient;
    }

    public HttpClient GetNotAuthorizedHttpClientAsync()
    {
        //THREAT ADDRESSED - CWE-522, credential sent on a request that must not carry one. Review finding
        //C-02. There is exactly ONE HttpClient instance behind both of these methods - it is registered
        //scoped, which in a WebAssembly host means one instance for the lifetime of the application - and
        //the authorized path above sets the token on its DefaultRequestHeaders, where it PERSISTS. So once
        //any authorized call had been made, this method handed back a client that still carried the bearer
        //token, and every request the caller believed to be anonymous was in fact authenticated. That
        //silently defeated least privilege and made the two methods' contracts untrue. Clearing the header
        //here restores the distinction the method name promises, and costs nothing: the authorized path sets
        //the header on every call, so it can never observe a cleared value.
        _httpClient.DefaultRequestHeaders.Authorization = null;
        return _httpClient;

    }
}