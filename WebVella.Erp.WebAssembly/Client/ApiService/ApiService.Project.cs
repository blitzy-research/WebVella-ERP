using Blazored.LocalStorage;

namespace WebVella.Erp.WebAssembly.ApiService;

public partial interface IApiService
{
    ValueTask<WvUser> GetCurrentUserAsync();
}

public partial class ApiService : IApiService
{
    public async ValueTask<WvUser> GetCurrentUserAsync()
    {
        //Review finding C-02. GetAuthorizedHttpClientAsync now THROWS ApiTokenException when no usable token
        //exists, instead of returning null and letting this line dereference it. No null check is added here
        //deliberately: a check would have to invent a return value for "not signed in", and a WvUser that is
        //null-but-not-an-error is exactly the ambiguity that produced the original defect. The exception is
        //the contract.
        var httpClient = await GetAuthorizedHttpClientAsync();

        return await httpClient.GetAndReadAsJsonAsync<WvUser>($"{apiProjectRoot}user/get-current");
        //return await httpClient.PostAndReadAsJsonAsync<object,WvUser>($"/api/v3/en_US/eql",null);
    }

}