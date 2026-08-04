using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components;

namespace WebVella.Erp.WebAssembly.Services;

public interface IAuthenticationService
{
	ValueTask<bool> HasTokenAsync();
	ValueTask<bool> LoginAsync(LoginModel model);

	/// <summary>
	/// Signs the client out, asking the server to revoke the bearer session first and clearing the locally
	/// held credential afterwards. The local credential is always cleared, including when the server call
	/// fails. Returns true when there is no longer a server-accepted session belonging to this client -
	/// either because the server confirmed the revocation or because no credential was held - and false when
	/// a credential was held but the server did not confirm that its session had been ended.
	/// </summary>
	ValueTask<bool> LogoutAsync();
}

public class AuthenticationService : IAuthenticationService
{
	private const string apiAuthRoot = "v3/en_US/auth/jwt/";

	private readonly HttpClient _httpClient;
	private readonly ITokenManagerService _tokenManagerService;
	private readonly AuthenticationStateProvider _customAuthenticationProvider;
	private readonly ILocalStorageService _localStorageService;
	
	public AuthenticationService(
		 HttpClient httpClient,
		ITokenManagerService tokenManagerService,
		ILocalStorageService localStorageService,
		AuthenticationStateProvider customAuthenticationProvider)
	{
		_httpClient = httpClient;
		_tokenManagerService = tokenManagerService;
		_localStorageService = localStorageService;
		_customAuthenticationProvider = customAuthenticationProvider;
	}

	public async ValueTask<bool> HasTokenAsync()
	{
		string token = await _tokenManagerService.GetTokenAsync();
		if (String.IsNullOrWhiteSpace(token))
			return false;

		return true;
	}

	public async ValueTask<bool> LoginAsync(LoginModel model)
	{
		AuthResponse authData = await _httpClient.PostAndReadAsJsonAsync<LoginModel, AuthResponse>($"{apiAuthRoot}token", model);
		string token = authData.Object?.ToString();
		if (string.IsNullOrWhiteSpace(token))
			return false;
		await _localStorageService.SetItemAsync("token", token);
		(_customAuthenticationProvider as CustomAuthenticationProvider).Notify();
		return true;
	}

	// THREAT ADDRESSED - review finding B3-SEAM-01, CWE-613 (insufficient session expiration), OWASP A07
	// Identification and Authentication Failures, and the Authentication Hardening standard's "proper logout
	// with session invalidation" clause.
	//
	// This method used to delete the token from local storage and nothing else. The server was never told,
	// so it recorded no revocation - and a bearer token is presented, not stored, which means any COPY of it
	// taken beforehand (a shared machine, a proxy log, a backup, an exfiltration payload) stayed a fully
	// valid credential for the remainder of its 24-hour lifetime and could be exchanged for a successor at
	// the refresh endpoint under the seven-day absolute horizon. The button said "logged out" while a
	// replayed credential kept working, which is the one outcome a sign-out control must never produce.
	//
	// The platform already carries the revocation mechanism - every issued token stamps a per-sign-in session
	// identifier, and the platform validator, the refresh mint site and the hosts' bearer handler all refuse
	// a revoked one - so this is purely about REACHING it. The request below is the reachable path: it is
	// authenticated with the very token being retired, so the server revokes the session the caller actually
	// holds and cannot be induced to revoke anybody else's.
	public async ValueTask<bool> LogoutAsync()
	{
		var revoked = false;

		try
		{
			// Read the credential exactly as stored rather than through ITokenManagerService, which would
			// refresh a token that is past its refresh hint - minting a brand new successor moments before
			// asking the server to destroy the session. The identifier is carried across refreshes so either
			// token revokes the same chain, but issuing one in order to retire it is needless work on a path
			// that must also succeed when the network is failing.
			string token = await _localStorageService.GetItemAsync<string>("token");
			if (string.IsNullOrWhiteSpace(token))
			{
				// No credential is held, so there is no server-accepted session belonging to this client for
				// the server to end. Reported as a completed sign-out rather than a failure.
				revoked = true;
			}
			else
			{
				// A REQUEST-scoped header, never _httpClient.DefaultRequestHeaders: this HttpClient is
				// shared with every other call the client makes, so assigning a default here would leave
				// the bearer credential attached to unrelated later requests - the opposite of signing out.
				//
				// The capital "Bearer" is load-bearing rather than cosmetic. The hosts resolve which
				// authentication handler sees a request by matching the Authorization prefix
				// case-SENSITIVELY, so a lower-case scheme is routed to the cookie handler instead, the
				// request is never authenticated as this session, and the revocation would silently record
				// nothing while this method reported success.
				using var request = new HttpRequestMessage(HttpMethod.Post, $"{apiAuthRoot}token/logout");
				request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

				using HttpResponseMessage serverResponse = await _httpClient.SendAsync(request);

				// Only a success status proves the session was ended. A 401 means the credential was already
				// unusable, which is harmless but is still not a confirmed revocation, so it is not claimed
				// as one.
				revoked = serverResponse.IsSuccessStatusCode;
			}
		}
		catch (Exception)
		{
			// Swallowed on purpose, and just as deliberately NOT reported as success. A browser client must
			// finish clearing its own state even when the server is unreachable, otherwise a network failure
			// would leave the user apparently signed in with a live credential in local storage - strictly
			// worse than the state this handles. Returning false instead of true is what keeps the outcome
			// honest: the caller is told the sign-out completed locally but was never confirmed by the
			// server, rather than being told the session is gone when it may not be.
			revoked = false;
		}
		finally
		{
			// Local state is cleared unconditionally, in a finally, so no failure above can strand the
			// credential in the browser. Ordered after the server call because the call needs the token.
			await _localStorageService.RemoveItemAsync($"token");
			(_customAuthenticationProvider as CustomAuthenticationProvider).Notify();
		}

		return revoked;
	}
}