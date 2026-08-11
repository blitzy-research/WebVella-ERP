using System.Net.Http.Json;
using System.Text.Json;

namespace WebVella.Erp.WebAssembly.Utilities;

public static class HttpExt
{
	/// <summary>
	/// Turns a failure response into the exception type that matches its status, preserving the server's
	/// own message.
	/// </summary>
	/// <remarks>
	/// <para>
	/// Review finding M-04. This method used to switch on an <c>ApiErrorType</c> discriminator that the
	/// server never sends. Because an absent enum deserializes to 0, and 0 was the member the 400 branch
	/// handled, validation errors happened to work while a 500 fell through to
	/// <c>throw new Exception("Not supported ApiErrorType 0 ...")</c> - so the one case where the server had
	/// something useful to say was the one case where the client discarded it and reported its own parsing
	/// confusion to the user instead.
	/// </para>
	/// <para>
	/// The status code is now the discriminator, because it is the part of the contract both ends actually
	/// agree on. 401 and 403 are handled explicitly; previously both fell past every branch and were
	/// returned as SUCCESS, so an unauthenticated or forbidden call surfaced as a deserialization failure
	/// somewhere further up, or as a silent null. Every branch reads the message from the real envelope, and
	/// no branch can now discard it: <see cref="ResolveMessage"/> falls back to the reason phrase when the
	/// body is empty or unparseable, which a bare 401 typically is.
	/// </para>
	/// </remarks>
	public static async Task<HttpResponseMessage> VerifyAsync(this HttpResponseMessage response)
	{
		if (response.IsSuccessStatusCode)
			return response;

		var error = await ReadErrorEnvelopeAsync(response);
		var message = ResolveMessage(error, response);

		switch (response.StatusCode)
		{
			case System.Net.HttpStatusCode.BadRequest:
				{
					//A 400 from this platform is a validation outcome. The per-field detail now comes from
					//the envelope's "errors" collection instead of the "validationData" dictionary that was
					//never populated.
					var validationException = new ValidationException(message);
					var fieldErrors = BuildFieldErrors(error);
					if (fieldErrors.Count > 0)
						validationException.AddData(fieldErrors);
					throw validationException;
				}

			case System.Net.HttpStatusCode.Unauthorized:
				//The credential is absent, expired or was not recognised. ApiTokenException is the type the
				//token pipeline already raises for that condition, so callers need no new handling.
				throw new ApiTokenException(message);

			case System.Net.HttpStatusCode.Forbidden:
				//Authenticated but not permitted. Distinct from 401 on purpose: re-authenticating cannot
				//help, so this must not be routed to the sign-in flow.
				throw new ApiException(message);

			case System.Net.HttpStatusCode.NotFound:
				throw new ApiException(message);

			default:
				//Everything else, including 500. The server no longer returns a stack trace on these paths -
				//that was removed as an information-disclosure fix - so there is nothing further to attach,
				//and the generic message it does return is what the user sees.
				throw new ApiException(message);
		}
	}

	/// <summary>
	/// Reads the failure envelope, or null when the body is absent or is not this platform's envelope.
	/// </summary>
	/// <remarks>
	/// Never throws. A parse failure here must not replace the real HTTP failure with a JSON exception,
	/// which would lose the status the caller needs in order to react correctly.
	/// </remarks>
	private static async Task<ApiErrorModel> ReadErrorEnvelopeAsync(HttpResponseMessage response)
	{
		try
		{
			return await response.Content.ReadFromJsonAsync<ApiErrorModel>();
		}
		catch
		{
			return null;
		}
	}

	/// <summary>
	/// The message to surface: the server's own text when it sent one, otherwise a description of the
	/// status. Never returns null or empty, so no caller can display a blank error.
	/// </summary>
	private static string ResolveMessage(ApiErrorModel error, HttpResponseMessage response)
	{
		if (!String.IsNullOrWhiteSpace(error?.Message))
			return error.Message;

		if (!String.IsNullOrWhiteSpace(response.ReasonPhrase))
			return $"{(int)response.StatusCode} {response.ReasonPhrase}";

		return $"Request failed with status code {(int)response.StatusCode}";
	}

	/// <summary>
	/// Groups the envelope's field errors by field name, in the shape <c>BaseException.AddData</c> expects.
	/// </summary>
	private static Dictionary<string, List<string>> BuildFieldErrors(ApiErrorModel error)
	{
		var result = new Dictionary<string, List<string>>();
		if (error?.Errors is null)
			return result;

		foreach (var item in error.Errors)
		{
			if (item is null || String.IsNullOrWhiteSpace(item.Message))
				continue;

			//A record-level error carries no field name. Grouping it under the empty key keeps it in the
			//same structure rather than discarding it, which is what the previous dictionary did.
			var key = item.Key ?? String.Empty;
			if (!result.TryGetValue(key, out var messages))
			{
				messages = new List<string>();
				result[key] = messages;
			}

			messages.Add(item.Message);
		}

		return result;
	}


	public static async Task<RT> PostAndReadAsJsonAsync<PT, RT>(this HttpClient httpClient, string apiUrl, PT postObject)
	{
		try
		{
			var response = await httpClient.PostAsJsonAsync<PT>(apiUrl, postObject);
			await response.VerifyAsync();
			var prefetch = await response.Content.ReadAsStringAsync();
			if (String.IsNullOrWhiteSpace(prefetch))
				return default(RT);

			return await response.Content.ReadFromJsonAsync<RT>();
		}
		catch (HttpRequestException httpException)
		{
			//this exception is thrown when no connection is established or connection get disconnected
			throw new ApiConnectionException("Няма връзка със сървър приложението", httpException);
		}
		catch (TaskCanceledException taskCanceledException)
		{
			//this exception is thrown when connection timeouts
			throw new ApiConnectionException("Връзката със сървър приложението се разпадна", taskCanceledException);
		}
		catch (Exception ex)
		{
			throw;
		}
	}

	public static async Task<string> PostAndReadAsStringAsync<PT>(this HttpClient httpClient, string apiUrl, PT postObject)
	{
		try
		{
			var response = await httpClient.PostAsJsonAsync<PT>(apiUrl, postObject);
			await response.VerifyAsync();
			return await response.Content.ReadAsStringAsync();
		}
		catch (HttpRequestException httpException)
		{
			//this exception is thrown when no connection is established or connection get disconnected
			throw new ApiConnectionException("Няма връзка със сървър приложението", httpException);
		}
		catch (TaskCanceledException taskCanceledException)
		{
			//this exception is thrown when connection timeouts
			throw new ApiConnectionException("Връзката със сървър приложението се разпадна", taskCanceledException);
		}
		catch (Exception)
		{
			throw;
		}
	}

	public static async Task<RT> GetAndReadAsJsonAsync<RT>(this HttpClient httpClient, string apiUrl) where RT : class
	{
		try
		{
			var response = await httpClient.GetAsync(apiUrl);
			await response.VerifyAsync();
			try
			{
				return await response.Content.ReadFromJsonAsync<RT>();
			}
			catch
			{
				var stringData = await response.Content.ReadAsStringAsync();
				if (string.IsNullOrWhiteSpace(stringData))
					return null;
				return JsonSerializer.Deserialize<RT>(stringData);
			}
		}
		catch (HttpRequestException httpException)
		{
			//this exception is thrown when no connection is established or connection get disconnected
			throw new ApiConnectionException("Няма връзка със сървър приложението", httpException);
		}
		catch (TaskCanceledException taskCanceledException)
		{
			//this exception is thrown when connection timeouts
			throw new ApiConnectionException("Връзката със сървър приложението се разпадна", taskCanceledException);
		}
		catch (Exception)
		{
			throw;
		}
	}


	public static async Task<int?> PostAndReadAsIntAsync<PT>(this HttpClient httpClient, string apiUrl, PT postObject)
	{
		try
		{
			var response = await httpClient.PostAsJsonAsync<PT>(apiUrl, postObject);
			await response.VerifyAsync();
			var content = await response.Content.ReadAsStringAsync();
			if (String.IsNullOrWhiteSpace(content))
				return null;
			if (int.TryParse(content, out int outInt))
				return outInt;

			throw new Exception("Api Request Response is not integer as expected");
		}
		catch (HttpRequestException httpException)
		{
			//this exception is thrown when no connection is established or connection get disconnected
			throw new ApiConnectionException("Няма връзка със сървър приложението", httpException);
		}
		catch (TaskCanceledException taskCanceledException)
		{
			//this exception is thrown when connection timeouts
			throw new ApiConnectionException("Връзката със сървър приложението се разпадна", taskCanceledException);
		}
		catch (Exception)
		{
			throw;
		}
	}

	public static async Task<int?> GetAndReadAsIntAsync(this HttpClient httpClient, string apiUrl)
	{
		try
		{
			var response = await httpClient.GetAsync(apiUrl);
			await response.VerifyAsync();
			var content = await response.Content.ReadAsStringAsync();
			if (String.IsNullOrWhiteSpace(content))
				return null;
			if (int.TryParse(content, out int outInt))
				return outInt;

			throw new Exception("Api Request Response is not integer as expected");

		}
		catch (HttpRequestException httpException)
		{
			//this exception is thrown when no connection is established or connection get disconnected
			throw new ApiConnectionException("Няма връзка със сървър приложението", httpException);
		}
		catch (TaskCanceledException taskCanceledException)
		{
			//this exception is thrown when connection timeouts
			throw new ApiConnectionException("Връзката със сървър приложението се разпадна", taskCanceledException);
		}
		catch (Exception)
		{
			throw;
		}
	}
}
