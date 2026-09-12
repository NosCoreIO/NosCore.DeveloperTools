using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Serialization;

namespace NosCore.ClientTools;

/// <summary>
/// Thin HTTP client for the NosCore auth endpoints. Two-step flow:
///   1) POST /api/v1/auth/thin/sessions — trades credentials for a JWT +
///      platformGameAccountId.
///   2) POST /api/v1/auth/codes (Bearer JWT) — trades the JWT for a
///      short-lived auth-code GUID the NosTale client hex-encodes into
///      its NoS0577 login packet.
/// </summary>
public sealed class NosCoreAuthClient : IDisposable
{
    private static readonly System.Text.Json.JsonSerializerOptions JsonOptions =
        new() { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase };

    private readonly HttpClient _http;
    private readonly Action<string>? _log;

    public NosCoreAuthClient(string baseAddress, Action<string>? log = null)
    {
        var handler = new HttpClientHandler
        {
            // NosCore WebApi ships with a self-signed dev cert on localhost:7001.
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
        };
        _http = new HttpClient(handler) { BaseAddress = new Uri(baseAddress.TrimEnd('/') + "/") };
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        _log = log;
    }

    public void Dispose() => _http.Dispose();

    public async Task<AuthResult> AuthenticateAsync(
        string username, string password, string gfLang, string locale, string? mfa, CancellationToken ct)
    {
        var sessionResponse = await PostAsync<SessionRequest, SessionResponse>(
            "api/v1/auth/thin/sessions", new SessionRequest(username, password, gfLang, locale, mfa), bearer: null, ct);

        var codeResponse = await PostAsync<CodeRequest, CodeResponse>(
            "api/v1/auth/thin/codes", new CodeRequest(sessionResponse.PlatformGameAccountId),
            bearer: sessionResponse.Token, ct);

        return new AuthResult(sessionResponse.Token, sessionResponse.PlatformGameAccountId, codeResponse.Code);
    }

    private async Task<TResp> PostAsync<TReq, TResp>(string path, TReq body, string? bearer, CancellationToken ct)
    {
        var reqJson = System.Text.Json.JsonSerializer.Serialize(body, JsonOptions);
        _log?.Invoke($"POST {path}");
        _log?.Invoke($"  req: {reqJson}");

        using var msg = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(reqJson, Encoding.UTF8, "application/json"),
        };
        if (bearer is not null)
        {
            msg.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        }

        using var resp = await _http.SendAsync(msg, ct);
        var respBody = await resp.Content.ReadAsStringAsync(ct);
        _log?.Invoke($"  resp: {(int)resp.StatusCode} {respBody}");

        if (!resp.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"{path} failed ({(int)resp.StatusCode}): {respBody}");
        }
        return System.Text.Json.JsonSerializer.Deserialize<TResp>(respBody, JsonOptions)
            ?? throw new InvalidOperationException($"{path} returned empty response.");
    }

    private sealed record SessionRequest(
        [property: JsonPropertyName("identity")] string Identity,
        [property: JsonPropertyName("password")] string Password,
        [property: JsonPropertyName("gfLang")] string GfLang,
        [property: JsonPropertyName("locale")] string Locale,
        [property: JsonPropertyName("mfa")] string? Mfa);

    private sealed record SessionResponse(
        [property: JsonPropertyName("token")] string Token,
        [property: JsonPropertyName("platformGameAccountId")] string PlatformGameAccountId);

    private sealed record CodeRequest(
        [property: JsonPropertyName("platformGameAccountId")] string PlatformGameAccountId);

    private sealed record CodeResponse(
        [property: JsonPropertyName("code")] string Code);
}

public sealed record AuthResult(string Token, string PlatformGameAccountId, string AuthCode);
