using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;
using System.Net.Http;
using System.Text;
using System.Text.Json;

public enum AdfsAuthType
{
    Wia,
    ClientSecret
}


public class AdfsClientAssertionProvider : ClientAssertionProviderBase
{
    private readonly HttpClient _client;
    private readonly ILogger _logger;
    private readonly string _clientId;
    private readonly string _resource;
    private readonly string _tokenEndpoint;
    private readonly AdfsAuthType _authType;
    private readonly string? _clientSecret;

    public AdfsClientAssertionProvider(
        Dictionary<string, object> providerData,
        ILogger logger,
        HttpClient httpClient,
        string? sectionName = null) // reserved for future use
    {
        _client = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        string GetRequired(string key) =>
            providerData.TryGetValue(key, out var value) && value is string s && !string.IsNullOrWhiteSpace(s)
                ? s
                : throw new InvalidOperationException($"{key} missing in CustomSignedAssertionProviderData");

        string GetOptional(string key, string defaultValue = "") =>
            providerData.TryGetValue(key, out var value) && value is string s && !string.IsNullOrWhiteSpace(s)
                ? s
                : defaultValue;

        var host = GetRequired("Host");
        var endpoint = GetOptional("Endpoint", "/adfs/oauth2/token/");
        _clientId = GetRequired("ClientId");
        _resource = GetRequired("Resource");

        _tokenEndpoint = $"{host.TrimEnd('/')}{endpoint}";

        var authType = GetOptional("AuthType", "WIA");
        _authType = authType.Equals("ClientSecret", StringComparison.OrdinalIgnoreCase)
            ? AdfsAuthType.ClientSecret
            : AdfsAuthType.Wia;

        if (_authType == AdfsAuthType.ClientSecret)
        {
            _clientSecret = GetRequired("ClientSecret");
        }

        _logger.LogDebug("AD FS provider initialized. Endpoint={Endpoint}, ClientId={ClientId}, Resource={Resource}, AuthType={AuthType}",
            _tokenEndpoint, _clientId, _resource, _authType);
    }


    protected override async Task<ClientAssertion> GetClientAssertionAsync(AssertionRequestOptions? options)
    {
        var body = new Dictionary<string, string>
        {
            { "client_id", _clientId },
            { "resource", _resource },
            { "grant_type", "client_credentials" },
            { "scope", "openid" }
        };

        if (_authType == AdfsAuthType.Wia)
        {
            body["use_windows_client_authentication"] = "true";
        }
        else if (_authType == AdfsAuthType.ClientSecret)
        {
            body["client_secret"] = _clientSecret!;
        }

        using var content = new FormUrlEncodedContent(body);
        content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue("application/x-www-form-urlencoded");

        _logger.LogInformation("Requesting AD FS token ({AuthType}) from {Endpoint} for resource {Resource}",
            _authType, _tokenEndpoint, _resource);

        var response = await _client.PostAsync(_tokenEndpoint, content, options?.CancellationToken ?? CancellationToken.None);
        var raw = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("AD FS token request failed: {Status}. Body: {Body}", response.StatusCode, raw);
            throw new InvalidOperationException($"AD FS token request failed: {(int)response.StatusCode} {response.ReasonPhrase}");
        }

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("AD FS token request failed: {Status}. Body: {Body}", response.StatusCode, raw);
            throw new InvalidOperationException(
                $"AD FS token request failed: {(int)response.StatusCode} {response.ReasonPhrase}");
        }

        using var doc = JsonDocument.Parse(raw);
        var accessToken = doc.RootElement.TryGetProperty("access_token", out var atEl) ? atEl.GetString() : null;
        var expiresIn = doc.RootElement.TryGetProperty("expires_in", out var eiEl) && eiEl.TryGetInt32(out var ei)
            ? ei
            : (int?)null;
        var tokenType = doc.RootElement.TryGetProperty("token_type", out var ttEl) ? ttEl.GetString() : null;

        if (string.IsNullOrWhiteSpace(accessToken))
            throw new InvalidOperationException("AD FS returned empty access_token.");

        if (!string.IsNullOrEmpty(tokenType) &&
            !tokenType.Equals("Bearer", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Unexpected token_type from AD FS: {TokenType}", tokenType);
        }

        var expiry = TryGetJwtExpiry(accessToken) ??
                     (expiresIn.HasValue
                         ? DateTimeOffset.UtcNow.AddSeconds(expiresIn.Value)
                         : DateTimeOffset.UtcNow.AddMinutes(60));

        var (iss, aud, sub) = TryGetJwtCoreClaims(accessToken);
        if (!string.IsNullOrEmpty(aud) && !aud.Equals(_resource, StringComparison.Ordinal))
        {
            _logger.LogWarning("AD FS token 'aud' does not match configured resource. aud={Aud}, resource={Resource}",
                aud, _resource);
        }

        _logger.LogInformation("AD FS assertion acquired. iss={Issuer}, sub={Subject}, aud={Audience}, exp={Expiry:u}",
            iss ?? "?", sub ?? "?", aud ?? "?", expiry);

        return new ClientAssertion(accessToken, expiry);
    }

    private static DateTimeOffset? TryGetJwtExpiry(string jwt)
    {
        try
        {
            var parts = jwt.Split('.');
            if (parts.Length < 2) return null;
            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
            using var payload = JsonDocument.Parse(payloadJson);
            if (payload.RootElement.TryGetProperty("exp", out var expEl) && expEl.TryGetInt64(out var exp))
            {
                // exp is seconds since epoch
                return DateTimeOffset.FromUnixTimeSeconds(exp);
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    private static (string? iss, string? aud, string? sub) TryGetJwtCoreClaims(string jwt)
    {
        try
        {
            var parts = jwt.Split('.');
            if (parts.Length < 2) return (null, null, null);
            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
            using var payload = JsonDocument.Parse(payloadJson);
            string? iss = payload.RootElement.TryGetProperty("iss", out var issEl) ? issEl.GetString() : null;
            string? aud = payload.RootElement.TryGetProperty("aud", out var audEl) ? audEl.GetString() : null;
            string? sub = payload.RootElement.TryGetProperty("sub", out var subEl) ? subEl.GetString() : null;
            return (iss, aud, sub);
        }
        catch
        {
            return (null, null, null);
        }
    }

    private static byte[] Base64UrlDecode(string base64Url)
    {
        string padded = base64Url.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }
}