# ADFS WIA Authentication Provider

A lightweight, host‑driven authentication provider that bridges **Active Directory Federation Services (AD FS)** with **Microsoft.Identity.Web** and the **Azure SDK**.
It enables applications to acquire tokens from AD FS using **Windows Integrated Authentication (WIA)** and expose them through the supported MicrosoftIdentityTokenCredential bridge. These tokens can then be used with **any** Azure service or app registration that supports **Federated Identity Credential**, such as Azure Key Vault, CI/CD pipelines (e.g., GitHub Actions), or Kubernetes workloads—eliminating the need for secrets or certificates.

---

## ✨ Features

- 🔑 Acquire AD FS tokens via Windows Integrated Authentication (Negotiate/Kerberos).
- 🧩 Plug‑and‑play with `Microsoft.Identity.Web` as a **CustomSignedAssertionProvider**.
- 🔄 Seamless integration with Azure SDK clients (`SecretClient`, `BlobClient`, etc.) via `MicrosoftIdentityTokenCredential`.
- 🛠️ Designed for **explicit DI wiring** — no hidden service locators.
- 📜 Defensive logging and diagnostics for token acquisition and JWT validation.

---

## 📦 Installation

```powershell
dotnet add package AdfsWiaAuthenticationProvider
````

## ⚙️ Configuration
Add an EntraId (or AzureAd) section to your appsettings.json:
````
"EntraId": {
  "Instance": "https://login.microsoftonline.com/",
  "TenantId": "<your_tenant>",
  "ClientId": "<your_app_registration__client_id_>",
  "ClientCredentials": [
    {
      "SourceType": "CustomSignedAssertion", <== must be CustomSignedAssertion
      "CustomSignedAssertionProviderName": "AdfsSignedAssertion", <== must be AdfsSignedAssertion
      "CustomSignedAssertionProviderData": {
        "AuthType": "WIA", <== must be either WIA or ClienSecret
        "ClientSecret": "client secret" <== needed only if AuthType is ClientSecret
        "Host": "https://adfs.contoso.com",
        "Endpoint": "/adfs/oauth2/token/",
        "ClientId": "<server_application_client_id>", <== from the Application Group in AD FS
        "Resource": "api://AzureADTokenExchange" <== should match the Federated Identity Credential scope in Entra Id, default is api://AzureADTokenExchange
      }
    }
  ]
}
````
--- 

##  🛠️ Service Registration
In Program.cs:
````
var builder = WebApplication.CreateBuilder(args);

// Named HttpClient for WIA
builder.Services.AddHttpClient("AdfsWia") // must be "AdfsWia" so the provider can use it
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        UseDefaultCredentials = true
    });

// Add Microsoft.Identity.Web for user sign-in
builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("EntraId"));

builder.Services.AddAuthorization();

// Add token acquisition and AD FS provider
builder.Services
    .AddTokenAcquisition()
    .AddInMemoryTokenCaches()
    .AddAdfsSignedAssertionProvider();

// Register your KeyVault provider (singleton if used by background services)
// Example using KeyVaultKeyProvider that uses SecretClient
builder.Services.AddSingleton<IKeyProvider, KeyVaultKeyProvider>();
````
In KeyVaultKeyProvider.cs (used as a sample):
````
public KeyVaultKeyProvider(
    IConfiguration config,
    ILoggerFactory loggerFactory,
    ITokenAcquirerFactory factory,
    IAuthenticationSchemeInformationProvider schemeInfo)
{
    _logger = loggerFactory.CreateLogger<KeyVaultKeyProvider>();

    var vaultUri = config["KeyVault:VaultUri"]
        ?? throw new InvalidOperationException("KeyVault:VaultUri missing");

    // Supported bridge from Microsoft.Identity.Web to Azure SDK
    var credential = new MicrosoftIdentityTokenCredential(factory, schemeInfo);

    _client = new SecretClient(new Uri(vaultUri), credential);
}
````
---
## 📋 Notes
- Requires AD FS configured for OAuth2 and Windows Integrated Authentication.
- Ensure the app pool identity (if hosted in IIS) has domain credentials for WIA.
- Since WIA is used, the app should be deployed on domain‑joined servers.
- For background services (e.g., periodic key refresh), register provider (i.e. KeyVaultKeyProvider) as a singleton so it can be injected into hosted services.

---
