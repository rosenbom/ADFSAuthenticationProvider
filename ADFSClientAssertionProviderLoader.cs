using Azure;
using Azure.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Web;
using Microsoft.Win32;
using System.Net.Http;
using System.Reflection;
using static System.Net.Mime.MediaTypeNames;

namespace ADFSWIAProvider
{
    public sealed class AdfsClientAssertionproviderLoader : ICustomSignedAssertionProvider
    {
        private readonly ILogger<AdfsClientAssertionproviderLoader> _logger;
        private readonly HttpClient _httpClient;

        public AdfsClientAssertionproviderLoader(
            ILogger<AdfsClientAssertionproviderLoader> logger,
            IHttpClientFactory clientFactory)
        {
            _logger = logger;
            _httpClient = clientFactory.CreateClient("AdfsWia");
        }

        public CredentialSource CredentialSource => CredentialSource.CustomSignedAssertion;
        public string Name => "AdfsSignedAssertion";

        public async Task LoadIfNeededAsync(
            CredentialDescription credentialDescription,
            CredentialSourceLoaderParameters? parameters = null)
        {
            if (credentialDescription.CachedValue is not AdfsClientAssertionProvider assertionProvider)
            {
                assertionProvider = new AdfsClientAssertionProvider(
                    credentialDescription.CustomSignedAssertionProviderData,
                    _logger,
                    _httpClient);
            }

            try
            {
                // Warm up once to validate
                _ = await assertionProvider.GetSignedAssertionAsync(null);
                credentialDescription.CachedValue = assertionProvider;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load AD FS signed assertion provider.");
                credentialDescription.Skip = true;
                throw;
            }
        }
    }
    public static class AdfsSignedAssertionRegistration
    {
        /// <summary>
        /// Registers the AD FS signed assertion provider and a TokenCredential.
        /// </summary>
        public static IServiceCollection AddAdfsSignedAssertionProvider(
            this IServiceCollection services)
        {
            // Register the loader itself
            services.TryAddScoped<ICustomSignedAssertionProvider, AdfsClientAssertionproviderLoader>();

            return services;
        }
    }

}