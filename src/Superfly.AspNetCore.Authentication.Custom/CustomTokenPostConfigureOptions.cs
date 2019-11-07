using System;
using System.Net.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;

namespace Superfly.AspNetCore.Authentication.Custom
{
    /// <summary>
    /// Used to setup defaults for all <see cref="CustomTokenOptions"/>.
    /// </summary>
    public class CustomTokenPostConfigureOptions : IPostConfigureOptions<CustomTokenOptions>
    {
        /// <summary>
        /// Invoked to post configure a TokenBearerOptions instance.
        /// </summary>
        /// <param name="name">The name of the options instance being configured.</param>
        /// <param name="options">The options instance to configure.</param>
        public void PostConfigure(string name, CustomTokenOptions options)
        {
            if (options.TokenValidationParameters?.CustomTokenValidateUrl == null)
            {
                throw new InvalidOperationException("The Custom Token Validate Url must be provided.");
            }
            else if (options.RequireHttpsMetadata && !options.TokenValidationParameters.CustomTokenValidateUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("The Custom Token Validate Url must use HTTPS unless disabled for development by setting RequireHttpsMetadata=false.");
            }
        }
    }
}
