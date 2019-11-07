using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System;

namespace Superfly.AspNetCore.Authentication.Custom
{
    public static class CustomTokenExtensions
    {
        public static AuthenticationBuilder AddCustomTokenBearer(this AuthenticationBuilder builder, string authenticationScheme, Action<CustomTokenOptions> configureOptions)
        {
            // TODO check why the consumer application logging configuration is not picked up by this package
            //builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<CustomTokenOptions>, CustomTokenPostConfigureOptions>());
            builder.Services.AddHttpClient();
            return builder.AddScheme<CustomTokenOptions, CustomTokenHandler>(authenticationScheme, null, configureOptions);
        }
    }
}
