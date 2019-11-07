using System;
using System.Collections.Generic;
using System.Linq;

namespace Superfly.AspNetCore.Authentication.Custom
{
    /// <summary>
    /// Options class provides information needed to control Bearer Authentication handler behavior
    /// </summary>
    public class CustomTokenValidationParameters : ICloneable
    {
        //
        // Summary:
        // Gets or sets the System.Collections.Generic.IEnumerable`1 that contains valid users that will be used to validate token.
        public IEnumerable<string> ValidUsers { get; set; } = new List<string>();
        //
        // Summary:
        // Gets or sets the flag to decide whether a ValidUsers check is required.
        public bool ValidateUsers { get; set; } = true;
        //
        // Summary:
        // Gets or sets authentication type which is used when creating ClaimsIdentity
        public string AuthenticationType { get; set; }
        //
        // Summary:
        // Gets or sets the token validation service endpoint
        public string CustomTokenValidateUrl { get; set; }
        //
        // Summary:
        // Gets or sets the autorization to communicate to the token validation service endpoint
        public string CustomTokenValidateSecret { get; set; }

        public object Clone()
        {
            return new CustomTokenValidationParameters
            {
                ValidUsers = new List<string>(ValidUsers.ToList()),
                ValidateUsers = ValidateUsers,
                AuthenticationType = AuthenticationType,
                CustomTokenValidateUrl = CustomTokenValidateUrl,
                CustomTokenValidateSecret = CustomTokenValidateSecret
            };
        }
    }
}
