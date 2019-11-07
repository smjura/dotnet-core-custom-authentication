using Superfly.AspNetCore.Authentication.Custom.Validators;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Superfly.AspNetCore.Authentication.Custom
{
    /// <summary>
    /// Options class provides information needed to control Bearer Authentication handler behavior
    /// </summary>
    public class CustomTokenOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// Gets or sets if HTTPS is required for the metadata address or authority.
        /// The default is true. This should be disabled only in development environments.
        /// </summary>
        public bool RequireHttpsMetadata { get; set; } = true;

        /// <summary>
        /// Gets or sets the challenge to put in the "WWW-Authenticate" header.
        /// </summary>
        public string Challenge { get; set; } = CustomTokenDefaults.AuthenticationScheme;

        /// <summary>
        /// The object provided by the application to process events raised by the bearer authentication handler.
        /// The application may implement the interface fully, or it may create an instance of TokenValidateEvents
        /// and assign delegates only to the events it wants to process.
        /// </summary>
        public new CustomTokenEvents Events
        {
            get { return (CustomTokenEvents)base.Events; }
            set { base.Events = value; }
        }

        /// <summary>
        /// Gets the ordered list of <see cref="ISecurityTokenValidator"/> used to validate access tokens.
        /// </summary>
        public IList<ICustomTokenValidator> SecurityTokenValidators { get; } = new List<ICustomTokenValidator>();

        /// <summary>
        /// Gets or sets the parameters used to validate identity tokens.
        /// </summary>
        /// <remarks>Contains the types and definitions required for validating a token.</remarks>
        /// <exception cref="ArgumentNullException">if 'value' is null.</exception>
        public CustomTokenValidationParameters TokenValidationParameters { get; set; } = new CustomTokenValidationParameters();

        /// <summary>
        /// Defines whether the token validation errors should be returned to the caller.
        /// Enabled by default, this option can be disabled to prevent the Custom Token handler
        /// from returning an error and an error_description in the WWW-Authenticate header.
        /// </summary>
        public bool IncludeErrorDetails { get; set; } = true;
    }
}
