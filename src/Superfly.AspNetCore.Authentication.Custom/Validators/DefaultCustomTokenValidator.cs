using Superfly.AspNetCore.Authentication.Custom.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace Superfly.AspNetCore.Authentication.Custom.Validators
{
    public class DefaultCustomTokenValidator : ICustomTokenValidator
    {
        private readonly HttpClient _httpClient;
        public DefaultCustomTokenValidator(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public bool CanReadToken(string tokenString)
        {
            if (tokenString == null)
            {
                var exception = new ArgumentNullException("tokenString");
                throw exception;
            }
            if (!Guid.TryParse(tokenString, out var tokenGuid))
            {
                return false;
            }
            return true;
        }

        public ClaimsPrincipal ValidateToken(string token, CustomTokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            if (token == null)
            {
                var exception = new ArgumentNullException("token");
                throw exception;
            }
            if (!Guid.TryParse(token, out var tokenGuid))
            {
                var exception = new ArgumentException("token");
                throw exception;
            }

            if (validationParameters == null)
            {
                var exception = new ArgumentNullException(nameof(validationParameters));
                throw exception;
            }

            IdpTokenValidationResult validationResult = ValidateTokenWithIdp(tokenGuid, validationParameters).Result;
            if (!validationResult.IsValid())
            {
                var exception = new SecurityTokenValidationException("Token is invalid or expired");
                throw exception;
            }
            if (!ValidateUser(validationResult.userName, validationParameters))
            { 
                var exception = new SecurityTokenInvalidAudienceException("User not authorized");
                throw exception;
            }

            ClaimsIdentity identity = CreateClaimsIdentity(validationResult.userName, validationParameters);

            validatedToken = new SimpleToken(new System.Collections.Specialized.NameValueCollection {
                { SimpleTokenConstants.Id, validationResult.userName},
                { SimpleTokenConstants.Issuer, "AIM"},
                { SimpleTokenConstants.Audience, "User"},
                { SimpleTokenConstants.Signature, null},
                { SimpleTokenConstants.ValidFrom, DateTimeOffset.UtcNow.ToString()},
                { SimpleTokenConstants.ExpiresOn, DateTimeOffset.UtcNow.AddDays(1).ToString()}
            });
            return new ClaimsPrincipal(identity);
        }
        /// <summary>
        /// Determines if the user owning the token is valid.
        /// </summary>
        private bool ValidateUser(string userName, CustomTokenValidationParameters validationParameters)
        {
            if (validationParameters.ValidateUsers)
            {
                return validationParameters.ValidUsers.Contains(userName, StringComparer.OrdinalIgnoreCase);
            }
            return true;
        }
        /// <summary>
        /// Determines if the user owning the token is valid.
        /// </summary>
        private async Task<IdpTokenValidationResult> ValidateTokenWithIdp(Guid tokenGuid, CustomTokenValidationParameters validationParameters)
        {
            var url = $"{validationParameters.CustomTokenValidateUrl}{tokenGuid.ToString()}";
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, url);
            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", validationParameters.CustomTokenValidateSecret);
            HttpResponseMessage response = await _httpClient.SendAsync(httpRequestMessage);
            string responseContent = await response.Content.ReadAsStringAsync();
            XmlSerializer xmlSerializer = new XmlSerializer(new IdpTokenValidationResult().GetType(), new XmlRootAttribute("oauthResponse"));
            return xmlSerializer.Deserialize(new StringReader(responseContent)) as IdpTokenValidationResult ?? new IdpTokenValidationResult();
        }
        private ClaimsIdentity CreateClaimsIdentity(string userName, CustomTokenValidationParameters validationParameters)
        {
            GenericIdentity myIdentity = new GenericIdentity(userName, validationParameters.AuthenticationType);
            return new ClaimsIdentity(myIdentity);
        }
    }
}
