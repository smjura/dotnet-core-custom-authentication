using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace Superfly.AspNetCore.Authentication.Custom.Validators
{
    public interface ICustomTokenValidator
    {
        bool CanReadToken(string securityToken);
        ClaimsPrincipal ValidateToken(string securityToken, CustomTokenValidationParameters validationParameters, out SecurityToken validatedToken);
    }
}
