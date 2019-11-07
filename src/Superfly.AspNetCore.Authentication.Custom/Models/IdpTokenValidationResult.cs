using System;
using System.Linq;

namespace Superfly.AspNetCore.Authentication.Custom.Models
{
    public class IdpTokenValidationResult
    {
        public string status { get; set; }
        public string userName { get; set; }
        public string userGuid { get; set; }
        public bool IsValid()
        {
            return !string.IsNullOrEmpty(userName) && !string.IsNullOrEmpty(userGuid) && status != null && status.IndexOf("success", StringComparison.OrdinalIgnoreCase) > -1;
        }
    }
}