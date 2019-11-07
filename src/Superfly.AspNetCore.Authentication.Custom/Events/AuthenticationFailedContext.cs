// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace Superfly.AspNetCore.Authentication.Custom
{
    public class AuthenticationFailedContext : ResultContext<CustomTokenOptions>
    {
        public AuthenticationFailedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            CustomTokenOptions options)
            : base(context, scheme, options) { }

        public Exception Exception { get; set; }
    }
}