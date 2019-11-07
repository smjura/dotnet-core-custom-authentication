// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Superfly.AspNetCore.Authentication.Custom.Validators;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Xunit;

namespace Superfly.AspNetCore.Authentication.Custom.Tests
{
    public class CustomTokenTests
    {
        private void ConfigureDefaults(CustomTokenOptions o)
        {
        }

        [Fact]
        public async Task CanForwardDefault()
        {
            var services = new ServiceCollection().AddLogging();

            services.AddAuthentication(o =>
            {
                o.DefaultScheme = CustomTokenDefaults.AuthenticationScheme;
                o.AddScheme<TestHandler>("auth1", "auth1");
            })
            .AddCustomTokenBearer(CustomTokenDefaults.AuthenticationScheme, o =>
            {
                ConfigureDefaults(o);
                o.ForwardDefault = "auth1";
            });

            var forwardDefault = new TestHandler();
            services.AddSingleton(forwardDefault);
            services.AddSingleton(CreateServer().CreateClient());
            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            Assert.Equal(0, forwardDefault.AuthenticateCount);
            Assert.Equal(0, forwardDefault.ForbidCount);
            Assert.Equal(0, forwardDefault.ChallengeCount);
            Assert.Equal(0, forwardDefault.SignInCount);
            Assert.Equal(0, forwardDefault.SignOutCount);

            await context.AuthenticateAsync();
            Assert.Equal(1, forwardDefault.AuthenticateCount);

            await context.ForbidAsync();
            Assert.Equal(1, forwardDefault.ForbidCount);

            await context.ChallengeAsync();
            Assert.Equal(1, forwardDefault.ChallengeCount);

            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignOutAsync());
            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignInAsync(new ClaimsPrincipal()));
        }

        [Fact]
        public async Task ForwardSignInThrows()
        {
            var services = new ServiceCollection().AddLogging();

            services.AddAuthentication(o =>
            {
                o.DefaultScheme = CustomTokenDefaults.AuthenticationScheme;
                o.AddScheme<TestHandler2>("auth1", "auth1");
                o.AddScheme<TestHandler>("specific", "specific");
            })
            .AddCustomTokenBearer(CustomTokenDefaults.AuthenticationScheme, o =>
            {
                ConfigureDefaults(o);
                o.ForwardDefault = "auth1";
                o.ForwardSignOut = "specific";
            });

            var specific = new TestHandler();
            services.AddSingleton(specific);
            var forwardDefault = new TestHandler2();
            services.AddSingleton(forwardDefault);
            services.AddSingleton(CreateServer().CreateClient());

            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignInAsync(new ClaimsPrincipal()));
        }

        [Fact]
        public async Task ForwardSignOutThrows()
        {
            var services = new ServiceCollection().AddLogging();

            services.AddAuthentication(o =>
            {
                o.DefaultScheme = CustomTokenDefaults.AuthenticationScheme;
                o.AddScheme<TestHandler2>("auth1", "auth1");
                o.AddScheme<TestHandler>("specific", "specific");
            })
            .AddCustomTokenBearer(CustomTokenDefaults.AuthenticationScheme, o =>
            {
                ConfigureDefaults(o);
                o.ForwardDefault = "auth1";
                o.ForwardSignOut = "specific";
            });

            var specific = new TestHandler();
            services.AddSingleton(specific);
            var forwardDefault = new TestHandler2();
            services.AddSingleton(forwardDefault);
            services.AddSingleton(CreateServer().CreateClient());

            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignOutAsync());
        }

        [Fact]
        public async Task ForwardForbidWinsOverDefault()
        {
            var services = new ServiceCollection().AddLogging();

            services.AddAuthentication(o =>
            {
                o.DefaultScheme = CustomTokenDefaults.AuthenticationScheme;
                o.DefaultSignInScheme = "auth1";
                o.AddScheme<TestHandler2>("auth1", "auth1");
                o.AddScheme<TestHandler>("specific", "specific");
            })
            .AddCustomTokenBearer(CustomTokenDefaults.AuthenticationScheme, o =>
            {
                ConfigureDefaults(o);
                o.ForwardDefault = "auth1";
                o.ForwardForbid = "specific";
            });

            var specific = new TestHandler();
            services.AddSingleton(specific);
            var forwardDefault = new TestHandler2();
            services.AddSingleton(forwardDefault);
            services.AddSingleton(CreateServer().CreateClient());

            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            await context.ForbidAsync();
            Assert.Equal(0, specific.SignOutCount);
            Assert.Equal(0, specific.AuthenticateCount);
            Assert.Equal(1, specific.ForbidCount);
            Assert.Equal(0, specific.ChallengeCount);
            Assert.Equal(0, specific.SignInCount);

            Assert.Equal(0, forwardDefault.AuthenticateCount);
            Assert.Equal(0, forwardDefault.ForbidCount);
            Assert.Equal(0, forwardDefault.ChallengeCount);
            Assert.Equal(0, forwardDefault.SignInCount);
            Assert.Equal(0, forwardDefault.SignOutCount);
        }

        [Fact]
        public async Task ForwardAuthenticateWinsOverDefault()
        {
            var services = new ServiceCollection().AddLogging();

            services.AddAuthentication(o =>
            {
                o.DefaultScheme = CustomTokenDefaults.AuthenticationScheme;
                o.DefaultSignInScheme = "auth1";
                o.AddScheme<TestHandler2>("auth1", "auth1");
                o.AddScheme<TestHandler>("specific", "specific");
            })
            .AddCustomTokenBearer(CustomTokenDefaults.AuthenticationScheme, o =>
            {
                ConfigureDefaults(o);
                o.ForwardDefault = "auth1";
                o.ForwardAuthenticate = "specific";
            });

            var specific = new TestHandler();
            services.AddSingleton(specific);
            var forwardDefault = new TestHandler2();
            services.AddSingleton(forwardDefault);
            services.AddSingleton(CreateServer().CreateClient());

            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            await context.AuthenticateAsync();
            Assert.Equal(0, specific.SignOutCount);
            Assert.Equal(1, specific.AuthenticateCount);
            Assert.Equal(0, specific.ForbidCount);
            Assert.Equal(0, specific.ChallengeCount);
            Assert.Equal(0, specific.SignInCount);

            Assert.Equal(0, forwardDefault.AuthenticateCount);
            Assert.Equal(0, forwardDefault.ForbidCount);
            Assert.Equal(0, forwardDefault.ChallengeCount);
            Assert.Equal(0, forwardDefault.SignInCount);
            Assert.Equal(0, forwardDefault.SignOutCount);
        }

        [Fact]
        public async Task ForwardChallengeWinsOverDefault()
        {
            var services = new ServiceCollection().AddLogging();
            services.AddAuthentication(o =>
            {
                o.DefaultScheme = CustomTokenDefaults.AuthenticationScheme;
                o.DefaultSignInScheme = "auth1";
                o.AddScheme<TestHandler>("specific", "specific");
                o.AddScheme<TestHandler2>("auth1", "auth1");
            })
            .AddCustomTokenBearer(CustomTokenDefaults.AuthenticationScheme, o =>
            {
                ConfigureDefaults(o);
                o.ForwardDefault = "auth1";
                o.ForwardChallenge = "specific";
            });

            var specific = new TestHandler();
            services.AddSingleton(specific);
            var forwardDefault = new TestHandler2();
            services.AddSingleton(forwardDefault);
            services.AddSingleton(CreateServer().CreateClient());

            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            await context.ChallengeAsync();
            Assert.Equal(0, specific.SignOutCount);
            Assert.Equal(0, specific.AuthenticateCount);
            Assert.Equal(0, specific.ForbidCount);
            Assert.Equal(1, specific.ChallengeCount);
            Assert.Equal(0, specific.SignInCount);

            Assert.Equal(0, forwardDefault.AuthenticateCount);
            Assert.Equal(0, forwardDefault.ForbidCount);
            Assert.Equal(0, forwardDefault.ChallengeCount);
            Assert.Equal(0, forwardDefault.SignInCount);
            Assert.Equal(0, forwardDefault.SignOutCount);
        }

        [Fact]
        public async Task ForwardSelectorWinsOverDefault()
        {
            var services = new ServiceCollection().AddLogging();
            services.AddAuthentication(o =>
            {
                o.DefaultScheme = CustomTokenDefaults.AuthenticationScheme;
                o.AddScheme<TestHandler2>("auth1", "auth1");
                o.AddScheme<TestHandler3>("selector", "selector");
                o.AddScheme<TestHandler>("specific", "specific");
            })
            .AddCustomTokenBearer(CustomTokenDefaults.AuthenticationScheme, o =>
            {
                ConfigureDefaults(o);
                o.ForwardDefault = "auth1";
                o.ForwardDefaultSelector = _ => "selector";
            });

            var specific = new TestHandler();
            services.AddSingleton(specific);
            var forwardDefault = new TestHandler2();
            services.AddSingleton(forwardDefault);
            var selector = new TestHandler3();
            services.AddSingleton(selector);
            services.AddSingleton(CreateServer().CreateClient());

            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            await context.AuthenticateAsync();
            Assert.Equal(1, selector.AuthenticateCount);

            await context.ForbidAsync();
            Assert.Equal(1, selector.ForbidCount);

            await context.ChallengeAsync();
            Assert.Equal(1, selector.ChallengeCount);

            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignOutAsync());
            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignInAsync(new ClaimsPrincipal()));

            Assert.Equal(0, forwardDefault.AuthenticateCount);
            Assert.Equal(0, forwardDefault.ForbidCount);
            Assert.Equal(0, forwardDefault.ChallengeCount);
            Assert.Equal(0, forwardDefault.SignInCount);
            Assert.Equal(0, forwardDefault.SignOutCount);
            Assert.Equal(0, specific.AuthenticateCount);
            Assert.Equal(0, specific.ForbidCount);
            Assert.Equal(0, specific.ChallengeCount);
            Assert.Equal(0, specific.SignInCount);
            Assert.Equal(0, specific.SignOutCount);
        }

        [Fact]
        public async Task NullForwardSelectorUsesDefault()
        {
            var services = new ServiceCollection().AddLogging();
            services.AddAuthentication(o =>
            {
                o.DefaultScheme = CustomTokenDefaults.AuthenticationScheme;
                o.AddScheme<TestHandler2>("auth1", "auth1");
                o.AddScheme<TestHandler3>("selector", "selector");
                o.AddScheme<TestHandler>("specific", "specific");
            })
            .AddCustomTokenBearer(CustomTokenDefaults.AuthenticationScheme, o =>
            {
                ConfigureDefaults(o);
                o.ForwardDefault = "auth1";
                o.ForwardDefaultSelector = _ => null;
            });

            var specific = new TestHandler();
            services.AddSingleton(specific);
            var forwardDefault = new TestHandler2();
            services.AddSingleton(forwardDefault);
            var selector = new TestHandler3();
            services.AddSingleton(selector);
            services.AddSingleton(CreateServer().CreateClient());

            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            await context.AuthenticateAsync();
            Assert.Equal(1, forwardDefault.AuthenticateCount);

            await context.ForbidAsync();
            Assert.Equal(1, forwardDefault.ForbidCount);

            await context.ChallengeAsync();
            Assert.Equal(1, forwardDefault.ChallengeCount);

            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignOutAsync());
            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignInAsync(new ClaimsPrincipal()));

            Assert.Equal(0, selector.AuthenticateCount);
            Assert.Equal(0, selector.ForbidCount);
            Assert.Equal(0, selector.ChallengeCount);
            Assert.Equal(0, selector.SignInCount);
            Assert.Equal(0, selector.SignOutCount);
            Assert.Equal(0, specific.AuthenticateCount);
            Assert.Equal(0, specific.ForbidCount);
            Assert.Equal(0, specific.ChallengeCount);
            Assert.Equal(0, specific.SignInCount);
            Assert.Equal(0, specific.SignOutCount);
        }

        [Fact]
        public async Task SpecificForwardWinsOverSelectorAndDefault()
        {
            var services = new ServiceCollection().AddLogging();
            services.AddAuthentication(o =>
            {
                o.DefaultScheme = CustomTokenDefaults.AuthenticationScheme;
                o.AddScheme<TestHandler2>("auth1", "auth1");
                o.AddScheme<TestHandler3>("selector", "selector");
                o.AddScheme<TestHandler>("specific", "specific");
            })
            .AddCustomTokenBearer(CustomTokenDefaults.AuthenticationScheme, o =>
            {
                ConfigureDefaults(o);
                o.ForwardDefault = "auth1";
                o.ForwardDefaultSelector = _ => "selector";
                o.ForwardAuthenticate = "specific";
                o.ForwardChallenge = "specific";
                o.ForwardSignIn = "specific";
                o.ForwardSignOut = "specific";
                o.ForwardForbid = "specific";
            });

            var specific = new TestHandler();
            services.AddSingleton(specific);
            var forwardDefault = new TestHandler2();
            services.AddSingleton(forwardDefault);
            var selector = new TestHandler3();
            services.AddSingleton(selector);
            services.AddSingleton(CreateServer().CreateClient());

            var sp = services.BuildServiceProvider();
            var context = new DefaultHttpContext();
            context.RequestServices = sp;

            await context.AuthenticateAsync();
            Assert.Equal(1, specific.AuthenticateCount);

            await context.ForbidAsync();
            Assert.Equal(1, specific.ForbidCount);

            await context.ChallengeAsync();
            Assert.Equal(1, specific.ChallengeCount);

            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignOutAsync());
            await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignInAsync(new ClaimsPrincipal()));

            Assert.Equal(0, forwardDefault.AuthenticateCount);
            Assert.Equal(0, forwardDefault.ForbidCount);
            Assert.Equal(0, forwardDefault.ChallengeCount);
            Assert.Equal(0, forwardDefault.SignInCount);
            Assert.Equal(0, forwardDefault.SignOutCount);
            Assert.Equal(0, selector.AuthenticateCount);
            Assert.Equal(0, selector.ForbidCount);
            Assert.Equal(0, selector.ChallengeCount);
            Assert.Equal(0, selector.SignInCount);
            Assert.Equal(0, selector.SignOutCount);
        }

        [Fact]
        public async Task VerifySchemeDefaults()
        {
            var services = new ServiceCollection();
            services.AddAuthentication().AddCustomTokenBearer(CustomTokenDefaults.AuthenticationScheme, null);
            var sp = services.BuildServiceProvider();
            var schemeProvider = sp.GetRequiredService<IAuthenticationSchemeProvider>();
            var scheme = await schemeProvider.GetSchemeAsync(CustomTokenDefaults.AuthenticationScheme);
            Assert.NotNull(scheme);
            Assert.Equal("CustomTokenHandler", scheme.HandlerType.Name);
            Assert.Null(scheme.DisplayName);
        }

        [Fact]
        public async Task SignInThrows()
        {
            var server = CreateServer(null,
            async (context, next) =>
            {
                await next();
                await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignInAsync(CustomTokenDefaults.AuthenticationScheme, new ClaimsPrincipal()));
            });
            var transaction = await server.SendAsync("https://example.com/signIn");

        }

        [Fact]
        public async Task SignOutThrows()
        {
            var server = CreateServer(null,
             async (context, next) =>
             {
                 await next();
                 await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignOutAsync(CustomTokenDefaults.AuthenticationScheme));
             });
            var transaction = await server.SendAsync("https://example.com/signOut");
            Assert.Equal(HttpStatusCode.OK, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task ThrowAtAuthenticationFailedEvent()
        {
            var server = CreateServer(o =>
            {
                o.Events = new CustomTokenEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        context.Response.StatusCode = 401;
                        throw new Exception();
                    },
                    OnMessageReceived = context =>
                    {
                        context.Token = "something";
                        return Task.FromResult(0);
                    }
                };
                o.SecurityTokenValidators.Clear();
                o.SecurityTokenValidators.Insert(0, new InvalidTokenValidator());
            },
            async (context, next) =>
            {
                try
                {
                    await next();
                    Assert.False(true, "Expected exception is not thrown");
                }
                catch (Exception)
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("i got this");
                }
            });

            var transaction = await server.SendAsync("https://example.com/signIn");

            Assert.Equal(HttpStatusCode.Unauthorized, transaction.Response.StatusCode);
        }

        [Fact]
        public async Task CustomHeaderReceived()
        {
            var server = CreateServer(o => o.EnsureValidCustomTokenOptions(), null, GetOkHttpResponseMessage());

            var response = await SendAsync(server, "http://example.com/validate", $"someHeader {Guid.NewGuid().ToString()}");
            Assert.Equal(HttpStatusCode.OK, response.Response.StatusCode);
            Assert.Equal("Yury", response.ResponseText);
        }

        [Fact]
        public async Task NoAuthenticationHeaderReceived()
        {
            var services = new ServiceCollection().AddLogging();
            var server = CreateServer();
            var response = await SendAsync(server, "http://example.com/validate");
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
        }

        [Fact]
        public async Task HeaderWithoutBearerReceived()
        {
            var services = new ServiceCollection().AddLogging();
            var server = CreateServer();
            var response = await SendAsync(server, "http://example.com/validate", "Token");
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
        }

        [Fact]
        public async Task UnrecognizedTokenReceived()
        {
            var services = new ServiceCollection().AddLogging();
            var server = CreateServer();
            var response = await SendAsync(server, "http://example.com/validate", $"{CustomTokenDefaults.AuthenticationScheme} blah");
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.Equal("", response.ResponseText);
        }

        [Fact]
        public async Task InvalidTokenReceived()
        {
            var services = new ServiceCollection().AddLogging();
            var server = CreateServer(options =>
            {
                options.SecurityTokenValidators.Clear();
                options.SecurityTokenValidators.Add(new InvalidTokenValidator());
                options.EnsureValidCustomTokenOptions();
            });

            var response = await SendAsync(server, "http://example.com/validate", $"{CustomTokenDefaults.AuthenticationScheme} {Guid.NewGuid().ToString()}");
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.Equal($"{CustomTokenDefaults.AuthenticationScheme} error=\"invalid_token\"", response.Response.Headers.WwwAuthenticate.First().ToString());
            Assert.Equal("", response.ResponseText);
        }

        [Theory]
        [InlineData(typeof(SecurityTokenInvalidAudienceException), "User not authorized")]
        [InlineData(typeof(SecurityTokenValidationException), "Token is invalid or expired")]
        public async Task ExceptionReportedInHeaderForAuthenticationFailures(Type errorType, string message)
        {
            var server = CreateServer(options =>
            {
                options.SecurityTokenValidators.Clear();
                options.SecurityTokenValidators.Add(new InvalidTokenValidator(errorType));
                options.EnsureValidCustomTokenOptions();
            });

            var response = await SendAsync(server, "http://example.com/validate", $"{CustomTokenDefaults.AuthenticationScheme} {Guid.NewGuid().ToString()}");
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.Equal($"{CustomTokenDefaults.AuthenticationScheme} error=\"invalid_token\", error_description=\"{message}\"", response.Response.Headers.WwwAuthenticate.First().ToString());
            Assert.Equal("", response.ResponseText);
        }
        [Theory]
        [InlineData(typeof(InvalidOperationException), "The Custom Token Validate Url must be provided.")]
        public async Task ExceptionReportedInHeaderForAuthenticationFailures2(Type errorType, string message)
        {
            var server = CreateServer(options =>
            {
                options.SecurityTokenValidators.Clear();
                options.SecurityTokenValidators.Add(new InvalidTokenValidateUrlValidator(errorType));
                options.EnsureValidCustomTokenOptions();
            });

            var response = await SendAsync(server, "http://example.com/validate", $"{CustomTokenDefaults.AuthenticationScheme} {Guid.NewGuid().ToString()}");
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.Equal($"{CustomTokenDefaults.AuthenticationScheme} error=\"invalid_token\", error_description=\"{message}\"", response.Response.Headers.WwwAuthenticate.First().ToString());
            Assert.Equal("", response.ResponseText);
        }
        [Theory]
        [InlineData(typeof(InvalidOperationException), "The Custom Token Validate Url must use HTTPS unless disabled for development by setting RequireHttpsMetadata=false.")]
        public async Task ExceptionReportedInHeaderForAuthenticationFailures3(Type errorType, string message)
        {
            var server = CreateServer(options =>
            {
                options.SecurityTokenValidators.Clear();
                options.SecurityTokenValidators.Add(new InvalidTokenValidateUrlRequireHttpsMetadataValidator(errorType));
                options.EnsureValidCustomTokenOptions();
            });

            var response = await SendAsync(server, "http://example.com/validate", $"{CustomTokenDefaults.AuthenticationScheme} {Guid.NewGuid().ToString()}");
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.Equal($"{CustomTokenDefaults.AuthenticationScheme} error=\"invalid_token\", error_description=\"{message}\"", response.Response.Headers.WwwAuthenticate.First().ToString());
            Assert.Equal("", response.ResponseText);
        }
        [Theory]
        [InlineData(typeof(ArgumentException))]
        public async Task ExceptionNotReportedInHeaderForOtherFailures(Type errorType)
        {
            var server = CreateServer(options =>
            {
                options.SecurityTokenValidators.Clear();
                options.SecurityTokenValidators.Add(new InvalidTokenValidator(errorType));
                options.EnsureValidCustomTokenOptions();
            });

            var response = await SendAsync(server, "http://example.com/validate", $"{CustomTokenDefaults.AuthenticationScheme} {Guid.NewGuid().ToString()}");
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.Equal($"{CustomTokenDefaults.AuthenticationScheme} error=\"invalid_token\"", response.Response.Headers.WwwAuthenticate.First().ToString());
            Assert.Equal("", response.ResponseText);
        }

        [Fact]
        public async Task ExceptionsReportedInHeaderForMultipleAuthenticationFailures()
        {
            var server = CreateServer(options =>
            {
                options.SecurityTokenValidators.Clear();
                options.SecurityTokenValidators.Add(new InvalidTokenValidator(typeof(SecurityTokenInvalidAudienceException)));
                options.SecurityTokenValidators.Add(new InvalidTokenValidator(typeof(SecurityTokenValidationException)));
                options.EnsureValidCustomTokenOptions();
            });

            var response = await SendAsync(server, "http://example.com/validate", $"{CustomTokenDefaults.AuthenticationScheme} {Guid.NewGuid().ToString()}");
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.Equal($"{CustomTokenDefaults.AuthenticationScheme} error=\"invalid_token\", error_description=\"User not authorized; Token is invalid or expired\"",
                response.Response.Headers.WwwAuthenticate.First().ToString());
            Assert.Equal("", response.ResponseText);
        }

        [Theory]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", null, null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, null, "custom_uri")]
        public async Task ExceptionsReportedInHeaderExposesUserDefinedError(string error, string description, string uri)
        {
            var server = CreateServer(options =>
            {
                options.Events = new CustomTokenEvents
                {
                    OnChallenge = context =>
                    {
                        context.Error = error;
                        context.ErrorDescription = description;
                        context.ErrorUri = uri;

                        return Task.FromResult(0);
                    }
                };
            });

            var response = await SendAsync(server, "http://example.com/validate", $"{CustomTokenDefaults.AuthenticationScheme} {Guid.NewGuid().ToString()}");
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.Equal("", response.ResponseText);

            var builder = new StringBuilder(CustomTokenDefaults.AuthenticationScheme);

            if (!string.IsNullOrEmpty(error))
            {
                builder.Append(" error=\"");
                builder.Append(error);
                builder.Append("\"");
            }
            if (!string.IsNullOrEmpty(description))
            {
                if (!string.IsNullOrEmpty(error))
                {
                    builder.Append(",");
                }

                builder.Append(" error_description=\"");
                builder.Append(description);
                builder.Append('\"');
            }
            if (!string.IsNullOrEmpty(uri))
            {
                if (!string.IsNullOrEmpty(error) ||
                    !string.IsNullOrEmpty(description))
                {
                    builder.Append(",");
                }

                builder.Append(" error_uri=\"");
                builder.Append(uri);
                builder.Append('\"');
            }

            Assert.Equal(builder.ToString(), response.Response.Headers.WwwAuthenticate.First().ToString());
        }

        [Fact]
        public async Task ExceptionNotReportedInHeaderWhenIncludeErrorDetailsIsFalse()
        {
            var server = CreateServer(o =>
            {
                o.IncludeErrorDetails = false;
            });

            var response = await SendAsync(server, "http://example.com/validate", $"{CustomTokenDefaults.AuthenticationScheme} {Guid.NewGuid().ToString()}");
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.Equal(CustomTokenDefaults.AuthenticationScheme, response.Response.Headers.WwwAuthenticate.First().ToString());
            Assert.Equal("", response.ResponseText);
        }

        [Fact]
        public async Task ExceptionNotReportedInHeaderWhenTokenWasMissing()
        {
            var server = CreateServer();

            var response = await SendAsync(server, "http://example.com/validate");
            Assert.Equal(HttpStatusCode.Unauthorized, response.Response.StatusCode);
            Assert.Equal(CustomTokenDefaults.AuthenticationScheme, response.Response.Headers.WwwAuthenticate.First().ToString());
            Assert.Equal("", response.ResponseText);
        }

        [Fact]
        public async Task EventOnMessageReceivedSkip_NoMoreEventsExecuted()
        {
            var server = CreateServer(options =>
            {
                options.Events = new CustomTokenEvents()
                {
                    OnMessageReceived = context =>
                    {
                        context.NoResult();
                        return Task.FromResult(0);
                    },
                    OnTokenValidated = context =>
                    {
                        throw new NotImplementedException();
                    },
                    OnAuthenticationFailed = context =>
                    {
                        throw new NotImplementedException(context.Exception.ToString());
                    },
                    OnChallenge = context =>
                    {
                        throw new NotImplementedException();
                    },
                };
            });

            var response = await SendAsync(server, "http://example.com/checkforerrors", $"{CustomTokenDefaults.AuthenticationScheme} {Guid.NewGuid().ToString()}");
            Assert.Equal(HttpStatusCode.OK, response.Response.StatusCode);
            Assert.Equal(string.Empty, response.ResponseText);
        }

        [Fact]
        public async Task EventOnMessageReceivedReject_NoMoreEventsExecuted()
        {
            var server = CreateServer(options =>
            {
                options.Events = new CustomTokenEvents()
                {
                    OnMessageReceived = context =>
                    {
                        context.Fail("Authentication was aborted from user code.");
                        context.Response.StatusCode = StatusCodes.Status202Accepted;
                        return Task.FromResult(0);
                    },
                    OnTokenValidated = context =>
                    {
                        throw new NotImplementedException();
                    },
                    OnAuthenticationFailed = context =>
                    {
                        throw new NotImplementedException(context.Exception.ToString());
                    },
                    OnChallenge = context =>
                    {
                        throw new NotImplementedException();
                    },
                };
            });

            var exception = await Assert.ThrowsAsync<Exception>(delegate
            {
                return SendAsync(server, "http://example.com/checkforerrors", $"{CustomTokenDefaults.AuthenticationScheme} {Guid.NewGuid().ToString()}");
            });

            Assert.Equal("Authentication was aborted from user code.", exception.InnerException.Message);
        }

        [Fact]
        public async Task EventOnChallengeSkip_ResponseNotModified()
        {
            var server = CreateServer(o =>
            {
                o.Events = new CustomTokenEvents()
                {
                    OnChallenge = context =>
                    {
                        context.HandleResponse();
                        return Task.FromResult(0);
                    },
                };
            });

            var response = await SendAsync(server, "http://example.com/unauthorized", $"{CustomTokenDefaults.AuthenticationScheme} {Guid.NewGuid().ToString()}");
            Assert.Equal(HttpStatusCode.OK, response.Response.StatusCode);
            Assert.Empty(response.Response.Headers.WwwAuthenticate);
            Assert.Equal(string.Empty, response.ResponseText);
        }

        class InvalidTokenValidator : ICustomTokenValidator
        {
            public InvalidTokenValidator()
            {
                ExceptionType = typeof(SecurityTokenException);
            }

            public InvalidTokenValidator(Type exceptionType)
            {
                ExceptionType = exceptionType;
            }

            public Type ExceptionType { get; set; }

            public bool CanValidateToken => true;

            public int MaximumTokenSizeInBytes
            {
                get { throw new NotImplementedException(); }
                set { throw new NotImplementedException(); }
            }

            public bool CanReadToken(string securityToken) => true;

            public ClaimsPrincipal ValidateToken(string securityToken, CustomTokenValidationParameters validationParameters, out SecurityToken validatedToken)
            {
                var constructor = ExceptionType.GetTypeInfo().GetConstructor(new[] { typeof(string) });
                var exception = (Exception)constructor.Invoke(new[] { ExceptionType.Name });
                throw exception;
            }
        }
        class InvalidTokenValidateUrlValidator : ICustomTokenValidator
        {
            public InvalidTokenValidateUrlValidator()
            {
                ExceptionType = typeof(InvalidOperationException);
            }

            public InvalidTokenValidateUrlValidator(Type exceptionType)
            {
                ExceptionType = exceptionType;
            }

            public Type ExceptionType { get; set; }

            public bool CanValidateToken => true;

            public int MaximumTokenSizeInBytes
            {
                get { throw new NotImplementedException(); }
                set { throw new NotImplementedException(); }
            }

            public bool CanReadToken(string securityToken) => true;

            public ClaimsPrincipal ValidateToken(string securityToken, CustomTokenValidationParameters validationParameters, out SecurityToken validatedToken)
            {
                var constructor = ExceptionType.GetTypeInfo().GetConstructor(new[] { typeof(string) });
                var exception = (Exception)constructor.Invoke(new[] { "The Custom Token Validate Url must be provided." });
                throw exception;
            }
        }
        class InvalidTokenValidateUrlRequireHttpsMetadataValidator : ICustomTokenValidator
        {
            public InvalidTokenValidateUrlRequireHttpsMetadataValidator()
            {
                ExceptionType = typeof(InvalidOperationException);
            }

            public InvalidTokenValidateUrlRequireHttpsMetadataValidator(Type exceptionType)
            {
                ExceptionType = exceptionType;
            }

            public Type ExceptionType { get; set; }

            public bool CanValidateToken => true;

            public int MaximumTokenSizeInBytes
            {
                get { throw new NotImplementedException(); }
                set { throw new NotImplementedException(); }
            }

            public bool CanReadToken(string securityToken) => true;

            public ClaimsPrincipal ValidateToken(string securityToken, CustomTokenValidationParameters validationParameters, out SecurityToken validatedToken)
            {
                var constructor = ExceptionType.GetTypeInfo().GetConstructor(new[] { typeof(string) });
                var exception = (Exception)constructor.Invoke(new[] { "The Custom Token Validate Url must use HTTPS unless disabled for development by setting RequireHttpsMetadata=false." });
                throw exception;
            }
        }
       
        private static TestServer CreateServer(Action<CustomTokenOptions> options = null, Func<HttpContext, Func<Task>, Task> handlerBeforeAuth = null, HttpResponseMessage mockedHttpResponseMessage = null)
        {
            var builder = new WebHostBuilder()
                .Configure(app =>
                {
                    if (handlerBeforeAuth != null)
                    {
                        app.Use(handlerBeforeAuth);
                    }

                    app.UseAuthentication();
                    app.Use(async (context, next) =>
                    {
                        if (context.Request.Path == new PathString("/checkforerrors"))
                        {
                            var result = await context.AuthenticateAsync(CustomTokenDefaults.AuthenticationScheme); // this used to be "Automatic"
                            if (result.Failure != null)
                            {
                                throw new Exception("Failed to authenticate", result.Failure);
                            }
                            return;
                        }
                        else if (context.Request.Path == new PathString("/validate"))
                        {
                            if (context.User == null ||
                                context.User.Identity == null ||
                                !context.User.Identity.IsAuthenticated)
                            {
                                context.Response.StatusCode = 401;
                                // REVIEW: no more automatic challenge
                                await context.ChallengeAsync(CustomTokenDefaults.AuthenticationScheme);
                                return;
                            }

                            var userName = context.User.Identity.Name;
                            if (userName == null)
                            {
                                context.Response.StatusCode = 500;
                                return;
                            }

                            await context.Response.WriteAsync(userName);
                        }
                        else if (context.Request.Path == new PathString("/token"))
                        {
                            var token = await context.GetTokenAsync("access_token");
                            await context.Response.WriteAsync(token);
                        }
                        else if (context.Request.Path == new PathString("/unauthorized"))
                        {
                            // Simulate Authorization failure 
                            var result = await context.AuthenticateAsync(CustomTokenDefaults.AuthenticationScheme);
                            await context.ChallengeAsync(CustomTokenDefaults.AuthenticationScheme);
                        }
                        else if (context.Request.Path == new PathString("/signIn"))
                        {
                            await Task.FromResult(new InvalidOperationException());
                        }
                        else if (context.Request.Path == new PathString("/signOut"))
                        {
                            await Task.FromResult(new InvalidOperationException()); 
                        }
                        else
                        {
                            await next();
                        }
                    });
                })
                .ConfigureServices(services =>
                {
                    services.AddAuthentication(CustomTokenDefaults.AuthenticationScheme).AddCustomTokenBearer(CustomTokenDefaults.AuthenticationScheme, options);
                    services.AddCustomTokenHandler();
                    services.AddHttpMessageHandlerMock(mockedHttpResponseMessage ?? new HttpResponseMessage());
                });

            return new TestServer(builder);
        }

        // TODO: see if we can share the TestExtensions SendAsync method (only diff is auth header)
        private static async Task<Transaction> SendAsync(TestServer server, string uri, string authorizationHeader = null)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, uri);
            if (!string.IsNullOrEmpty(authorizationHeader))
            {
                request.Headers.Add("Authorization", authorizationHeader);
            }

            var transaction = new Transaction
            {
                Request = request,
                Response = await server.CreateClient().SendAsync(request),
            };

            transaction.ResponseText = await transaction.Response.Content.ReadAsStringAsync();

            if (transaction.Response.Content != null &&
                transaction.Response.Content.Headers.ContentType != null &&
                transaction.Response.Content.Headers.ContentType.MediaType == "text/xml")
            {
                transaction.ResponseElement = XElement.Parse(transaction.ResponseText);
            }

            return transaction;
        }
        private static Func<HttpContext, Func<Task>, Task> AddRequiredServices(IServiceCollection services, HttpResponseMessage httpResponseMessage = null)
        {
            return async (context, next) =>
            {
                //services.AddCustomTokenHandler();
                //services.AddHttpMessageHandlerMock(httpResponseMessage ?? new HttpResponseMessage());
                await next();
            };
        }
        private static HttpResponseMessage GetOkHttpResponseMessage()
        {
            return new HttpResponseMessage()
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent("<oauthResponse><status>Success</status><userName>Yury</userName><userGuid>guid</userGuid></oauthResponse>"),
            };
        }
        private static HttpResponseMessage GetUnauthorizedResponseMessage()
        {
            return new HttpResponseMessage()
            {
                StatusCode = HttpStatusCode.Unauthorized
            };
        }
        private static HttpResponseMessage GetNotFoundResponseMessage()
        {
            return new HttpResponseMessage()
            {
                StatusCode = HttpStatusCode.NotFound
            };
        }
        private static HttpResponseMessage GetTokenValidationFailedResponseMessage()
        {
            return new HttpResponseMessage()
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent("<oauthResponse><status>Error</status><userName></userName></oauthResponse>"),
            };
        }
    }
}
