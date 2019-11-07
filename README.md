
# CDK.Authentication.


An implementation of ```AuthenticationHandler<TOption>``` that implements the ```IAuthenticationHandler``` interface.

For reference, use [Microsoft dotnet core security repo](https://github.com/aspnet/Security)  



## Getting started

```csharp
public class Startup
{
  public void ConfigureServices(IServicesCollection services)
  {
    services.AddAuthentication()
    .AddCustomTokenBearer(YourApp.Configuration.AuthenticationConfiguration.AuthenticationSchema, options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateUsers = YourApp.Configuration.AuthenticationConfiguration.ValidateUsers,
            ValidUsers = new List<string>(YourApp.Configuration.AuthenticationConfiguration.ValidUsers),
            TokenValidateUrl = YourApp.Configuration.AuthenticationConfiguration.TokenIssuer,
            TokenValidateSecret = YourApp.Configuration.AuthenticationConfiguration.AuthorizarionToken,
            AuthenticationType = YourApp.Configuration.AuthenticationConfiguration.AuthenticationSchema
        };
        options.RequireHttpsMetadata = YourApp.Configuration.AuthenticationConfiguration.IssuerRequireHttps ?? !_env.IsDevelopmentOrLocalDocker();
    });
  }
}
```

Configure the following ```TokenValidationParameters``` for all your environments:


## TokenValidationParameters

```TokenValidationParameters.ValidUsers``` - array of allowed user names

```TokenValidationParameters.ValidateUsers``` - boolean flag which can be used to turn off the user names validation

```TokenValidationParameters.TokenValidateUrl``` - endpoint URL to validate incoming access tokens  

```TokenValidationParameters.TokenValidateSecret``` - secret (refresh token) to authorize validation requests 

```TokenValidationParameters.AuthenticationType``` - auth schema, example "my-bearer"

## IssuerRequireHttps

```IssuerRequireHttps``` - boolean flag to specify if HTTPS is required for the ```TokenValidateUrl``` authority. Default is "true". This should be disabled only in development environments.

## Sample appsettings.json for your application:
```javascript
{
  "AuthenticationConfiguration": {
    "ValidateUsers": true,
    "TokenValidateUrl": "https://your-idp-provider-url.com/validate/",
    "IssuerRequireHttps": true,
    "ValidUsers": [ "sys-user-1", "sys-user-2" ],
    "TokenValidateSecret": "1b111111-1ddd-1d1d-ad11-1cfc1111e111"
  }
}
```

test note 1
test note 2
master note 3