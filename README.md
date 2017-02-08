[![Build status](https://ci.appveyor.com/api/projects/status/o9gplvau6o6582wj/branch/master?svg=true)](https://ci.appveyor.com/project/vmrocha/jwt/branch/master)

# JSON Web Token

JSON Web Token implementation for .NET based on [RFC 7519](https://tools.ietf.org/html/rfc7519).

## How to Use

### Create Token

You can use the `JsonWebToken` class to create a token using the method `CreateToken()`.

```cs
var key = Encoding.UTF8.GetBytes("secret");
var jsongWebToken = new JsonWebToken();
var token = jsongWebToken.CreateToken(key);
```

It is also possible to call `CreateToken()` passing a payload (also known as claims) and an [Expiration Time](https://tools.ietf.org/html/rfc7519#section-4.1.4). The following code will create a token that will expire in 10 minutes from the current UTC time.

```cs
var key = Encoding.UTF8.GetBytes("secret");
var claims = new Dictionary<string, object>
{
    { "name", "John Doe" },
    { "admin", true }
};
var token = jsongWebToken.CreateToken(key, , DateTime.UtcNow.AddMinutes(10));
```

### Decode Token

An existing token can be decoded using the method `Decode()`.

```cs
var jsongWebToken = new JsonWebToken();
TokenInformation tokenInfo = jsongWebToken.Decode(token);
```

The `TokenInformation` class exposes four main properties: `Header`, `Claims`, `ExpiresOn` and `HasExpired`. If the `key` is provided, the `Decode` method will also validate the signature throwing an `InvalidSignatureException` if the validation fails.

```cs
try
{
    var key = Encoding.UTF8.GetBytes("secret");
    var jsongWebToken = new JsonWebToken();
    jsongWebToken.Decode(token, key);
}
catch (InvalidSignatureException ex)
{
    Console.WriteLine($"Invalid {ex.InvalidSignature}, expected {ex.ExpectedSignature}.");
}
```
