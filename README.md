[![Build status](https://ci.appveyor.com/api/projects/status/o9gplvau6o6582wj/branch/master?svg=true)](https://ci.appveyor.com/project/vmrocha/jwt/branch/master)

# JSON Web Token

JSON Web Token .NET implementation based on [RFC 7519](https://tools.ietf.org/html/rfc7519).

## How to use

### Create token

You can use the `JsonWebToken` class to create a token using the method `CreateToken()`.

```cs
var key = Encoding.UTF8.GetBytes("secret");
var claims = new Dictionary<string, object>
{
    { RegisteredClaims.Subject, "1234567890"},
    { "name", "John Doe" },
    { "admin", true }
};

var jsongWebToken = new JsonWebToken();
var token = jsongWebToken.CreateToken(claims, AlgorithmMethod.HS256, key);
```

The previous code will generate the following token.

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```
(line breaks were added for display purposes only)

An optional parameter on `CreateToken()` is provided to set the [Expiration Time](https://tools.ietf.org/html/rfc7519#section-4.1.4). The following code will create a token that will expire in 10 minutes from the current UTC time.

```cs
var token = jsongWebToken.CreateToken(null, AlgorithmMethod.HS256, key, DateTime.UtcNow.AddMinutes(10));
```

### Decode token

An existing token can be decoded using the method `Decode()`.

```cs
var key = Encoding.UTF8.GetBytes("secret");
var jsongWebToken = new JsonWebToken();
var claims = jsongWebToken.Decode(token, key);
```

### Token validation

Currently the `Decode()` method validate the token signature and the [Expiration Time](https://tools.ietf.org/html/rfc7519#section-4.1.4) if it is present in the payload. If one of them fails, the library will throw an exception accordingly.

```cs
try
{
    var claims = jsongWebToken.Decode(token, key);
    // ...
}
catch (TokenExpiredException ex)
{
    Console.WriteLine($"Token expired on {ex.ExpiredOn}");
}
catch (InvalidSignatureException ex)
{
    Console.WriteLine($"Invalid {ex.InvalidSignature}, expected {ex.ExpectedSignature}.");
}
```
