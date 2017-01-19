using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Text;

namespace JsonWebToken.Tests
{
    [TestFixture]
    public class JsonWebTokenTests
    {
        private byte[] _key;
        private JsonWebToken _jsongWebToken;

        [SetUp]
        public void SetUp()
        {
            _key = Encoding.UTF8.GetBytes("secret");
            _jsongWebToken = new JsonWebToken();
        }

        [Test]
        public void CreateToken()
        {
            var expectedToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

            var token = _jsongWebToken.CreateToken(new Dictionary<string, object>
            {
                { RegisteredClaims.Subject, "1234567890"},
                { "name", "John Doe" },
                { "admin", true }
            }, AlgorithmMethod.HS256, _key);

            Assert.That(token, Is.EqualTo(expectedToken));
        }

        [Test]
        public void DecodeToken()
        {
            var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

            var claims = _jsongWebToken.Decode(token, _key);

            Assert.That(claims.Count, Is.EqualTo(3));
            Assert.That(claims[RegisteredClaims.Subject], Is.EqualTo("1234567890"));
            Assert.That(claims["name"], Is.EqualTo("John Doe"));
            Assert.That(claims["admin"], Is.EqualTo(true));
        }

        [Test]
        public void ValidateTokenSignature()
        {
            var validSignature = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
            var invalidSignature = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7Hga";
            var invalidToken = $"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.{invalidSignature}";

            try
            {
                _jsongWebToken.Decode(invalidToken, _key);
                Assert.IsTrue(false, "Token signature not validated.");
            }
            catch (InvalidSignatureException ex)
            {
                Assert.That(ex.InvalidSignature, Is.EqualTo(invalidSignature));
                Assert.That(ex.ExpectedSignature, Is.EqualTo(validSignature));
            }
        }

        [Test]
        public void CreateTokenWithExpirationTime()
        {
            var expiresOn = DateTime.UtcNow.AddMinutes(30);
            var expiresOnUnix = UnixTimeStamp.ToUnixTimeStamp(expiresOn);

            var token = _jsongWebToken.CreateToken(new Dictionary<string, object>
            {
                { RegisteredClaims.Subject, "1234567890"},
                { "name", "John Doe" },
                { "admin", true }
            }, AlgorithmMethod.HS256, _key, expiresOn);

            var claims = _jsongWebToken.Decode(token, _key);

            Assert.That(claims["exp"], Is.EqualTo(expiresOnUnix));
        }

        [Test]
        public void ValidateExpirationTime()
        {
            var expiresOn = DateTime.UtcNow.AddMinutes(-1);
            var expiresOnUnix = UnixTimeStamp.ToUnixTimeStamp(expiresOn);

            // Rounding milliseconds for comparison
            expiresOn = UnixTimeStamp.ToDateTime(expiresOnUnix);

            var token = _jsongWebToken.CreateToken(null, AlgorithmMethod.HS256, _key, expiresOn);

            try
            {
                _jsongWebToken.Decode(token, _key);
                Assert.IsTrue(false, "Token expiration time not validated.");
            }
            catch (TokenExpiredException ex)
            {
                Assert.That(ex.ExpiredOn, Is.EqualTo(expiresOn));
            }
        }
    }
}
