using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace JsonWebToken.Tests
{
    [TestFixture]
    public class JsonWebTokenTests
    {
        private string _genericToken;
        private Dictionary<string, object> _genericClaims;
        private byte[] _key;
        private JsonWebToken _jsongWebToken;

        [SetUp]
        public void SetUp()
        {
            _key = Encoding.UTF8.GetBytes("secret");
            _jsongWebToken = new JsonWebToken();
            _genericToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
            _genericClaims = new Dictionary<string, object>
            {
                { RegisteredClaims.Subject, "1234567890"},
                { "name", "John Doe" },
                { "admin", true }
            };
        }

        [Test]
        public void CreateToken()
        {
            var token = _jsongWebToken.CreateToken(_genericClaims, AlgorithmMethod.HS256, _key);

            Assert.That(token, Is.EqualTo(_genericToken));
        }

        [Test]
        public void DecodeToken()
        {
            var tokenInfo = _jsongWebToken.Decode(_genericToken, _key);

            Assert.That(tokenInfo.Claims.Count, Is.EqualTo(3));
            Assert.That(tokenInfo.Claims[RegisteredClaims.Subject], Is.EqualTo("1234567890"));
            Assert.That(tokenInfo.Claims["name"], Is.EqualTo("John Doe"));
            Assert.That(tokenInfo.Claims["admin"], Is.EqualTo(true));
        }

        [Test]
        public void ValidateTokenSignature()
        {
            var validSignature = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
            var invalidSignature = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7Hga";
            var invalidToken = RemoveWriteSpaces(string.Format(
                @"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
                  eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.{0}",
                invalidSignature));

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

            var tokenInfo = _jsongWebToken.Decode(token, _key);

            Assert.That(tokenInfo.Claims[RegisteredClaims.ExpirationTime], Is.EqualTo(expiresOnUnix));
        }

        [Test]
        public void ValidateExpirationTime()
        {
            var expiresOn = DateTime.UtcNow.AddMinutes(-1);
            var expiresOnUnix = UnixTimeStamp.ToUnixTimeStamp(expiresOn);
            var expiredOn = UnixTimeStamp.ToDateTime(expiresOnUnix);

            var token = _jsongWebToken.CreateToken(null, AlgorithmMethod.HS256, _key, expiresOn);
            var tokenInfo = _jsongWebToken.Decode(token, _key);

            Assert.That(tokenInfo.HasExpired, Is.True);
            Assert.That(tokenInfo.ExpiresOn, Is.EqualTo(expiredOn));
        }

        private string RemoveWriteSpaces(string input)
        {
            return Regex.Replace(input, @"\s+", "");
        }
    }
}
