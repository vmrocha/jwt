using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Text;

namespace VmRocha.Jwt.Tests
{
    [TestFixture]
    public class JsonWebTokenCreateTokenTests
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
        public void WithKey()
        {
            var token = _jsongWebToken.CreateToken(_key);

            var tokenInfo = _jsongWebToken.Decode(token, _key);

            Assert.AreEqual(0, tokenInfo.Claims.Count);
            Assert.IsNull(tokenInfo.ExpiresOn);
            Assert.IsFalse(tokenInfo.HasExpired);
            Assert.AreEqual(tokenInfo.Header["alg"], AlgorithmMethod.HS256.ToString());
            Assert.AreEqual(tokenInfo.Header["typ"], "JWT");
        }

        [Test]
        public void WithKeyExpiration()
        {
            var temp = DateTime.UtcNow.AddDays(1);
            var expirationTimeUnix = UnixTimeStamp.ToUnixTimeStamp(temp);
            var expirationTime = UnixTimeStamp.ToDateTime(expirationTimeUnix);

            var token = _jsongWebToken.CreateToken(_key, expirationTime);

            var tokenInfo = _jsongWebToken.Decode(token);

            Assert.AreEqual(1, tokenInfo.Claims.Count);
            Assert.AreEqual(expirationTime, tokenInfo.ExpiresOn);
            Assert.IsFalse(tokenInfo.HasExpired);
            Assert.AreEqual(tokenInfo.Header["alg"], AlgorithmMethod.HS256.ToString());
            Assert.AreEqual(tokenInfo.Header["typ"], "JWT");
        }

        [Test]
        public void WithKeyClaims()
        {
            var claims = new Dictionary<string, object>
            {
                { RegisteredClaims.Issuer, "WithKeyClaims" }
            };

            var token = _jsongWebToken.CreateToken(_key, claims);

            var tokenInfo = _jsongWebToken.Decode(token, _key);

            Assert.AreEqual(1, tokenInfo.Claims.Count);
            Assert.AreEqual("WithKeyClaims", tokenInfo.Claims[RegisteredClaims.Issuer]);
            Assert.IsNull(tokenInfo.ExpiresOn);
            Assert.IsFalse(tokenInfo.HasExpired);
            Assert.AreEqual(tokenInfo.Header["alg"], AlgorithmMethod.HS256.ToString());
            Assert.AreEqual(tokenInfo.Header["typ"], "JWT");
        }

        [Test]
        public void WithKeyClaimsMethod()
        {
            var claims = new Dictionary<string, object>
            {
                { RegisteredClaims.Issuer, "WithKeyClaimsMethod" }
            };

            var token = _jsongWebToken.CreateToken(_key, claims, AlgorithmMethod.HS384);

            var tokenInfo = _jsongWebToken.Decode(token, _key);

            Assert.AreEqual(1, tokenInfo.Claims.Count);
            Assert.AreEqual("WithKeyClaimsMethod", tokenInfo.Claims[RegisteredClaims.Issuer]);
            Assert.IsNull(tokenInfo.ExpiresOn);
            Assert.IsFalse(tokenInfo.HasExpired);
            Assert.AreEqual(tokenInfo.Header["alg"], AlgorithmMethod.HS384.ToString());
            Assert.AreEqual(tokenInfo.Header["typ"], "JWT");
        }
    }
}
