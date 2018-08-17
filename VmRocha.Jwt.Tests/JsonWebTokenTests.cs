using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Text;

namespace VmRocha.Jwt.Tests
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
            var token = _jsongWebToken.CreateToken(_key, _genericClaims);
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
        public void CreateTokenWithExpirationTime()
        {
            var expiresOn = DateTime.UtcNow.AddMinutes(30);
            var expiresOnUnix = UnixTimeStamp.ToUnixTimeStamp(expiresOn);

            var token = _jsongWebToken.CreateToken(_key, new Dictionary<string, object>
            {
                { RegisteredClaims.Subject, "1234567890"},
                { "name", "John Doe" },
                { "admin", true }
            }, AlgorithmMethod.HS256, expiresOn);

            var tokenInfo = _jsongWebToken.Decode(token, _key);

            Assert.That(tokenInfo.Claims[RegisteredClaims.ExpirationTime], Is.EqualTo(expiresOnUnix));
        }

        [Test]
        public void ValidateExpirationTime()
        {
            var temp = DateTime.UtcNow.AddDays(-1);
            var expirationTimeUnix = UnixTimeStamp.ToUnixTimeStamp(temp);
            var expirationTime = UnixTimeStamp.ToDateTime(expirationTimeUnix);

            var token = _jsongWebToken.CreateToken(_key, expirationTime);
            var tokenInfo = _jsongWebToken.Decode(token, _key);

            Assert.That(tokenInfo.HasExpired, Is.True);
            Assert.That(tokenInfo.ExpiresOn, Is.EqualTo(expirationTime));
        }

        [Test]
        public void AddSelectedAlgorithmToHeader()
        {
            var hs256 = _jsongWebToken.CreateToken(_key, AlgorithmMethod.HS256);
            var hs384 = _jsongWebToken.CreateToken(_key, AlgorithmMethod.HS384);
            var hs512 = _jsongWebToken.CreateToken(_key, AlgorithmMethod.HS512);

            Assert.AreEqual("HS256", _jsongWebToken.Decode(hs256, _key).Header["alg"]);
            Assert.AreEqual("HS384", _jsongWebToken.Decode(hs384, _key).Header["alg"]);
            Assert.AreEqual("HS512", _jsongWebToken.Decode(hs512, _key).Header["alg"]);
        }

        [Test]
        public void HasExpiredFalseWithNoExpireInformation()
        {
            var token = _jsongWebToken.CreateToken(_key);

            var information = _jsongWebToken.Decode(token, _key);

            Assert.IsNull(information.ExpiresOn);
            Assert.IsFalse(information.HasExpired);
        }

        [Test]
        public void OverwriteExpirationTimeWhenAlreadyPresent()
        {
            var expirationTime = DateTime.Today.AddDays(1);
            var claims = new Dictionary<string, object>
            {
                { RegisteredClaims.ExpirationTime, DateTime.Now },
            };

            var token = _jsongWebToken.CreateToken(_key, claims, expirationTime);
            var information = _jsongWebToken.Decode(token, _key);

            Assert.AreEqual(information.ExpiresOn, expirationTime);
        }
    }
}
