using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Text;

namespace JsonWebToken.Tests
{
    [TestFixture]
    public class JsonWebTokenExceptionTests
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
        public void InvalidBase64UrlFormatException()
        {
            var invalidToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwmFtZSI6IkgRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxONFh7Hga";

            Assert.That(() => _jsongWebToken.Decode(invalidToken, _key),
                Throws.Exception
                  .TypeOf<FormatException>()
                  .With.Message.EqualTo("Invalid base64url string."));
        }

        [Test]
        public void InvalidSignatureException()
        {
            var validSignature = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
            var invalidSignature = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7Hga";
            var invalidToken = string.Format("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.{0}",
                invalidSignature);

            Assert.That(() => _jsongWebToken.Decode(invalidToken, _key),
                Throws.Exception
                  .TypeOf<InvalidSignatureException>()
                  .With.Property("InvalidSignature").EqualTo(invalidSignature)
                  .With.Property("ExpectedSignature").EqualTo(validSignature));
        }

        [Test]
        public void AlgorithmNotImplementedException()
        {
            var rs256Token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE";

            Assert.That(() => _jsongWebToken.Decode(rs256Token, _key),
                Throws.Exception
                  .TypeOf<NotImplementedException>()
                  .With.Message.EqualTo("Algorithm not implemented: RS256"));
        }

        [Test]
        public void InvalidExpirationTimeException()
        {
            var claims = new Dictionary<string, object>
            {
                { RegisteredClaims.ExpirationTime, "invalid"},
            };

            var token = _jsongWebToken.CreateToken(_key, claims);

            Assert.That(() => _jsongWebToken.Decode(token, _key).HasExpired,
                Throws.Exception.TypeOf<InvalidExpirationTimeException>()
                .With.Property("InvalidExpirationTime").EqualTo("invalid"));
        }
    }
}
