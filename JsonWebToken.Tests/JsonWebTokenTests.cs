using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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

            var payload = _jsongWebToken.Decode(token, _key);

            Assert.That(payload.Count, Is.EqualTo(3));
            Assert.That(payload[RegisteredClaims.Subject], Is.EqualTo("1234567890"));
            Assert.That(payload["name"], Is.EqualTo("John Doe"));
            Assert.That(payload["admin"], Is.EqualTo(true));
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
    }
}
