using NUnit.Framework;
using System.Text;

namespace JsonWebToken.Tests
{
    [TestFixture]
    public class Base64UrlTests
    {
        private string _encoded;
        private byte[] _decoded;
        private Base64Url _base64Url;

        [SetUp]
        public void SetUp()
        {
            _base64Url = new Base64Url();
            _encoded = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
            _decoded = Encoding.UTF8.GetBytes(@"{""alg"":""HS256"",""typ"":""JWT""}");
        }

        [Test]
        public void Encode()
        {
            Assert.That(_base64Url.Encode(_decoded), Is.EqualTo(_encoded));
        }

        [Test]
        public void Decode()
        {
            Assert.That(_base64Url.Decode(_encoded), Is.EqualTo(_decoded));
        }
    }
}
