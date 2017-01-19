using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace JsonWebToken
{
    /// <summary>
    /// Used to create, decode and validate JSON Web Tokens.
    /// </summary>
    public class JsonWebToken
    {
        private readonly Base64Url _base64Url;
        private readonly JavaScriptSerializer _serializer;

        public JsonWebToken()
        {
            _base64Url = new Base64Url();
            _serializer = new JavaScriptSerializer();
        }

        /// <summary>
        /// Creates a JWT token in the format of {header}.{payload}.{signature}.
        /// </summary>
        /// <param name="payload">Payload information. Also known as claims.</param>
        /// <param name="method">Algoritm method to be used.</param>
        /// <param name="key">The key used to sign the token.</param>
        /// <returns>JWT token in the format of {header}.{payload}.{signature}.</returns>
        public string CreateToken(Dictionary<string, object> payload, AlgorithmMethod method, byte[] key)
        {
            var header = new Dictionary<string, string>()
            {
                { "alg", method.ToString() },
                { "typ", "JWT" }
            };
            
            var encodedHeader = _base64Url.Encode(GetBytes(_serializer.Serialize(header)));
            var encodedPayload = _base64Url.Encode(GetBytes(_serializer.Serialize(payload)));
            var encodedSignature = CreateSignature(method, key, encodedHeader, encodedPayload);

            return $"{encodedHeader}.{encodedPayload}.{encodedSignature}";
        }

        /// <summary>
        /// Decode token, validates it and returns the payload as a <see cref="System.Collections.Generic.Dictionary{String, Object}"/>.
        /// </summary>
        /// <param name="token">Encoded JWT token.</param>
        /// <returns>Token payload as a <see cref="System.Collections.Generic.Dictionary{String, Object}"/>.</returns>
        public Dictionary<string, object> Decode(string token, byte[] key)
        {
            var parts = token.Split('.');
            var decodedHeader = _base64Url.Decode(parts[0]);
            var decodedPayload = _base64Url.Decode(parts[1]);

            var header = _serializer.Deserialize<Dictionary<string, string>>(GetString(decodedHeader));
            var payload = _serializer.Deserialize<Dictionary<string, object>>(GetString(decodedPayload));

            var algorithm = (AlgorithmMethod)Enum.Parse(typeof(AlgorithmMethod), header["alg"]);
            var signature = CreateSignature(algorithm, key, parts[0], parts[1]);

            if (!string.Equals(signature, parts[2]))
            {
                throw new InvalidSignatureException(parts[2], signature);
            }
            
            return payload;
        }

        /// <summary>
        /// Creates an instance of <see cref="System.Security.Cryptography.HMAC"/> based on <see cref="AlgorithmMethod"/>.)
        /// </summary>
        /// <param name="method">Algorithm method.</param>
        /// <param name="key">Key used to instanciate the <see cref="System.Security.Cryptography.HMAC"/> algorithm class.</param>
        /// <returns>A new instance of <see cref="System.Security.Cryptography.HMAC"/>.</returns>
        private HMAC CreateAlgorithm(AlgorithmMethod method, byte[] key)
        {
            switch (method)
            {
                case AlgorithmMethod.HS256: return new HMACSHA256(key);
                case AlgorithmMethod.HS384: return new HMACSHA384(key);
                case AlgorithmMethod.HS512: return new HMACSHA512(key);
            }

            throw new Exception("Invalid algorithm: " + method);
        }

        /// <summary>
        /// Get the bytes representation of the UTF8 string.
        /// </summary>
        /// <param name="value">String to be encoded to bytes.</param>
        /// <returns>Byte array representation of the string.</returns>
        private byte[] GetBytes(string value)
        {
            return Encoding.UTF8.GetBytes(value);
        }

        /// <summary>
        /// Get the bytes representation of the UTF8 string.
        /// </summary>
        /// <param name="value">String to be encoded to bytes.</param>
        /// <returns>Byte array representation of the string.</returns>
        private string GetString(byte[] bytes)
        {
            return Encoding.UTF8.GetString(bytes);
        }

        /// <summary>
        /// Creates a valid signature based on the algorithm, key, header and payload.
        /// </summary>
        /// <param name="method">Algorith used to calculate the signature hash.</param>
        /// <param name="key">Key used to hash the signature.</param>
        /// <param name="encodedHeader">Encoded JWT header.</param>
        /// <param name="encodedPayload">Encoded JWT payload.</param>
        /// <returns></returns>
        private string CreateSignature(AlgorithmMethod method, byte[] key, string encodedHeader, string encodedPayload)
        {
            return _base64Url.Encode(CreateAlgorithm(method, key).ComputeHash(GetBytes($"{encodedHeader}.{encodedPayload}")));
        }
    }
}
