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
        public string CreateToken(Dictionary<string, object> payload, AlgorithmMethod method, byte[] key, DateTime? expirationTime = null)
        {
            if (payload == null)
            {
                payload = new Dictionary<string, object>();
            }

            var header = new Dictionary<string, string>()
            {
                { "alg", method.ToString() },
                { "typ", "JWT" }
            };

            IncludeExpirationTime(payload, expirationTime);
            
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
            var decodedClaims = _base64Url.Decode(parts[1]);

            var header = _serializer.Deserialize<Dictionary<string, string>>(GetString(decodedHeader));
            var claims = _serializer.Deserialize<Dictionary<string, object>>(GetString(decodedClaims));

            var algorithm = (AlgorithmMethod)Enum.Parse(typeof(AlgorithmMethod), header["alg"]);
            var signature = CreateSignature(algorithm, key, parts[0], parts[1]);

            if (!string.Equals(signature, parts[2]))
            {
                throw new InvalidSignatureException(parts[2], signature);
            }

            var expirationTime = GetExpirationTime(claims);
            if (expirationTime.HasValue)
            {
                if (expirationTime < UnixTimeStamp.ToUnixTimeStamp(DateTime.UtcNow))
                {
                    throw new TokenExpiredException(UnixTimeStamp.ToDateTime(expirationTime.Value));
                }
            }
            
            return claims;
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

        /// <summary>
        /// Includes or overrides the expiration time for a given payload. See <see cref="RegisteredClaims.ExpirationTime"/>.
        /// </summary>
        /// <param name="payload">Payload to be updated.</param>
        /// <param name="expirationTime">Expiration time in the format of <see cref="DateTime"/>. It will be converted to Unix Time.</param>
        private void IncludeExpirationTime(Dictionary<string, object> payload, DateTime? expirationTime)
        {
            if (expirationTime.HasValue)
            {
                long unixTimeStamp = UnixTimeStamp.ToUnixTimeStamp(expirationTime.Value);
                if (payload.ContainsKey(RegisteredClaims.ExpirationTime))
                {
                    payload[RegisteredClaims.ExpirationTime] = unixTimeStamp;
                }
                else
                {
                    payload.Add(RegisteredClaims.ExpirationTime, unixTimeStamp);
                }
            }
        }

        /// <summary>
        /// Extract the <see cref="RegisteredClaims.ExpirationTime"/> from the payload if it is valid.
        /// </summary>
        /// <param name="payload">JWT payload information.</param>
        /// <returns></returns>
        private long? GetExpirationTime(Dictionary<string, object> payload)
        {
            if (payload != null &&
                payload.ContainsKey(RegisteredClaims.ExpirationTime) &&
                payload[RegisteredClaims.ExpirationTime] != null)
            {
                var expirationValue = payload[RegisteredClaims.ExpirationTime].ToString();

                long unixTime = 0;
                if (long.TryParse(expirationValue, out unixTime))
                {
                    return unixTime;
                }
            }

            return null;
        }
    }
}
