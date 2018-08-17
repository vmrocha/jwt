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
        /// Creates a JWT token in the format of {header}.{claims}.{signature}.
        /// </summary>
        /// <param name="key">The key used to sign the token.</param>
        /// <returns>JWT token in the format of {header}.{claims}.{signature}.</returns>
        public string CreateToken(byte[] key)
        {
            return CreateToken(key, null, AlgorithmMethod.HS256, null);
        }

        /// <summary>
        /// Creates a JWT token in the format of {header}.{claims}.{signature}.
        /// </summary>
        /// <param name="key">The key used to sign the token.</param>
        /// <param name="expirationTime">The <see cref="RegisteredClaims.ExpirationTime"/>.</param>
        /// <returns>JWT token in the format of {header}.{claims}.{signature}.</returns>
        public string CreateToken(byte[] key, DateTime? expirationTime)
        {
            return CreateToken(key, null, AlgorithmMethod.HS256, expirationTime);
        }

        /// <summary>
        /// Creates a JWT token in the format of {header}.{claims}.{signature}.
        /// </summary>
        /// <param name="claims">User claims, also known as token payload information.</param>
        /// <param name="key">The key used to sign the token.</param>
        /// <returns>JWT token in the format of {header}.{claims}.{signature}.</returns>
        public string CreateToken(byte[] key, Dictionary<string, object> claims)
        {
            return CreateToken(key, claims, AlgorithmMethod.HS256, null);
        }

        /// <summary>
        /// Creates a JWT token in the format of {header}.{claims}.{signature}.
        /// </summary>
        /// <param name="claims">User claims, also known as token payload information.</param>
        /// <param name="key">The key used to sign the token.</param>
        /// <param name="expirationTime">The <see cref="RegisteredClaims.ExpirationTime"/>.</param>
        /// <returns>JWT token in the format of {header}.{claims}.{signature}.</returns>
        public string CreateToken(byte[] key, Dictionary<string, object> claims, DateTime? expirationTime)
        {
            return CreateToken(key, claims, AlgorithmMethod.HS256, expirationTime);
        }

        /// <summary>
        /// Creates a JWT token in the format of {header}.{claims}.{signature}.
        /// </summary>
        /// <param name="key">The key used to sign the token.</param>
        /// <param name="method">Algoritm method to be used.</param>
        /// <returns>JWT token in the format of {header}.{claims}.{signature}.</returns>
        public string CreateToken(byte[] key, AlgorithmMethod method)
        {
            return CreateToken(key, null, method, null);
        }

        /// <summary>
        /// Creates a JWT token in the format of {header}.{claims}.{signature}.
        /// </summary>
        /// <param name="key">The key used to sign the token.</param>
        /// <param name="claims">User claims, also known as token payload information.</param>
        /// <param name="method">Algoritm method to be used.</param>
        /// <returns>JWT token in the format of {header}.{claims}.{signature}.</returns>
        public string CreateToken(byte[] key, Dictionary<string, object> claims, AlgorithmMethod method)
        {
            return CreateToken(key, claims, method, null);
        }

        /// <summary>
        /// Creates a JWT token in the format of {header}.{claims}.{signature}.
        /// </summary>
        /// <param name="claims">User claims, also known as token payload information.</param>
        /// <param name="method">Algoritm method to be used.</param>
        /// <param name="key">The key used to sign the token.</param>
        /// <param name="expirationTime">The <see cref="RegisteredClaims.ExpirationTime"/>.</param>
        /// <returns>JWT token in the format of {header}.{claims}.{signature}.</returns>
        public string CreateToken(byte[] key, Dictionary<string, object> claims, AlgorithmMethod method, DateTime? expirationTime)
        {
            if (claims == null)
            {
                claims = new Dictionary<string, object>();
            }

            var header = new Dictionary<string, string>()
            {
                { "alg", method.ToString() },
                { "typ", "JWT" }
            };

            IncludeExpirationTime(claims, expirationTime);

            var encodedHeader = _base64Url.Encode(GetBytes(_serializer.Serialize(header)));
            var encodedPayload = _base64Url.Encode(GetBytes(_serializer.Serialize(claims)));
            var encodedSignature = CreateSignature(method, key, encodedHeader, encodedPayload);

            return $"{encodedHeader}.{encodedPayload}.{encodedSignature}";
        }

        /// <summary>
        /// Decode token, validates it and returns the user claims in a <see cref="Dictionary{String, Object}"/>.
        /// </summary>
        /// <param name="token">Encoded JWT token.</param>
        /// <returns>User claims as populated in a <see cref="Dictionary{String, Object}"/>.</returns>
        public TokenInformation Decode(string token)
        {
            return Decode(token, null);
        }

        /// <summary>
        /// Decode token, validates it and returns the user claims in a <see cref="Dictionary{String, Object}"/>.
        /// </summary>
        /// <param name="token">Encoded JWT token.</param>
        /// <param name="key">Key used to validate the token signature.</param>
        /// <returns>User claims as populated in a <see cref="Dictionary{String, Object}"/>.</returns>
        public TokenInformation Decode(string token, byte[] key)
        {
            var parts = token.Split('.');

            var header = parts[0];
            var claims = parts[1];
            var signature = parts[2];

            var decodedHeader = _base64Url.Decode(parts[0]);
            var decodedClaims = _base64Url.Decode(parts[1]);

            var headerDictionary = _serializer.Deserialize<Dictionary<string, string>>(GetString(decodedHeader));
            var claimsDictionary = _serializer.Deserialize<Dictionary<string, object>>(GetString(decodedClaims));

            if (key != null)
            {

                if (!Enum.TryParse(headerDictionary["alg"], out AlgorithmMethod algorithm))
                {
                    throw new NotImplementedException($"Algorithm not implemented: {headerDictionary["alg"]}");
                }

                var expectedSignature = CreateSignature(algorithm, key, header, claims);

                if (!string.Equals(signature, expectedSignature))
                {
                    throw new InvalidSignatureException(signature, expectedSignature);
                }
            }

            return new TokenInformation(headerDictionary, claimsDictionary);
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
                default: return new HMACSHA512(key);
            }
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
        /// <param name="bytes">Byte array representation of the string.</param>
        /// <returns>String representation of the byte array.</returns>
        private string GetString(byte[] bytes)
        {
            return Encoding.UTF8.GetString(bytes);
        }

        /// <summary>
        /// Creates a valid signature based on the algorithm, key, header and claims/payload.
        /// </summary>
        /// <param name="method">Algorith used to calculate the signature hash.</param>
        /// <param name="key">Key used to hash the signature.</param>
        /// <param name="encodedHeader">Encoded JWT header.</param>
        /// <param name="encodedClaims">Encoded JWT payload or claims.</param>
        /// <returns></returns>
        private string CreateSignature(AlgorithmMethod method, byte[] key, string encodedHeader, string encodedClaims)
        {
            return _base64Url.Encode(CreateAlgorithm(method, key).ComputeHash(GetBytes($"{encodedHeader}.{encodedClaims}")));
        }

        /// <summary>
        /// Includes or overrides the expiration time for a given payload/claims. See <see cref="RegisteredClaims.ExpirationTime"/>.
        /// </summary>
        /// <param name="claims">Claims information, also known as JWT payload.</param>
        /// <param name="expirationTime">Expiration time in the format of <see cref="DateTime"/>. It will be converted to Unix Time.</param>
        private void IncludeExpirationTime(IDictionary<string, object> claims, DateTime? expirationTime)
        {
            if (expirationTime.HasValue)
            {
                var unixTimeStamp = UnixTimeStamp.ToUnixTimeStamp(expirationTime.Value);
                if (claims.ContainsKey(RegisteredClaims.ExpirationTime))
                {
                    claims[RegisteredClaims.ExpirationTime] = unixTimeStamp;
                }
                else
                {
                    claims.Add(RegisteredClaims.ExpirationTime, unixTimeStamp);
                }
            }
        }
    }
}
