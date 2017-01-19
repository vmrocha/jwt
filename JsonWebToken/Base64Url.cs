using System;

namespace JsonWebToken
{
    public class Base64Url
    {
        /// <summary>
        /// Encode input string using Base64 URL encoding.
        /// </summary>
        /// <param name="input">Byte representation of the string to encode.</param>
        /// <returns>Encoded string.</returns>
        public string Encode(byte[] input)
        {
            string output = Convert.ToBase64String(input);
            output = output.Split('=')[0];     // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding

            return output;
        }

        /// <summary>
        /// Decode a Base64 URL encoded string.
        /// </summary>
        /// <param name="input">Encoded string.</param>
        /// <returns>Decoded string int a byte array representation.</returns>
        public byte[] Decode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding

            switch (output.Length % 4)         // Pad with trailing '='s
            {
                case 0: break;                 // No pad chars in this case
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break;  // One pad char
                default: throw new FormatException("Invalid base64url string.");
            }

            return Convert.FromBase64String(output);
        }
    }
}
