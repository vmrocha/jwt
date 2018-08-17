using System;

namespace VmRocha.Jwt
{
    /// <summary>
    /// Should be thrown if the token signature is not valid.
    /// </summary>
    public class InvalidSignatureException : Exception
    {
        public InvalidSignatureException(string signature, string expected)
            : base("Invalid signature.")
        {
            InvalidSignature = signature;
            ExpectedSignature = expected;
        }

        /// <summary>
        /// Invalid signature found in token.
        /// </summary>
        public string InvalidSignature { get; private set; }

        /// <summary>
        /// Expected signature to consider the token as valid.
        /// </summary>
        public string ExpectedSignature { get; private set; }
    }
}
