using System;

namespace JsonWebToken
{
    /// <summary>
    /// Should be trown if <see cref="RegisteredClaims.ExpirationTime"/> is invalid when
    /// the property <see cref="TokenInformation.HasExpired"/> is accessed.
    /// </summary>
    public class InvalidExpirationTimeException : Exception
    {
        /// <summary>
        /// Creates a new instance of <see cref="InvalidExpirationTimeException"/>.
        /// </summary>
        /// <param name="invalidExpirationTime">The invalid <see cref="RegisteredClaims.ExpirationTime"/>.</param>
        public InvalidExpirationTimeException(object invalidExpirationTime)
            : base("Invalid expiration time.")
        {
            InvalidExpirationTime = invalidExpirationTime;
        }

        /// <summary>
        /// The invalid expiration time fond in the token payload.
        /// </summary>
        public object InvalidExpirationTime { get; set; }
    }
}
