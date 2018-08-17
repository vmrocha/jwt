using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace JsonWebToken
{
    public sealed class TokenInformation
    {
        public TokenInformation(IDictionary<string, string> header, IDictionary<string, object> claims)
        {
            Header = new ReadOnlyDictionary<string, string>(header);
            Claims = new ReadOnlyDictionary<string, object>(claims);
        }

        /// <summary>
        /// Read-only dictionary that contains the header information.
        /// </summary>
        public IReadOnlyDictionary<string, string> Header { get; }

        /// <summary>
        /// Read-only dictionary that contains all the token claims.
        /// </summary>
        public IReadOnlyDictionary<string, object> Claims { get; }

        /// <summary>
        /// Verifies if the <see cref="RegisteredClaims.ExpirationTime"/> is less than
        /// the current UTC time.
        /// </summary>
        public bool HasExpired
        {
            get
            {
                var expirationTime = GetExpirationTime();
                if (expirationTime.HasValue)
                {
                    return expirationTime.Value < UnixTimeStamp.ToUnixTimeStamp(DateTime.UtcNow);
                }

                return false;
            }
        }

        /// <summary>
        /// Gets the Unix TimeStamp information from the claims dictionary
        /// and returns it as <see cref="DateTime"/> object.
        /// </summary>
        public DateTime? ExpiresOn
        {
            get
            {
                var expirationTime = GetExpirationTime();
                if (expirationTime.HasValue)
                {
                    return UnixTimeStamp.ToDateTime(expirationTime.Value);
                }

                return null;
            }
        }

        /// <summary>
        /// Extract the <see cref="RegisteredClaims.ExpirationTime"/> from the claims dictionary if it is valid.
        /// </summary>
        /// <returns>Expiration time in Unix TimeStamp format or <code>null</code> if not found or invalid.</returns>
        private long? GetExpirationTime()
        {
            if (Claims.ContainsKey(RegisteredClaims.ExpirationTime))
            {
                var expirationValue = Claims[RegisteredClaims.ExpirationTime].ToString();

                if (!long.TryParse(expirationValue, out var unixTime))
                {
                    throw new InvalidExpirationTimeException(expirationValue);
                }

                return unixTime;
            }

            return null;
        }
    }
}
