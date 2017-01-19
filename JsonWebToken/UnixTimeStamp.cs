using System;

namespace JsonWebToken
{
    public static class UnixTimeStamp
    {
        private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Converts <see cref="DateTime"/> to Unix TimeStamp format.
        /// </summary>
        /// <param name="date">Microsoft .NET DateTime format.</param>
        /// <returns>Unix TimeStamp format.</returns>
        public static long ToUnixTimeStamp(DateTime date)
        {
            return (long)Math.Round((date - UnixEpoch).TotalSeconds);
        }

        /// <summary>
        /// Converts from Unix TimeStamp format to <see cref="DateTime"/>.
        /// </summary>
        /// <param name="unixTimeStamp">Unix TimeStamp value.</param>
        /// <returns>Current time in <see cref="DateTime"/> format.</returns>
        public static DateTime ToDateTime(long unixTimeStamp)
        {
            return UnixEpoch.AddSeconds(unixTimeStamp);
        }
    }
}
