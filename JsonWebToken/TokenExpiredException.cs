using System;

namespace JsonWebToken
{
    public class TokenExpiredException : Exception
    {
        public TokenExpiredException(DateTime expiredOn)
        {
            ExpiredOn = expiredOn;
        }

        public DateTime ExpiredOn { get; private set; }
    }
}
