using System;

namespace HMACSerialiser.Errors
{
    /// <summary>
    /// Custom exception class for tampered or expired signature
    /// </summary>
    public class BadTokenException : Exception
    {
        public BadTokenException() { }

        public BadTokenException(string message) : base(message) { }

        public BadTokenException(string message, Exception innerException) : base(message, innerException) { }
    }
}
