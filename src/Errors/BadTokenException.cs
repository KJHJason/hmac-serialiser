using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HMACSerialiser.Errors
{
    // Custom exception class for bad signature
    public class BadTokenException : Exception
    {
        public BadTokenException() { }

        public BadTokenException(string message) : base(message) { }

        public BadTokenException(string message, Exception innerException) : base(message, innerException) { }
    }
}
