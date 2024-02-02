using System;

namespace HMACSerialiser.Base64Encoders
{
    public static class Base64Encoder
    {
        public static string Base64Encode(byte[] data)
            => Convert.ToBase64String(data);

        public static byte[] Base64Decode(string data)
            => Convert.FromBase64String(data);

        public static bool ContainsBase64Chars(string data)
        {
            foreach (char c in data)
            {
                // characters: [^A-Za-z0-9+/=]
                if (char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=')
                    return true;
            }
            return false;
        }
    } 
}
