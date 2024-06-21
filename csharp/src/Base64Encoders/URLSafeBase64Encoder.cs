using System;
using System.Text;

namespace HMACSerialiser.Base64Encoders
{
    public static class URLSafeBase64Encoder
    {
        /// <summary>
        /// Base64 encodes a byte array
        /// </summary>
        /// <param name="data">The byte array to encode</param>
        /// <returns>A URLSafe base64 encoded string</returns>
        public static string Encode(byte[] data)
        {
            string base64 = Convert.ToBase64String(data);
            return base64.Replace('+', '-').Replace('/', '_').Replace("=", "");
        }

        /// <summary>
        /// Base64 encodes a string using UTF8 encoding
        /// </summary>
        /// <param name="data">The string to encode</param>
        /// <returns>A URLSafe base64 encoded string</returns>
        public static string Encode(string data)
            => Encode(Encoding.UTF8.GetBytes(data));

        /// <summary>
        /// Base64 decodes a URLSafe base64 encoded string
        /// </summary>
        /// <param name="data">The URLSafe base64 encoded string</param>
        /// <returns>The decoded byte array</returns>
        public static byte[] Decode(string data)
        {
            string incoming = data.Replace('_', '/').Replace('-', '+');
            incoming = Padding.Pad(incoming);

            byte[] bytes = Convert.FromBase64String(incoming);
            return bytes;
        }

        /// <summary>
        /// Base64 decodes a URLSafe base64 encoded string and returns the result as a string using UTF8 encoding
        /// </summary>
        /// <param name="data">The URLSafe base64 encoded string</param>
        /// <returns>The decoded string (UTF-8)</returns>
        public static string DecodeToString(string data)
            => Encoding.UTF8.GetString(Decode(data));

        /// <summary>
        /// Checks if the provided string contains any URLSafe base64 characters
        /// </summary>
        /// <param name="data">The string to check</param>
        /// <returns>A boolean indicating whether the provided string contains any URLSafe base64 characters</returns>
        public static bool ContainsBase64Chars(string data)
        {
            foreach (char c in data)
            {
                // characters: [^A-Za-z0-9-_=]
                if (char.IsLetterOrDigit(c) || c == '-' || c == '_' || c == '=')
                    return true;
            }
            return false;
        }
    }
}
