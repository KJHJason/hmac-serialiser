namespace HMACSerialiser.Base64Encoders
{
    internal class Padding
    {
        /// <summary>
        /// Pads the provided string with the correct number of padding characters to make it a valid base64 string
        /// </summary>
        /// <param name="data">The base64 encoded string to pad</param>
        /// <returns>The padded base64 encoded string</returns>
        public static string Pad(string data)
        {
            switch (data.Length % 4)
            {
                case 2: data += "=="; break;
                case 3: data += "="; break;
            }
            return data;
        }
    }
}
