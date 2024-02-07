using HMACSerialiser.Base64Encoders;
using HMACSerialiser.HMAC;

namespace HMACSerialiser
{
    public class URLSafeSerialiser : Serialiser
    {
        /// <summary>
        /// Initialise a new instance of the URLSafeSerialiser class to cryptographically sign and verify data that can be used in URLs.
        /// </summary>
        /// <param name="key">The secret key to use</param>
        /// <param name="salt">The salt to use</param>
        /// <param name="hashAlgorithm">The HMAC hash function to use</param>
        /// <param name="info">The context and application specific information (can be empty).</param>
        /// <param name="sep">The separator to use. However, it must not contain any URLSafe base64 characters.</param>
        public URLSafeSerialiser(
            object key, 
            object salt, 
            HMACHelper.HMACHashAlgorithm hashAlgorithm = HMACHelper.DefaultAlgorithm,
			object info = null,
			string sep = HMACHelper.DefaultSeparator)
                : base(key, salt, hashAlgorithm, info, sep)
        {
        }

        protected override string Base64Encode(byte[] data)
            => URLSafeBase64Encoder.Encode(data);

        protected override string Base64Encode(string data)
            => URLSafeBase64Encoder.Encode(data);

        protected override byte[] Base64Decode(string data)
            => URLSafeBase64Encoder.Decode(data);

        protected override string Base64DecodeToString(string data)
            => URLSafeBase64Encoder.DecodeToString(data);

        protected override bool CheckSepIsValidLogic()
            => URLSafeBase64Encoder.ContainsBase64Chars(_sep);
    }
}
