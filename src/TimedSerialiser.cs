using System;
using System.Linq;
using System.Text;
using HMACSerialiser.Errors;
using HMACSerialiser.HMAC;

namespace HMACSerialiser
{
    public class TimedSerialiser : Serialiser, ITimedSerialiser
    {
        private readonly long _maxAge; // in seconds

        /// <summary>
        /// Initialises a new instance of the TimedSerialiser class to cryptographically sign and verify data that can expire.
        /// </summary>
        /// <param name="key">The secret key to use</param>
        /// <param name="salt">The salt to use</param>
        /// <param name="maxAge">The maximum age of the signature in seconds</param>
        /// <param name="hashAlgorithm">The HMAC hash function to use</param>
        /// <param name="info">The context and application specific information (can be empty).</param>
        /// <param name="sep">The separator to use. However, it must not contain any base64 characters.</param>
        public TimedSerialiser(
            object key, 
            object salt,
            long maxAge, 
            HMACHelper.HMACHashAlgorithm hashAlgorithm = HMACHelper.DefaultAlgorithm,
			object info = null,
			string sep = HMACHelper.DefaultSeparator)
                : base(key, salt, hashAlgorithm, info, sep)
        {
            _maxAge = maxAge;
        }

        protected (string data, string timestamp, byte[] signature) SplitTokenWithTimestamp(string signedToken)
        {
            var split = signedToken.Split(new string[] { _sep }, StringSplitOptions.None);
            if (split.Length != 3)
                throw new BadTokenException("Invalid token format");

            string data, timestamp;
            byte[] signature;
            try
            {
                // all are base64 encoded
                data = split[0];
                timestamp = split[1];
                signature = Base64Decode(split[2]);
            }
            catch (FormatException)
            {
                throw new BadTokenException("Data or signature is not base64 encoded");
            }

            return (data, timestamp, signature);
        }

        /// <summary>
        /// Dumps the provided payload into a base64 encoded string and signs it.
        /// </summary>
        /// <param name="data">The payload to sign</param>
        /// <param name="dateTime">The timestamp to use instead of the default DateTime.UtcNow</param>
        /// <returns>The serialised token that it is temporarily valid based on the MaxAge provided in the constructor</returns>
        public string Dumps(object data, DateTimeOffset dateTime)
        {
            string encodedData = Base64Encode(SerialiseObject(data));
            string timestamp = dateTime.ToUnixTimeSeconds().ToString();
            string encodedTimestamp = Base64Encode(timestamp);

            // combine data, separator and timestamp (all are in bytes)
            byte[] combined = Encoding.UTF8.GetBytes(encodedData)
                .Concat(Encoding.UTF8.GetBytes(_sep))
                .Concat(Encoding.UTF8.GetBytes(encodedTimestamp))
                .ToArray();

            byte[] mac = HMACHelper.GetHMACDigest(DeriveKey(), combined, _hashAlgorithm);
            string signature = Base64Encode(mac);
            string dataString = encodedData + _sep + encodedTimestamp;
            return dataString + _sep + signature;
        }

        /// <summary>
        /// Dumps the provided payload into a base64 encoded string and signs it.
        /// </summary>
        /// <param name="data">The payload to sign</param>
        /// <returns>The serialised token that it is temporarily valid based on the MaxAge provided in the constructor</returns>
        public override string Dumps(object data)
            => Dumps(data, DateTimeOffset.UtcNow);

        protected override string LoadsLogic(string signedToken)
        {

            (string encodedData, string encodedTimestamp, byte[] signature) = SplitTokenWithTimestamp(signedToken);

            byte[] data = Encoding.UTF8.GetBytes(encodedData)
                .Concat(Encoding.UTF8.GetBytes(_sep))
                .Concat(Encoding.UTF8.GetBytes(encodedTimestamp))
                .ToArray();
            var mac = HMACHelper.GetHMACDigest(DeriveKey(), data, _hashAlgorithm);
            if (!HMACHelper.CompareDigest(mac, signature))
                throw new BadTokenException("Data has been tampered or signature does not match");

            long timestamp = long.Parse(Base64DecodeToString(encodedTimestamp));
            long age = ((DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds() - timestamp;
            if (age >= _maxAge)
                throw new BadTokenException("Signature has expired");

            return encodedData;
        }
    }
}
