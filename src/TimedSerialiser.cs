using System;
using System.Linq;
using System.Text;
using HMACSerialiser.Errors;
using HMACSerialiser.HMAC;

namespace HMACSerialiser
{
    public class TimedSerialiser : Serialiser
    {
        private readonly long _maxAge; // in seconds

        public TimedSerialiser(
            object key, object salt, long maxAge, string sep = HMACHelper.DefaultSeparator, HMACHelper.HMACHashAlgorithm hashAlgorithm = HMACHelper.DefaultAlgorithm)
                : base(key, salt, sep, hashAlgorithm)
        {
            _maxAge = maxAge;
        }

        protected (string data, string timestamp, byte[] signature) SplitTokenWithTimestamp(string signedToken)
        {
            var split = signedToken.Split(_sep);
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

        public override string Dumps(object data)
        {
            string encodedData = Base64Encode(SerialiseObject(data));
            byte[] timestamp = BitConverter.GetBytes(((DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds());
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

            long timestamp = BitConverter.ToInt64(Base64Decode(encodedTimestamp), 0);
            long age = ((DateTimeOffset)DateTime.UtcNow).ToUnixTimeSeconds() - timestamp;
            if (age > _maxAge)
                throw new BadTokenException("Signature has expired");

            return encodedData;
        }
    }
}
