using HMACSerialiser.Base64Encoders;
using System;

namespace HMACSerialiser
{
    public class TimedURLSafeSerialiser : TimedSerialiser
    {
        public TimedURLSafeSerialiser(
            object key, object salt, long maxAge, string sep = HMACHelper.DefaultSeparator, HMACHelper.HMACHashAlgorithm hashAlgorithm = HMACHelper.DefaultAlgorithm)
                : base(key, salt, maxAge, sep, hashAlgorithm)
        {
        }

        protected override string Base64Encode(byte[] data)
            => URLSafeBase64Encoder.Base64Encode(data);

        protected override byte[] Base64Decode(string data)
            => URLSafeBase64Encoder.Base64Decode(data);

        protected override bool CheckSepIsValidLogic()
            => URLSafeBase64Encoder.ContainsBase64Chars(_sep);
    }
}
