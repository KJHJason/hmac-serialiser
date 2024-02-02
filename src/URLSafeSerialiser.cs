using System;
using HMACSerialiser.Base64Encoders;
using HMACSerialiser.HMAC;

namespace HMACSerialiser
{
    public class URLSafeSerialiser : Serialiser
    {
        public URLSafeSerialiser(
            object key, object salt, string sep = HMACHelper.DefaultSeparator, HMACHelper.HMACHashAlgorithm hashAlgorithm = HMACHelper.DefaultAlgorithm)
                : base(key, salt, sep, hashAlgorithm)
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
