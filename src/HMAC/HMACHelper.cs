using System;
using System.Text;
using System.Security.Cryptography;

namespace HMACSerialiser.HMAC
{
    public static class HMACHelper
    {
        public const HMACHashAlgorithm DefaultAlgorithm = HMACHashAlgorithm.SHA1;
        public const string DefaultSeparator = ".";

        public enum HMACHashAlgorithm
        {
            SHA1,
            SHA256,
            SHA384,
            SHA512
        }

        internal static int GetHashSize(HMACHashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case HMACHashAlgorithm.SHA1:
                    return 160;
                case HMACHashAlgorithm.SHA256:
                    return 256;
                case HMACHashAlgorithm.SHA384:
                    return 384;
                case HMACHashAlgorithm.SHA512:
                    return 512;
                default:
                    throw new NotImplementedException("Unsupported hash algorithm " + hashAlgorithm.ToString());
            }
        }

        internal static int GetHashSizeInBytes(HMACHashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case HMACHashAlgorithm.SHA1:
                    return 20;
                case HMACHashAlgorithm.SHA256:
                    return 32;
                case HMACHashAlgorithm.SHA384:
                    return 48;
                case HMACHashAlgorithm.SHA512:
                    return 64;
                default:
                    throw new NotImplementedException("Unsupported hash algorithm " + hashAlgorithm.ToString());
            }
        }

        // Mainly to expand the key to the corresponding block size of the hash algorithm
        internal static int GetLengthForHKDF(HMACHashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case HMACHashAlgorithm.SHA1:
                    return 64; // Since SHA1 uses 512-bits blocks
                case HMACHashAlgorithm.SHA256:
                    return 64; // Since SHA256 uses 512-bits blocks
                case HMACHashAlgorithm.SHA384:
                    return 128; // Since SHA384 uses 1024-bits blocks
                case HMACHashAlgorithm.SHA512:
                    return 128; // Since SHA512 uses 1024-bits blocks
                default:
                    throw new NotImplementedException("Unsupported hash algorithm " + hashAlgorithm.ToString());
            }
        }

        internal static byte[] ConvertToBytes(object value)
        {
            if (value == null)
                return null;

            if (value is byte[] byteArray)
                return byteArray;

            if (value is string stringValue)
                return Encoding.UTF8.GetBytes(stringValue);

            throw new ArgumentException("Unsupported type for key or salt");
        }

        internal static byte[] GetHMACDigest(byte[] key, byte[] data, HMACHashAlgorithm hashAlgorithm = HMACHashAlgorithm.SHA1)
        {
            using (KeyedHashAlgorithm hmac = GetHMACInstance(hashAlgorithm, key))
            {
                byte[] hashBytes = hmac.ComputeHash(data);
                return hashBytes;
            }
        }

        internal static byte[] GetHMACDigest(byte[] key, string data, HMACHashAlgorithm hashAlgorithm = HMACHashAlgorithm.SHA1)
            => GetHMACDigest(key, Encoding.UTF8.GetBytes(data), hashAlgorithm);

        internal static KeyedHashAlgorithm GetHMACInstance(HMACHashAlgorithm hashAlgorithm, byte[] key)
        {
            switch (hashAlgorithm)
            {
                case HMACHashAlgorithm.SHA1:
                    return new HMACSHA1(key);
                case HMACHashAlgorithm.SHA256:
                    return new HMACSHA256(key);
                case HMACHashAlgorithm.SHA384:
                    return new HMACSHA384(key);
                case HMACHashAlgorithm.SHA512:
                    return new HMACSHA512(key);
                default:
                    throw new NotImplementedException("Unsupported hash algorithm " + hashAlgorithm.ToString());
            }
        }

        internal static bool CompareDigest(byte[] mac1, byte[] mac2)
        {
            if (mac1 == null || mac2 == null)
                return false;

            if (mac1.Length != mac2.Length)
                return false;

            int result = 0;
            for (int i = 0; i < mac1.Length; i++)
            {
                // Using XOR bitwise operator to compare corresponding bytes.
                // If the bytes are equal, the XOR result will be 0; otherwise, it will be 1.
                // After that, we use the OR bitwise operator to accumulate the XOR results with the previous result.
                result |= mac1[i] ^ mac2[i];
            }

            return result == 0;
        }
    }
}
