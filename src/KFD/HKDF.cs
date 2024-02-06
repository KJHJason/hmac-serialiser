using System;
using System.Linq;
using System.Security.Cryptography;
using static HMACSerialiser.HMAC.HMACHelper;

namespace HMACSerialiser.KFD
{
    public static class HKDF
    {
        private static byte[] HMACDigest(byte[] key, byte[] data, HMACHashAlgorithm hashFunction)
        {
            using (KeyedHashAlgorithm hmac = GetHMACInstance(hashFunction, key))
            {
                return hmac.ComputeHash(data);
            }
        }

        private static byte[] Extract(byte[] salt, byte[] ikm, HMACHashAlgorithm hashFunction)
        {
            if (salt.Length == 0)
                salt = new byte[GetHashSizeInBytes(hashFunction)];

            return HMACDigest(salt, ikm, hashFunction);
        }

        private static byte[] Expand(byte[] prk, byte[] info, int length, HMACHashAlgorithm hashFunction)
        {
            int hashLength = GetHashSizeInBytes(hashFunction);
            int iterations = (int)Math.Ceiling((double)length / hashLength);
            byte[] okm = new byte[length];
            byte[] t = new byte[0];
            int offset = 0;

            for (int i = 1; i <= iterations; i++)
            {
                t = HMACDigest(prk, ConcatenateArrays(t, info, new byte[] { (byte)i }), hashFunction);
                Buffer.BlockCopy(t, 0, okm, offset, Math.Min(hashLength, length - offset));
                offset += hashLength;
            }

            return okm;
        }

        private static byte[] ConcatenateArrays(params byte[][] arrays)
        {
            int totalLength = arrays.Sum(arr => arr.Length);
            byte[] result = new byte[totalLength];
            int offset = 0;

            foreach (byte[] array in arrays)
            {
                Buffer.BlockCopy(array, 0, result, offset, array.Length);
                offset += array.Length;
            }

            return result;
        }

        /// <summary>
        /// Performs a simple key derivation function (KDF) based on the HMAC message authentication code (RFC 5869).
        /// </summary>
        /// <param name="hashFunction">The hash algorithm used for HMAC operations.</param>
        /// <param name="ikm">The input keying material like your secret key.</param>
        /// <param name="outputLen">The length to expand to in bytes.</param>
        /// <param name="salt">The salt value (a non-secret random value).</param>
        /// <param name="info">The context and application specific information (can be empty).</param>
        public static byte[] DeriveKey(HMACHashAlgorithm hashFunction, byte[] ikm, int outputLen, byte[] salt = null, byte[] info = null)
        {
            if (ikm == null || ikm.Length == 0)
                throw new ArgumentNullException(nameof(ikm));
            if (outputLen < 1)
                throw new ArgumentException("Length must be greater than 0", nameof(outputLen));

            int hashSizeInBytes = GetHashSizeInBytes(hashFunction);
            if (salt == null || salt.Length == 0)
                salt = new byte[hashSizeInBytes];
            if (info == null || info.Length == 0)
                info = new byte[0];

            int maxOkmLength = 255 * hashSizeInBytes;
            if (outputLen > maxOkmLength) 
                throw new ArgumentException($"Output length must be less than or equal to {maxOkmLength}", nameof(outputLen));

            byte[] prk = Extract(salt, ikm, hashFunction);
            return Expand(prk, info, outputLen, hashFunction);
        }
    }
}
