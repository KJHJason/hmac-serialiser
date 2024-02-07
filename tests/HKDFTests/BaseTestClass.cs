using Microsoft.VisualStudio.TestTools.UnitTesting;
using HMACSerialiser.Base64Encoders;
using HMACSerialiser.KFD;
using static HMACSerialiser.HMAC.HMACHelper;

namespace HKDFTests
{
    public class BaseTestClass
    {
        private static readonly HMACHashAlgorithm[] hashAlgorithms = new HMACHashAlgorithm[] {
            HMACHashAlgorithm.SHA1,
                HMACHashAlgorithm.SHA256,
                HMACHashAlgorithm.SHA384,
                HMACHashAlgorithm.SHA512
        };

        protected static void TestOutputs(byte[] ikm, byte[] salt, byte[] info, int len, string[] expectedOutputs)
        {
            int idx = 0;
            foreach (var hashAlgorithm in hashAlgorithms)
            {
                byte[] okm = HKDF.DeriveKey(
                    hashFunction: hashAlgorithm,
                    ikm: ikm,
                    salt: salt,
                    info: info,
                    outputLen: len
                );
                string expected = expectedOutputs[idx++];
                string actual = Base64Encoder.Encode(okm);
                Assert.AreEqual(expected, actual);
            }
        }
    }
}
