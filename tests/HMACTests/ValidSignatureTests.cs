using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using HMACSerialiser.Base64Encoders;
using System.Text;
using static HMACSerialiser.HMAC.HMACHelper;
using HMACSerialiser;

namespace HMACTests
{
    [TestClass]
    public class ValidSignatureTests : BaseTestClass
    {
        private const string _key = "secretkey";
        private const string _salt = "randomsalt";
        private const string _info = "testing";
        private const int _maxAge = 3600;
        private const string _data = "KJHJason/HMACSerialiser";
        private static readonly DateTimeOffset _dateTime = new DateTimeOffset(2024, 2, 1, 0, 0, 0, TimeSpan.Zero); // 1706745600 (Unix time)

        private static readonly string encodedData = Base64Encoder.Encode(_data);
        private static readonly string urlsafeEncodedData = URLSafeBase64Encoder.Encode(_data);

        private static readonly string timestamp = _dateTime.ToUnixTimeSeconds().ToString();
        private static readonly string encodedUnixTime = Base64Encoder.Encode(timestamp);
        private static readonly string urlsafeEncodedUnixTime = URLSafeBase64Encoder.Encode(timestamp);

        protected override ISerialiser[] InitialiseAllSerialisers(object key, object salt, HMACHashAlgorithm hashFunction, object info, int maxAge) 
            => new ISerialiser[] 
            {
                new Serialiser(key, salt, hashFunction, info),
                new URLSafeSerialiser(key, salt, hashFunction, info),
            };

        private void TestsOutputs(ISerialiser[] serialisers, string[] expected)
        {
            int i = 0;
            foreach (var serialiser in serialisers)
            {
                string signed = serialiser.Dumps(_data);
                Assert.AreEqual(expected[i++], signed);
            }
        }

        private void TestsOutputs(ITimedSerialiser[] serialisers, string[] expected)
        {
            int i = 0;
            foreach (var serialiser in serialisers)
            {
                string signed = serialiser.Dumps(_data, _dateTime);
                Assert.AreEqual(expected[i++], signed);
            }
        }

        #region HMACSHA1
        // Keyed-Hash Message Authentication Code (HMAC) using SHA-1 hash algorithm
        // Key: YhiPE5Tw6O70WAfZYP3tqKe7JxdAn1zxGRiM9UdcMUP5cgHg8YU3W7TrPj7nOzCychwGtF0AqtoWfHAhgTz8Yg==

        [TestMethod]
        public void HMACSHA1Serialisers()
        {
            ISerialiser[] serialisers = InitialiseAllSerialisers(
                _key, _salt, HMACHashAlgorithm.SHA1, _info, 0);

            // [Serialiser, URLSafeSerialiser]
            string[] expected = new string[] 
            {
                $"{encodedData}.o4Bln1A17yxv6uY8Jf7BUKZceeg",
                $"{urlsafeEncodedData}.o4Bln1A17yxv6uY8Jf7BUKZceeg",
            };
            TestsOutputs(serialisers, expected);
        }

        [TestMethod]
        public void HMACSHA1TimedSerialisers()
        {
            ITimedSerialiser[] serialisers = InitialiseTimedSerialisers(
                _key, _salt, HMACHashAlgorithm.SHA1, _info, _maxAge);

            // [TimedSerialiser, TimedURLSafeSerialiser]
            string[] expected = new string[] 
            {
                $"{encodedData}.{encodedUnixTime}.myC2PU9USJhV52Sm0xoqmdi/dWo",
                $"{urlsafeEncodedData}.{urlsafeEncodedUnixTime}.myC2PU9USJhV52Sm0xoqmdi_dWo",
            };
            TestsOutputs(serialisers, expected);
        }

        #endregion

        #region HMACSHA256
        // Keyed-Hash Message Authentication Code (HMAC) using SHA-256 hash algorithm
        // Key: yLTVpkjI3yV29DVoc1RGvxGAOVgMnEpRK7WPx/ahgxQP7Pz76yd4C76vO80uKrZzTyclHatZOvWe7KfpqwlDOw==

        [TestMethod]
        public void HMACSHA256Serialisers()
        {
            ISerialiser[] serialisers = InitialiseAllSerialisers(
                _key, _salt, HMACHashAlgorithm.SHA256, _info, 0);

            // [Serialiser, URLSafeSerialiser]
            string[] expected = new string[] 
            {
                $"{encodedData}.PQERg33/tFni59L421IH7mLje0QUZIpfWwwK2nGBjS8",
                $"{urlsafeEncodedData}.PQERg33_tFni59L421IH7mLje0QUZIpfWwwK2nGBjS8",
            };
            TestsOutputs(serialisers, expected);
        }

        [TestMethod]
        public void HMACSHA256TimedSerialisers()
        {
            ITimedSerialiser[] serialisers = InitialiseTimedSerialisers(
                _key, _salt, HMACHashAlgorithm.SHA256, _info, _maxAge);

            // [TimedSerialiser, TimedURLSafeSerialiser]
            string[] expected = new string[] 
            {
                $"{encodedData}.{encodedUnixTime}.LhAOIwiAo130GPK0xz1Z/2N/Ztru/AgfyBRlyCRRdBE",
                $"{urlsafeEncodedData}.{urlsafeEncodedUnixTime}.LhAOIwiAo130GPK0xz1Z_2N_Ztru_AgfyBRlyCRRdBE",
            };
            TestsOutputs(serialisers, expected);
        }

        #endregion

        #region HMACSHA384
        // Keyed-Hash Message Authentication Code (HMAC) using SHA-384 hash algorithm
        // Key: ZfIUvWC1l3SnsYfcxwcoAFo8t+cr3LBIa+eYuM34XhPNjBjcSoOMe16nZ7UHapUGuB+nrjUvgkF7ZvnusATRZ1AGonjSH5NfjCL6wfh2Fc0T8nrnN/ns/OfiFTT0cPdLFd8gEosPCy18WiE4XckF2qaMwASK9g6t1tVmltqsGes=

        [TestMethod]
        public void HMACSHA384Serialisers()
        {
            ISerialiser[] serialisers = InitialiseAllSerialisers(
                _key, _salt, HMACHashAlgorithm.SHA384, _info, 0);

            // [Serialiser, URLSafeSerialiser]
            string[] expected = new string[] 
            {
                $"{encodedData}.kMdnRpYh6JmSSTIlIxqM0cwph+uaMK/GdhfAINkA/y0dw/I/7EdDiR5qft6ykMbb",
                $"{urlsafeEncodedData}.kMdnRpYh6JmSSTIlIxqM0cwph-uaMK_GdhfAINkA_y0dw_I_7EdDiR5qft6ykMbb",
            };
            TestsOutputs(serialisers, expected);
        }

        [TestMethod]
        public void HMACSHA384TimedSerialisers()
        {
            ITimedSerialiser[] serialisers = InitialiseTimedSerialisers(
                _key, _salt, HMACHashAlgorithm.SHA384, _info, _maxAge);

            // [TimedSerialiser, TimedURLSafeSerialiser]
            string[] expected = new string[] 
            {
                $"{encodedData}.{encodedUnixTime}.UkXLRk6qgDIpFG5ZPcvf/93nrqSCwHiSk83t4S1oZ4/M71VnIryhZKJPEOBKybI6",
                $"{urlsafeEncodedData}.{urlsafeEncodedUnixTime}.UkXLRk6qgDIpFG5ZPcvf_93nrqSCwHiSk83t4S1oZ4_M71VnIryhZKJPEOBKybI6",
            };
            TestsOutputs(serialisers, expected);
        }

        #endregion

        #region HMACSHA512
        // Keyed-Hash Message Authentication Code (HMAC) using SHA-512 hash algorithm
        // Key: Vgvzk+GGnQmLTc8hIJKwj3+RaB5+vZlLzlfw+W/eZYG+Ihb3uDdLoqWpW1bcOixJEjzfKXc+ew3Ykb06ugLpbpGIM8lBjNBlJ+F9cvUFLrM+7UYhISdwvn5dBt7geA/fAlwEWfBZ2boTgeLT6w7LQAZ06S7XuQ8B31dHq9LoBYQ=

        [TestMethod]
        public void HMACSHA512Serialisers()
        {
            ISerialiser[] serialisers = InitialiseAllSerialisers(
                _key, _salt, HMACHashAlgorithm.SHA512, _info, 0);

            // [Serialiser, URLSafeSerialiser]
            string[] expected = new string[] 
            {
                $"{encodedData}.cb6m0rDv1im8RPOo8QrNOxxOs2EQpM6FlseR2FPD2J+Zi0lOcBn5nLcwVj7NgLrnAsG/f3kfqYIl7XPYS6zEpw",
                $"{urlsafeEncodedData}.cb6m0rDv1im8RPOo8QrNOxxOs2EQpM6FlseR2FPD2J-Zi0lOcBn5nLcwVj7NgLrnAsG_f3kfqYIl7XPYS6zEpw",
            };
            TestsOutputs(serialisers, expected);
        }

        [TestMethod]
        public void HMACSHA512TimedSerialisers()
        {
            ITimedSerialiser[] serialisers = InitialiseTimedSerialisers(
                _key, _salt, HMACHashAlgorithm.SHA512, _info, _maxAge);

            // [TimedSerialiser, TimedURLSafeSerialiser]
            string[] expected = new string[] 
            {
                $"{encodedData}.{encodedUnixTime}.RFxkZ5sKdaJkOnq3z4H365xoB2pZB0CVEl75L/4mat5BD17mbIM8sf4Kof2feuzIbU8TKOfk3QpTVaQ33Hvnyg",
                $"{urlsafeEncodedData}.{urlsafeEncodedUnixTime}.RFxkZ5sKdaJkOnq3z4H365xoB2pZB0CVEl75L_4mat5BD17mbIM8sf4Kof2feuzIbU8TKOfk3QpTVaQ33Hvnyg",
            };
            TestsOutputs(serialisers, expected);
        }

        #endregion
    }
}
