using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Collections.Generic;
using HMACSerialiser;
using static HMACSerialiser.HMAC.HMACHelper;

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

        private readonly JSONPayload _json;
        private const string serialiser = "serialiser";
        private const string urlsafeSerialiser = "urlsafe-serialiser";
        private const string timedSerialiser = "timed-serialiser";
        private const string timedUrlsafeSerialiser = "timed-urlsafe-serialiser";
        private const string sha1 = "sha1";
        private const string sha256 = "sha256";
        private const string sha384 = "sha384";
        private const string sha512 = "sha512";

        public ValidSignatureTests()
        {
            string hmacReferencePyOutput = "{\"sha1\": {\"serialiser\": \"S0pISmFzb24vSE1BQ1NlcmlhbGlzZXI.o4Bln1A17yxv6uY8Jf7BUKZceeg\", \"urlsafe-serialiser\": \"S0pISmFzb24vSE1BQ1NlcmlhbGlzZXI.o4Bln1A17yxv6uY8Jf7BUKZceeg\", \"timed-serialiser\": \"S0pISmFzb24vSE1BQ1NlcmlhbGlzZXI.MTcwNjc0NTYwMA.myC2PU9USJhV52Sm0xoqmdi/dWo\", \"timed-urlsafe-serialiser\": \"S0pISmFzb24vSE1BQ1NlcmlhbGlzZXI.MTcwNjc0NTYwMA.myC2PU9USJhV52Sm0xoqmdi_dWo\"}, \"sha256\": {\"serialiser\": \"S0pISmFzb24vSE1BQ1NlcmlhbGlzZXI.PQERg33/tFni59L421IH7mLje0QUZIpfWwwK2nGBjS8\", \"urlsafe-serialiser\": \"S0pISmFzb24vSE1BQ1NlcmlhbGlzZXI.PQERg33_tFni59L421IH7mLje0QUZIpfWwwK2nGBjS8\", \"timed-serialiser\": \"S0pISmFzb24vSE1BQ1NlcmlhbGlzZXI.MTcwNjc0NTYwMA.LhAOIwiAo130GPK0xz1Z/2N/Ztru/AgfyBRlyCRRdBE\", \"timed-urlsafe-serialiser\": \"S0pISmFzb24vSE1BQ1NlcmlhbGlzZXI.MTcwNjc0NTYwMA.LhAOIwiAo130GPK0xz1Z_2N_Ztru_AgfyBRlyCRRdBE\"}, \"sha384\": {\"serialiser\": \"S0pISmFzb24vSE1BQ1NlcmlhbGlzZXI.kMdnRpYh6JmSSTIlIxqM0cwph+uaMK/GdhfAINkA/y0dw/I/7EdDiR5qft6ykMbb\", \"urlsafe-serialiser\": \"S0pISmFzb24vSE1BQ1NlcmlhbGlzZXI.kMdnRpYh6JmSSTIlIxqM0cwph-uaMK_GdhfAINkA_y0dw_I_7EdDiR5qft6ykMbb\", \"timed-serialiser\": \"S0pISmFzb24vSE1BQ1NlcmlhbGlzZXI.MTcwNjc0NTYwMA.UkXLRk6qgDIpFG5ZPcvf/93nrqSCwHiSk83t4S1oZ4/M71VnIryhZKJPEOBKybI6\", \"timed-urlsafe-serialiser\": \"S0pISmFzb24vSE1BQ1NlcmlhbGlzZXI.MTcwNjc0NTYwMA.UkXLRk6qgDIpFG5ZPcvf_93nrqSCwHiSk83t4S1oZ4_M71VnIryhZKJPEOBKybI6\"}, \"sha512\": {\"serialiser\": \"S0pISmFzb24vSE1BQ1NlcmlhbGlzZXI.cb6m0rDv1im8RPOo8QrNOxxOs2EQpM6FlseR2FPD2J+Zi0lOcBn5nLcwVj7NgLrnAsG/f3kfqYIl7XPYS6zEpw\", \"urlsafe-serialiser\": \"S0pISmFzb24vSE1BQ1NlcmlhbGlzZXI.cb6m0rDv1im8RPOo8QrNOxxOs2EQpM6FlseR2FPD2J-Zi0lOcBn5nLcwVj7NgLrnAsG_f3kfqYIl7XPYS6zEpw\", \"timed-serialiser\": \"S0pISmFzb24vSE1BQ1NlcmlhbGlzZXI.MTcwNjc0NTYwMA.RFxkZ5sKdaJkOnq3z4H365xoB2pZB0CVEl75L/4mat5BD17mbIM8sf4Kof2feuzIbU8TKOfk3QpTVaQ33Hvnyg\", \"timed-urlsafe-serialiser\": \"S0pISmFzb24vSE1BQ1NlcmlhbGlzZXI.MTcwNjc0NTYwMA.RFxkZ5sKdaJkOnq3z4H365xoB2pZB0CVEl75L_4mat5BD17mbIM8sf4Kof2feuzIbU8TKOfk3QpTVaQ33Hvnyg\"}}";
            using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(hmacReferencePyOutput)))
            {
                _json = new JSONPayload(JsonDocument.Parse(ms));
            }
        }

        private string GetExpected(string hashFunction, string serialiser)
        {
            // sample data: { "sha1" : { "serialiser" : "data.signature" } }
            var hashFunc = _json.Get<Dictionary<string, string>>(key: hashFunction);
            return hashFunc[serialiser];
        }

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
                GetExpected(sha1, serialiser),
                GetExpected(sha1, urlsafeSerialiser),
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
                GetExpected(sha1, timedSerialiser),
                GetExpected(sha1, timedUrlsafeSerialiser),
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
                GetExpected(sha256, serialiser),
                GetExpected(sha256, urlsafeSerialiser),
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
                GetExpected(sha256, timedSerialiser),
                GetExpected(sha256, timedUrlsafeSerialiser),
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
                GetExpected(sha384, serialiser),
                GetExpected(sha384, urlsafeSerialiser),
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
                GetExpected(sha384, timedSerialiser),
                GetExpected(sha384, timedUrlsafeSerialiser),
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
                GetExpected(sha512, serialiser),
                GetExpected(sha512, urlsafeSerialiser),
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
                GetExpected(sha512, timedSerialiser),
                GetExpected(sha512, timedUrlsafeSerialiser),
            };
            TestsOutputs(serialisers, expected);
        }

        #endregion
    }
}
