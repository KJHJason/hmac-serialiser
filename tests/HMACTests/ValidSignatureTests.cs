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

        private static readonly string encodedData = Convert.ToBase64String(Encoding.UTF8.GetBytes(_data));
        private static readonly string urlsafeEncodedData = URLSafeBase64Encoder.Base64Encode(Encoding.UTF8.GetBytes(_data));

        private static readonly byte[] timestampBytes = Encoding.UTF8.GetBytes(_dateTime.ToUnixTimeSeconds().ToString());
        private static readonly string encodedUnixTime = Convert.ToBase64String(timestampBytes);
        private static readonly string urlsafeEncodedUnixTime = URLSafeBase64Encoder.Base64Encode(timestampBytes);


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
                $"{encodedData}.Xz4h5lldXM2j6ZFo6VuGGA0B5+I=",
                $"{urlsafeEncodedData}.Xz4h5lldXM2j6ZFo6VuGGA0B5-I=",
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
                $"{encodedData}.{encodedUnixTime}.tEy7zeJ97QbUGPFRlOhSs+lwvBE=",
                $"{urlsafeEncodedData}.{urlsafeEncodedUnixTime}.tEy7zeJ97QbUGPFRlOhSs-lwvBE=",
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
                $"{encodedData}.RXqJxlU3oAbDve2Mknw2HYblpFhjxnopK6IEdCFeUqs=",
                $"{urlsafeEncodedData}.RXqJxlU3oAbDve2Mknw2HYblpFhjxnopK6IEdCFeUqs=",
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
                $"{encodedData}.{encodedUnixTime}.eLOxS2h4C5aeudi6DNc9N53LFvN3KCZrtbF0tIk0/y8=",
                $"{urlsafeEncodedData}.{urlsafeEncodedUnixTime}.eLOxS2h4C5aeudi6DNc9N53LFvN3KCZrtbF0tIk0_y8=",
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
                $"{encodedData}.9w4JAhHckAI3I8fKy0L9Bq+3RYxtrvk4KelxWIsv6MuaVpEJsaQ4sWxyvNkiaXPQ",
                $"{urlsafeEncodedData}.9w4JAhHckAI3I8fKy0L9Bq-3RYxtrvk4KelxWIsv6MuaVpEJsaQ4sWxyvNkiaXPQ",
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
                $"{encodedData}.{encodedUnixTime}.l50UItfiTIHxr0WrzXEMPwe0LMZqO3pFSOfFu3c369xJds34cTLhi7w+pXQ04x+f",
                $"{urlsafeEncodedData}.{urlsafeEncodedUnixTime}.l50UItfiTIHxr0WrzXEMPwe0LMZqO3pFSOfFu3c369xJds34cTLhi7w-pXQ04x-f",
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
                $"{encodedData}.wifr1DwcDlp0q3wUCErD2uKh37+T7BRvomIjD23c7KWJXa0sfF0X3daokxvuY2LDNtISvwRTj5cZxWE1tA4JJw==",
                $"{urlsafeEncodedData}.wifr1DwcDlp0q3wUCErD2uKh37-T7BRvomIjD23c7KWJXa0sfF0X3daokxvuY2LDNtISvwRTj5cZxWE1tA4JJw==",
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
                $"{encodedData}.{encodedUnixTime}.kXtK/hFtErgVRpsPuLuuOt4rOLuuAdsOJVgsGMOKcAYQjWh6dhdyklw+DPRJJ/2Zx1LK8mstAW2/HMTH4PZHPA==",
                $"{urlsafeEncodedData}.{urlsafeEncodedUnixTime}.kXtK_hFtErgVRpsPuLuuOt4rOLuuAdsOJVgsGMOKcAYQjWh6dhdyklw-DPRJJ_2Zx1LK8mstAW2_HMTH4PZHPA==",
            };
            TestsOutputs(serialisers, expected);
        }

        #endregion
    }
}
