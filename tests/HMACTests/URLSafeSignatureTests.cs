using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using HMACSerialiser;
using static HMACSerialiser.HMAC.HMACHelper;

namespace HMACTests
{
	[TestClass]
	public class URLSafeSignatureTests : BaseTestClass
	{
        protected override ISerialiser[] InitialiseAllSerialisers(object key, object salt, HMACHashAlgorithm hashFunction, object info, int maxAge)
            => new ISerialiser[]
            {
                new URLSafeSerialiser(key, salt, hashFunction, info),
                new TimedURLSafeSerialiser(key, salt, maxAge, hashFunction, info),
            };

        private bool IsValidURL(string signedToken)
			=> Uri.IsWellFormedUriString($"https://github.com/KJHJason/HMACSerialiser?token={signedToken}", UriKind.Absolute);

        [TestMethod]
		public void URLSafeTokens()
		{
			var serialisers = GetAllSerialisers();
            var data = "Hello, World!";
            foreach (var serialiserByHashFunc in serialisers.GetList())
			{
                foreach (var serialiser in serialiserByHashFunc)
				{
                    string signed = serialiser.Dumps(data);
                    var result = serialiser.LoadsString(signed);
                    Assert.AreEqual(data, result);
                    Assert.IsTrue(IsValidURL(signed));
                }
            }
		}
	}
}
