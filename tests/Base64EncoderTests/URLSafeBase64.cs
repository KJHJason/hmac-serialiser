using Microsoft.VisualStudio.TestTools.UnitTesting;
using HMACSerialiser.Base64Encoders;

namespace Base64EncoderTests
{
    [TestClass]
    public class URLSafeBase64
    {
        [TestMethod]
        public void TestURLSafeBase64()
        {
            string data = "~~~https://github.com/KJHJason/HMACSerialiser~~~";
            string encodedData = URLSafeBase64Encoder.Encode(data);
            string decodedData = URLSafeBase64Encoder.DecodeToString(encodedData);

            Assert.AreEqual("fn5-aHR0cHM6Ly9naXRodWIuY29tL0tKSEphc29uL0hNQUNTZXJpYWxpc2Vyfn5-", encodedData);
            Assert.AreEqual(data, decodedData);
        }
    }
}
