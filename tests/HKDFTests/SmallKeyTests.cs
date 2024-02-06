using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace HKDFTests
{
    [TestClass]
    public class SmallKeyTests : BaseTestClass
    {
        [TestMethod]
        public void SmallKeyTest()
        {
            byte[] ikm = Encoding.UTF8.GetBytes("!");
            byte[] salt = null;
            byte[] info = null;
            int len = 64;
            var expectedOutputs = new string[] 
            {
                // SHA1
                "C2uArPn5XncXFV6Sg4JPGO8xkB9B4WyFQ85a5ZQNGd5mDqEfJ8YQFARIrgMW2s+lND5JpK48/HKUpcHnmh1YTw==",
                // SHA256
                "Y4hEt9oTXeQzLoojMokZ9i5sHPDHORuavsj79S/SNyfQGgkxUccggtjjl/FUFHIBLYEnMTXBJuAmt45NGusrYA==",
                // SHA384
                "s2nMfyleeDdTQOQZqmhIpNFHCwWclImXqCay8Q2YqcTuqst20VsFRnk2C+JgubxIOw0riXf2pcW83bpk5cohLA==",
                // SHA512
                "1YSIWCxVzQ6rwsIqrzVTrUGK5nLdMeaaSfwJS+JktEoDKAUWPRVxcOG0CfsSL6Y2yDEo462V1/H8IzrwvqZydA==",
            };
            TestOutputs(ikm, salt, info, len, expectedOutputs);
        }

        [TestMethod]
        public void SmallKeyTestWithSalt()
        {
            byte[] ikm = Encoding.UTF8.GetBytes("!");
            byte[] salt = Encoding.UTF8.GetBytes("!!!!!!custom.salt!!!!!!!!!!!!!!!!!!!!!!!!");
            byte[] info = null;
            int len = 64;
            var expectedOutputs = new string[] 
            {
                // SHA1
                "mdQsI+Pa7YsnAQYdjV2Nl1z9I2vpsGmh+nAso4/xy7GYkv9m0czwD/VpRrPzixP7FXbMzfVaVY2JMQcKVsD4/w==",
                // SHA256
                "tGbvtTBwikAVbgQEJ870tYh8xRsP1jVAYU/9t1UiD7k0y72Pyv24gYlGXMQlQyRETWg/QwA3jCaeVn0F69OtZA==",
                // SHA384
                "C8ERNx8HEc5KQi7d7jjH9lGKqmf4/O3j30Vq2P5sl1wOh6cMGhMsWXPIOMeHdrKKGSvp5LyqNcJtI1xgpwhJcg==",
                // SHA512
                "gHASsEAJ9we0U6wB3WLU275rlPLNiqnW3hEiOwSFRSmtpKnQKLQMWMKQYi1FfQXh4s1q39DJt8C0xrAVPFpIVQ==",
            };
            TestOutputs(ikm, salt, info, len, expectedOutputs);
        }

        [TestMethod]
        public void SmallKeyTestWithInfo()
        {
            byte[] ikm = Encoding.UTF8.GetBytes("!");
            byte[] salt = null;
            byte[] info = Encoding.UTF8.GetBytes("@@@derived.key!!!!!!!!!!!!!!!!!!");
            int len = 64;
            var expectedOutputs = new string[] 
            {
                // SHA1
                "7bYqeDDESDxpLCTBiJszmvf8+dDRFWPIQqk3vq5pAuJWDyiuS4S7zvXmcKda/QsloXNWCRsVt1OI9xmSpZCErA==",
                // SHA256
                "mKsc2FwY1jIlzpKPlYFaYuuxRTZZHQ9XP2w/kbOjR4tSLwwPAOBLaTwYj8dQkm1hM6NDR4gPE7XSOTDPzBF2Vg==",
                // SHA384
                "SCjNmY0QuZuX31dAeSqlAc4/V+qziLo1TPksfLYWPbpgHZdJLNxNxZeroyHqDhlRDM+01eahbLlKbWwLlftwVg==",
                // SHA512
                "DGQrR5dF+Y3hmogwxFp9doJi3HIpsqx5DuwUv43ec3rtE+giMRcXUGtMYwT92bNJswSO3Pp52V5Kf+WmniSpSw==",
            };
            TestOutputs(ikm, salt, info, len, expectedOutputs);
        }

        [TestMethod]
        public void SmallKeyTestWithSaltAndInfo()
        {
            byte[] ikm = Encoding.UTF8.GetBytes("!");
            byte[] salt = Encoding.UTF8.GetBytes("!!!!!!custom.salt!!!!!!!!!!!!!!!!!!!!!!!!");
            byte[] info = Encoding.UTF8.GetBytes("@@@derived.key!!!!!!!!!!!!!!!!!!");
            int len = 64;
            var expectedOutputs = new string[] 
            {
                // SHA1
                "0SvQkzmkSEJpgIXdWFj4AgfhwgJIwgRLjYd1VbiVblIUwOysABKC2vM6i9AtYNRLA3i1ZQhuVg6tCF79ex3mQg==",
                // SHA256
                "YtxMANtI41sZ6BQnV/Qj72rxloOa7BD1VfO/CCHb3S8qIVNIcpJuFoLu2nE+PAilSPlwVooLKS7Oh/BY7UWIZQ==",
                // SHA384
                "K2a2DfGAT6F8rLi8ITUWtpnsOr8CCIGEm6QuGbU9K3obJCLpkp3/o/FwOTnQu1tDTRPxzfa34D8p2mwWsooU/w==",
                // SHA512
                "6TYjN7QU+8PRwmgIf2WQFeFpaNWwAHx908Nu+pPbQQhBuNDCGX8VnBfRSwzgo8PJUzUpC3LCn4rhYRtzQWsVZg==",
            };
            TestOutputs(ikm, salt, info, len, expectedOutputs);
        }

    }
}
