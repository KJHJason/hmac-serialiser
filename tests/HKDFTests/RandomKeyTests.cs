using Microsoft.VisualStudio.TestTools.UnitTesting;
using HMACSerialiser.Base64Encoders;
using System.Text;

namespace HKDFTests
{
	[TestClass]
	public class RandomKeyTests : BaseTestClass
	{
		[TestMethod]
		public void Key1()
		{
			byte[] ikm = Base64Encoder.Base64Decode("CwsLCwsLCwsLCwsLCwsLCwsLCwsLCw==");
			byte[] salt = Base64Encoder.Base64Decode("AAECAwQFBgcICQoLDA==");
			byte[] info = Base64Encoder.Base64Decode("8PHy8/T19vf4+Q==");
			int len = 42;
			var expectedOutputs = new string[]
			{
				// SHA1
				"1gAP+1tQvTlwsmABd5j7nI35zi4sFrbNcJzKB9w8+c8m1sbXUNCq9ayU",
				// SHA256
				"PLJfJfqs1XqQQ09k0DYvKi0tCpDPGlpMXbAtVuzExb80AHII1biHGFhl",
				// SHA384
				"m1CXqGA4uAUwkHakSzqfOAY+JbUW3L82nzlM+rQ2hfdItkV3Y+TwIE/F",
				// SHA512
				"gyOQCGzacftHYlu1zrFo5MjiahoW7TTZ/H/pLBSBV5M42jYsuNn5JdfL",
			};
			TestOutputs(ikm, salt, info, len, expectedOutputs);
		}

		[TestMethod]
		public void Key2()
		{
			byte[] ikm = Base64Encoder.Base64Decode("CwsLCwsLCwsLCwsLCwsLCwsLCwsLCw==");
			byte[] salt = null;
			byte[] info = null;
			int len = 17;
			var expectedOutputs = new string[]
			{
				// SHA1
				"CsGvcAKz12HR5VKY2p0FBrk=",
				// SHA256
				"jaTndaVjwY9xX4AqBjxaMbg=",
				// SHA384
				"yMlucQ+JsNeZC8povN7Iz4U=",
				// SHA512
				"9foCsYKYpyqMI4mKhwNHLG4=",
			};
			TestOutputs(ikm, salt, info, len, expectedOutputs);
		}

		[TestMethod]
		public void Key3()
		{
			byte[] ikm = Base64Encoder.Base64Decode("dGVzdGtleXRoYXRpc3RvdGFsbHlzZWNyZXR0ZXN0a2V5dGhhdGlzdG90YWxseXNlY3JldA==");
			byte[] salt = null;
			byte[] info = null;
			int len = 128;
			var expectedOutputs = new string[]
			{
				// SHA1
				"onCSN+z+X3bqHbsNRYHt8TIVHbN/JFuwwLpPZ4QuDjrqnjocfpe8Hnzw3Cn/WnFmb5Cv96IOAiaQnzpyhNR4Db0WUZkcoRjCiCPVo8li4elQTua1+waMO5Ac1oB9DanE11d9uc4bXmhyIUayi+GzUnrxLmChjil6qhzJK7jh37U=",
				// SHA256
				"0/dMTIioTmDzGMxJXhclL16kigG/SenCrqyruha4BIWGHfFulFXGJDJqKdl6/w0F3rWKUb/krAnJ4ogX+ediwzr1Xwi3CglkEfrwCreDXjWxccA8Ec2UXYXNcTiU9LHXnnvE/u61wUQ20FRNpMLF60+WLvC5WREMLgffwr7wEvY=",
				// SHA384
				"sYISZeKiQW07Lyrm2xB0rFrO9dGrRA2gpFsOQYLQ8ExtFu8/LSq/xA9AevA8rBqy2nqISi0ydSPQtPrSTFc9HIygx3ky5LMKn18eSd1dS+voDhdTtGQYmTb+wKx/okrgy6oT4wWrOdKoGFO7Vd+JN/7UQ6s2Sg2kjT3irDQWNDk=",
				// SHA512
				"oUFUjlKb2UkPQUg1lTBkKmhljy4FscsQB/BNKZxo6OK75b4ZukhHVpkNpyWVFOEACRemWnNxE7qYv0FwzUwsR0fh9IlIkhZOCl9BfjyE0GNdD1Y3SLTsIy+JPlY2CBCF2QohaYd2MC8b9t8FzaymDrrS87cfUxoNbWDmzWItPus=",
			};
			TestOutputs(ikm, salt, info, len, expectedOutputs);
		}

		[TestMethod]
		public void Key3WithSalt()
		{
			byte[] ikm = Base64Encoder.Base64Decode("dGVzdGtleXRoYXRpc3RvdGFsbHlzZWNyZXR0ZXN0a2V5dGhhdGlzdG90YWxseXNlY3JldA==");
			byte[] salt = Base64Encoder.Base64Decode("Y3VzdG9tLnNhbHQ=");
			byte[] info = null;
			int len = 128;
			var expectedOutputs = new string[]
			{
				// SHA1
				"osjRJ7F916lizNpga7cCHhIkBiz6xHZxlTuAS/8ERTxw1n19lh6Aavgv0i+RJdzUpBgMh4QE6KadcfFmkChJeHsFRP45PF50h3kvTj8qwQLFM2zcN3Dk6ZBjwEie0tRAZNKqcIGHy230Xs9YAZ5WuXK5Tks1pIxy02jZZoLopTU=",
				// SHA256
				"YSB7mrRZcpPPFcGVnyWG8Vfu0W8kC3el3JoIgjFwZMRR17YbSlbG9Ss64ZaqlsoqRPiVJc+IcmWq6g7PvuuwESIw0yFbgAq7ZXLRYpl161WnzJfhbW5rYw1Cu7c613X9xC76JLwoUm9r4m9WrODPd+2b+3LIjcKUF4IPD4fge1A=",
				// SHA384
				"ktBIQqwGuIe28L7lQwVoay8ZA1ulABTiT658theaJMSa9UPgfQS7ZWL4twSvehkS3blMAFtMEjXKNG68jjxmQUaOVjcuR2UXAN1xr74JIdk0o+YtWip31YZpfMXOFY7Ph1/86g0Ji3hHGOCR3NrCqGyWxAifWB3SMUUhNA4yw8c=",
				// SHA512
				"+phwcLBIILyTP/zW902icKktJUIHF07y4JwzgMnhCphWcrvgNSD8DghDY000RC45Wa7DP6CZXZVaeiigOE0VwUMZbDtIt4RCn6eJgy/EjU16OvsOlGcHWsTpJ9MXMxADnPRGxWWZi8+RIOx/XRUOtL7uBRqh2RdnFAl2rnH80KE=",
			};
			TestOutputs(ikm, salt, info, len, expectedOutputs);
		}

		[TestMethod]
		public void Key3WithInfo()
		{
			byte[] ikm = Base64Encoder.Base64Decode("dGVzdGtleXRoYXRpc3RvdGFsbHlzZWNyZXR0ZXN0a2V5dGhhdGlzdG90YWxseXNlY3JldA==");
			byte[] salt = null;
			byte[] info = Encoding.UTF8.GetBytes("some info here for the hkdf!");
			int len = 128;
			var expectedOutputs = new string[]
			{
				// SHA1
				"KFY6by58M/hH4WPc5tHMcBP8a2c9MTgfFjgC8g0WEa5wTTMtpjZC6QutwqcevcVOErS1vd0fICfU4B76lc+nToTHZICKrWNiBPGZ/O00IFIvSb6LMwEvvOpap6xaHfy5Kn+AGGehppsQKMDOndK1YdeQCxZOtQ+0vSLHT4Geejc=",
				// SHA256
				"PAUB7Oi1n2wB9rbpW0mPVeEPGe4UNOpYpPzhPR+W/V7XfQec3o2aVSLdp2rVG/xAKoO/aQfuSyR4rGE1KIXk9Yb6KIxiISjwA+Fm449N4fNzpUHWVUiXfQzXbs3FmgSf4dEt8ZllwrxynGpi5LVW0ciRsVAH5tq/cbi6RLa84I4=",
				// SHA384
				"BOT08DYWogL5Nl68GjDam3PBlH/PuwzFthepO/A9u3BxFAZjaAOSfJuoze6obeN9CcjdO+BV8pBRbFRGqOyHLB0SD6rIA1oYcFVGPXBtNIZOdTVTT0q2656WBPLqk7f5r9ThXSA5otquB+q1Dmj2xQ3cRXVp0D3ZVlwrQ2fvKtE=",
				// SHA512
				"Q/nqgxo5B8persN3cFzGtgHc2rwO3mb1vLfkDsEhD3XSn9Hk8pdPLfyvW97jrM11SqnziOvjWggcDAAAHDIkr+xkN4MaBgYvFnC3S2tEeygMSP7fZFNuOvw/YRPbxyRvW65bNPaEgMivszqZJ8XLF99M2Q6ADuj8QNjPYq7a/eU=",
			};
			TestOutputs(ikm, salt, info, len, expectedOutputs);
		}

		[TestMethod]
		public void Key4()
		{
			byte[] ikm = Base64Encoder.Base64Decode("dGVzdGtleXRoYXRpc3RvdGFsbHlzZWNyZXRhbmRzZWN1cmV0ZXN0a2V5dGhhdGlzdG90YWxseXNlY3JldGFuZHNlY3VyZQ==");
			byte[] salt = null;
			byte[] info = null;
			int len = 71;
			var expectedOutputs = new string[]
			{
				// SHA1
				"haG41xB8CV28DEr9RQuGBfnbkttG54efiA4QFGtbNqq9FYmFqvb++aXiu+25uxqnavas1lyg21f0FZ+S5nVcl9d6VGD+qEk=",
				// SHA256
				"16OqJ+sXJGzcYUY93sbFVleMAbFC7z680bTemCwqz/smXw51zm9Rzs3DBse8Q7m4EWrxjnXgY7EBW9V8roszlPrRdYSF63c=",
				// SHA384
				"mA82PVbN2x+VRVpQUDme5cAnvBSHH/u9jtg/qKn2Ru8nacWtBFwev8l5rr4iglJ1PgKMv4U+dIfRE/2XXfB1GK6/6cIMHoA=",
				// SHA512
				"+JalRA8ZEUaHGzCk+3S7vtZssx9UZO1gbgF4WN+4pjZfs/mkhJOKjkPr51Mf1P5/TwwJ1EjeNTOlmCqqMKAu7X63TzXBwpI=",
			};
			TestOutputs(ikm, salt, info, len, expectedOutputs);
		}

		[TestMethod]
		public void Key4WithInfoAndSalt()
		{
			byte[] ikm = Base64Encoder.Base64Decode("dGVzdGtleXRoYXRpc3RvdGFsbHlzZWNyZXRhbmRzZWN1cmV0ZXN0a2V5dGhhdGlzdG90YWxseXNlY3JldGFuZHNlY3VyZQ==");
			byte[] salt = Encoding.UTF8.GetBytes("notreallyasecretsalt!");
			byte[] info = Encoding.UTF8.GetBytes("!@@@some info here for the hkdf!");
			int len = 71;
			var expectedOutputs = new string[]
			{
				// SHA1
				"0jLRh1DqSTzm7C3k2BHz8MVz2iiFhZAFRsquPw8sAWNH/qh3BW1uyXXxwaXJowiZl6jlxmdLkgbmHp8aPdOgJ3S6/nUJpms=",
				// SHA256
				"Do1Kfmj7ckymO9JZjP0ZWtYhX6xw0JlhMAt16Hpax8vPRbk+4KUW90pLESwVGAwxKrtBeMCVz7xgNI0UZ5Ml1t9Zpu9a5UY=",
				// SHA384
				"3d7REH38zNGS9/hipso5zp2qVCG9icBbo2c8KazXWwxUY/XrSLmcjinCJ8aezzbaZYWVwPLVwTVjeSXqsoEu1f0+wyxlJ8s=",
				// SHA512
				"bPTSPVtjIa2zJMIG3YRmKcrbTJzaRZbJFUfCjgdDLGbeybmg9+8OLmINwgf9rg2EpKx5b/aLo8HizowgabNzX5Mi5tSkkRw=",
			};
			TestOutputs(ikm, salt, info, len, expectedOutputs);
		}
	}
}
