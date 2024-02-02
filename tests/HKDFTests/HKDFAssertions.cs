using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using HMACSerialiser.Base64Encoders;
using HMACSerialiser.KFD;
using System.Text;
using HMACSerialiser.HMAC;

namespace HMACSerialiserTests
{
    [TestClass]
    public class HKDFAssertions
    {
        [TestMethod]
        public void Key1()
        {
            byte[] ikm = Base64Encoder.Base64Decode("CwsLCwsLCwsLCwsLCwsLCwsLCwsLCw==");
            byte[] salt = Base64Encoder.Base64Decode("AAECAwQFBgcICQoLDA==");
            byte[] info = Base64Encoder.Base64Decode("8PHy8/T19vf4+Q==");
            int len = 42;
            string expected = "PLJfJfqs1XqQQ09k0DYvKi0tCpDPGlpMXbAtVuzExb80AHII1biHGFhl";
            var hashAlgorithm = HMACHelper.HMACHashAlgorithm.SHA256;

            byte[] okm = HKDF.DeriveKey(
                hashFunction: hashAlgorithm,
                ikm: ikm,
                salt: salt,
                info: info,
                outputLen: len
            );
            string actual = Base64Encoder.Base64Encode(okm);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void Key2()
        {
            byte[] ikm = Base64Encoder.Base64Decode("CwsLCwsLCwsLCwsLCwsLCwsLCwsLCw==");
            byte[] salt = null;
            byte[] info = null;
            int len = 42;
            string expected = "jaTndaVjwY9xX4AqBjxaMbihH1xe4Yeew0VOXzxzjS2dIBOV+qS2GpbI";
            var hashAlgorithm = HMACHelper.HMACHashAlgorithm.SHA256;

            byte[] okm = HKDF.DeriveKey(
                hashFunction: hashAlgorithm,
                ikm: ikm,
                salt: salt,
                info: info,
                outputLen: len
            );
            string actual = Base64Encoder.Base64Encode(okm);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void Key3()
        {
            byte[] ikm = Base64Encoder.Base64Decode("dGVzdGtleXRoYXRpc3RvdGFsbHlzZWNyZXR0ZXN0a2V5dGhhdGlzdG90YWxseXNlY3JldA==");
            byte[] salt = Base64Encoder.Base64Decode("Y3VzdG9tLnNhbHQ=");
            byte[] info = null;
            int len = 64;
            string expected = "YSB7mrRZcpPPFcGVnyWG8Vfu0W8kC3el3JoIgjFwZMRR17YbSlbG9Ss64ZaqlsoqRPiVJc+IcmWq6g7PvuuwEQ==";
            var hashAlgorithm = HMACHelper.HMACHashAlgorithm.SHA256;

            byte[] okm = HKDF.DeriveKey(
                hashFunction: hashAlgorithm,
                ikm: ikm,
                salt: salt,
                info: info,
                outputLen: len
            );
            string actual = Base64Encoder.Base64Encode(okm);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void Key3WithoutSalt()
        {
            byte[] ikm = Base64Encoder.Base64Decode("dGVzdGtleXRoYXRpc3RvdGFsbHlzZWNyZXR0ZXN0a2V5dGhhdGlzdG90YWxseXNlY3JldA==");
            byte[] salt = null;
            byte[] info = null;
            int len = 64;
            string expected = "0/dMTIioTmDzGMxJXhclL16kigG/SenCrqyruha4BIWGHfFulFXGJDJqKdl6/w0F3rWKUb/krAnJ4ogX+ediww==";
            var hashAlgorithm = HMACHelper.HMACHashAlgorithm.SHA256;

            byte[] okm = HKDF.DeriveKey(
                hashFunction: hashAlgorithm,
                ikm: ikm,
                salt: salt,
                info: info,
                outputLen: len
            );
            string actual = Base64Encoder.Base64Encode(okm);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void Key3WithInfo()
        {
            byte[] ikm = Base64Encoder.Base64Decode("dGVzdGtleXRoYXRpc3RvdGFsbHlzZWNyZXR0ZXN0a2V5dGhhdGlzdG90YWxseXNlY3JldA==");
            byte[] salt = null;
            byte[] info = Encoding.UTF8.GetBytes("some info here for the hkdf!");
            int len = 64;
            string expected = "PAUB7Oi1n2wB9rbpW0mPVeEPGe4UNOpYpPzhPR+W/V7XfQec3o2aVSLdp2rVG/xAKoO/aQfuSyR4rGE1KIXk9Q==";
            var hashAlgorithm = HMACHelper.HMACHashAlgorithm.SHA256;

            byte[] okm = HKDF.DeriveKey(
                hashFunction: hashAlgorithm,
                ikm: ikm,
                salt: salt,
                info: info,
                outputLen: len
            );
            string actual = Base64Encoder.Base64Encode(okm);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void Key4()
        {
            byte[] ikm = Base64Encoder.Base64Decode("dGVzdGtleXRoYXRpc3RvdGFsbHlzZWNyZXRhbmRzZWN1cmV0ZXN0a2V5dGhhdGlzdG90YWxseXNlY3JldGFuZHNlY3VyZQ==");
            byte[] salt = null;
            byte[] info = null;
            int len = 64;
            string expected = "16OqJ+sXJGzcYUY93sbFVleMAbFC7z680bTemCwqz/smXw51zm9Rzs3DBse8Q7m4EWrxjnXgY7EBW9V8roszlA==";
            var hashAlgorithm = HMACHelper.HMACHashAlgorithm.SHA256;

            byte[] okm = HKDF.DeriveKey(
                hashFunction: hashAlgorithm,
                ikm: ikm,
                salt: salt,
                info: info,
                outputLen: len
            );
            string actual = Base64Encoder.Base64Encode(okm);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void Key4WithInfoAndSalt()
        {
            byte[] ikm = Base64Encoder.Base64Decode("dGVzdGtleXRoYXRpc3RvdGFsbHlzZWNyZXRhbmRzZWN1cmV0ZXN0a2V5dGhhdGlzdG90YWxseXNlY3JldGFuZHNlY3VyZQ==");
            byte[] salt = Encoding.UTF8.GetBytes("notreallyasecretsalt!");
            byte[] info = Encoding.UTF8.GetBytes("!@@@some info here for the hkdf!");
            int len = 64;
            string expected = "Do1Kfmj7ckymO9JZjP0ZWtYhX6xw0JlhMAt16Hpax8vPRbk+4KUW90pLESwVGAwxKrtBeMCVz7xgNI0UZ5Ml1g==";
            var hashAlgorithm = HMACHelper.HMACHashAlgorithm.SHA256;

            byte[] okm = HKDF.DeriveKey(
                hashFunction: hashAlgorithm,
                ikm: ikm,
                salt: salt,
                info: info,
                outputLen: len
            );
            string actual = Base64Encoder.Base64Encode(okm);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void SmallKeyTest()
        {
            byte[] ikm = Encoding.UTF8.GetBytes("!");
            byte[] salt = null;
            byte[] info = null;
            int len = 64;
            string expected = "Y4hEt9oTXeQzLoojMokZ9i5sHPDHORuavsj79S/SNyfQGgkxUccggtjjl/FUFHIBLYEnMTXBJuAmt45NGusrYA==";
            var hashAlgorithm = HMACHelper.HMACHashAlgorithm.SHA256;

            byte[] okm = HKDF.DeriveKey(
                hashFunction: hashAlgorithm,
                ikm: ikm,
                salt: salt,
                info: info,
                outputLen: len
            );
            string actual = Base64Encoder.Base64Encode(okm);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void SmallKeyTestWithSalt()
        {
            byte[] ikm = Encoding.UTF8.GetBytes("!");
            byte[] salt = Encoding.UTF8.GetBytes("!!!!!!custom.salt!!!!!!!!!!!!!!!!!!!!!!!!");
            byte[] info = null;
            int len = 64;
            string expected = "tGbvtTBwikAVbgQEJ870tYh8xRsP1jVAYU/9t1UiD7k0y72Pyv24gYlGXMQlQyRETWg/QwA3jCaeVn0F69OtZA==";
            var hashAlgorithm = HMACHelper.HMACHashAlgorithm.SHA256;

            byte[] okm = HKDF.DeriveKey(
                hashFunction: hashAlgorithm,
                ikm: ikm,
                salt: salt,
                info: info,
                outputLen: len
            );
            string actual = Base64Encoder.Base64Encode(okm);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void SmallKeyTestWithInfo()
        {
            byte[] ikm = Encoding.UTF8.GetBytes("!");
            byte[] salt = null;
            byte[] info = Encoding.UTF8.GetBytes("@@@derived.key!!!!!!!!!!!!!!!!!!");
            int len = 64;
            string expected = "mKsc2FwY1jIlzpKPlYFaYuuxRTZZHQ9XP2w/kbOjR4tSLwwPAOBLaTwYj8dQkm1hM6NDR4gPE7XSOTDPzBF2Vg==";
            var hashAlgorithm = HMACHelper.HMACHashAlgorithm.SHA256;

            byte[] okm = HKDF.DeriveKey(
                hashFunction: hashAlgorithm,
                ikm: ikm,
                salt: salt,
                info: info,
                outputLen: len
            );
            string actual = Base64Encoder.Base64Encode(okm);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void SmallKeyTestWithSaltAndInfo()
        {
            byte[] ikm = Encoding.UTF8.GetBytes("!");
            byte[] salt = Encoding.UTF8.GetBytes("!!!!!!custom.salt!!!!!!!!!!!!!!!!!!!!!!!!");
            byte[] info = Encoding.UTF8.GetBytes("@@@derived.key!!!!!!!!!!!!!!!!!!");
            int len = 64;
            string expected = "YtxMANtI41sZ6BQnV/Qj72rxloOa7BD1VfO/CCHb3S8qIVNIcpJuFoLu2nE+PAilSPlwVooLKS7Oh/BY7UWIZQ==";
            var hashAlgorithm = HMACHelper.HMACHashAlgorithm.SHA256;

            byte[] okm = HKDF.DeriveKey(
                hashFunction: hashAlgorithm,
                ikm: ikm,
                salt: salt,
                info: info,
                outputLen: len
            );
            string actual = Base64Encoder.Base64Encode(okm);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void BigKeyTest()
        {
            byte[] ikm = Encoding.UTF8.GetBytes("e064a8ca0802224cbeec061a57cd955f772be06444ab02b734c2f73b3754cace73d349371186bf414c90eada277b207e92e2b77819d5cc56cb163c2331da81e6300e30e75ef0372c6698375dc894c52cc55f2def27a52f6b9e24eea334448c97c9af5e366504d2d95b66ac0f8c8ab645365517bbff39eed0fe0ee564572ba032ff885a2794170e423bd624a1b89a867d4276155562c1d9459881469b10e798789f541ed445cb795245a13f312381145ac6db7b773aded62a038a72a1c3241f386202210af4d6c4fcee1e465c471a1f0104d636e3552a63f65469d0a84af2c805f5d2b33a6926d5790c9184691843d359cafee2417618fc15348fa7154ce09cb332eadca64c2812273a72bba6f6762aa09f36c5f1cf51fb499c287359a957671b03690e050a15163b437d6b9be386a38a3854c391ae733b1537b3d908894b8ab00ae71785305e050807f3c2020aa318a8c45b03eeabc6a53f62b51327c5a551c981bde9c1a9e6b1b88a8414b156c3d79855702735675229c56c1b7e722ba42794bfa6c7e403e9743bc6747a5d4fda5c9dbb79b56555f69b855f52ec093914f7702f78eee7d7617a3f4864677025e16f6a197827ca9b05ec28aed74867608d7dd63da87bc09917ef9b4d7b1688591d665c194f156912d3efcee980603c347311663ade4d4f26a8046fc68e35d06f9ce8c61779e29931c321ebb1441d67336d06438deaeefd76ca91b40792b005c78670df11976d0fd353768c7acf22197b8d111915dde389c9390d5d60d2d2fa32f7e250a657aa16a9ca01a9cb62a7e3924dc7b61040f922b740b9dc9c96f1067b1fb1904bf8ee915816bd88839c03907d46d348ec2ed75bd505a356d74ae6183a29eb011e09c0e5e4a18dc706f00560d16716722569e987c2f99bc69bd80d04a4f1d768e31ed3522b5cdf346c38bffb720c676f7b2cc04d1395a378020d3aabbcec6b20fb53e30ef62968d08186736ae0711fcafdadab3e147b5c64364729f207ff7e253bc838f87e0bb7df63d03e42aef1d827836d3743af42081c15da84dbbd8eaa51af3d36e5b84d337ed7598803aa9deef2d6beb6711f12bc132d59bd3f05e50d97a6b48b4952a811aad3c65eef891eb996ee1bb753eec98f6c6c90c6d891b4107392a105c03cf4a4c9dfaaadcdd49b3692c5a2a0f8f7cd8b4f352c2f3bda16e7f43f58bcc80e26b4aefbebf2ebb67c9f98c3f4079c6021faf2a006a1c09455f42bda09ec961bcb8afc0318f4a98a5386eb1ade082a1776c38b808ec9f2c59c3a0b24e4b4467a0fcfdb21775e2a9dd1621f8137e33961496b801d14534271787459b587e661e66b89f31ef748d8f164b706a12892556bf4ff2b66ab0749edbcd6ea53f6f962365003c6e40aa3cd48cf8cad7da41fead5e19f73");
            byte[] salt = null;
            byte[] info = null;
            int len = 64;
            string expected = "Wke0fZDymADHJihbD5Du8uHqo/tEvxgbBUXsbKPLqfwhcKg6oxjb59Tgg9EOXLX72HSRr1fjrn+M70Knc2l22A==";
            var hashAlgorithm = HMACHelper.HMACHashAlgorithm.SHA256;

            byte[] okm = HKDF.DeriveKey(
                hashFunction: hashAlgorithm,
                ikm: ikm,
                salt: salt,
                info: info,
                outputLen: len
            );
            string actual = Base64Encoder.Base64Encode(okm);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void BigKeyTestWithSalt()
        {
            byte[] ikm = Encoding.UTF8.GetBytes("e064a8ca0802224cbeec061a57cd955f772be06444ab02b734c2f73b3754cace73d349371186bf414c90eada277b207e92e2b77819d5cc56cb163c2331da81e6300e30e75ef0372c6698375dc894c52cc55f2def27a52f6b9e24eea334448c97c9af5e366504d2d95b66ac0f8c8ab645365517bbff39eed0fe0ee564572ba032ff885a2794170e423bd624a1b89a867d4276155562c1d9459881469b10e798789f541ed445cb795245a13f312381145ac6db7b773aded62a038a72a1c3241f386202210af4d6c4fcee1e465c471a1f0104d636e3552a63f65469d0a84af2c805f5d2b33a6926d5790c9184691843d359cafee2417618fc15348fa7154ce09cb332eadca64c2812273a72bba6f6762aa09f36c5f1cf51fb499c287359a957671b03690e050a15163b437d6b9be386a38a3854c391ae733b1537b3d908894b8ab00ae71785305e050807f3c2020aa318a8c45b03eeabc6a53f62b51327c5a551c981bde9c1a9e6b1b88a8414b156c3d79855702735675229c56c1b7e722ba42794bfa6c7e403e9743bc6747a5d4fda5c9dbb79b56555f69b855f52ec093914f7702f78eee7d7617a3f4864677025e16f6a197827ca9b05ec28aed74867608d7dd63da87bc09917ef9b4d7b1688591d665c194f156912d3efcee980603c347311663ade4d4f26a8046fc68e35d06f9ce8c61779e29931c321ebb1441d67336d06438deaeefd76ca91b40792b005c78670df11976d0fd353768c7acf22197b8d111915dde389c9390d5d60d2d2fa32f7e250a657aa16a9ca01a9cb62a7e3924dc7b61040f922b740b9dc9c96f1067b1fb1904bf8ee915816bd88839c03907d46d348ec2ed75bd505a356d74ae6183a29eb011e09c0e5e4a18dc706f00560d16716722569e987c2f99bc69bd80d04a4f1d768e31ed3522b5cdf346c38bffb720c676f7b2cc04d1395a378020d3aabbcec6b20fb53e30ef62968d08186736ae0711fcafdadab3e147b5c64364729f207ff7e253bc838f87e0bb7df63d03e42aef1d827836d3743af42081c15da84dbbd8eaa51af3d36e5b84d337ed7598803aa9deef2d6beb6711f12bc132d59bd3f05e50d97a6b48b4952a811aad3c65eef891eb996ee1bb753eec98f6c6c90c6d891b4107392a105c03cf4a4c9dfaaadcdd49b3692c5a2a0f8f7cd8b4f352c2f3bda16e7f43f58bcc80e26b4aefbebf2ebb67c9f98c3f4079c6021faf2a006a1c09455f42bda09ec961bcb8afc0318f4a98a5386eb1ade082a1776c38b808ec9f2c59c3a0b24e4b4467a0fcfdb21775e2a9dd1621f8137e33961496b801d14534271787459b587e661e66b89f31ef748d8f164b706a12892556bf4ff2b66ab0749edbcd6ea53f6f962365003c6e40aa3cd48cf8cad7da41fead5e19f73");
            byte[] salt = Encoding.UTF8.GetBytes("custom.salt!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            byte[] info = null;
            int len = 64;
            string expected = "QLpQxBIqFzsowou5i4tlxZaU79i/TgcN6Bu2oNzr3NG14HVZh0+UOHim9Tg0hz+cZEsP+btgF2EEpUy3uWsDkg==";
            var hashAlgorithm = HMACHelper.HMACHashAlgorithm.SHA256;

            byte[] okm = HKDF.DeriveKey(
                hashFunction: hashAlgorithm,
                ikm: ikm,
                salt: salt,
                info: info,
                outputLen: len
            );
            string actual = Base64Encoder.Base64Encode(okm);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void BigKeyTestWithInfo()
        {
            byte[] ikm = Encoding.UTF8.GetBytes("e064a8ca0802224cbeec061a57cd955f772be06444ab02b734c2f73b3754cace73d349371186bf414c90eada277b207e92e2b77819d5cc56cb163c2331da81e6300e30e75ef0372c6698375dc894c52cc55f2def27a52f6b9e24eea334448c97c9af5e366504d2d95b66ac0f8c8ab645365517bbff39eed0fe0ee564572ba032ff885a2794170e423bd624a1b89a867d4276155562c1d9459881469b10e798789f541ed445cb795245a13f312381145ac6db7b773aded62a038a72a1c3241f386202210af4d6c4fcee1e465c471a1f0104d636e3552a63f65469d0a84af2c805f5d2b33a6926d5790c9184691843d359cafee2417618fc15348fa7154ce09cb332eadca64c2812273a72bba6f6762aa09f36c5f1cf51fb499c287359a957671b03690e050a15163b437d6b9be386a38a3854c391ae733b1537b3d908894b8ab00ae71785305e050807f3c2020aa318a8c45b03eeabc6a53f62b51327c5a551c981bde9c1a9e6b1b88a8414b156c3d79855702735675229c56c1b7e722ba42794bfa6c7e403e9743bc6747a5d4fda5c9dbb79b56555f69b855f52ec093914f7702f78eee7d7617a3f4864677025e16f6a197827ca9b05ec28aed74867608d7dd63da87bc09917ef9b4d7b1688591d665c194f156912d3efcee980603c347311663ade4d4f26a8046fc68e35d06f9ce8c61779e29931c321ebb1441d67336d06438deaeefd76ca91b40792b005c78670df11976d0fd353768c7acf22197b8d111915dde389c9390d5d60d2d2fa32f7e250a657aa16a9ca01a9cb62a7e3924dc7b61040f922b740b9dc9c96f1067b1fb1904bf8ee915816bd88839c03907d46d348ec2ed75bd505a356d74ae6183a29eb011e09c0e5e4a18dc706f00560d16716722569e987c2f99bc69bd80d04a4f1d768e31ed3522b5cdf346c38bffb720c676f7b2cc04d1395a378020d3aabbcec6b20fb53e30ef62968d08186736ae0711fcafdadab3e147b5c64364729f207ff7e253bc838f87e0bb7df63d03e42aef1d827836d3743af42081c15da84dbbd8eaa51af3d36e5b84d337ed7598803aa9deef2d6beb6711f12bc132d59bd3f05e50d97a6b48b4952a811aad3c65eef891eb996ee1bb753eec98f6c6c90c6d891b4107392a105c03cf4a4c9dfaaadcdd49b3692c5a2a0f8f7cd8b4f352c2f3bda16e7f43f58bcc80e26b4aefbebf2ebb67c9f98c3f4079c6021faf2a006a1c09455f42bda09ec961bcb8afc0318f4a98a5386eb1ade082a1776c38b808ec9f2c59c3a0b24e4b4467a0fcfdb21775e2a9dd1621f8137e33961496b801d14534271787459b587e661e66b89f31ef748d8f164b706a12892556bf4ff2b66ab0749edbcd6ea53f6f962365003c6e40aa3cd48cf8cad7da41fead5e19f73");
            byte[] salt = null;
            byte[] info = Encoding.UTF8.GetBytes("derived.key!!!!!!!!!!!!!!!!!!");
            int len = 64;
            string expected = "RqtixLu98vE947awOHKfZbxGg5q491pvBJChwNlEGGNukqv4J8NnCf8vntK6AfK3wx6c26S317B9xYLnY2sHrg==";
            var hashAlgorithm = HMACHelper.HMACHashAlgorithm.SHA256;

            byte[] okm = HKDF.DeriveKey(
                hashFunction: hashAlgorithm,
                ikm: ikm,
                salt: salt,
                info: info,
                outputLen: len
            );
            string actual = Base64Encoder.Base64Encode(okm);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void BigKeyTestWithSaltAndInfo()
        {
            byte[] ikm = Encoding.UTF8.GetBytes("e064a8ca0802224cbeec061a57cd955f772be06444ab02b734c2f73b3754cace73d349371186bf414c90eada277b207e92e2b77819d5cc56cb163c2331da81e6300e30e75ef0372c6698375dc894c52cc55f2def27a52f6b9e24eea334448c97c9af5e366504d2d95b66ac0f8c8ab645365517bbff39eed0fe0ee564572ba032ff885a2794170e423bd624a1b89a867d4276155562c1d9459881469b10e798789f541ed445cb795245a13f312381145ac6db7b773aded62a038a72a1c3241f386202210af4d6c4fcee1e465c471a1f0104d636e3552a63f65469d0a84af2c805f5d2b33a6926d5790c9184691843d359cafee2417618fc15348fa7154ce09cb332eadca64c2812273a72bba6f6762aa09f36c5f1cf51fb499c287359a957671b03690e050a15163b437d6b9be386a38a3854c391ae733b1537b3d908894b8ab00ae71785305e050807f3c2020aa318a8c45b03eeabc6a53f62b51327c5a551c981bde9c1a9e6b1b88a8414b156c3d79855702735675229c56c1b7e722ba42794bfa6c7e403e9743bc6747a5d4fda5c9dbb79b56555f69b855f52ec093914f7702f78eee7d7617a3f4864677025e16f6a197827ca9b05ec28aed74867608d7dd63da87bc09917ef9b4d7b1688591d665c194f156912d3efcee980603c347311663ade4d4f26a8046fc68e35d06f9ce8c61779e29931c321ebb1441d67336d06438deaeefd76ca91b40792b005c78670df11976d0fd353768c7acf22197b8d111915dde389c9390d5d60d2d2fa32f7e250a657aa16a9ca01a9cb62a7e3924dc7b61040f922b740b9dc9c96f1067b1fb1904bf8ee915816bd88839c03907d46d348ec2ed75bd505a356d74ae6183a29eb011e09c0e5e4a18dc706f00560d16716722569e987c2f99bc69bd80d04a4f1d768e31ed3522b5cdf346c38bffb720c676f7b2cc04d1395a378020d3aabbcec6b20fb53e30ef62968d08186736ae0711fcafdadab3e147b5c64364729f207ff7e253bc838f87e0bb7df63d03e42aef1d827836d3743af42081c15da84dbbd8eaa51af3d36e5b84d337ed7598803aa9deef2d6beb6711f12bc132d59bd3f05e50d97a6b48b4952a811aad3c65eef891eb996ee1bb753eec98f6c6c90c6d891b4107392a105c03cf4a4c9dfaaadcdd49b3692c5a2a0f8f7cd8b4f352c2f3bda16e7f43f58bcc80e26b4aefbebf2ebb67c9f98c3f4079c6021faf2a006a1c09455f42bda09ec961bcb8afc0318f4a98a5386eb1ade082a1776c38b808ec9f2c59c3a0b24e4b4467a0fcfdb21775e2a9dd1621f8137e33961496b801d14534271787459b587e661e66b89f31ef748d8f164b706a12892556bf4ff2b66ab0749edbcd6ea53f6f962365003c6e40aa3cd48cf8cad7da41fead5e19f73");
            byte[] salt = Encoding.UTF8.GetBytes("custom.salt!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            byte[] info = Encoding.UTF8.GetBytes("derived.key!!!!!!!!!!!!!!!!!!");
            int len = 64;
            string expected = "O1sVsHjMcBF1Rb1Ct/HmMmi1RYwfKA5rSEb3V7OMpHfmh9y+pL3yGRRGBaL09patmYmv6r9bE++TlOE3/uEQRQ==";
            var hashAlgorithm = HMACHelper.HMACHashAlgorithm.SHA256;

            byte[] okm = HKDF.DeriveKey(
                hashFunction: hashAlgorithm,
                ikm: ikm,
                salt: salt,
                info: info,
                outputLen: len
            );
            string actual = Base64Encoder.Base64Encode(okm);
            Assert.AreEqual(expected, actual);
        }
    }
}
