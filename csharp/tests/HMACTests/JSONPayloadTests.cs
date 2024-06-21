using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using HMACSerialiser;

namespace HMACTests
{
    [TestClass]
    public class JSONPayloadTests : BaseTestClass
    {
        [TestMethod]
        public void ValidJsonPayload()
        {
            // sample data
            string username = "Jason";
            int age = 20;
            DateTime created = DateTime.Now;
            double wallet = 10.00;
            bool verified = true;
            List<string> sessions = new List<string>
            {
                "session1",
                "session2"
            };
            var family = new Dictionary<string, string>
            {
                { "father", "John"},
                { "mother", "Jane" },
            };

            // create a JSON object
            object data = new
            {
                username,
                age,
                created,
                wallet,
                verified,
                sessions,
                family,
            };

            var serialisers = GetAllSerialisers();
            foreach (var serialiserByHashFunc in serialisers.GetList())
            {
                foreach (var serialiser in serialiserByHashFunc)
                {
                    JSONPayload result;
                    try
                    {
                        string signed = serialiser.Dumps(data);
                        result = serialiser.Loads(signed);
                    }
                    catch (Exception e)
                    {
                        Assert.Fail($"Unexpected exception: {e.Message}");
                        return;
                    }

                    string fallbackEmail = "notexist@mail.com";
                    string actualEmail = result.Get("email", fallbackEmail);
                    Assert.AreEqual(fallbackEmail, actualEmail);

                    string actualUsername = result.Get<string>("username");
                    Assert.AreEqual(username, actualUsername);

                    int actualAge = result.Get<int>("age");
                    Assert.AreEqual(age, actualAge);

                    DateTime actualCreated = result.Get<DateTime>("created");
                    Assert.AreEqual(created, actualCreated);

                    double actualWallet = result.Get<double>("wallet");
                    Assert.AreEqual(wallet, actualWallet);

                    bool actualVerified = result.Get<bool>("verified");
                    Assert.AreEqual(verified, actualVerified);

                    List<string> actualSessions = result.Get<List<string>>("sessions");
                    CollectionAssert.AreEqual(sessions, actualSessions);

                    Dictionary<string, string> actualFamily = result.Get<Dictionary<string, string>>("family");
                    CollectionAssert.AreEqual(family, actualFamily);
                }
            }
        }

        [TestMethod]
        public void JsonArrayPayload()
        {
            var data = new List<string>
            {
                "item1",
                "item2",
                "item3",
            };

            var serialisers = GetAllSerialisers();
            foreach (var serialiserByHashFunc in serialisers.GetList())
            {
                foreach (var serialiser in serialiserByHashFunc)
                {
                    JSONPayload result;
                    try
                    {
                        string signed = serialiser.Dumps(data);
                        result = serialiser.Loads(signed);
                    }
                    catch (Exception e)
                    {
                        Assert.Fail($"Unexpected exception: {e.Message}");
                        return;
                    }

                    List<string> actualData = result.Get<List<string>>();
                    CollectionAssert.AreEqual(data, actualData);
                }
            }
        }
    }
}
