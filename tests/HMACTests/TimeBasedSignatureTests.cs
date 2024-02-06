using    Microsoft.VisualStudio.TestTools.UnitTesting;
using    System;
using    HMACSerialiser;
using    static    HMACSerialiser.HMAC.HMACHelper;
using    HMACSerialiser.Errors;

namespace    HMACTests
{
                [TestClass]
                public    class    TimeBasedSignatureTests    :    BaseTestClass
                {
                                protected    override    ISerialiser[]    InitialiseAllSerialisers(object    key,    object    salt,    HMACHashAlgorithm    hashFunction,    object    info,    int    maxAge)
                                                =>    new    ISerialiser[]
                                                {
                                                                new    TimedSerialiser(key,    salt,    maxAge,    hashFunction,    info),
                                                                new    TimedURLSafeSerialiser(key,    salt,    maxAge,    hashFunction,    info),
                                                };

                                [TestMethod]
                                public    void    ValidSignature()
                                {
                                                var    serialisers    =    GetAllSerialisers();
                                                var    data    =    "Hello,    World!";
                                                foreach    (var    serialiserByHashFunc    in    serialisers.GetList())
                                                {
                                                                foreach    (var    serialiser    in    serialiserByHashFunc)
                                                                {
                                                                                string    signed    =    serialiser.Dumps(data);
                                                                                var    result    =    serialiser.LoadsString(signed);
                                                                                Assert.AreEqual(data,    result);
                                                                }
                                                }
                                }

                                [TestMethod]
                                public    void    ExpiredSignature()
                                {
                                                var    serialisers    =    GetAllSerialisers(null,    null,    null,    1);
                                                var    data    =    "Hello,    World!";
                                                foreach    (var    serialiserByHashFunc    in    serialisers.GetList())
                                                {
                                                                foreach    (var    serialiser    in    serialiserByHashFunc)
                                                                {
                                                                                string    signed    =    serialiser.Dumps(data);
                                                                                System.Threading.Thread.Sleep(1000    +    1);
                                                                                try
                                                                                {
                                                                                                serialiser.LoadsString(signed);
                                                                                                Assert.Fail("Expected    exception    not    thrown");
                                                                                }
                                                                                catch    (BadTokenException)
                                                                                {
                                                                                                //    Expected    exception
                                                                                }
                                                                                catch    (AssertFailedException)
                                                                                {
                                                                                                //    to    avoid    double    fail
                                                                                }
                                                                                catch    (Exception    e)
                                                                                {
                                                                                                Assert.Fail($"Unexpected    exception:    {e.Message}");
                                                                                }
                                                                }
                                                }
                                }
                }
}
