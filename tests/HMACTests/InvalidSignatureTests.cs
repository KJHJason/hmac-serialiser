using    Microsoft.VisualStudio.TestTools.UnitTesting;
using    System;
using    System.Text;
using    HMACSerialiser.Errors;

namespace    HMACTests
{
                [TestClass]
                public    class    InvalidSignatureTests    :    BaseTestClass
                {
                                [TestMethod]
                                public    void    TamperedSignature()
                                {
                                                var    serialisers    =    GetAllSerialisers();
                                                var    data    =    "Hello,    World!";
                                                foreach    (var    serialiserByHashFunc    in    serialisers.GetList())
                                                {
                                                                foreach    (var    serialiser    in    serialiserByHashFunc)
                                                                {
                                                                                string    signed    =    serialiser.Dumps(data);
                                                                                var    parts    =    signed.Split('.');
                                                                                var    signature    =    parts[parts.Length    -    1];
                                                                                var    tamperedSignature    =    "a"    +    signature;
                                                                                parts    =    parts.AsSpan(0,    parts.Length    -    1).ToArray();
                                                                                signed    =    string.Join(".",    parts)    +    "."    +    tamperedSignature;

                                                                                try
                                                                                {
                                                                                                serialiser.LoadsString(signed);
                                                                                                Assert.Fail("Expected    exception    not    thrown");
                                                                                }
                                                                                catch    (BadTokenException)
                                                                                {    
                                                                                                //    Expected    exception
                                                                                }
                                                                                catch    (Exception    e)
                                                                                {
                                                                                                Assert.Fail($"Unexpected    exception:    {e.Message}");
                                                                                }
                                                                }
                                                }
                                }

                                [TestMethod]
                                public    void    TamperedData()
                                {
                                                var    serialisers    =    GetAllSerialisers();
                                                var    data    =    "Hello,    World!";
                                                foreach    (var    serialiserByHashFunc    in    serialisers.GetList())
                                                {
                                                                foreach    (var    serialiser    in    serialiserByHashFunc)
                                                                {
                                                                                string    signed    =    serialiser.Dumps(data);
                                                                                var    parts    =    signed.Split('.');
                                                                                var    tamperedPayload    =    Convert.ToBase64String(
                                                                                                Encoding.UTF8.GetBytes("Goodbye,    World!")
                                                                                );
                                                                                parts[0]    =    tamperedPayload;
                                                                                signed    =    string.Join(".",    parts);

                                                                                try
                                                                                {
                                                                                                serialiser.LoadsString(signed);
                                                                                                Assert.Fail("Expected    exception    not    thrown");
                                                                                }
                                                                                catch    (BadTokenException)
                                                                                {
                                                                                                //    Expected    exception
                                                                                }
                                                                                catch    (Exception    e)
                                                                                {
                                                                                                Assert.Fail($"Unexpected    exception:    {e.Message}");
                                                                                }
                                                                }
                                                }
                                }

                                [TestMethod]
                                public    void    TamperedDataAndSignature()
                                {
                                                var    serialisers    =    GetAllSerialisers();
                                                var    data    =    "Hello,    World!";
                                                foreach    (var    serialiserByHashFunc    in    serialisers.GetList())
                                                {
                                                                foreach    (var    serialiser    in    serialiserByHashFunc)
                                                                {
                                                                                string    signed    =    serialiser.Dumps(data);
                                                                                var    parts    =    signed.Split('.');
                                                                                var    tamperedPayload    =    Convert.ToBase64String(
                                                                                                Encoding.UTF8.GetBytes("Goodbye,    World!")
                                                                                );
                                                                                parts[0]    =    tamperedPayload;
                                                                                var    signature    =    parts[parts.Length    -    1];
                                                                                var    tamperedSignature    =    "abb"    +    signature;
                                                                                parts    =    parts.AsSpan(0,    parts.Length    -    1).ToArray();
                                                                                signed    =    string.Join(".",    parts)    +    "."    +    tamperedSignature;

                                                                                try
                                                                                {
                                                                                                serialiser.LoadsString(signed);
                                                                                                Assert.Fail("Expected    exception    not    thrown");
                                                                                }
                                                                                catch    (BadTokenException)
                                                                                {
                                                                                                //    Expected    exception
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
