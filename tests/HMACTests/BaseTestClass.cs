using System;
using HMACSerialiser;
using static HMACSerialiser.HMAC.HMACHelper;

namespace HMACTests
{
    public class BaseTestClass
    {
        protected const int maxAge = 3600;
        protected const string key = "KJHJason";
        protected const string info = "tests";
        protected const string salt = "HMACSerialiser";
        private static readonly HMACHashAlgorithm[] hashAlgorithms = new HMACHashAlgorithm[]
        {
            HMACHashAlgorithm.SHA1,
            HMACHashAlgorithm.SHA256,
            HMACHashAlgorithm.SHA384,
            HMACHashAlgorithm.SHA512
        };

        protected virtual ISerialiser[] InitialiseAllSerialisers(object key, object salt, HMACHashAlgorithm hashFunction, object info, int maxAge)
            => new ISerialiser[]
            {
                new Serialiser(key, salt, hashFunction, info),
                new TimedSerialiser(key, salt, maxAge, hashFunction, info),
                new URLSafeSerialiser(key, salt, hashFunction, info),
                new TimedURLSafeSerialiser(key, salt, maxAge, hashFunction, info),
            };
        protected Serialisers GetAllSerialisers()
            => GetAllSerialisers(key, salt, info, maxAge);

        protected Serialisers GetAllSerialisers(object key, object salt, object info, int maxAge)
        {
            if (key == null)
                key = BaseTestClass.key;
            if (salt == null)
                salt = BaseTestClass.salt;
            if (info == null)
                info = BaseTestClass.info;

            var serialisers = new Serialisers { };
            foreach (var hashFunction in hashAlgorithms)
            {
                var serialisersToAdd = InitialiseAllSerialisers(
                    key, salt, hashFunction, info, maxAge);

                switch (hashFunction)
                {
                    case HMACHashAlgorithm.SHA1:
                        serialisers.SHA1Serialisers = serialisersToAdd;
                        break;
                    case HMACHashAlgorithm.SHA256:
                        serialisers.SHA256Serialisers = serialisersToAdd;
                        break;
                    case HMACHashAlgorithm.SHA384:
                        serialisers.SHA384Serialisers = serialisersToAdd;
                        break;
                    case HMACHashAlgorithm.SHA512:
                        serialisers.SHA512Serialisers = serialisersToAdd;
                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }
            }
            return serialisers;
        }

        protected ITimedSerialiser[] InitialiseTimedSerialisers(object key, object salt, HMACHashAlgorithm hashFunction, object info, int maxAge)
            => new ITimedSerialiser[]
            {
                new TimedSerialiser(key, salt, maxAge, hashFunction, info),
                new TimedURLSafeSerialiser(key, salt, maxAge, hashFunction, info),
            };
    }
}
