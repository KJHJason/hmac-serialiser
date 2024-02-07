using System;

namespace HMACSerialiser
{
    public interface ITimedSerialiser : ISerialiser
    {
        string Dumps(object data, DateTimeOffset dateTime);
    }
}
