using System;

namespace HMACSerialiser
{
	public interface ISerialiser
	{
		string Dumps(object data);
		JSONPayload Loads(string data);
		string LoadsString(string data);
	}

	public interface ITimedSerialiser : ISerialiser
	{
        string Dumps(object data, DateTimeOffset dateTime);
    }
}
