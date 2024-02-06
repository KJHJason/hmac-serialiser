using HMACSerialiser;
using System.Collections.Generic;

namespace HMACTests
{
	public class Serialisers
	{
		public ISerialiser[] SHA1Serialisers { get; set; }
		public ISerialiser[] SHA256Serialisers { get; set; }
		public ISerialiser[] SHA384Serialisers { get; set; }
		public ISerialiser[] SHA512Serialisers { get; set; }

		public List<ISerialiser[]> GetList()
		{
			return new List<ISerialiser[]>
			{
				SHA1Serialisers,
				SHA256Serialisers,
				SHA384Serialisers,
				SHA512Serialisers
			};
		}
	}
}
