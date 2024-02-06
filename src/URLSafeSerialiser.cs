using    HMACSerialiser.Base64Encoders;
using    HMACSerialiser.HMAC;

namespace    HMACSerialiser
{
                public    class    URLSafeSerialiser    :    Serialiser
                {
                                public    URLSafeSerialiser(
                                                object    key,    
                                                object    salt,    
                                                HMACHelper.HMACHashAlgorithm    hashAlgorithm    =    HMACHelper.DefaultAlgorithm,
                                                object    info    =    null,
                                                string    sep    =    HMACHelper.DefaultSeparator)
                                                                :    base(key,    salt,    hashAlgorithm,    info,    sep)
                                {
                                }

                                protected    override    string    Base64Encode(byte[]    data)
                                                =>    URLSafeBase64Encoder.Base64Encode(data);

                                protected    override    byte[]    Base64Decode(string    data)
                                                =>    URLSafeBase64Encoder.Base64Decode(data);

                                protected    override    bool    CheckSepIsValidLogic()
                                                =>    URLSafeBase64Encoder.ContainsBase64Chars(_sep);
                }
}
