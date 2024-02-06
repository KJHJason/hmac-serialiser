using    System;
using    System.Text;
using    System.Text.Json;
using    HMACSerialiser.Base64Encoders;
using    HMACSerialiser.Errors;
using    HMACSerialiser.KFD;
using    HMACSerialiser.HMAC;
using    System.Diagnostics;

namespace    HMACSerialiser
{
                public    class    Serialiser    :    ISerialiser
                {
                                protected    readonly    string    _sep;    //    separator
                                protected    readonly    byte[]    _key;
                                protected    readonly    byte[]    _salt;
                                protected    readonly    byte[]    _info;
                                protected    readonly    HMACHelper.HMACHashAlgorithm    _hashAlgorithm;

                                public    Serialiser(
                                                object    key,    
                                                object    salt,    
                                                HMACHelper.HMACHashAlgorithm    hashAlgorithm    =    HMACHelper.DefaultAlgorithm,    
                                                object    info    =    null,    
                                                string    sep    =    HMACHelper.DefaultSeparator)
                                {
                                                _info    =    HMACHelper.ConvertToBytes(info);
                                                _hashAlgorithm    =    hashAlgorithm;
                                                _sep    =    sep;
                                                CheckSepIsValid();

                                                if    (salt    ==    null)
                                                                salt    =    "default.salt";
                                                _salt    =    HMACHelper.ConvertToBytes(salt);
                                                _key    =    HMACHelper.ConvertToBytes(key);
                                }

                                //    Instead    of    deriving    the    key    straight-away    in    the    constructor,    we    derive    it    when    it    is    needed.
                                protected    byte[]    DeriveKey()
                                {
                                                //    Using    HKDF    (RFC5869)    to    derive    the    key    and    also    to
                                                //    expand    the    key    to    the    corresponding    block    size    of    the    hash    algorithm.
                                                //    This    is    mainly    to    prevent    the    key    from    being    too    short    and    get    padded    with    0x00    bytes.
                                                //    Additionally,    if    the    key    is    longer    than    the    hash    algorithm's    block    size,
                                                //    the    key    will    be    hashed    to    reduce    its    length    and    gets    padded    to    the    hash    algorithm's    block    size.
                                                //    Although,    this    is    not    a    problem    with    HMAC    as    long    as    the    key    is    not    leaked.
                                                //    However,    the    shorter    key,    the    less    effort    needed    to    brute-force    it.
                                                byte[]    key    =    HKDF.DeriveKey(
                                                                hashFunction:    _hashAlgorithm,
                                                                ikm:    _key,
                                                                salt:    _salt,
                                                                info:    _info,
                                                                outputLen:    HMACHelper.GetLengthForHKDF(_hashAlgorithm)
                                                );
                                                //    Debug.WriteLine($"Key:    {Base64Encode(key)}");
                                                return    key;
                                }

                                protected    virtual    string    Base64Encode(byte[]    data)
                                                =>    Base64Encoder.Base64Encode(data);

                                protected    virtual    byte[]    Base64Decode(string    data)
                                                =>    Base64Encoder.Base64Decode(data);

                                protected    virtual    bool    CheckSepIsValidLogic()
                                                =>    Base64Encoder.ContainsBase64Chars(_sep);

                                private    void    CheckSepIsValid()
                                {
                                                if    (CheckSepIsValidLogic())
                                                                throw    new    ArgumentException("Separator    cannot    contain    base64    characters",    nameof(_sep));
                                }

                                protected    byte[]    SerialiseObject(object    data)
                                {
                                                if    (data    is    string    stringValue)
                                                                return    Encoding.UTF8.GetBytes(stringValue);

                                                return    JsonSerializer.SerializeToUtf8Bytes(data);
                                }

                                protected    string    DeserialiseString(string    encodedData)
                                                =>    Encoding.UTF8.GetString(Base64Decode(encodedData));

                                protected    JSONPayload    DeserialiseObject(string    encodedData)
                                                =>    new    JSONPayload(JsonDocument.Parse(DeserialiseString(encodedData)));

                                protected    string    CombineData(params    byte[][]    data)
                                {
                                                if    (data.Length    ==    1)
                                                                return    Base64Encode(data[0]);

                                                var    combined    =    new    StringBuilder();
                                                foreach    (var    item    in    data)
                                                {
                                                                combined.Append(Base64Encode(item));
                                                                combined.Append(_sep);
                                                }

                                                if    (combined.Length    >    0)
                                                                //    Remove    the    last    separator
                                                                combined.Remove(combined.Length    -    _sep.Length,    _sep.Length);

                                                return    combined.ToString();
                                }

                                public    virtual    string    Dumps(object    data)
                                {
                                                byte[]    serialisedData    =    SerialiseObject(data);
                                                string    dataToSign    =    Base64Encode(serialisedData);

                                                byte[]    mac    =    HMACHelper.GetHMACDigest(DeriveKey(),    Encoding.UTF8.GetBytes(dataToSign),    _hashAlgorithm);
                                                string    signature    =    Base64Encode(mac);
                                                return    dataToSign    +    _sep    +    signature;
                                }

                                protected    (string    data,    byte[]    signature)    SplitToken(string    signedToken)
                                {
                                                var    split    =    signedToken.Split(_sep);
                                                if    (split.Length    !=    2)
                                                                throw    new    BadTokenException("Invalid    token    format");

                                                string    data;
                                                byte[]    signature;
                                                try
                                                {
                                                                //    both    are    base64    encoded
                                                                data    =    split[0];
                                                                signature    =    Base64Decode(split[1]);
                                                }
                                                catch    (FormatException)
                                                {
                                                                throw    new    BadTokenException("Data    or    signature    is    not    base64    encoded");
                                                }

                                                return    (data,    signature);
                                }

                                protected    virtual    string    LoadsLogic(string    signedToken)
                                {
                                                (string    encodedData,    byte[]    signature)    =    SplitToken(signedToken);
                                                byte[]    mac    =    HMACHelper.GetHMACDigest(DeriveKey(),    Encoding.UTF8.GetBytes(encodedData),    _hashAlgorithm);
                                                if    (!HMACHelper.CompareDigest(mac,    signature))
                                                                throw    new    BadTokenException("Data    has    been    tampered    or    signature    does    not    match");
                                                return    encodedData;
                                }

                                public    string    LoadsString(string    signedToken)
                                {
                                                string    encodedData    =    LoadsLogic(signedToken);
                                                return    DeserialiseString(encodedData);
                                }

                                public    JSONPayload    Loads(string    signedToken)
                                {
                                                string    encodedData    =    LoadsLogic(signedToken);
                                                return    DeserialiseObject(encodedData);
                                }
                }
}
