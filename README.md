# HMACSerialiser

## Project Description

This is a simple serialiser that uses HMAC to sign the data before serialising it. This is similar to a JWT token but uses HMAC only.

This started off to address the use of `SHA256(message | secretKey)` in the company I was attached to during my internship which is susceptible to length extension attacks.

Hence, I started developing this library as a side project after work and it is heavily inspired by Python's [ItsDangerous](https://github.com/pallets/itsdangerous) library with various modifications like using HKDF (RFC 5869) for the key derivation.

## Security Considerations

This library uses HMAC to sign the data before serialising it. This is to ensure that the data is not tampered with.

Additionally, HMAC is not susceptible to length extension attacks.

Furthermore, this library uses HKDF (RFC 5869) to derive the key from the secret key and the salt. This is to ensure that the key is not directly used as the HMAC key.

Additionally, from my research and understanding, the key will be hashed with the hash function provided if the key is longer than the block size of the hash function.

On other hand, if the key is shorter than the block size of the hash function, it will be padded with zeros or `0x00` to match the block size.

Although it is not really a concern due to how HMAC works, it does reduce the effort needed to brute-force the key if it is padded with zeros.

Hence, HKDF is used to address this risk by deriving the key from the secret key and the salt and expanding it to the hash function's block size.

## Challenges

To support backward compatibility, I had to support up to .NET 3.1 which is used by the company I was attached to.

This meant that I had to implement the HKDF algorithm from scratch as it was only available in .NET 5.0 and above.

Although it is not recommended to re-invent the wheel, I have added various test cases to ensure that the HKDF implementation is correct.

## Sample Usage

Mainly importing the following namespaces:

```csharp
using HMACSerialiser;
using HMACSerialiser.Errors;
using static HMACSerialiser.HMAC.HMACHelper;
```

Signing and verifying a token with a JSON payload;

```csharp
string key = "secret";
string salt = "something-random";
HMACHashAlgorithm hashFunction = HMACHashAlgorithm.SHA1;

var serialiser = new Serialiser(key, salt, hashFunction);
object data = new { Name = "John Doe", Age = 25 };
string token = serialiser.Dumps(data); // eyJOYW1lIjoiSm9obiBEb2UiLCJBZ2UiOjI1fQ.m4km5yvsgL1V3fzPrEg/Ay9eX0c

try 
{
    JSONPayload payload = serialiser.Loads(token);
}
catch (BadTokenException) 
{
    // Handle bad token
}

JsonDocument document = payload.jsonDoc;
// or
string name = payload.Get<string>("Name");
int age = payload.Get<int>("Age");
```

Signing and verifying a token with a string payload with 1 hour a time limit;

```csharp
string key = "secret";
string salt = "something-random";
HMACHashAlgorithm hashFunction = HMACHashAlgorithm.SHA256;

int maxAge = 3600; // 1 hour in seconds
var serialiser = new TimedSerialiser(key, salt, maxAge, hashFunction);
string data = "Message that should not tampered with!";
string token = serialiser.Dumps(data); // TWVzc2FnZSB0aGF0IHNob3VsZCBub3QgdGFtcGVyZWQgd2l0aCE.MTcwNzI3OTk4Nw.dTOD5GbC/V46IAKKMpIFJQF7kG+7wKjq3aoZWbB9cDE

try 
{
    string message = serialiser.LoadsString(token);
    Assert.Equal(data, message);
}
catch (BadTokenException) 
{
    // Handle bad/expired token
}
```

Using a URLSafe serialiser to be used in URLs like JWT;

```csharp
string key = "secret";
string salt = "something-random";
string info = "unique-context-info";
HMACHashAlgorithm hashFunction = HMACHashAlgorithm.SHA384;

var serialiser = new URLSafeSerialiser(key, salt, hashFunction, info);
string data = "Note that this message can be still read by users by base64 decoding it!";
string token = serialiser.Dumps(data); // Tm90ZSB0aGF0IHRoaXMgbWVzc2FnZSBjYW4gYmUgc3RpbGwgcmVhZCBieSB1c2VycyBieSBiYXNlNjQgZGVjb2RpbmcgaXQh.zNYNQ2Uq3OayBPRn6ItYRUzSmCmb5vHbTAfgJPK9GzEHxdrFQen5yLR2HZo7q-Kn

try 
{
    string message = serialiser.LoadsString(token);
    Assert.Equal(data, message);
}
catch (BadTokenException) 
{
    // Handle bad token
}
```

Although it is not recommended to change the default separator of `.` used in the serialised token unless you know what you are doing, you can do so by setting the sep parameter in the constructor.

However, the separator should not be a character that is used in the base64 encoding of the payload and the HMAC signature.

Base64 Characters: `[A-Za-z0-9+/=]`

URLSafe Base64 Characters: `[A-Za-z0-9-_=]`

Though for URLSafe tokens, the separator should be a character that can be safely used in URLs to prevent unexpected behaviour like using `?` as the separator as it used to separate the query string from the URL.

```csharp
string key = "secret";
string salt = "something-random";
int maxAge = 20; // 20 seconds
HMACHashAlgorithm hashFunction = HMACHashAlgorithm.SHA512;

var serialiser = new TimedURLSafeSerialiser(key, salt, maxAge, hashFunction, sep: "!");
string data = "nurture";
string token = serialiser.Dumps(data); // bnVydHVyZQ!MTcwNzI4MDA0Mw!8StFXyv9pg6mwvCU7-gef3tgs-QyqeSbZRipryKu7PUyG3DNOhsyjVDKcH3-kFCEvDpQI4DxSleOsm9mV4VW9w

try 
{
    string message = serialiser.LoadsString(token);
    Assert.Equal(data, message);
}
catch (BadTokenException) 
{
    // Handle bad token
}
```

Also, you can use the included base64 encoders:

However, in my implementation, I have removed the padding `=` from the base64 encoded string to slightly reduce the length of the token.

```csharp
using HMACSerialiser.Base64Encoders;

string data = "~~~https://github.com/KJHJason/HMACSerialiser~~~";

string base64Data = Base64Encoder.Encode(data);
Assert.Equal("fn5+aHR0cHM6Ly9naXRodWIuY29tL0tKSEphc29uL0hNQUNTZXJpYWxpc2Vyfn5+", base64Data);
string decodedString = Base64Encoder.DecodeToString(base64);
Assert.Equal("~~~https://github.com/KJHJason/HMACSerialiser~~~", decodedString);

string urlSafeBase64Data = URLSafeBase64Encoder.Encode(data);
Assert.Equal("fn5-aHR0cHM6Ly9naXRodWIuY29tL0tKSEphc29uL0hNQUNTZXJpYWxpc2Vyfn5-", urlSafeDecodedString);
string urlSafeDecodedString = URLSafeBase64Encoder.DecodeToString(urlSafeBase64Data);
Assert.Equal("~~~https://github.com/KJHJason/HMACSerialiser~~~", urlSafeBase64Data);
```
