import json
import hmac
import base64
import hashlib
import typing

SHA1 = "sha1"
SHA256 = "sha256"
SHA384 = "sha384"
SHA512 = "sha512"

def string_to_hash_fn(hash_name: str) -> typing.Any:
    if hash_name == SHA1:
        return hashlib.sha1
    if hash_name == SHA256:
        return hashlib.sha256
    if hash_name == SHA384:
        return hashlib.sha384
    if hash_name == SHA512:
        return hashlib.sha512

    raise ValueError(f"Invalid hash function: {hash_name}")

def digest(key: bytes, data: str | bytes, hash_fn: typing.Any, urlsafe: bool, encode: bool = True) -> bytes:
    if (isinstance(data, str)):
        data = data.encode("utf-8")
    digest = hmac.new(key, data, hash_fn).digest()

    if urlsafe:
        return base64.urlsafe_b64encode(digest).replace(b"=", b"") if encode else digest
    return base64.b64encode(digest).replace(b"=", b"") if encode else digest

class Data:
    def __init__(self, data: bytes, urlsafe_data: bytes, unix_data: bytes):
        self.data = data
        self.urlsafe_data = urlsafe_data
        self.base64_unix = base64.b64encode(unix_data).decode("utf-8").replace("=", "").encode("utf-8")
        self.urlsafe_unix = base64.urlsafe_b64encode(unix_data).decode("utf-8").replace("=", "").encode("utf-8")

def hmac_logic(key: bytes, data: Data, hash_name: str, sep: str | bytes = ".") -> dict[str, str]:
    if isinstance(sep, str):
        sep = sep.encode("utf-8")

    hash_fn = string_to_hash_fn(hash_name)
    timed_serialiser_data = data.data + sep + data.base64_unix
    timed_urlsafe_serialiser_data = data.urlsafe_data + sep + data.urlsafe_unix
    hmac_result = {
        "serialiser": (
            data.data + sep + digest(key, data.data, hash_fn, False)).decode("utf-8"),

        "urlsafe-serialiser": (
            data.urlsafe_data + sep + digest(key, data.urlsafe_data, hash_fn, True)).decode("utf-8"),

        "timed-serialiser": (
            timed_serialiser_data + sep + digest(key, timed_serialiser_data, hash_fn, False)).decode("utf-8"),

        "timed-urlsafe-serialiser": (
            timed_urlsafe_serialiser_data + sep + digest(key, timed_urlsafe_serialiser_data, hash_fn, True)).decode("utf-8"),
    }
    return hmac_result

def main() -> None:
    sep = "."
    unix_time = "1706745600".encode("utf-8")
    msg = "KJHJason/HMACSerialiser".encode("utf-8")
    data = base64.b64encode(msg).replace(b"=", b"")
    urlsafe_data = base64.urlsafe_b64encode(msg).replace(b"=", b"")
    file_path = "./tests/HMACTests/HMACOutputs.txt"

    keys = {
        SHA1:   "YhiPE5Tw6O70WAfZYP3tqKe7JxdAn1zxGRiM9UdcMUP5cgHg8YU3W7TrPj7nOzCychwGtF0AqtoWfHAhgTz8Yg==",
        SHA256: "yLTVpkjI3yV29DVoc1RGvxGAOVgMnEpRK7WPx/ahgxQP7Pz76yd4C76vO80uKrZzTyclHatZOvWe7KfpqwlDOw==",
        SHA384: "ZfIUvWC1l3SnsYfcxwcoAFo8t+cr3LBIa+eYuM34XhPNjBjcSoOMe16nZ7UHapUGuB+nrjUvgkF7ZvnusATRZ1AGonjSH5NfjCL6wfh2Fc0T8nrnN/ns/OfiFTT0cPdLFd8gEosPCy18WiE4XckF2qaMwASK9g6t1tVmltqsGes=",
        SHA512: "Vgvzk+GGnQmLTc8hIJKwj3+RaB5+vZlLzlfw+W/eZYG+Ihb3uDdLoqWpW1bcOixJEjzfKXc+ew3Ykb06ugLpbpGIM8lBjNBlJ+F9cvUFLrM+7UYhISdwvn5dBt7geA/fAlwEWfBZ2boTgeLT6w7LQAZ06S7XuQ8B31dHq9LoBYQ=",
    }
    hash_fns = [SHA1, SHA256, SHA384, SHA512]

    hmac_result: dict[str, str] = {}
    for hash_fn in hash_fns:
        key = base64.b64decode(keys[hash_fn])
        result = hmac_logic(key, Data(data, urlsafe_data, unix_time), hash_fn, sep)
        hmac_result[hash_fn] = result

    dumped = json.dumps(hmac_result)
    with open(file_path, "w") as file:
        file.write(dumped)

    print("Dumped JSON:")
    print(dumped)

if __name__ == "__main__":
    main()
