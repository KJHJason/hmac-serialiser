import hmac
import base64
import hashlib

# TODO: Change hash function accordingly
hashfunc = hashlib.sha512
def digest(key: bytes, msg: str | bytes) -> bytes:
    if (isinstance(msg, str)):
        msg = msg.encode()
    return hmac.new(key, msg, hashfunc).digest()

# TODO: Change key
key = base64.b64decode("Vgvzk+GGnQmLTc8hIJKwj3+RaB5+vZlLzlfw+W/eZYG+Ihb3uDdLoqWpW1bcOixJEjzfKXc+ew3Ykb06ugLpbpGIM8lBjNBlJ+F9cvUFLrM+7UYhISdwvn5dBt7geA/fAlwEWfBZ2boTgeLT6w7LQAZ06S7XuQ8B31dHq9LoBYQ=")
msg = "KJHJason/HMACSerialiser".encode()

data = base64.b64encode(msg).replace(b"=", b"")
print("Encoded Data:", data)
print("HMAC Serialiser:", base64.b64encode(digest(key, data)))

print()

urlsafe_data = base64.urlsafe_b64encode(msg).replace(b"=", b"")
print("URLSafe Encoded Data:", urlsafe_data)
print("HMAC URLSafeSerialiser:", base64.urlsafe_b64encode(digest(key, urlsafe_data)))

print()

unix_time = "1706745600".encode()
unix = base64.b64encode(unix_time).decode().replace("=", "")
urlsafe_unix = base64.urlsafe_b64encode(unix_time).decode().replace("=", "")

timed_data = data.decode() + "." + unix
print("Encoded Timed Data:", timed_data)
print("HMAC TimedSerialiser:", base64.b64encode(digest(key, timed_data)))

print()

urlsafe_timed_data = urlsafe_data.decode() + "." + urlsafe_unix
print("URLSafe Encoded Timed Data:", urlsafe_timed_data)
print("HMAC TimedURLSafeSerialiser:", base64.urlsafe_b64encode(digest(key, urlsafe_timed_data)))
