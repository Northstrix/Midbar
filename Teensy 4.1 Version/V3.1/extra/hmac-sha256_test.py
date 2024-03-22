"""
Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2024
For more information please visit
https://sourceforge.net/projects/midbar/
https://github.com/Northstrix/Midbar
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
"""
import hashlib
import hmac

# Define the hmac-sha256 key stored in an array as a hex string
key_hex = "3627909A29C31381A071EC27F7C9CA97726182AED29A7DDD2E54353322CFB30A"

# Convert the hex string to bytes
key = bytes.fromhex(key_hex)

# Define the input array as a string
input_str = "abc"

# Convert the input string to bytes
message = input_str.encode('utf-8')

# Calculate the tag using hmac-sha256
tag = hmac.new(key, message, hashlib.sha256).hexdigest()

print(tag)