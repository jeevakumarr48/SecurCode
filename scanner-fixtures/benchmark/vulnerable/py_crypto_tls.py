import hashlib
import random
import ssl
import tempfile

import jwt
import requests
from Crypto.Cipher import AES, DES

path = tempfile.mktemp()  # expect: PYSEC011
digest = hashlib.md5(b"data").hexdigest()  # expect: PYSEC012
legacy = hashlib.new("sha1")  # expect: PYSEC012
cipher = DES.new(b"8bytekey")  # expect: PYSEC013
block = AES.new(b"0123456789abcdef", AES.MODE_ECB)  # expect: PYSEC013
reset_token = random.randint(100000, 999999)  # expect: PYSEC014
response = requests.get("https://internal.example.net", verify=False)  # expect: PYSEC015
context = ssl._create_unverified_context()  # expect: PYSEC015
claims = jwt.decode(token_value, options={"verify_signature": False})  # expect: PYSEC021
plain = requests.get("http://api.partner-service.net/v1/data")  # expect: PYSEC019
