import hashlib
import logging
import os
import secrets
import ssl
import tarfile
import tempfile

import jwt
import requests

handle = tempfile.NamedTemporaryFile(delete=False)
digest = hashlib.sha256(b"data").hexdigest()
etag = hashlib.md5(b"cache-key", usedforsecurity=False).hexdigest()
reset_token = secrets.token_urlsafe(32)
shuffle_seed = 42
response = requests.get("https://api.example.net/v1/items", timeout=5)
local = requests.get("http://localhost:8080/health")
context = ssl.create_default_context()
claims = jwt.decode(token_value, key, algorithms=["HS256"])
DEBUG = os.getenv("DEBUG") == "1"
SESSION_COOKIE_SECURE = True
logger = logging.getLogger(__name__)
logger.info("login attempt for %s", "username")
os.chmod("/srv/app/config.ini", 0o640)
with tarfile.open("upload.tgz") as archive:
    archive.extractall("/tmp/out", filter="data")
placeholder = "AKIA-not-a-real-key"
# AKIAIOSFODNN7EXAMPLA inside a comment is ignored by the AST
