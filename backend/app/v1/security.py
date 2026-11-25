"""Password hashing, opaque tokens, TOTP and credential encryption."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

from .settings import platform_settings

# OWASP-recommended Argon2id parameters (m=19 MiB, t=2, p=1) or stronger.
_hasher = PasswordHasher(time_cost=3, memory_cost=19 * 1024, parallelism=1, hash_len=32, salt_len=16)
_DUMMY_HASH = _hasher.hash("securcode-timing-equaliser-not-a-password")

COMMON_PASSWORDS = {
    "password1234", "123456789012", "qwertyuiop12", "letmein12345", "administrator",
    "welcome12345", "passw0rd1234", "securcode123", "changeme1234", "iloveyou1234",
}


def validate_password_policy(password: str, email: str | None = None) -> None:
    """Length-first policy (NIST SP 800-63B) with a small deny list."""
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")
    if len(password) > 256:
        raise ValueError("Password must contain at most 256 characters.")
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS or len(set(password)) < 5:
        raise ValueError("Password is too common or too repetitive.")
    if email:
        local = email.split("@", 1)[0].lower()
        if len(local) >= 4 and local in lowered:
            raise ValueError("Password must not contain your email name.")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, stored: str | None) -> tuple[bool, bool]:
    """Return (valid, needs_rehash). Supports imported legacy scrypt hashes."""
    if not stored:
        _equalise_timing(password)
        return False, False
    if stored.startswith("scrypt$"):
        try:
            _, salt_hex, digest_hex = stored.split("$", 2)
            digest = hashlib.scrypt(
                password.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1, dklen=32
            ).hex()
        except (ValueError, TypeError):
            return False, False
        return hmac.compare_digest(digest, digest_hex), True
    try:
        _hasher.verify(stored, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False, False
    return True, _hasher.check_needs_rehash(stored)


def _equalise_timing(password: str) -> None:
    try:
        _hasher.verify(_DUMMY_HASH, password)
    except VerificationError:
        pass


def equalise_timing(password: str) -> None:
    """Spend comparable time when the account does not exist."""
    _equalise_timing(password)


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


# --- Credential encryption ---------------------------------------------------------

class EncryptionUnavailable(RuntimeError):
    pass


def _fernet() -> Fernet:
    key = platform_settings.encryption_key
    if not key:
        raise EncryptionUnavailable(
            "SECURCODE_ENCRYPTION_KEY is not configured; integration credentials cannot be stored."
        )
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, TypeError) as error:
        raise EncryptionUnavailable("SECURCODE_ENCRYPTION_KEY is not a valid Fernet key.") from error


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except InvalidToken as error:
        raise EncryptionUnavailable("Stored credential could not be decrypted with the current key.") from error


def encryption_available() -> bool:
    try:
        _fernet()
    except EncryptionUnavailable:
        return False
    return True


# --- TOTP (RFC 6238) -------------------------------------------------------------

def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    padded = secret + "=" * (-len(secret) % 8)
    key = base64.b32decode(padded, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def totp_code(secret: str, at: float | None = None) -> str:
    return _hotp(secret, int((at if at is not None else time.time()) // 30))


def verify_totp(secret: str, code: str, last_counter: int | None, at: float | None = None) -> int | None:
    """Return the matched counter, rejecting replays of an already-used code."""
    if not re.fullmatch(r"\d{6}", code or ""):
        return None
    now_counter = int((at if at is not None else time.time()) // 30)
    for counter in (now_counter - 1, now_counter, now_counter + 1):
        if last_counter is not None and counter <= last_counter:
            continue
        if hmac.compare_digest(_hotp(secret, counter), code):
            return counter
    return None


def totp_uri(secret: str, email: str) -> str:
    from urllib.parse import quote

    return f"otpauth://totp/SecurCode:{quote(email)}?secret={secret}&issuer=SecurCode&digits=6&period=30"


# --- Redaction --------------------------------------------------------------------

_SECRET_VALUE = re.compile(
    r"""(?ix)
    (
      (?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth)[\w-]*
      \s*[:=]\s*
    )
    (["'`]?)([^"'`\s]{4,})(\2)
    """
)
_KNOWN_TOKENS = re.compile(
    r"(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}"
    r"|sk_live_[A-Za-z0-9]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


def redact_snippet(snippet: str | None, max_length: int = 400) -> str | None:
    """Mask secret-looking values before a code snippet is stored or shown."""
    if snippet is None:
        return None
    text = snippet[:max_length]
    text = _SECRET_VALUE.sub(lambda m: f"{m.group(1)}{m.group(2)}****REDACTED****{m.group(4)}", text)
    text = _KNOWN_TOKENS.sub("****REDACTED****", text)
    return text
