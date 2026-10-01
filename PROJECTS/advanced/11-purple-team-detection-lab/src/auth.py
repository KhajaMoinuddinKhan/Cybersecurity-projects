"""Password and signed-session helpers for the local dashboard."""
from __future__ import annotations
import base64, hashlib, hmac, os, secrets, time

_ITERATIONS = 310_000

def hash_password(password: str) -> str:
    if len(password) < 12: raise ValueError("PURPLE_ADMIN_PASSWORD must contain at least 12 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return f"pbkdf2_sha256${_ITERATIONS}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"

def verify_password(password: str, encoded: str) -> bool:
    try:
        _, iterations, salt_text, digest_text = encoded.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.urlsafe_b64decode(salt_text), int(iterations))
        return hmac.compare_digest(base64.urlsafe_b64encode(digest).decode(), digest_text)
    except (ValueError, TypeError): return False

def _secret() -> bytes:
    value = os.getenv("PURPLE_SESSION_SECRET")
    if not value: raise RuntimeError("Set PURPLE_SESSION_SECRET before enabling dashboard login")
    return value.encode()

def configured() -> bool:
    return bool(os.getenv("PURPLE_ADMIN_PASSWORD")) and bool(os.getenv("PURPLE_SESSION_SECRET"))

def issue_session() -> str:
    expires = int(time.time()) + 12 * 60 * 60
    body = f"{expires}.{secrets.token_urlsafe(18)}"
    signature = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{signature}"

def valid_session(value: str | None) -> bool:
    if not value: return False
    try:
        expires, nonce, signature = value.split(".", 2)
        body = f"{expires}.{nonce}"
        return int(expires) > int(time.time()) and hmac.compare_digest(signature, hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest())
    except (ValueError, RuntimeError): return False

def configured_password_hash() -> str:
    password = os.getenv("PURPLE_ADMIN_PASSWORD")
    if not password: raise RuntimeError("Set PURPLE_ADMIN_PASSWORD before logging in")
    # A process-local derived value avoids putting a password in the database.
    salt = os.getenv("PURPLE_PASSWORD_SALT", "purple-team-admin")
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _ITERATIONS).hex()

def verify_configured_password(password: str) -> bool:
    try: return hmac.compare_digest(configured_password_hash(), hashlib.pbkdf2_hmac("sha256", password.encode(), os.getenv("PURPLE_PASSWORD_SALT", "purple-team-admin").encode(), _ITERATIONS).hex())
    except RuntimeError: return False
