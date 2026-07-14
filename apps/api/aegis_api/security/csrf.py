import hashlib
import hmac
import secrets


def issue_csrf_token(session_binding: bytes) -> str:
    """Create a random token bound to server-side session material."""
    nonce = secrets.token_bytes(32)
    signature = hmac.digest(session_binding, nonce, hashlib.sha256)
    return f"{nonce.hex()}.{signature.hex()}"


def verify_csrf_token(token: str, session_binding: bytes) -> bool:
    try:
        nonce_hex, provided_hex = token.split(".", maxsplit=1)
        nonce = bytes.fromhex(nonce_hex)
        provided = bytes.fromhex(provided_hex)
    except (ValueError, TypeError):
        return False
    expected = hmac.digest(session_binding, nonce, hashlib.sha256)
    return len(nonce) == 32 and hmac.compare_digest(provided, expected)
