import hashlib
import secrets


def issue_secret() -> str:
    return secrets.token_urlsafe(32)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def issue_sensor_credential(sensor_id: str) -> tuple[str, str]:
    secret = issue_secret()
    credential = f"{sensor_id}.{secret}"
    return credential, hash_secret(credential)
