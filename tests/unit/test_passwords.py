from aegis_api.security.passwords import PasswordService


def test_argon2_password_hash_is_salted_and_verifiable() -> None:
    service = PasswordService()
    first = service.hash("long-enough-password")
    second = service.hash("long-enough-password")
    assert first.startswith("$argon2id$")
    assert first != second
    assert service.verify(first, "long-enough-password")
    assert not service.verify(first, "wrong-password")
    assert not service.verify(None, "long-enough-password")
