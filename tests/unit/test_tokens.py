from aegis_api.security.tokens import hash_secret, issue_secret, issue_sensor_credential


def test_secrets_are_random_and_only_hashes_need_storage() -> None:
    first = issue_secret()
    second = issue_secret()
    assert first != second
    assert len(hash_secret(first)) == 64
    assert first not in hash_secret(first)


def test_sensor_credential_is_bound_to_sensor_identifier() -> None:
    credential, credential_hash = issue_sensor_credential("sensor-id")
    assert credential.startswith("sensor-id.")
    assert credential_hash == hash_secret(credential)
