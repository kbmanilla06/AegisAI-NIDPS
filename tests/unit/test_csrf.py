from aegis_api.security.csrf import issue_csrf_token, verify_csrf_token


def test_csrf_token_is_bound_to_session_material() -> None:
    token = issue_csrf_token(b"session-a")
    assert verify_csrf_token(token, b"session-a")
    assert not verify_csrf_token(token, b"session-b")


def test_malformed_csrf_token_fails_closed() -> None:
    assert not verify_csrf_token("not-a-token", b"session-a")
