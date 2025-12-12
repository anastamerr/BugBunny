import hashlib
import hmac


def test_verify_github_signature_valid():
    from src.integrations.github_webhook import verify_github_signature

    secret = "test-secret"
    body = b'{"hello":"world"}'
    sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

    assert verify_github_signature(
        secret=secret, body=body, signature_256=f"sha256={sig}"
    )


def test_verify_github_signature_invalid():
    from src.integrations.github_webhook import verify_github_signature

    assert not verify_github_signature(
        secret="test-secret", body=b"{}", signature_256="sha256=deadbeef"
    )


def test_normalize_repo_list():
    from src.integrations.github_webhook import normalize_repo_list

    assert normalize_repo_list(None) == []
    assert normalize_repo_list("") == []
    assert normalize_repo_list("a/b") == ["a/b"]
    assert normalize_repo_list("a/b, c/d\n e/f") == ["a/b", "c/d", "e/f"]

