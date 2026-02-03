from src.config import get_settings


def test_get_settings_reads_env(monkeypatch):
    get_settings.cache_clear()
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")
    monkeypatch.setenv("API_PREFIX", "/api-test")

    settings = get_settings()
    assert settings.github_token == "token-123"
    assert settings.api_prefix == "/api-test"

    monkeypatch.setenv("GITHUB_TOKEN", "token-456")
    settings_cached = get_settings()
    assert settings_cached.github_token == "token-123"

    get_settings.cache_clear()
    settings_new = get_settings()
    assert settings_new.github_token == "token-456"
