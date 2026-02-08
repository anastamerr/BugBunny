from src.services.scanner.zap_utils import dockerize_target_url


def test_dockerize_target_url_rewrites_localhost_and_strips_fragment():
    effective, original_netloc, docker_netloc = dockerize_target_url(
        "http://localhost:3001/#/"
    )

    assert effective == "http://host.docker.internal:3001/"
    assert original_netloc == "localhost:3001"
    assert docker_netloc == "host.docker.internal:3001"


def test_dockerize_target_url_strips_fragment_for_remote_hosts():
    effective, original_netloc, docker_netloc = dockerize_target_url(
        "https://example.com/app#/dashboard"
    )

    assert effective == "https://example.com/app"
    assert original_netloc is None
    assert docker_netloc is None
