from __future__ import annotations

from typing import Optional, Tuple
from urllib.parse import urlparse, urlunparse

from .types import DynamicFinding


_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
_DOCKER_HOSTNAME = "host.docker.internal"


def dockerize_target_url(target_url: str) -> Tuple[str, Optional[str], Optional[str]]:
    """Rewrite localhost targets so Docker can reach them.

    Returns:
        effective_url: URL to hand to ZAP inside Docker.
        original_netloc: Original network location (host[:port]) for display.
        docker_netloc: Docker network location used by ZAP.
    """
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        return target_url, None, None

    hostname = parsed.hostname or ""
    if hostname not in _LOCAL_HOSTS:
        return target_url, None, None

    port = parsed.port
    docker_netloc = f"{_DOCKER_HOSTNAME}:{port}" if port else _DOCKER_HOSTNAME
    effective = urlunparse(parsed._replace(netloc=docker_netloc))
    return effective, parsed.netloc, docker_netloc


def rewrite_finding_for_display(
    finding: DynamicFinding, original_netloc: Optional[str], docker_netloc: Optional[str]
) -> DynamicFinding:
    """Replace Docker-only hostnames in findings with the original target host."""
    if not original_netloc or not docker_netloc:
        return finding

    def _rewrite(url: str) -> str:
        if not url:
            return url
        parsed = urlparse(url)
        if parsed.netloc != docker_netloc:
            return url
        return urlunparse(parsed._replace(netloc=original_netloc))

    finding.matched_at = _rewrite(finding.matched_at)
    finding.endpoint = _rewrite(finding.endpoint)
    if finding.evidence:
        finding.evidence = [
            evidence.replace(docker_netloc, original_netloc)
            for evidence in finding.evidence
        ]
    return finding


def rewrite_url_for_display(
    value: Optional[str], original_netloc: Optional[str], docker_netloc: Optional[str]
) -> Optional[str]:
    if not value or not original_netloc or not docker_netloc:
        return value
    parsed = urlparse(value)
    if parsed.netloc != docker_netloc:
        return value
    return urlunparse(parsed._replace(netloc=original_netloc))
