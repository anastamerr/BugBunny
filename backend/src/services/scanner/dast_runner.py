from __future__ import annotations

import logging
from typing import Awaitable, Callable, Dict, List, Optional

from ...config import get_settings
from .dast_base import BaseDASTRunner
from .types import DynamicFinding
from .zap_client import ZapDockerSession, ZapError, is_docker_available
from .zap_parser import parse_zap_alert
from .zap_utils import dockerize_target_url, rewrite_finding_for_display

logger = logging.getLogger(__name__)


class DASTRunner(BaseDASTRunner):
    def __init__(self) -> None:
        super().__init__()
        self.settings = get_settings()
        self.last_error: str | None = None

    def is_available(self) -> bool:
        if self.settings.zap_base_url:
            return True
        return is_docker_available()

    async def scan(
        self,
        target_url: str,
        auth_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
        progress_cb: Optional[Callable[[str, Optional[str]], Awaitable[None]]] = None,
    ) -> List[DynamicFinding]:
        self.last_error = None
        if not self.is_available():
            self.last_error = "Docker is not available for running ZAP."
            return []

        # Apply default auth header from env if no explicit headers provided
        effective_auth_headers = auth_headers
        if not effective_auth_headers and self.settings.dast_default_auth_header:
            effective_auth_headers = _parse_default_auth_header(
                self.settings.dast_default_auth_header
            )
            if effective_auth_headers:
                logger.debug(
                    "Applied default auth header from DAST_DEFAULT_AUTH_HEADER"
                )

        effective_target, original_netloc, docker_netloc = dockerize_target_url(
            target_url
        )
        try:
            async with ZapDockerSession(
                image=self.settings.zap_docker_image,
                api_key=self.settings.zap_api_key,
                timeout_seconds=self.settings.zap_timeout_seconds,
                request_timeout_seconds=self.settings.zap_request_timeout_seconds,
                extra_hosts=_parse_extra_hosts(self.settings.zap_docker_extra_hosts),
                base_url=self.settings.zap_base_url,
                host_port=self.settings.zap_host_port,
                keepalive_seconds=self.settings.zap_keepalive_seconds,
                host_header=self.settings.zap_host_header,
            ) as zap:
                async def _progress(phase: str, message: Optional[str] = None) -> None:
                    if not progress_cb:
                        return
                    try:
                        await progress_cb(phase, message)
                    except Exception as exc:  # pragma: no cover - best-effort
                        logger.debug("DAST progress callback failed: %s", exc)

                rule_descriptions = await _apply_auth_headers(
                    zap, effective_auth_headers, cookies
                )
                try:
                    await _progress("dast.spider", "Spidering target")
                    spider_id = await zap.spider_scan(
                        effective_target,
                        max_children=self.settings.zap_max_depth,
                        recurse=True,
                    )
                    await zap.wait_spider(spider_id)

                    await _progress("dast.active_scan", "Active scanning target")
                    scan_id = await zap.active_scan(
                        url=effective_target,
                        recurse=True,
                        scan_policy_name=self.settings.zap_scan_policy,
                    )
                    await zap.wait_active(scan_id)

                    await _progress("dast.alerts", "Collecting DAST alerts")
                    alerts = await zap.alerts(base_url=effective_target)
                finally:
                    await _remove_auth_headers(zap, rule_descriptions)

            findings: List[DynamicFinding] = []
            for alert in alerts:
                parsed = parse_zap_alert(alert, fallback_url=effective_target)
                if parsed:
                    findings.append(
                        rewrite_finding_for_display(
                            parsed, original_netloc, docker_netloc
                        )
                    )
            return findings
        except ZapError as exc:
            self.last_error = str(exc)
            logger.error("ZAP scan failed for %s: %s", target_url, exc)
            return []


async def _apply_auth_headers(
    zap: ZapDockerSession,
    auth_headers: Optional[Dict[str, str]],
    cookies: Optional[str],
) -> List[str]:
    descriptions: List[str] = []
    if not auth_headers and not cookies:
        return descriptions
    for header, value in (auth_headers or {}).items():
        if not header:
            continue
        description = f"scanguard-auth-{header}"
        try:
            await zap.add_header_rule(description, header, value or "")
            descriptions.append(description)
        except ZapError as exc:
            logger.warning("Failed to set ZAP auth header %s: %s", header, exc)
    if cookies:
        description = "scanguard-auth-cookie"
        try:
            await zap.add_header_rule(description, "Cookie", cookies)
            descriptions.append(description)
        except ZapError as exc:
            logger.warning("Failed to set ZAP cookies: %s", exc)
    return descriptions


async def _remove_auth_headers(
    zap: ZapDockerSession, descriptions: List[str]
) -> None:
    for description in descriptions:
        try:
            await zap.remove_header_rule(description)
        except ZapError as exc:
            logger.debug("Failed to remove ZAP header rule %s: %s", description, exc)


def _parse_extra_hosts(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_default_auth_header(value: Optional[str]) -> Optional[Dict[str, str]]:
    """Parse DAST_DEFAULT_AUTH_HEADER env var into auth headers dict.

    Expected format: "Header-Name: header value"
    Example: "Authorization: Bearer token123"

    Args:
        value: Raw header string from env var

    Returns:
        Dict with single header, or None if invalid
    """
    if not value:
        return None

    value = value.strip()
    if ":" not in value:
        logger.warning(
            "Invalid DAST_DEFAULT_AUTH_HEADER format (missing colon): %s",
            value[:50],
        )
        return None

    # Split on first colon only
    parts = value.split(":", 1)
    if len(parts) != 2:
        return None

    header_name = parts[0].strip()
    header_value = parts[1].strip()

    if not header_name:
        logger.warning("DAST_DEFAULT_AUTH_HEADER has empty header name")
        return None

    return {header_name: header_value}
