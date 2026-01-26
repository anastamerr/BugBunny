from __future__ import annotations

import logging
from typing import Dict, List, Optional

from ...config import get_settings
from .types import DynamicFinding
from .zap_client import ZapDockerSession, ZapError, is_docker_available
from .zap_parser import parse_zap_alert

logger = logging.getLogger(__name__)


class DASTRunner:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.last_error: str | None = None

    def is_available(self) -> bool:
        return is_docker_available()

    async def scan(
        self,
        target_url: str,
        auth_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
    ) -> List[DynamicFinding]:
        self.last_error = None
        if not self.is_available():
            self.last_error = "Docker is not available for running ZAP."
            return []

        try:
            async with ZapDockerSession(
                image=self.settings.zap_docker_image,
                api_key=self.settings.zap_api_key,
                timeout_seconds=self.settings.zap_timeout_seconds,
                request_timeout_seconds=self.settings.zap_request_timeout_seconds,
            ) as zap:
                rule_descriptions = await _apply_auth_headers(
                    zap, auth_headers, cookies
                )
                try:
                    spider_id = await zap.spider_scan(
                        target_url,
                        max_children=self.settings.zap_max_depth,
                        recurse=True,
                    )
                    await zap.wait_spider(spider_id)

                    scan_id = await zap.active_scan(
                        url=target_url,
                        recurse=True,
                        scan_policy_name=self.settings.zap_scan_policy,
                    )
                    await zap.wait_active(scan_id)

                    alerts = await zap.alerts(base_url=target_url)
                finally:
                    await _remove_auth_headers(zap, rule_descriptions)

            findings: List[DynamicFinding] = []
            for alert in alerts:
                parsed = parse_zap_alert(alert, fallback_url=target_url)
                if parsed:
                    findings.append(parsed)
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
