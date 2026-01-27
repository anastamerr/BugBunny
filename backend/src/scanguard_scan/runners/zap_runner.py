from __future__ import annotations

import asyncio
import logging
import shutil
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import httpx

from ..config import get_scan_settings

logger = logging.getLogger(__name__)


class ZapError(RuntimeError):
    def __init__(self, message: str, kind: str = "tool_error") -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class DastAlertData:
    plugin_id: str
    name: str
    risk: str
    confidence: str
    url: str
    param: str
    evidence: Optional[str]
    cwe_id: Optional[int]
    raw: Dict[str, Any]


@dataclass(frozen=True)
class DastRunResult:
    alerts: List[DastAlertData]
    metrics: Dict[str, Any]
    error_kind: Optional[str] = None
    error_message: Optional[str] = None


def _get_free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _normalize_risk(value: Any) -> str:
    text = str(value or "").strip().lower()
    if "high" in text:
        return "high"
    if "medium" in text:
        return "medium"
    if "low" in text:
        return "low"
    if "info" in text:
        return "info"
    return text or "info"


def _extract_cwe_id(value: Any) -> Optional[int]:
    if value is None:
        return None
    text = str(value)
    digits = "".join(ch for ch in text if ch.isdigit())
    if not digits:
        return None
    try:
        return int(digits)
    except ValueError:
        return None


def parse_zap_alert(alert: Dict[str, Any]) -> Optional[DastAlertData]:
    plugin_id = str(alert.get("pluginId") or alert.get("pluginid") or "")
    name = str(alert.get("alert") or alert.get("name") or "")
    if not plugin_id and not name:
        return None

    risk = _normalize_risk(alert.get("risk") or alert.get("riskDesc"))
    confidence = str(alert.get("confidence") or alert.get("confidenceDesc") or "")
    url = str(alert.get("url") or alert.get("uri") or "")
    param = str(alert.get("param") or "")
    evidence = str(alert.get("evidence") or "") or None
    cwe_id = _extract_cwe_id(alert.get("cweid") or alert.get("cweId"))

    return DastAlertData(
        plugin_id=plugin_id or name,
        name=name or plugin_id,
        risk=risk,
        confidence=confidence,
        url=url,
        param=param,
        evidence=evidence,
        cwe_id=cwe_id,
        raw=alert,
    )


def _auth_present(headers: Dict[str, str], cookies: str) -> bool:
    if cookies.strip():
        return True
    return any(value.strip() for value in headers.values())


def _cookies_header(cookies: str) -> str:
    return cookies.strip()


async def _docker_logs(container_id: str, tail: int = 200) -> str:
    result = await asyncio.to_thread(
        subprocess.run,
        ["docker", "logs", "--tail", str(tail), container_id],
        capture_output=True,
        text=True,
        check=False,
    )
    output = (result.stdout or result.stderr or "").strip()
    return output

async def _probe_target(
    target_url: str,
    *,
    headers: Dict[str, str],
    cookies: str,
    timeout_seconds: int = 10,
) -> Tuple[bool, Optional[str], Optional[str]]:
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            request_headers = dict(headers)
            if cookies:
                request_headers["Cookie"] = _cookies_header(cookies)
            response = await client.get(target_url, headers=request_headers)
    except httpx.ConnectError:
        return False, "unreachable", "Target unreachable"
    except httpx.RequestError as exc:
        return False, "unreachable", f"Target unreachable: {exc}"

    if response.status_code in (401, 403):
        return False, "auth_required", "Target requires authentication"
    if response.status_code == 429:
        return False, "rate_limited", "Target rate limited"
    return True, None, None


class ZapRunner:
    def __init__(self) -> None:
        self.settings = get_scan_settings()

    def _docker_available(self) -> bool:
        return shutil.which("docker") is not None

    async def run(
        self,
        target_url: str,
        *,
        headers: Dict[str, str],
        cookies: str,
        timeout_seconds: int,
        spider_minutes: int,
        active_scan_minutes: int,
    ) -> DastRunResult:
        if not self._docker_available():
            return DastRunResult(
                alerts=[],
                metrics={},
                error_kind="tool_error",
                error_message="Docker is not available for running ZAP.",
            )

        auth_present = _auth_present(headers, cookies)
        reachable, error_kind, error_message = await _probe_target(
            target_url, headers=headers, cookies=cookies
        )
        if not reachable:
            if error_kind == "auth_required" and auth_present:
                # Continue, but remember auth might be failing
                pass
            else:
                return DastRunResult(
                    alerts=[],
                    metrics={},
                    error_kind=error_kind,
                    error_message=error_message,
                )

        container_id = None
        client: Optional[httpx.AsyncClient] = None
        base_url = None
        started_at = time.monotonic()
        spider_urls: List[str] = []
        alerts: List[DastAlertData] = []
        error_kind = None
        error_message = None
        try:
            port = _get_free_port()
            container_name = f"scanguard-zap-{uuid.uuid4().hex[:10]}"
            cmd = [
                "docker",
                "run",
                "-d",
                "--rm",
                "-p",
                f"{port}:8080",
                "--name",
                container_name,
                self.settings.zap_docker_image,
                "zap.sh",
                "-daemon",
                "-host",
                "0.0.0.0",
                "-port",
                "8080",
                "-config",
                "api.addrs.addr.name=.*",
                "-config",
                "api.addrs.addr.regex=true",
            ]
            if self.settings.zap_api_key:
                cmd.extend(["-config", f"api.key={self.settings.zap_api_key}"])
            else:
                cmd.extend(["-config", "api.disablekey=true"])

            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip()
                raise ZapError(
                    f"Failed to start ZAP container: {detail or 'unknown error'}",
                    "tool_error",
                )

            container_id = (result.stdout or "").strip()
            base_url = f"http://127.0.0.1:{port}"
            client = httpx.AsyncClient(base_url=base_url, timeout=30)

            try:
                await _wait_ready(client, self.settings.zap_api_key, timeout_seconds)
            except ZapError as exc:
                log_snip = ""
                if container_id:
                    log_snip = await _docker_logs(container_id)
                if log_snip:
                    raise ZapError(
                        f"{exc} | ZAP logs:\n{log_snip}", exc.kind
                    ) from exc
                raise

            rule_descriptions = await _apply_auth_rules(
                client, self.settings.zap_api_key, headers, cookies
            )
            try:
                spider_id = await _start_spider(client, self.settings.zap_api_key, target_url)
                spider_deadline = time.monotonic() + max(1, spider_minutes) * 60
                overall_deadline = started_at + timeout_seconds
                timed_out = False
                if not await _wait_scan(
                    client,
                    self.settings.zap_api_key,
                    "spider",
                    spider_id,
                    min(spider_deadline, overall_deadline),
                ):
                    timed_out = True
                spider_urls = await _spider_results(
                    client, self.settings.zap_api_key, spider_id
                )

                if not timed_out and time.monotonic() < overall_deadline:
                    scan_id = await _start_active_scan(
                        client, self.settings.zap_api_key, target_url
                    )
                    active_deadline = time.monotonic() + max(1, active_scan_minutes) * 60
                    if not await _wait_scan(
                        client,
                        self.settings.zap_api_key,
                        "ascan",
                        scan_id,
                        min(active_deadline, overall_deadline),
                    ):
                        timed_out = True
                if timed_out:
                    error_kind = "timeout"
                    error_message = "DAST exceeded configured timeout."

                raw_alerts = await _fetch_alerts(
                    client, self.settings.zap_api_key, target_url
                )
                alerts = [a for a in (parse_zap_alert(item) for item in raw_alerts) if a]
            finally:
                await _remove_auth_rules(client, self.settings.zap_api_key, rule_descriptions)
        except ZapError as exc:
            error_kind = exc.kind
            error_message = str(exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("ZAP scan failed")
            error_kind = "tool_error"
            error_message = str(exc)
        finally:
            if client:
                await client.aclose()
            if container_id:
                await asyncio.to_thread(
                    subprocess.run,
                    ["docker", "stop", container_id],
                    capture_output=True,
                    text=True,
                    check=False,
                )

        metrics = {
            "duration_seconds": int(time.monotonic() - started_at),
            "spider_url_count": len(spider_urls),
            "alert_count": len(alerts),
        }

        if error_kind is None:
            if len(spider_urls) < self.settings.dast_min_spider_urls:
                error_kind = "insufficient_coverage"
                error_message = "Spider discovered too few URLs to validate findings."
            elif not reachable and auth_present:
                error_kind = "auth_required"
                error_message = "Target likely blocked authentication."

        return DastRunResult(
            alerts=alerts,
            metrics=metrics,
            error_kind=error_kind,
            error_message=error_message,
        )


async def _wait_ready(
    client: httpx.AsyncClient, api_key: Optional[str], timeout_seconds: int
) -> None:
    deadline = time.monotonic() + min(120, timeout_seconds)
    last_error: Optional[str] = None
    while time.monotonic() < deadline:
        try:
            await _zap_view(client, api_key, "core", "version")
            return
        except ZapError as exc:
            last_error = str(exc)
            await asyncio.sleep(1)
    raise ZapError(
        f"ZAP daemon did not become ready: {last_error or 'timeout'}",
        "timeout",
    )


async def _zap_view(
    client: httpx.AsyncClient, api_key: Optional[str], component: str, view: str, params: Dict[str, Any] | None = None
) -> Dict[str, Any]:
    return await _zap_request(client, api_key, f"/JSON/{component}/view/{view}/", params)


async def _zap_action(
    client: httpx.AsyncClient, api_key: Optional[str], component: str, action: str, params: Dict[str, Any] | None = None
) -> Dict[str, Any]:
    return await _zap_request(client, api_key, f"/JSON/{component}/action/{action}/", params)


async def _zap_request(
    client: httpx.AsyncClient,
    api_key: Optional[str],
    path: str,
    params: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    payload = dict(params or {})
    if api_key:
        payload["apikey"] = api_key
    try:
        response = await client.get(path, params=payload)
    except httpx.RequestError as exc:
        detail = str(exc) or exc.__class__.__name__
        raise ZapError(f"ZAP API request failed: {detail}", "tool_error") from exc
    if response.status_code != 200:
        raise ZapError(
            f"ZAP API returned {response.status_code}: {response.text}", "tool_error"
        )
    try:
        return response.json()
    except ValueError as exc:
        raise ZapError("ZAP API returned invalid JSON", "tool_error") from exc


async def _apply_auth_rules(
    client: httpx.AsyncClient,
    api_key: Optional[str],
    headers: Dict[str, str],
    cookies: str,
) -> List[str]:
    descriptions: List[str] = []
    for header, value in headers.items():
        if not header or value is None:
            continue
        description = f"scanguard-{uuid.uuid4().hex[:8]}"
        params = {
            "description": description,
            "enabled": "true",
            "matchType": "REQ_HEADER",
            "matchString": header,
            "replacement": value,
        }
        await _zap_action(client, api_key, "replacer", "addRule", params)
        descriptions.append(description)
    if cookies.strip():
        description = f"scanguard-cookie-{uuid.uuid4().hex[:8]}"
        params = {
            "description": description,
            "enabled": "true",
            "matchType": "REQ_HEADER",
            "matchString": "Cookie",
            "replacement": _cookies_header(cookies),
        }
        await _zap_action(client, api_key, "replacer", "addRule", params)
        descriptions.append(description)
    return descriptions


async def _remove_auth_rules(
    client: httpx.AsyncClient, api_key: Optional[str], descriptions: List[str]
) -> None:
    for description in descriptions:
        try:
            await _zap_action(
                client, api_key, "replacer", "removeRule", {"description": description}
            )
        except ZapError:
            continue


async def _start_spider(
    client: httpx.AsyncClient, api_key: Optional[str], target_url: str
) -> str:
    data = await _zap_action(
        client, api_key, "spider", "scan", {"url": target_url, "recurse": "true"}
    )
    scan_id = str(data.get("scan") or "")
    if not scan_id:
        raise ZapError("ZAP spider did not return scan id", "tool_error")
    return scan_id


async def _spider_results(
    client: httpx.AsyncClient, api_key: Optional[str], scan_id: str
) -> List[str]:
    data = await _zap_view(
        client, api_key, "spider", "results", {"scanId": scan_id}
    )
    results = data.get("results") or []
    if isinstance(results, list):
        return [str(item) for item in results]
    return []


async def _start_active_scan(
    client: httpx.AsyncClient, api_key: Optional[str], target_url: str
) -> str:
    data = await _zap_action(
        client, api_key, "ascan", "scan", {"url": target_url, "recurse": "true"}
    )
    scan_id = str(data.get("scan") or "")
    if not scan_id:
        raise ZapError("ZAP active scan did not return scan id", "tool_error")
    return scan_id


async def _wait_scan(
    client: httpx.AsyncClient,
    api_key: Optional[str],
    component: str,
    scan_id: str,
    deadline: float,
) -> bool:
    while time.monotonic() < deadline:
        data = await _zap_view(
            client, api_key, component, "status", {"scanId": scan_id}
        )
        status = str(data.get("status") or "0")
        try:
            progress = int(status)
        except ValueError:
            progress = 0
        if progress >= 100:
            return True
        await asyncio.sleep(2)
    return False


async def _fetch_alerts(
    client: httpx.AsyncClient, api_key: Optional[str], target_url: str
) -> List[Dict[str, Any]]:
    data = await _zap_view(
        client, api_key, "core", "alerts", {"baseurl": target_url}
    )
    alerts = data.get("alerts") or []
    if isinstance(alerts, list):
        return alerts
    return []
