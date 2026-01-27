from __future__ import annotations

import asyncio
import logging
import shutil
import socket
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class ZapError(RuntimeError):
    def __init__(self, message: str, kind: str = "tooling") -> None:
        super().__init__(message)
        self.kind = kind


def is_docker_available() -> bool:
    return shutil.which("docker") is not None


def _get_free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _bool(value: bool | None) -> str | None:
    if value is None:
        return None
    return "true" if value else "false"


class ZapDockerSession:
    def __init__(
        self,
        image: str,
        api_key: Optional[str],
        timeout_seconds: int,
        request_timeout_seconds: Optional[int] = None,
    ) -> None:
        self.image = image
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.request_timeout_seconds = request_timeout_seconds or min(
            30, max(5, timeout_seconds // 6)
        )
        self.container_id: Optional[str] = None
        self.container_name: Optional[str] = None
        self.base_url: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "ZapDockerSession":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        await self.stop()

    async def start(self) -> None:
        if not is_docker_available():
            raise ZapError("Docker is not available for running ZAP.", "tooling")

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
            self.image,
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
        if self.api_key:
            cmd.extend(["-config", f"api.key={self.api_key}"])
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
                "tooling",
            )

        self.container_id = (result.stdout or "").strip()
        self.container_name = container_name
        self.base_url = f"http://127.0.0.1:{port}"
        # Force Host header to match the ZAP daemon bind port inside the container.
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.request_timeout_seconds,
            headers={"Host": "127.0.0.1:8080"},
        )

        try:
            await self._wait_ready()
        except Exception:
            await self.stop()
            raise

    async def stop(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
        if not self.container_id:
            return
        await asyncio.to_thread(
            subprocess.run,
            ["docker", "stop", self.container_id],
            capture_output=True,
            text=True,
            check=False,
        )
        self.container_id = None
        self.container_name = None
        self.base_url = None

    async def _wait_ready(self) -> None:
        deadline = time.monotonic() + min(180, self.timeout_seconds)
        last_error: Optional[str] = None
        while time.monotonic() < deadline:
            try:
                await self._view("core", "version")
                return
            except ZapError as exc:
                last_error = str(exc)
                await asyncio.sleep(1.0)
        raise ZapError(
            f"ZAP daemon did not become ready: {last_error or 'timeout'}",
            "timeout",
        )

    async def _request(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not self._client:
            raise ZapError("ZAP client not started", "tooling")
        payload: Dict[str, Any] = dict(params or {})
        if self.api_key:
            payload["apikey"] = self.api_key
        try:
            response = await self._client.get(path, params=payload)
        except httpx.TimeoutException as exc:
            raise ZapError(f"ZAP API timeout: {exc}", "timeout") from exc
        except httpx.RequestError as exc:
            raise ZapError(f"ZAP API error: {exc}", "tooling") from exc

        if response.status_code != 200:
            raise ZapError(
                f"ZAP API returned {response.status_code}: {response.text}",
                "tooling",
            )
        try:
            return response.json()
        except ValueError as exc:
            raise ZapError("ZAP API returned invalid JSON", "tooling") from exc

    async def _action(
        self, component: str, action: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        return await self._request(f"/JSON/{component}/action/{action}/", params)

    async def _view(
        self, component: str, view: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        return await self._request(f"/JSON/{component}/view/{view}/", params)

    async def spider_scan(
        self,
        url: str,
        *,
        max_children: Optional[int] = None,
        recurse: bool = True,
        context_name: Optional[str] = None,
        subtree_only: Optional[bool] = None,
    ) -> str:
        params: Dict[str, Any] = {"url": url, "recurse": _bool(recurse)}
        if max_children is not None:
            params["maxChildren"] = str(max_children)
        if context_name:
            params["contextName"] = context_name
        if subtree_only is not None:
            params["subtreeOnly"] = _bool(subtree_only)
        data = await self._action("spider", "scan", params)
        scan_id = str(data.get("scan") or "")
        if not scan_id:
            raise ZapError("ZAP spider did not return scan id", "tooling")
        return scan_id

    async def wait_spider(self, scan_id: str) -> None:
        await self._wait_status("spider", scan_id)

    async def active_scan(
        self,
        *,
        url: Optional[str] = None,
        recurse: bool = True,
        in_scope_only: Optional[bool] = None,
        scan_policy_name: Optional[str] = None,
        method: Optional[str] = None,
        post_data: Optional[str] = None,
        context_id: Optional[str] = None,
    ) -> str:
        params: Dict[str, Any] = {"recurse": _bool(recurse)}
        if url:
            params["url"] = url
        if in_scope_only is not None:
            params["inScopeOnly"] = _bool(in_scope_only)
        if scan_policy_name:
            params["scanPolicyName"] = scan_policy_name
        if method:
            params["method"] = method
        if post_data is not None:
            params["postData"] = post_data
        if context_id:
            params["contextId"] = context_id

        data = await self._action("ascan", "scan", params)
        scan_id = str(data.get("scan") or "")
        if not scan_id:
            raise ZapError("ZAP active scan did not return scan id", "tooling")
        return scan_id

    async def wait_active(self, scan_id: str) -> None:
        await self._wait_status("ascan", scan_id)

    async def alerts(self, base_url: Optional[str] = None) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"count": "5000"}
        if base_url:
            params["baseurl"] = base_url
        data = await self._view("core", "alerts", params)
        alerts = data.get("alerts")
        if isinstance(alerts, list):
            return alerts
        return []

    async def create_context(self, name: str) -> str:
        data = await self._action("context", "newContext", {"contextName": name})
        context_id = str(data.get("contextId") or "")
        if not context_id:
            raise ZapError("ZAP context did not return context id", "tooling")
        return context_id

    async def include_in_context(self, name: str, regex: str) -> None:
        await self._action(
            "context", "includeInContext", {"contextName": name, "regex": regex}
        )

    async def remove_context(self, name: str) -> None:
        await self._action("context", "removeContext", {"contextName": name})

    async def add_header_rule(self, description: str, header: str, value: str) -> None:
        await self._action(
            "replacer",
            "addRule",
            {
                "description": description,
                "enabled": "true",
                "matchType": "REQ_HEADER",
                "matchRegex": "false",
                "matchString": header,
                "replacement": value,
            },
        )

    async def remove_header_rule(self, description: str) -> None:
        await self._action("replacer", "removeRule", {"description": description})

    async def _wait_status(self, component: str, scan_id: str) -> None:
        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            data = await self._view(component, "status", {"scanId": scan_id})
            raw = data.get("status")
            try:
                status = int(raw)
            except (TypeError, ValueError):
                status = 0
            if status >= 100:
                return
            await asyncio.sleep(2.0)
        raise ZapError(f"ZAP {component} scan timed out", "timeout")
