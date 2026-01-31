from __future__ import annotations

import asyncio
import logging
import shutil
import socket
import subprocess
import sys
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


def _normalize_scan_id(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return None if value < 0 else str(value)
    if isinstance(value, float):
        return None
    try:
        text = str(value).strip()
    except Exception:
        return None
    if not text:
        return None
    if not text.isdigit():
        return None
    return str(int(text))


def _ensure_scan_id(
    value: Any,
    *,
    context: str,
    response: Dict[str, Any],
) -> str:
    scan_id = _normalize_scan_id(value)
    if not scan_id:
        raise ZapError(
            "ZAP returned invalid scan id for "
            f"{context}: {value!r}. response={response}",
            "tooling",
        )
    return scan_id


def _validate_scan_id(scan_id: Any, *, context: str) -> str:
    normalized = _normalize_scan_id(scan_id)
    if not normalized:
        raise ZapError(
            f"Invalid scan id for {context}: {scan_id!r}",
            "tooling",
        )
    return normalized


def _extract_scan_id_value(response: Dict[str, Any]) -> Any:
    for key in ("scan", "scanId", "scanid", "scan_id"):
        if key in response:
            return response.get(key)
    return None


class ZapDockerSession:
    def __init__(
        self,
        image: str,
        api_key: Optional[str],
        timeout_seconds: int,
        request_timeout_seconds: Optional[int] = None,
        extra_hosts: Optional[list[str]] = None,
        base_url: Optional[str] = None,
        host_port: Optional[int] = None,
        keepalive_seconds: Optional[int] = None,
        host_header: Optional[str] = None,
    ) -> None:
        self.image = image
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.request_timeout_seconds = request_timeout_seconds or min(
            30, max(5, timeout_seconds // 6)
        )
        self.extra_hosts = extra_hosts or []
        self.base_url = base_url.strip() if base_url else None
        self.host_port = host_port
        self.keepalive_seconds = keepalive_seconds
        self.host_header = host_header.strip() if host_header else None
        self._managed_container = self.base_url is None
        self.container_id: Optional[str] = None
        self.container_name: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "ZapDockerSession":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        await self.stop()

    async def start(self) -> None:
        if not self._managed_container:
            headers: Dict[str, str] = {}
            if self.host_header:
                headers["Host"] = self.host_header
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.request_timeout_seconds,
                headers=headers or None,
            )
            logger.debug(
                "ZAP client configured: base_url=%s host_header=%s timeout=%s",
                self.base_url,
                self.host_header or "none",
                self.request_timeout_seconds,
            )
            try:
                await self._wait_ready()
            except Exception:
                await self.stop()
                raise
            return

        if not is_docker_available():
            raise ZapError("Docker is not available for running ZAP.", "tooling")

        port = self.host_port or _get_free_port()
        container_name = f"scanguard-zap-{uuid.uuid4().hex[:10]}"
        logger.debug("Starting ZAP container %s on host port %s", container_name, port)
        cmd = [
            "docker",
            "run",
            "-d",
            "--rm",
            "-p",
            f"{port}:8080",
            "--name",
            container_name,
        ]
        for host_entry in self.extra_hosts:
            if host_entry:
                cmd.extend(["--add-host", host_entry])
        if sys.platform.startswith("linux"):
            cmd.extend(["--add-host", "host.docker.internal:host-gateway"])
        cmd.extend(
            [
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
        )
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
        logger.debug(
            "ZAP container started: id=%s name=%s base_url=%s",
            self.container_id,
            self.container_name,
            self.base_url,
        )
        # Force Host header to match the ZAP daemon bind port inside the container.
        host_header = self.host_header or "127.0.0.1:8080"
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.request_timeout_seconds,
            headers={"Host": host_header},
        )
        logger.debug(
            "ZAP client configured: base_url=%s host_header=%s timeout=%s",
            self.base_url,
            host_header,
            self.request_timeout_seconds,
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
        if not self._managed_container:
            return
        if not self.container_id:
            return
        container_id = self.container_id
        container_name = self.container_name
        if self.keepalive_seconds and self.keepalive_seconds > 0:
            logger.info(
                "Keeping ZAP container %s alive for %ss (base_url=%s)",
                container_name or container_id,
                self.keepalive_seconds,
                self.base_url,
            )

            async def _delayed_stop() -> None:
                await asyncio.sleep(self.keepalive_seconds)
                logger.debug("Stopping ZAP container %s", container_id)
                await asyncio.to_thread(
                    subprocess.run,
                    ["docker", "stop", container_id],
                    capture_output=True,
                    text=True,
                    check=False,
                )

            try:
                asyncio.get_running_loop().create_task(_delayed_stop())
            except RuntimeError:
                await asyncio.to_thread(
                    subprocess.run,
                    ["docker", "stop", container_id],
                    capture_output=True,
                    text=True,
                    check=False,
                )
        else:
            logger.debug("Stopping ZAP container %s", container_id)
            await asyncio.to_thread(
                subprocess.run,
                ["docker", "stop", container_id],
                capture_output=True,
                text=True,
                check=False,
            )
        self.container_id = None
        self.container_name = None

    async def _wait_ready(self) -> None:
        deadline = time.monotonic() + self.timeout_seconds
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
        scan_id = _ensure_scan_id(
            _extract_scan_id_value(data),
            context=f"spider scan (url={url}, params={params})",
            response=data,
        )
        logger.debug("ZAP spider scan started: scan_id=%s url=%s", scan_id, url)
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
        scan_id = _ensure_scan_id(
            _extract_scan_id_value(data),
            context=f"active scan (url={url or 'n/a'}, params={params})",
            response=data,
        )
        logger.debug(
            "ZAP active scan started: scan_id=%s url=%s method=%s",
            scan_id,
            url or "",
            method or "",
        )
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
        scan_id = _validate_scan_id(scan_id, context=f"{component} status polling")
        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            data = await self._view(component, "status", {"scanId": scan_id})
            raw = data.get("status")
            try:
                status = int(raw)
            except (TypeError, ValueError):
                status = 0
            logger.debug(
                "ZAP %s status: scan_id=%s status=%s",
                component,
                scan_id,
                status,
            )
            if status >= 100:
                return
            await asyncio.sleep(2.0)
        raise ZapError(f"ZAP {component} scan timed out", "timeout")

    async def get_urls(self, base_url: Optional[str] = None) -> List[str]:
        """Get all URLs discovered by the spider.

        Args:
            base_url: Optional base URL to filter results.

        Returns:
            List of discovered URL strings.
        """
        params: Dict[str, Any] = {}
        if base_url:
            params["baseurl"] = base_url
        data = await self._view("core", "urls", params)
        urls = data.get("urls")
        if isinstance(urls, list):
            return [str(url) for url in urls]
        return []

    async def get_messages(
        self, base_url: Optional[str] = None, start: int = 0, count: int = 5000
    ) -> List[Dict[str, Any]]:
        """Get HTTP messages (requests/responses) from the history.

        Args:
            base_url: Optional base URL to filter results.
            start: Starting index.
            count: Number of messages to return.

        Returns:
            List of message dictionaries with request/response details.
        """
        params: Dict[str, Any] = {"start": str(start), "count": str(count)}
        if base_url:
            params["baseurl"] = base_url
        data = await self._view("core", "messages", params)
        messages = data.get("messages")
        if isinstance(messages, list):
            return messages
        return []

    async def get_params(self, site: str) -> List[Dict[str, Any]]:
        """Get all parameters found for a given site.

        Args:
            site: The site URL (e.g., http://host.docker.internal:8080).

        Returns:
            List of parameter dictionaries with name, type, and URL info.
        """
        params: Dict[str, Any] = {"site": site}
        data = await self._view("params", "params", params)
        parameters = data.get("Parameters")
        if isinstance(parameters, list):
            return parameters
        return []
