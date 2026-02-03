from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .route_parser import RouteParser
from .types import TriagedFinding
from .zap_parser import classify_vulnerability


class SASTMetadataExtractor:
    """Extract endpoint/method/parameter metadata from SAST findings."""

    def __init__(self) -> None:
        self._route_parser = RouteParser()
        self._cached_repo: Optional[Path] = None
        self._cached_routes: Dict[str, List[str]] = {}

    def enrich_findings(
        self, findings: List[TriagedFinding], repo_path: Path
    ) -> None:
        route_map = self._get_route_map(repo_path)
        for finding in findings:
            self._enrich_finding(finding, repo_path, route_map)

    def _get_route_map(self, repo_path: Path) -> Dict[str, List[str]]:
        if self._cached_repo != repo_path:
            self._cached_repo = repo_path
            self._cached_routes = self._route_parser.parse_routes(repo_path)
        return self._cached_routes

    def _enrich_finding(
        self,
        finding: TriagedFinding,
        repo_path: Path,
        route_map: Dict[str, List[str]],
    ) -> None:
        if not finding.sast_vuln_type:
            finding.sast_vuln_type = classify_vulnerability(
                f"{finding.rule_id} {finding.rule_message or ''}",
                rule_id=finding.rule_id,
            )

        combined = f"{finding.code_snippet or ''}\n{finding.context_snippet or ''}"

        endpoint, method = self._extract_route_from_context(
            finding.context_snippet or ""
        )
        if not endpoint:
            endpoint, method = self._extract_route_from_file(
                repo_path, finding.file_path
            )
        if not endpoint:
            endpoint, _confidence = self._resolve_endpoint(
                finding.file_path, repo_path, route_map
            )

        if endpoint and not finding.sast_endpoint:
            finding.sast_endpoint = endpoint
        if method and not finding.sast_http_method:
            finding.sast_http_method = method
        if not finding.sast_http_method:
            finding.sast_http_method = self._detect_http_method(combined)

        if not finding.sast_parameter:
            param = self._extract_parameter(combined)
            if not param and endpoint:
                param = self._param_from_route(endpoint)
            finding.sast_parameter = param or "id"

    def _extract_route_from_context(
        self, snippet: str
    ) -> Tuple[Optional[str], Optional[str]]:
        if not snippet:
            return None, None

        patterns = [
            # Flask/FastAPI decorators: @app.get("/path")
            (
                re.compile(
                    r"@(?:\w+)\.(get|post|put|delete|patch|options|head)\(\s*['\"]([^'\"]+)['\"]",
                    re.IGNORECASE,
                ),
                True,
            ),
            # Flask: @app.route("/path", methods=["POST", "GET"])
            (
                re.compile(
                    r"@(?:\w+)\.route\(\s*['\"]([^'\"]+)['\"](?:[^)]*methods\s*=\s*\[([^\]]+)\])?",
                    re.IGNORECASE,
                ),
                False,
            ),
            # Express/Koa: router.post("/path")
            (
                re.compile(
                    r"(?:router|app|server)\.(get|post|put|delete|patch|all)\(\s*['\"]([^'\"]+)['\"]",
                    re.IGNORECASE,
                ),
                True,
            ),
            # Express Router(): Router().get("/path")
            (
                re.compile(
                    r"Router\(\)\.(get|post|put|delete|patch|all)\(\s*['\"]([^'\"]+)['\"]",
                    re.IGNORECASE,
                ),
                True,
            ),
            # Go routers: r.GET("/path")
            (
                re.compile(
                    r"\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\(\s*['\"`]([^'\"`]+)['\"`]",
                    re.IGNORECASE,
                ),
                True,
            ),
            # Spring Boot: @GetMapping("/path")
            (
                re.compile(
                    r"@(?:Get|Post|Put|Delete|Patch)Mapping\(\s*['\"]([^'\"]+)['\"]",
                    re.IGNORECASE,
                ),
                False,
            ),
            # Spring Boot: @RequestMapping(value="/path", method=RequestMethod.POST)
            (
                re.compile(
                    r"@RequestMapping\([^)]*?(?:value\s*=\s*)?['\"]([^'\"]+)['\"][^)]*?(?:method\s*=\s*RequestMethod\.([A-Z]+))?",
                    re.IGNORECASE,
                ),
                False,
            ),
        ]

        for pattern, has_method_first in patterns:
            match = pattern.search(snippet)
            if not match:
                continue

            if has_method_first:
                method = match.group(1)
                path = match.group(2)
            else:
                path = match.group(1)
                method = match.group(2) if match.lastindex and match.lastindex >= 2 else None

            if not path:
                continue

            endpoint = self._normalize_endpoint(path)
            method = self._normalize_method(method)
            return endpoint, method

        return None, None

    def _extract_route_from_file(
        self, repo_path: Path, file_path: str
    ) -> Tuple[Optional[str], Optional[str]]:
        if not repo_path or not file_path:
            return None, None
        try:
            content = (repo_path / file_path).read_text(errors="ignore")
        except OSError:
            return None, None
        return self._extract_route_from_context(content)

    def _resolve_endpoint(
        self,
        file_path: str,
        repo_path: Path,
        route_map: Dict[str, List[str]],
    ) -> Tuple[Optional[str], float]:
        rel_path = file_path
        if repo_path:
            rel_path = file_path.replace(str(repo_path), "").lstrip("/\\")

        endpoint, confidence = self._route_parser.find_endpoint_for_file(
            rel_path, route_map
        )
        if endpoint:
            return self._normalize_endpoint(endpoint), confidence

        endpoint = self._map_file_to_endpoint(rel_path)
        return self._normalize_endpoint(endpoint), 0.35

    def _map_file_to_endpoint(self, rel_path: str) -> str:
        patterns = [
            (r"api/routes?/(.+?)\.py$", r"/api/\1"),
            (r"routes?/(.+?)\.py$", r"/\1"),
            (r"routes?/(.+?)\.js$", r"/\1"),
            (r"routes?/(.+?)\.ts$", r"/\1"),
            (r"controllers?/(.+?)Controller\.java$", r"/\1"),
            (r"controllers?/(.+?)Controller\.py$", r"/\1"),
            (r"handlers?/(.+?)_handler\.go$", r"/\1"),
            (r"handlers?/(.+?)Handler\.java$", r"/\1"),
            (r"views?/(.+?)\.py$", r"/\1"),
            (r"pages?/api/(.+?)\.(ts|js)x?$", r"/api/\1"),
            (r"app/(.+?)/route\.(ts|js)$", r"/\1"),
        ]

        for pattern, replacement in patterns:
            match = re.search(pattern, rel_path, re.IGNORECASE)
            if match:
                endpoint = re.sub(pattern, replacement, rel_path, flags=re.IGNORECASE)
                endpoint = endpoint.lower()
                endpoint = re.sub(r"_", "-", endpoint)
                endpoint = re.sub(r"\[(\w+)\]", r":\1", endpoint)
                return endpoint

        filename = rel_path.split("/")[-1].rsplit(".", 1)[0]
        for suffix in [
            "_controller",
            "controller",
            "_handler",
            "handler",
            "_view",
            "view",
        ]:
            if filename.lower().endswith(suffix):
                filename = filename[: -len(suffix)]
                break

        return f"/{filename.lower().replace('_', '-')}"

    def _detect_http_method(self, code: str) -> str:
        combined = (code or "").lower()
        method_indicators = [
            (["post", "create", "insert", "add"], "POST"),
            (["put", "update", "modify", "edit"], "PUT"),
            (["delete", "remove", "destroy"], "DELETE"),
            (["patch"], "PATCH"),
        ]
        for indicators, method in method_indicators:
            if any(indicator in combined for indicator in indicators):
                return method
        return "GET"

    def _extract_parameter(self, code: str) -> Optional[str]:
        patterns = [
            r"request\.args\.get\(['\"](\w+)['\"]",
            r"request\.form\.get\(['\"](\w+)['\"]",
            r"request\.values\.get\(['\"](\w+)['\"]",
            r"request\.json\.get\(['\"](\w+)['\"]",
            r"request\.GET\.get\(['\"](\w+)['\"]",
            r"request\.POST\.get\(['\"](\w+)['\"]",
            r"request\.data\.get\(['\"](\w+)['\"]",
            r"req\.query\.(\w+)",
            r"req\.body\.(\w+)",
            r"req\.params\.(\w+)",
            r"req\.query\[['\"](\w+)['\"]\]",
            r"req\.body\[['\"](\w+)['\"]\]",
            r"params\[:['\"]?(\w+)",
            r'@RequestParam.*?["\'](\w+)["\']',
            r'@PathVariable.*?["\'](\w+)["\']',
            r"(\w+):\s*(?:str|int|float|bool)\s*=\s*Query",
            r"(\w+):\s*(?:str|int|float|bool)\s*=\s*Body",
            r"(\w+):\s*(?:str|int|float|bool)\s*=\s*Path",
            r"getParameter\(['\"](\w+)['\"]",
        ]

        for pattern in patterns:
            match = re.search(pattern, code, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _param_from_route(self, endpoint: str) -> Optional[str]:
        if not endpoint:
            return None
        # Express style :id
        match = re.search(r":([A-Za-z_][A-Za-z0-9_]*)", endpoint)
        if match:
            return match.group(1)
        # Flask/Java style <int:id> or {id}
        match = re.search(r"<[^:>]*:?([A-Za-z_][A-Za-z0-9_]*)>", endpoint)
        if match:
            return match.group(1)
        match = re.search(r"{([A-Za-z_][A-Za-z0-9_]*)}", endpoint)
        if match:
            return match.group(1)
        return None

    def _normalize_endpoint(self, endpoint: str) -> str:
        if not endpoint:
            return endpoint
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            return endpoint
        if not endpoint.startswith("/"):
            return f"/{endpoint}"
        return endpoint

    def _normalize_method(self, method: Optional[str]) -> Optional[str]:
        if not method:
            return None
        return method.strip().upper()
