"""
Route Parser - Extract actual API endpoints from code.

Instead of relying on heuristics to map file paths to endpoints,
this module parses actual route definitions from common frameworks.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class RouteParser:
    """Extract actual API endpoints from code."""

    def parse_routes(self, repo_path: Path) -> Dict[str, List[str]]:
        """
        Parse routes from repository.

        Returns: {file_path: [list of endpoints]}
        """
        routes: Dict[str, List[str]] = {}

        try:
            repo_path = Path(repo_path)

            # Parse Python files
            for py_file in repo_path.rglob("*.py"):
                try:
                    endpoints = self._parse_python_routes(py_file)
                    if endpoints:
                        rel_path = str(py_file.relative_to(repo_path))
                        routes[rel_path] = endpoints
                except Exception as e:
                    logger.debug(f"Failed to parse {py_file}: {e}")

            # Parse JavaScript files
            for js_file in repo_path.rglob("*.js"):
                try:
                    endpoints = self._parse_js_routes(js_file)
                    if endpoints:
                        rel_path = str(js_file.relative_to(repo_path))
                        routes[rel_path] = endpoints
                except Exception as e:
                    logger.debug(f"Failed to parse {js_file}: {e}")

            # Parse TypeScript files
            for ts_file in repo_path.rglob("*.ts"):
                try:
                    endpoints = self._parse_js_routes(ts_file)
                    if endpoints:
                        rel_path = str(ts_file.relative_to(repo_path))
                        routes[rel_path] = endpoints
                except Exception as e:
                    logger.debug(f"Failed to parse {ts_file}: {e}")

            # Parse Go files
            for go_file in repo_path.rglob("*.go"):
                try:
                    endpoints = self._parse_go_routes(go_file)
                    if endpoints:
                        rel_path = str(go_file.relative_to(repo_path))
                        routes[rel_path] = endpoints
                except Exception as e:
                    logger.debug(f"Failed to parse {go_file}: {e}")

            # Parse Java files
            for java_file in repo_path.rglob("*.java"):
                try:
                    endpoints = self._parse_java_routes(java_file)
                    if endpoints:
                        rel_path = str(java_file.relative_to(repo_path))
                        routes[rel_path] = endpoints
                except Exception as e:
                    logger.debug(f"Failed to parse {java_file}: {e}")

            logger.info(f"Parsed routes from {len(routes)} files")

        except Exception as e:
            logger.warning(f"Route parsing failed: {e}")

        return routes

    def _parse_python_routes(self, file_path: Path) -> List[str]:
        """Parse Flask/FastAPI/Django routes from Python file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        endpoints = []

        # Flask: @app.route("/path") or @blueprint.route("/path")
        flask_pattern = r'@(?:\w+)\.route\(\s*["\']([^"\']+)["\']'
        endpoints.extend(re.findall(flask_pattern, content))

        # FastAPI: @app.get("/path"), @app.post("/path"), etc.
        fastapi_pattern = r"@(?:\w+)\.(?:get|post|put|delete|patch|options|head)\(\s*[\"']([^\"']+)[\"']"
        endpoints.extend(re.findall(fastapi_pattern, content))

        # FastAPI router: @router.get("/path")
        router_pattern = r"@router\.(?:get|post|put|delete|patch)\(\s*[\"']([^\"']+)[\"']"
        endpoints.extend(re.findall(router_pattern, content))

        # Django: path("path/", view) or url(r"^path/$", view)
        django_path_pattern = r'path\(\s*["\']([^"\']+)["\']'
        endpoints.extend(re.findall(django_path_pattern, content))

        django_url_pattern = r'url\(\s*r?["\']?\^?([^"\'$]+)'
        for match in re.findall(django_url_pattern, content):
            # Clean up regex patterns
            clean = re.sub(r"[\^$]", "", match)
            clean = re.sub(r"\(\?P<\w+>[^)]+\)", ":param", clean)
            if clean:
                endpoints.append("/" + clean.strip("/"))

        # Django REST Framework: @action decorator
        drf_action_pattern = r'@action\([^)]*detail\s*=\s*(True|False)[^)]*\)'
        # Note: DRF actions are harder to extract without the full context

        return list(set(e for e in endpoints if e and not e.startswith("{")))

    def _parse_js_routes(self, file_path: Path) -> List[str]:
        """Parse Express/Next.js/Koa routes from JavaScript/TypeScript file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        endpoints = []

        # Express: router.get("/path", ...), app.post("/path", ...)
        express_pattern = (
            r'(?:router|app|server)\.(?:get|post|put|delete|patch|all)\(\s*["\']([^"\']+)["\']'
        )
        endpoints.extend(re.findall(express_pattern, content))

        # Express Router: Router().get("/path")
        router_pattern = r'Router\(\)\.(?:get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']'
        endpoints.extend(re.findall(router_pattern, content))

        # Next.js API routes: file path based
        file_str = str(file_path)
        if "/pages/api/" in file_str or "/app/api/" in file_str:
            # Convert file path to route
            if "/pages/api/" in file_str:
                route_part = file_str.split("/pages/api/")[-1]
            else:
                route_part = file_str.split("/app/api/")[-1]

            # Remove extensions
            route_part = re.sub(r"\.(js|ts|jsx|tsx)$", "", route_part)
            # Handle route.js in app directory
            route_part = re.sub(r"/route$", "", route_part)
            # Convert [id] to :id
            route_part = re.sub(r"\[(\w+)\]", r":\1", route_part)
            # Handle index files
            route_part = re.sub(r"/index$", "", route_part)

            if route_part:
                endpoints.append(f"/api/{route_part}")

        # Hono/Fastify patterns similar to Express
        hono_pattern = r'\.(?:get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']'
        endpoints.extend(re.findall(hono_pattern, content))

        return list(set(e for e in endpoints if e and not e.startswith("{")))

    def _parse_go_routes(self, file_path: Path) -> List[str]:
        """Parse Go HTTP routes (net/http, gin, echo, chi)."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        endpoints = []

        # net/http: http.HandleFunc("/path", handler)
        net_http_pattern = r'(?:http\.)?HandleFunc\(\s*["`]([^"`]+)["`]'
        endpoints.extend(re.findall(net_http_pattern, content))

        # Gin: r.GET("/path", handler)
        gin_pattern = r'\.(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\(\s*["`]([^"`]+)["`]'
        endpoints.extend(re.findall(gin_pattern, content))

        # Echo: e.GET("/path", handler)
        echo_pattern = r'\.(?:GET|POST|PUT|DELETE|PATCH)\(\s*["`]([^"`]+)["`]'
        endpoints.extend(re.findall(echo_pattern, content))

        # Chi: r.Get("/path", handler)
        chi_pattern = r'\.(?:Get|Post|Put|Delete|Patch)\(\s*["`]([^"`]+)["`]'
        endpoints.extend(re.findall(chi_pattern, content))

        return list(set(e for e in endpoints if e and not e.startswith("{")))

    def _parse_java_routes(self, file_path: Path) -> List[str]:
        """Parse Spring Boot routes from Java file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        endpoints = []

        # Spring: @RequestMapping("/path")
        request_mapping_pattern = r'@RequestMapping\([^)]*(?:value\s*=\s*)?["\']([^"\']+)["\']'
        endpoints.extend(re.findall(request_mapping_pattern, content))

        # Spring: @GetMapping("/path"), @PostMapping("/path"), etc.
        method_mapping_pattern = (
            r"@(?:Get|Post|Put|Delete|Patch)Mapping\(\s*[\"']([^\"']+)[\"']"
        )
        endpoints.extend(re.findall(method_mapping_pattern, content))

        # Spring: @GetMapping(value = "/path")
        method_mapping_value_pattern = (
            r"@(?:Get|Post|Put|Delete|Patch)Mapping\([^)]*value\s*=\s*[\"']([^\"']+)[\"']"
        )
        endpoints.extend(re.findall(method_mapping_value_pattern, content))

        return list(set(e for e in endpoints if e and not e.startswith("{")))

    def find_endpoint_for_file(
        self, file_path: str, all_routes: Dict[str, List[str]]
    ) -> Tuple[Optional[str], float]:
        """
        Find the best matching endpoint for a file.

        Returns: (endpoint, confidence)
        """
        # Direct match
        if file_path in all_routes and all_routes[file_path]:
            return all_routes[file_path][0], 0.95

        # Normalize the file path
        normalized = file_path.replace("\\", "/").lstrip("/")

        # Try normalized path
        if normalized in all_routes and all_routes[normalized]:
            return all_routes[normalized][0], 0.95

        # Fuzzy match - find file with similar name
        filename = Path(file_path).stem.lower()
        for route_file, endpoints in all_routes.items():
            route_filename = Path(route_file).stem.lower()
            if filename == route_filename and endpoints:
                return endpoints[0], 0.85

        # Check if filename is in route file path
        for route_file, endpoints in all_routes.items():
            if filename in route_file.lower() and endpoints:
                return endpoints[0], 0.70

        return None, 0.0
