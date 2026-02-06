"""
Targeted DAST Runner - Attacks specific SAST findings with OWASP ZAP.

Instead of blindly scanning the entire app, this runner:
1. Maps SAST findings to likely endpoints/parameters
2. Runs focused ZAP spider + active scan for that endpoint
3. Confirms exploitability when matching ZAP alerts are produced
"""

from __future__ import annotations

import asyncio
import logging
import re
import shlex
import uuid
from pathlib import Path
from typing import Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from ...config import get_settings
from .commit_verifier import CommitVerifier
from .dast_base import AttackFindingsList, BaseDASTRunner
from .route_parser import RouteParser
from .types import DASTAttackConfig, DASTAttackResult, DiscoveredEndpoint, TriagedFinding
from .zap_client import ZapDockerSession, ZapError, is_docker_available
from .zap_parser import (
    VULN_KEYWORDS,
    alert_matches_vuln_type,
    classify_vulnerability,
    parse_zap_alert,
)
from .zap_utils import dockerize_target_url, rewrite_finding_for_display

logger = logging.getLogger(__name__)


def _extract_status_code(response_header: str) -> Optional[int]:
    if not response_header:
        return None
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", response_header)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


class TargetedDASTRunner(BaseDASTRunner):
    """
    Executes focused ZAP active scans based on SAST findings.
    """

    def __init__(
        self,
        timeout: int = 120,
        auth_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.timeout = timeout
        self.settings = get_settings()
        self.last_error: str | None = None
        effective_headers = auth_headers
        if not effective_headers and self.settings.dast_default_auth_header:
            effective_headers = _parse_default_auth_header(
                self.settings.dast_default_auth_header
            )
        self.auth_headers = self._normalize_headers(effective_headers)
        self.cookies = cookies
        self.route_parser = RouteParser()
        self.commit_verifier = CommitVerifier()
        self.attack_findings = AttackFindingsList(call=self._attack_findings_impl)

    def _normalize_headers(
        self, headers: Optional[Dict[str, str]]
    ) -> Dict[str, str]:
        if not headers:
            return {}
        normalized: Dict[str, str] = {}
        for key, value in headers.items():
            if key is None:
                continue
            header_key = str(key).strip()
            if not header_key:
                continue
            normalized[header_key] = "" if value is None else str(value)
        return normalized

    def is_available(self) -> bool:
        """Check if Docker is installed (required for ZAP container)."""
        if self.settings.zap_base_url:
            return True
        return is_docker_available()

    def _build_route_map(self, repo_path: str) -> Dict[str, List[str]]:
        if not repo_path:
            return {}
        path = Path(repo_path)
        if not path.exists():
            return {}
        return self.route_parser.parse_routes(path)

    async def _spider_discover_routes(
        self,
        zap: ZapDockerSession,
        target_base_url: str,
    ) -> List[DiscoveredEndpoint]:
        """
        Spider the target URL to discover all available endpoints.

        Args:
            zap: Active ZAP session.
            target_base_url: Base URL to spider (e.g., http://host:8080/WebGoat).

        Returns:
            List of discovered endpoints with URLs, methods, and parameters.
        """
        logger.info("Spidering target to discover routes: %s", target_base_url)

        try:
            # Run spider with reasonable depth
            spider_id = await zap.spider_scan(
                target_base_url,
                max_children=self.settings.zap_max_depth,
                recurse=True,
                subtree_only=False,
            )
            await zap.wait_spider(spider_id)
        except ZapError as exc:
            logger.warning("Spider discovery failed: %s", exc)
            return []

        # Get all discovered URLs
        try:
            discovered_urls = await zap.get_urls(base_url=_base_url(target_base_url))
        except ZapError as exc:
            logger.warning("Failed to get discovered URLs: %s", exc)
            return []

        if not discovered_urls:
            logger.warning("Spider found no URLs at %s", target_base_url)
            return []

        logger.info("Spider discovered %d URLs", len(discovered_urls))

        # Get parameters for the target site
        site_url = _base_url(target_base_url)
        try:
            params_data = await zap.get_params(site_url)
        except ZapError:
            params_data = []

        # Build a map of URL -> parameters
        url_params: Dict[str, Dict[str, List[str]]] = {}
        for param in params_data:
            param_url = str(param.get("url") or "")
            param_name = str(param.get("name") or "")
            param_type = str(param.get("type") or "").lower()

            if not param_url or not param_name:
                continue

            if param_url not in url_params:
                url_params[param_url] = {"query": [], "form": []}

            if param_type in ("url", "query", "get"):
                url_params[param_url]["query"].append(param_name)
            elif param_type in ("form", "post", "body"):
                url_params[param_url]["form"].append(param_name)
            else:
                # Default to query param
                url_params[param_url]["query"].append(param_name)

        # Get HTTP messages to determine methods and extract more info
        try:
            messages = await zap.get_messages(base_url=site_url, count=5000)
        except ZapError:
            messages = []

        status_by_url: Dict[str, List[int]] = {}
        status_by_path: Dict[str, List[int]] = {}

        for msg in messages:
            msg_url = str(msg.get("url") or "")
            if not msg_url:
                continue
            status_code = _extract_status_code(str(msg.get("responseHeader") or ""))
            if status_code is None:
                continue
            status_by_url.setdefault(msg_url, []).append(status_code)
            msg_path = urlparse(msg_url).path or "/"
            status_by_path.setdefault(msg_path, []).append(status_code)

        # Build method map from messages
        url_methods: Dict[str, str] = {}
        for msg in messages:
            req_header = str(msg.get("requestHeader") or "")
            if req_header:
                parts = req_header.split(" ", 2)
                if len(parts) >= 2:
                    method = parts[0].upper()
                    msg_url = str(msg.get("url") or "")
                    if msg_url:
                        url_methods[msg_url] = method

        # Convert to DiscoveredEndpoint objects
        endpoints: List[DiscoveredEndpoint] = []
        seen_paths: set = set()

        for url in discovered_urls:
            parsed = urlparse(url)
            path = parsed.path or "/"

            # Deduplicate by path (we might get same path with different query params)
            if path in seen_paths:
                # Update existing endpoint with additional params if found
                for ep in endpoints:
                    if ep.path == path:
                        params_info = url_params.get(url, {"query": [], "form": []})
                        for qp in params_info["query"]:
                            if qp not in ep.query_params:
                                ep.query_params.append(qp)
                        for fp in params_info["form"]:
                            if fp not in ep.form_params:
                                ep.form_params.append(fp)
                        break
                continue

            seen_paths.add(path)

            # Extract query params from URL
            query_params: List[str] = []
            if parsed.query:
                for pair in parsed.query.split("&"):
                    if "=" in pair:
                        param_name = pair.split("=", 1)[0]
                        if param_name and param_name not in query_params:
                            query_params.append(param_name)

            # Add params from ZAP's param discovery
            params_info = url_params.get(url, {"query": [], "form": []})
            for qp in params_info["query"]:
                if qp not in query_params:
                    query_params.append(qp)

            form_params = params_info["form"]
            status_codes = list(
                {
                    *status_by_url.get(url, []),
                    *status_by_path.get(path, []),
                }
            )
            status_codes.sort()

            # Extract path segments that look like IDs or dynamic values
            path_segments = self._extract_dynamic_segments(path)

            # Determine HTTP method (default to GET)
            method = url_methods.get(url, "GET")

            endpoints.append(
                DiscoveredEndpoint(
                    url=url,
                    path=path,
                    method=method,
                    query_params=query_params,
                    form_params=form_params,
                    path_segments=path_segments,
                    status_codes=status_codes,
                )
            )

        logger.info(
            "Discovered %d unique endpoints with %d total parameters",
            len(endpoints),
            sum(len(ep.query_params) + len(ep.form_params) for ep in endpoints),
        )

        return endpoints

    def _extract_dynamic_segments(self, path: str) -> List[str]:
        """Extract path segments that look like dynamic values (IDs, numbers, etc.)."""
        segments: List[str] = []
        parts = path.strip("/").split("/")

        for part in parts:
            # Check for numeric IDs
            if re.match(r"^\d+$", part):
                segments.append(part)
            # Check for UUIDs
            elif re.match(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                part,
                re.IGNORECASE,
            ):
                segments.append(part)
            # Check for alphanumeric IDs (e.g., attack9, lesson5)
            elif re.match(r"^[a-zA-Z]+\d+$", part):
                segments.append(part)

        return segments

    def _fuzzy_match_finding_to_endpoint(
        self,
        finding: TriagedFinding,
        discovered_endpoints: List[DiscoveredEndpoint],
    ) -> Tuple[Optional[DiscoveredEndpoint], float]:
        """
        Match a SAST finding to a discovered endpoint.

        Scoring factors:
        - Vuln type keyword in URL path (e.g., "sql" in path for SQLi finding): +0.3
        - Numeric ID match (e.g., "Lesson9" matches "/attack9"): +0.2
        - Parameter name match (e.g., "account" param in both): +0.3
        - Class/file name fragment match: +0.2

        Returns:
            Tuple of (best matching endpoint or None, confidence score).
            Returns None if score < 0.4.
        """
        if not discovered_endpoints:
            return None, 0.0

        # Extract info from the finding
        rule_id = finding.rule_id.lower()
        rule_message = (finding.rule_message or "").lower()
        file_path = finding.file_path.lower()
        code_snippet = (finding.code_snippet or "").lower()
        context_snippet = (finding.context_snippet or "").lower()
        combined_code = f"{code_snippet} {context_snippet}"

        # Determine vulnerability type
        vuln_type = classify_vulnerability(
            f"{rule_id} {rule_message}", rule_id=finding.rule_id
        )

        # Extract file name without extension
        file_name = Path(finding.file_path).stem.lower()

        # Extract numbers from file name (e.g., "SqlInjectionLesson9" -> ["9"])
        file_numbers = re.findall(r"\d+", file_name)

        # Extract parameter names from code
        finding_params = self._extract_params_from_code(combined_code)

        # Extract class/function name fragments
        class_name = (finding.class_name or "").lower()
        function_name = (finding.function_name or "").lower()
        name_fragments = set()
        if class_name:
            # Split camelCase/PascalCase into words
            name_fragments.update(re.findall(r"[a-z]+", class_name))
        if function_name:
            name_fragments.update(re.findall(r"[a-z]+", function_name))

        best_match: Optional[DiscoveredEndpoint] = None
        best_score = 0.0

        for endpoint in discovered_endpoints:
            score = 0.0
            path_lower = endpoint.path.lower()

            # 1. Vuln type keyword in URL path (+0.3)
            if vuln_type:
                vuln_keywords = VULN_KEYWORDS.get(vuln_type, [])
                # Check for vuln-related keywords in the path
                for keyword in vuln_keywords:
                    # Remove spaces and check
                    keyword_simple = keyword.replace(" ", "").replace("-", "")
                    if keyword_simple in path_lower.replace("-", "").replace("/", ""):
                        score += 0.3
                        break
                # Also check for common shortened versions
                vuln_short = vuln_type.replace("-", "")
                if vuln_short in path_lower.replace("-", ""):
                    score += 0.3

            # 2. Numeric ID match (+0.2)
            if file_numbers:
                # Extract numbers from path segments
                for segment in endpoint.path_segments:
                    segment_numbers = re.findall(r"\d+", segment)
                    if any(n in file_numbers for n in segment_numbers):
                        score += 0.2
                        break
                # Also check the full path for matching numbers
                path_numbers = re.findall(r"\d+", path_lower)
                if any(n in file_numbers for n in path_numbers):
                    score += 0.1  # Lower weight for general path number match

            # 3. Parameter name match (+0.3)
            all_endpoint_params = set(
                p.lower() for p in endpoint.query_params + endpoint.form_params
            )
            if finding_params and all_endpoint_params:
                matching_params = finding_params & all_endpoint_params
                if matching_params:
                    # Full score if key param matches
                    score += 0.3
                    logger.debug(
                        "Parameter match: %s in endpoint %s",
                        matching_params,
                        endpoint.path,
                    )

            # 4. Class/file name fragment match (+0.2)
            if name_fragments:
                path_words = set(re.findall(r"[a-z]+", path_lower))
                matching_fragments = name_fragments & path_words
                if matching_fragments:
                    score += 0.2

            # Also check file name fragments against path
            file_name_words = set(re.findall(r"[a-z]+", file_name))
            path_words = set(re.findall(r"[a-z]+", path_lower))
            if file_name_words & path_words:
                score += 0.1

            if score > best_score:
                best_score = score
                best_match = endpoint

        # Only return a match if confidence is >= 0.4
        if best_score >= 0.4 and best_match:
            logger.info(
                "Fuzzy matched finding '%s' to endpoint '%s' (score: %.2f)",
                finding.file_path,
                best_match.path,
                best_score,
            )
            return best_match, best_score

        logger.debug(
            "No confident match for finding '%s' (best score: %.2f)",
            finding.file_path,
            best_score,
        )
        return None, best_score

    def _extract_params_from_code(self, code: str) -> set:
        """Extract parameter names from code snippets."""
        params: set = set()

        patterns = [
            r"request\.args\.get\(['\"](\w+)['\"]",
            r"request\.form\.get\(['\"](\w+)['\"]",
            r"request\.values\.get\(['\"](\w+)['\"]",
            r"request\.json\.get\(['\"](\w+)['\"]",
            r"request\.GET\.get\(['\"](\w+)['\"]",
            r"request\.POST\.get\(['\"](\w+)['\"]",
            r"request\.data\.get\(['\"](\w+)['\"]",
            r'request\.getParameter\(["\'](\w+)["\']',
            r"req\.query\.(\w+)",
            r"req\.body\.(\w+)",
            r"req\.params\.(\w+)",
            r"params\[:['\"]?(\w+)",
            r'@RequestParam.*?["\'](\w+)["\']',
            r'@PathVariable.*?["\'](\w+)["\']',
            r'get\(["\'](\w+)["\']',
            r'getParameter\(["\'](\w+)["\']',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, code, re.IGNORECASE)
            params.update(m.lower() for m in matches)

        return params

    def _resolve_endpoint(
        self,
        file_path: str,
        repo_path: str,
        route_map: Optional[Dict[str, List[str]]],
    ) -> Tuple[str, float]:
        rel_path = file_path
        if repo_path:
            rel_path = file_path.replace(repo_path, "").lstrip("/\\")

        if route_map:
            endpoint, confidence = self.route_parser.find_endpoint_for_file(
                rel_path, route_map
            )
            if endpoint:
                return endpoint, confidence

        endpoint = self._map_file_to_endpoint(file_path, repo_path)
        return endpoint, 0.35

    async def _attack_findings_impl(
        self,
        target_base_url: str,
        sast_findings: List[TriagedFinding],
        repo_path: str,
        commit_sha: Optional[str] = None,
        scan_id: Optional[uuid.UUID] = None,
        progress_cb: Optional[Callable[[str, Optional[str]], Awaitable[None]]] = None,
        progress_every: int = 5,
    ) -> List[DASTAttackResult]:
        """
        Attack each SAST finding to confirm exploitability.

        Args:
            target_base_url: Live app URL (e.g., https://app.example.com)
            sast_findings: Vulnerabilities found by SAST (AI triage is metadata only)
            repo_path: Path to cloned repo (to map findings to endpoints)
            commit_sha: Expected commit SHA for verification (optional)
            scan_id: Scan ID for updating verification status (optional)

        Returns:
            List of DAST results showing which findings are exploitable
        """
        self.last_error = None

        async def _progress(phase: str, message: Optional[str] = None) -> None:
            if not progress_cb:
                return
            try:
                await progress_cb(phase, message)
            except Exception as exc:  # pragma: no cover - best-effort
                logger.debug("DAST progress callback failed: %s", exc)

        # Verify deployment matches scanned commit if SHA provided
        if commit_sha and scan_id:
            should_verify = True

            # Skip verification if pipeline already set a scan-level status.
            try:
                from ...db.session import SessionLocal
                from ...models import Scan

                db = SessionLocal()
                try:
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    final_statuses = {"verified", "commit_mismatch", "verification_error"}
                    if scan and scan.dast_verification_status in final_statuses:
                        should_verify = False
                        logger.info(
                            "Skipping deployment verification for scan %s (status already %s)",
                            scan_id,
                            scan.dast_verification_status,
                        )
                finally:
                    db.close()
            except Exception as e:
                logger.error("Failed to read verification status: %s", e)

            if should_verify:
                try:
                    verification_status, message = await self.commit_verifier.verify_deployment(
                        target_base_url, commit_sha
                    )
                except Exception as e:
                    verification_status, message = "verification_error", f"Verification failed: {e}"

                # Best-effort: persist status (pipeline should normally do this first)
                try:
                    from ...db.session import SessionLocal
                    from ...models import Scan

                    db = SessionLocal()
                    try:
                        scan = db.query(Scan).filter(Scan.id == scan_id).first()
                        if scan:
                            scan.dast_verification_status = verification_status
                            db.commit()
                            logger.info(
                                "Scan %s verification: %s - %s",
                                scan_id,
                                verification_status,
                                message,
                            )
                    finally:
                        db.close()
                except Exception as e:
                    logger.error("Failed to update verification status: %s", e)

                if verification_status == "commit_mismatch":
                    logger.error("⚠️ DAST running against mismatched deployment! %s", message)
                elif verification_status == "verification_error":
                    logger.warning("⚠️ Could not verify deployment: %s", message)

        # DAST is the judge: attack all SAST findings regardless of AI opinion.
        valid_findings = list(sast_findings)
        if not valid_findings:
            logger.info("No SAST findings to verify")
            return []

        if not self.is_available():
            self.last_error = "Docker is not available for running ZAP."
            return [
                DASTAttackResult(
                    finding_id=f"{f.rule_id}:{f.file_path}:{f.line_start}",
                    attack_succeeded=False,
                    confidence=0.0,
                    verification_status="error_tooling",
                    proof_of_exploit=None,
                    evidence=[],
                    error=self.last_error,
                    is_reachable=None,
                )
                for f in valid_findings
            ]

        effective_base_url, original_netloc, docker_netloc = dockerize_target_url(
            target_base_url
        )
        timeout_seconds = min(self.settings.zap_timeout_seconds, self.timeout)
        route_map = self._build_route_map(repo_path)

        attack_configs: List[DASTAttackConfig] = []
        missing_configs: List[DASTAttackResult] = []
        try:
            async with ZapDockerSession(
                image=self.settings.zap_docker_image,
                api_key=self.settings.zap_api_key,
                timeout_seconds=timeout_seconds,
                request_timeout_seconds=self.settings.zap_request_timeout_seconds,
                extra_hosts=_parse_extra_hosts(self.settings.zap_docker_extra_hosts),
                base_url=self.settings.zap_base_url,
                host_port=self.settings.zap_host_port,
                keepalive_seconds=self.settings.zap_keepalive_seconds,
                host_header=self.settings.zap_host_header,
            ) as zap:
                rule_descriptions = await _apply_auth_headers(
                    zap, self.auth_headers, self.cookies
                )
                try:
                    # Spider-first: Discover all routes before attacking
                    logger.info("Starting spider-first route discovery...")
                    await _progress("dast.spider", "Spidering target to discover endpoints")
                    discovered_endpoints = await self._spider_discover_routes(
                        zap, effective_base_url
                    )

                    if discovered_endpoints:
                        logger.info(
                            "Spider discovered %d endpoints, will use fuzzy matching",
                            len(discovered_endpoints),
                        )
                        await _progress(
                            "dast.spider",
                            f"Spider discovered {len(discovered_endpoints)} endpoints",
                        )
                    else:
                        logger.warning(
                            "Spider found no endpoints, falling back to file-based mapping"
                        )
                        await _progress(
                            "dast.spider",
                            "Spider found no endpoints; using repo-based mapping",
                        )

                    # Generate attack configs with spider-matched endpoints
                    for finding in valid_findings:
                        config = self._generate_attack_config(
                            finding,
                            effective_base_url,
                            repo_path,
                            route_map=route_map,
                            discovered_endpoints=discovered_endpoints,
                        )
                        if config:
                            attack_configs.append(config)
                        else:
                            logger.info(
                                "No DAST attack available for rule: %s in %s",
                                finding.rule_id,
                                finding.file_path,
                            )
                            missing_configs.append(
                                DASTAttackResult(
                                    finding_id=f"{finding.rule_id}:{finding.file_path}:{finding.line_start}",
                                    attack_succeeded=False,
                                    confidence=0.3,
                                    verification_status="inconclusive_mapping",
                                    proof_of_exploit=None,
                                    evidence=[
                                        "No mapped endpoint or vulnerability type available for targeted DAST.",
                                    ],
                                    is_reachable=None,
                                )
                            )

                    if not attack_configs:
                        logger.info("No attack configs generated for findings")
                        return missing_configs

                    # Execute attacks
                    results: List[DASTAttackResult] = []
                    total = len(attack_configs)
                    await _progress(
                        "dast.targeted",
                        f"Running targeted scans for {total} finding(s)",
                    )
                    for index, config in enumerate(attack_configs, start=1):
                        if index == 1 or index % max(1, progress_every) == 0:
                            await _progress(
                                "dast.targeted",
                                f"Targeted scan {index}/{total}: {config.target_endpoint}",
                            )
                        results.append(
                            await self._execute_attack(
                                zap,
                                config,
                                original_netloc=original_netloc,
                                docker_netloc=docker_netloc,
                            )
                        )

                    results.extend(missing_configs)
                finally:
                    await _remove_auth_headers(zap, rule_descriptions)
        except ZapError as exc:
            self.last_error = str(exc)
            if not attack_configs and not missing_configs:
                return [
                    DASTAttackResult(
                        finding_id=f"{f.rule_id}:{f.file_path}:{f.line_start}",
                        attack_succeeded=False,
                        confidence=0.0,
                        verification_status=_status_from_error(exc),
                        proof_of_exploit=None,
                        evidence=[],
                        error=str(exc),
                        is_reachable=None,
                    )
                    for f in valid_findings
                ]
            return [
                DASTAttackResult(
                    finding_id=config.finding_id,
                    attack_succeeded=False,
                    confidence=0.0,
                    verification_status=_status_from_error(exc),
                    proof_of_exploit=None,
                    evidence=[],
                    error=str(exc),
                )
                for config in attack_configs
            ] + missing_configs

        confirmed_count = sum(1 for r in results if r.attack_succeeded)
        logger.info(
            "DAST verification complete: %d/%d findings confirmed exploitable",
            confirmed_count,
            len(results),
        )

        return results

    def _generate_attack_config(
        self,
        finding: TriagedFinding,
        base_url: str,
        repo_path: str,
        route_map: Optional[Dict[str, List[str]]] = None,
        discovered_endpoints: Optional[List[DiscoveredEndpoint]] = None,
    ) -> Optional[DASTAttackConfig]:
        rule_id = finding.rule_id.lower()
        rule_message = (finding.rule_message or "").lower()

        vuln_type = finding.sast_vuln_type or classify_vulnerability(
            f"{rule_id} {rule_message}",
            rule_id=finding.rule_id,
        )
        if not vuln_type:
            return None
        if not finding.sast_vuln_type:
            finding.sast_vuln_type = vuln_type

        # Try spider-first fuzzy matching if we have discovered endpoints
        matched_endpoint: Optional[DiscoveredEndpoint] = None
        match_confidence = 0.0

        if discovered_endpoints:
            matched_endpoint, match_confidence = self._fuzzy_match_finding_to_endpoint(
                finding, discovered_endpoints
            )

        endpoint_discovered = False
        endpoint_status_codes: Optional[List[int]] = None

        if matched_endpoint and match_confidence >= 0.4:
            # Use the discovered endpoint
            endpoint_path = matched_endpoint.path
            target_url = urljoin(
                base_url.rstrip("/") + "/", matched_endpoint.path.lstrip("/")
            )
            confidence = match_confidence
            endpoint_discovered = True
            endpoint_status_codes = (
                matched_endpoint.status_codes if matched_endpoint else None
            )

            # Use parameter from matched endpoint if available, else extract from code
            parameter = finding.sast_parameter
            if not parameter:
                if matched_endpoint.query_params:
                    parameter = matched_endpoint.query_params[0]
                elif matched_endpoint.form_params:
                    parameter = matched_endpoint.form_params[0]
            if not parameter:
                parameter = self._extract_parameter(finding)

            # Use method from discovered endpoint unless SAST signals otherwise
            http_method = matched_endpoint.method
            if (
                finding.sast_http_method
                and http_method.upper() == "GET"
                and finding.sast_http_method.upper() != "GET"
            ):
                http_method = finding.sast_http_method

            logger.info(
                "Using spider-matched endpoint for %s: %s (confidence: %.2f)",
                finding.file_path,
                target_url,
                confidence,
            )
        else:
            # Fall back to file-based endpoint resolution
            if finding.sast_endpoint:
                endpoint = finding.sast_endpoint
                confidence = 0.6
            else:
                endpoint, confidence = self._resolve_endpoint(
                    finding.file_path,
                    repo_path,
                    route_map,
                )
            endpoint_path = endpoint
            target_url = urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))
            parameter = finding.sast_parameter or self._extract_parameter(finding)
            http_method = finding.sast_http_method or self._detect_http_method(finding)

            logger.debug(
                "Using file-based mapping for %s: %s (confidence: %.2f)",
                finding.file_path,
                target_url,
                confidence,
            )

        finding_id = f"{finding.rule_id}:{finding.file_path}:{finding.line_start}"

        if not finding.sast_endpoint:
            finding.sast_endpoint = endpoint_path
        if not finding.sast_http_method:
            finding.sast_http_method = http_method
        if not finding.sast_parameter:
            finding.sast_parameter = parameter

        return DASTAttackConfig(
            finding_id=finding_id,
            vuln_type=vuln_type,
            vuln_keywords=VULN_KEYWORDS.get(vuln_type, []),
            target_endpoint=target_url,
            target_parameter=parameter,
            http_method=http_method,
            sast_rule_id=finding.rule_id,
            endpoint_mapping_confidence=confidence,
            endpoint_discovered=endpoint_discovered,
            endpoint_status_codes=endpoint_status_codes,
        )

    def _map_file_to_endpoint(self, file_path: str, repo_path: str) -> str:
        # Remove repo path prefix
        rel_path = file_path.replace(repo_path, "").lstrip("/")

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

    def _extract_parameter(self, finding: TriagedFinding) -> str:
        code = finding.code_snippet or ""
        context = finding.context_snippet or ""
        combined = f"{code} {context}"

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
            r"(\w+):\s*(?:str|int|float|bool)\s*=\s*Query",
            r"(\w+):\s*(?:str|int|float|bool)\s*=\s*Body",
            r"(\w+):\s*(?:str|int|float|bool)\s*=\s*Path",
            r"params\[:['\"]?(\w+)",
            r"@RequestParam.*?['\"](\w+)['\"]",
            r"@PathVariable.*?['\"](\w+)['\"]",
            r"['\"](\w+)['\"]\s*[:\]]\s*request",
            r"get\(['\"](\w+)['\"]",
        ]

        for pattern in patterns:
            match = re.search(pattern, combined)
            if match:
                return match.group(1)

        if finding.function_name:
            parts = finding.function_name.split("_")
            if len(parts) >= 2 and parts[0] in ["get", "update", "delete", "find"]:
                return parts[1]

        return "id"

    def _detect_http_method(self, finding: TriagedFinding) -> str:
        code = (finding.code_snippet or "").lower()
        context = (finding.context_snippet or "").lower()
        combined = f"{code} {context}"

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

    async def _execute_attack(
        self,
        zap: ZapDockerSession,
        config: DASTAttackConfig,
        *,
        original_netloc: Optional[str],
        docker_netloc: Optional[str],
    ) -> DASTAttackResult:
        logger.info(
            "DAST attacking %s for %s vulnerability",
            config.target_endpoint,
            config.vuln_type,
        )

        target_url, post_data = _prepare_target_request(config)
        target_location = _strip_query(target_url)
        curl_command = _build_curl_command(
            target_url,
            config.http_method,
            post_data,
            self.auth_headers,
            self.cookies,
        )
        evidence = _build_dast_evidence(
            config=config,
            target_url=target_url,
            post_data=post_data,
        )
        reachability_score, reachability_reason = _reachability_from_config(
            config
        )
        context_name = f"scanguard-{uuid.uuid4().hex[:8]}"
        context_id: Optional[str] = None

        try:
            context_id = await zap.create_context(context_name)
            include_regex = _build_include_regex(target_url)
            await zap.include_in_context(context_name, include_regex)
        except ZapError as exc:
            logger.debug("ZAP context setup failed: %s", exc)
            context_id = None

        try:
            spider_id = await zap.spider_scan(
                target_url,
                max_children=self.settings.zap_max_depth,
                recurse=False,
                context_name=context_name if context_id else None,
                subtree_only=True,
            )
            await zap.wait_spider(spider_id)
        except ZapError as exc:
            return DASTAttackResult(
                finding_id=config.finding_id,
                attack_succeeded=False,
                confidence=0.2 if exc.kind == "timeout" else 0.1,
                verification_status=_status_from_error(exc),
                evidence=evidence + ["ZAP spider blocked the request."],
                matched_at=target_location,
                endpoint=_base_url(target_url),
                proof_of_exploit=curl_command,
                is_reachable=False,
                reachability_score=0.0,
                reachability_reason="ZAP spider did not complete; reachability unknown.",
                error=str(exc),
            )

        try:
            scan_id = await zap.active_scan(
                url=target_url,
                recurse=False,
                in_scope_only=None,
                scan_policy_name=self.settings.zap_scan_policy,
                method=config.http_method,
                post_data=post_data,
                context_id=context_id,
            )
            await zap.wait_active(scan_id)
        except ZapError as exc:
            return DASTAttackResult(
                finding_id=config.finding_id,
                attack_succeeded=False,
                confidence=0.2 if exc.kind == "timeout" else 0.1,
                verification_status=_status_from_error(exc),
                evidence=evidence,
                matched_at=target_location,
                endpoint=_base_url(target_url),
                proof_of_exploit=curl_command,
                is_reachable=True,
                reachability_score=reachability_score,
                reachability_reason=reachability_reason,
                error=str(exc),
            )
        finally:
            if context_id:
                try:
                    await zap.remove_context(context_name)
                except ZapError:
                    logger.debug("Failed to remove ZAP context %s", context_name)

        try:
            alerts = await zap.alerts(base_url=_base_url(target_url))
        except ZapError as exc:
            return DASTAttackResult(
                finding_id=config.finding_id,
                attack_succeeded=False,
                confidence=0.0,
                verification_status=_status_from_error(exc),
                proof_of_exploit=curl_command,
                evidence=evidence,
                matched_at=target_location,
                endpoint=_base_url(target_url),
                is_reachable=True,
                reachability_score=reachability_score,
                reachability_reason=reachability_reason,
                error=str(exc),
            )

        relevant_alerts = [
            alert
            for alert in alerts
            if _alert_targets_endpoint(alert, target_url)
            and alert_matches_vuln_type(alert, config.vuln_type)
        ]

        if relevant_alerts:
            parsed = parse_zap_alert(relevant_alerts[0], fallback_url=target_url)
            if parsed:
                parsed = rewrite_finding_for_display(
                    parsed, original_netloc, docker_netloc
                )
            parsed_evidence = parsed.evidence if parsed else []
            combined = _merge_evidence(parsed_evidence, evidence)
            return DASTAttackResult(
                finding_id=config.finding_id,
                attack_succeeded=True,
                confidence=0.95,
                verification_status="confirmed_exploitable",
                proof_of_exploit=curl_command,
                evidence=combined,
                matched_at=parsed.matched_at if parsed else target_location,
                endpoint=parsed.endpoint if parsed else _base_url(target_url),
                template_id=parsed.template_id if parsed else None,
                severity=parsed.severity if parsed else None,
                cve_ids=parsed.cve_ids if parsed else None,
                cwe_ids=parsed.cwe_ids if parsed else None,
                is_reachable=True,
                reachability_score=max(0.8, reachability_score),
                reachability_reason=reachability_reason,
            )

        blocked_status = _blocked_status(config.endpoint_status_codes or [])
        if blocked_status:
            status = blocked_status
            confidence = 0.35
            evidence.append(
                "ZAP responses suggest authentication or rate limits are blocking access."
            )
        elif config.endpoint_discovered or config.endpoint_mapping_confidence >= 0.45:
            status = "attempted_not_reproduced"
            confidence = 0.6
        else:
            status = "inconclusive_mapping"
            confidence = 0.35
        return DASTAttackResult(
            finding_id=config.finding_id,
            attack_succeeded=False,
            confidence=confidence,
            verification_status=status,
            proof_of_exploit=curl_command,
            evidence=evidence + ["ZAP active scan completed with no matching alerts."],
            matched_at=target_location,
            endpoint=_base_url(target_url),
            is_reachable=True,
            reachability_score=reachability_score,
            reachability_reason=reachability_reason,
        )

    def map_results_to_findings(
        self,
        triaged_findings: List[TriagedFinding],
        dast_results: List[DASTAttackResult],
        repo_path: str,
    ) -> Tuple[List[TriagedFinding], int]:
        result_map: Dict[str, DASTAttackResult] = {}
        for result in dast_results:
            result_map[result.finding_id] = result

        confirmed_count = 0

        for finding in triaged_findings:

            finding_id = f"{finding.rule_id}:{finding.file_path}:{finding.line_start}"
            dast_result = result_map.get(finding_id)

            if dast_result:
                finding.dast_verification_status = dast_result.verification_status
                # Persist DAST attempt details even when an exploit is not confirmed
                # so the UI can show that targeted runtime verification was performed.
                finding.dast_matched_at = dast_result.matched_at
                finding.dast_endpoint = dast_result.endpoint
                finding.dast_curl_command = dast_result.proof_of_exploit
                finding.dast_evidence = dast_result.evidence
                finding.dast_cve_ids = dast_result.cve_ids
                finding.dast_cwe_ids = dast_result.cwe_ids
                if dast_result.is_reachable:
                    score = dast_result.reachability_score
                    if score is None:
                        score = finding.reachability_score
                    if not finding.is_reachable or (
                        score is not None
                        and (
                            finding.reachability_score is None
                            or score > finding.reachability_score
                        )
                    ):
                        finding.is_reachable = True
                        if score is not None:
                            finding.reachability_score = score
                        finding.reachability_reason = _merge_reachability_reason(
                            finding.reachability_reason,
                            dast_result.reachability_reason,
                        )
                if dast_result.attack_succeeded:
                    finding.confirmed_exploitable = True
                    finding.is_false_positive = False
                    current_confidence = finding.ai_confidence
                    if not isinstance(current_confidence, (int, float)):
                        current_confidence = 0.0
                    finding.ai_confidence = min(
                        1.0, max(0.0, float(current_confidence)) + 0.2
                    )
                    confirmed_count += 1

        return triaged_findings, confirmed_count


def _prepare_target_request(config: DASTAttackConfig) -> Tuple[str, Optional[str]]:
    parsed = urlparse(config.target_endpoint)
    query = dict(parse_qsl(parsed.query))
    post_data = None

    if config.http_method.upper() == "GET":
        if config.target_parameter and config.target_parameter not in query:
            query[config.target_parameter] = "scanguard"
        new_query = urlencode(query)
        target_url = urlunparse(parsed._replace(query=new_query))
        return target_url, None

    if config.target_parameter:
        post_data = urlencode({config.target_parameter: "scanguard"})
    return config.target_endpoint, post_data


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return url


def _build_include_regex(url: str) -> str:
    parsed = urlparse(url)
    host = re.escape(parsed.netloc)
    path = re.escape(parsed.path or "/")
    return rf"^https?://{host}{path}.*"


def _strip_query(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return url
    return urlunparse(parsed._replace(query="", fragment=""))


def _build_curl_command(
    url: str,
    method: str,
    post_data: Optional[str],
    auth_headers: Dict[str, str],
    cookies: Optional[str],
) -> str:
    parts = ["curl", "-sS", "-X", method.upper()]
    if method.upper() != "GET" and post_data:
        parts += [
            "-H",
            "Content-Type: application/x-www-form-urlencoded",
            "--data",
            post_data,
        ]
    for header in sorted(auth_headers.keys()):
        if header:
            parts += ["-H", f"{header}: <redacted>"]
    if cookies:
        parts += ["-H", "Cookie: <redacted>"]
    parts.append(url)
    return " ".join(shlex.quote(part) for part in parts)


def _build_dast_evidence(
    *,
    config: DASTAttackConfig,
    target_url: str,
    post_data: Optional[str],
) -> List[str]:
    evidence: List[str] = []
    param = config.target_parameter or "n/a"
    payload_hint = "body" if post_data else "query"
    evidence.append(
        f"dast_target={target_url} method={config.http_method.upper()} param={param} location={payload_hint}"
    )
    if config.endpoint_discovered:
        evidence.append("dast_discovery=spider")
    if config.endpoint_status_codes:
        codes = ",".join(str(code) for code in config.endpoint_status_codes)
        evidence.append(f"dast_status_codes={codes}")
    return evidence


def _reachability_from_config(
    config: DASTAttackConfig,
) -> Tuple[float, str]:
    score = max(0.4, min(0.95, 0.4 + 0.6 * config.endpoint_mapping_confidence))
    reason = "Endpoint inferred from repository routes."
    if config.endpoint_discovered:
        score = max(score, 0.8)
        reason = "ZAP spider discovered the endpoint."
    if config.endpoint_status_codes:
        codes = ",".join(str(code) for code in config.endpoint_status_codes)
        reason = f"{reason} Observed HTTP status codes: {codes}."
    return score, reason


def _alert_targets_endpoint(alert: Dict[str, str], target_url: str) -> bool:
    alert_url = str(alert.get("url") or "")
    if not alert_url:
        return False
    alert_parsed = urlparse(alert_url)
    target_parsed = urlparse(target_url)
    if alert_parsed.scheme != target_parsed.scheme:
        return False
    if alert_parsed.netloc != target_parsed.netloc:
        return False
    if target_parsed.path and not alert_parsed.path.startswith(target_parsed.path):
        return False
    return True


def _merge_evidence(primary: List[str], secondary: List[str]) -> List[str]:
    merged: List[str] = []
    for item in primary + secondary:
        if item and item not in merged:
            merged.append(item)
    return merged


def _merge_reachability_reason(
    current: Optional[str], update: Optional[str]
) -> Optional[str]:
    if not update:
        return current
    if not current:
        return update
    if update in current:
        return current
    return f"{current} | {update}"


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
        except ZapError:
            logger.debug("Failed to remove ZAP header rule %s", description)


def _status_from_error(exc: ZapError) -> str:
    text = str(exc).lower()
    if "url_not_found" in text or "bad request" in text or " 400" in text:
        return "bad_request"
    if getattr(exc, "kind", "") == "timeout":
        return "error_timeout"
    return "error_tooling"


def _blocked_status(status_codes: List[int]) -> Optional[str]:
    if not status_codes:
        return None
    if any(code in {401, 403} for code in status_codes):
        return "blocked_auth_required"
    if any(code == 429 for code in status_codes):
        return "blocked_rate_limit"
    return None


def _parse_default_auth_header(value: Optional[str]) -> Optional[Dict[str, str]]:
    if not value:
        return None
    raw = value.strip()
    if ":" not in raw:
        logger.warning(
            "Invalid DAST_DEFAULT_AUTH_HEADER format (missing colon): %s",
            raw[:50],
        )
        return None
    parts = raw.split(":", 1)
    if len(parts) != 2:
        return None
    header_name = parts[0].strip()
    header_value = parts[1].strip()
    if not header_name:
        logger.warning("DAST_DEFAULT_AUTH_HEADER has empty header name")
        return None
    return {header_name: header_value}


def _parse_extra_hosts(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]
