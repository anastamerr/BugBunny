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
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from ...config import get_settings
from .commit_verifier import CommitVerifier
from .route_parser import RouteParser
from .types import DASTAttackConfig, DASTAttackResult, TriagedFinding
from .zap_client import ZapDockerSession, ZapError, is_docker_available
from .zap_parser import (
    VULN_KEYWORDS,
    alert_matches_vuln_type,
    classify_vulnerability,
    parse_zap_alert,
)

logger = logging.getLogger(__name__)


class TargetedDASTRunner:
    """
    Executes focused ZAP active scans based on SAST findings.
    """

    def __init__(
        self,
        timeout: int = 120,
        auth_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
    ) -> None:
        self.timeout = timeout
        self.settings = get_settings()
        self.last_error: str | None = None
        self.auth_headers = self._normalize_headers(auth_headers)
        self.cookies = cookies
        self.route_parser = RouteParser()
        self.commit_verifier = CommitVerifier()

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
        return is_docker_available()

    def _build_route_map(self, repo_path: str) -> Dict[str, List[str]]:
        if not repo_path:
            return {}
        path = Path(repo_path)
        if not path.exists():
            return {}
        return self.route_parser.parse_routes(path)

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

    async def attack_findings(
        self,
        target_base_url: str,
        sast_findings: List[TriagedFinding],
        repo_path: str,
        commit_sha: Optional[str] = None,
        scan_id: Optional[uuid.UUID] = None,
    ) -> List[DASTAttackResult]:
        """
        Attack each SAST finding to confirm exploitability.

        Args:
            target_base_url: Live app URL (e.g., https://app.example.com)
            sast_findings: Vulnerabilities found by SAST (after AI filtering)
            repo_path: Path to cloned repo (to map findings to endpoints)
            commit_sha: Expected commit SHA for verification (optional)
            scan_id: Scan ID for updating verification status (optional)

        Returns:
            List of DAST results showing which findings are exploitable
        """
        self.last_error = None

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

        attack_configs: List[DASTAttackConfig] = []
        route_map = self._build_route_map(repo_path)

        for finding in sast_findings:
            if finding.is_false_positive:
                continue

            config = self._generate_attack_config(
                finding,
                target_base_url,
                repo_path,
                route_map=route_map,
            )
            if config:
                attack_configs.append(config)
            else:
                logger.info(
                    "No DAST attack available for rule: %s in %s",
                    finding.rule_id,
                    finding.file_path,
                )

        if not attack_configs:
            logger.info("No SAST findings suitable for DAST verification")
            return []

        if not self.is_available():
            self.last_error = "Docker is not available for running ZAP."
            return [
                DASTAttackResult(
                    finding_id=config.finding_id,
                    attack_succeeded=False,
                    confidence=0.0,
                    verification_status="error_tooling",
                    proof_of_exploit=None,
                    evidence=[],
                    error=self.last_error,
                )
                for config in attack_configs
            ]

        timeout_seconds = min(self.settings.zap_timeout_seconds, self.timeout)

        try:
            async with ZapDockerSession(
                image=self.settings.zap_docker_image,
                api_key=self.settings.zap_api_key,
                timeout_seconds=timeout_seconds,
                request_timeout_seconds=self.settings.zap_request_timeout_seconds,
            ) as zap:
                rule_descriptions = await _apply_auth_headers(
                    zap, self.auth_headers, self.cookies
                )
                try:
                    results: List[DASTAttackResult] = []
                    for config in attack_configs:
                        results.append(await self._execute_attack(zap, config))
                finally:
                    await _remove_auth_headers(zap, rule_descriptions)
        except ZapError as exc:
            self.last_error = str(exc)
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
            ]

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
    ) -> Optional[DASTAttackConfig]:
        rule_id = finding.rule_id.lower()
        rule_message = (finding.rule_message or "").lower()

        vuln_type = classify_vulnerability(f"{rule_id} {rule_message}")
        if not vuln_type:
            return None

        endpoint, confidence = self._resolve_endpoint(
            finding.file_path,
            repo_path,
            route_map,
        )
        target_url = urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))

        parameter = self._extract_parameter(finding)
        finding_id = f"{finding.rule_id}:{finding.file_path}:{finding.line_start}"

        return DASTAttackConfig(
            finding_id=finding_id,
            vuln_type=vuln_type,
            vuln_keywords=VULN_KEYWORDS.get(vuln_type, []),
            target_endpoint=target_url,
            target_parameter=parameter,
            http_method=self._detect_http_method(finding),
            sast_rule_id=finding.rule_id,
            endpoint_mapping_confidence=confidence,
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
    ) -> DASTAttackResult:
        logger.info(
            "DAST attacking %s for %s vulnerability",
            config.target_endpoint,
            config.vuln_type,
        )

        target_url, post_data = _prepare_target_request(config)
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
            blocked = _detect_blocking_status(str(exc))
            if blocked:
                return DASTAttackResult(
                    finding_id=config.finding_id,
                    attack_succeeded=False,
                    confidence=0.35,
                    verification_status=blocked,
                    proof_of_exploit=None,
                    evidence=["ZAP spider blocked the request."],
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
            status = _status_from_error(exc)
            return DASTAttackResult(
                finding_id=config.finding_id,
                attack_succeeded=False,
                confidence=0.2 if status == "error_timeout" else 0.0,
                verification_status=status,
                proof_of_exploit=None,
                evidence=[],
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
            status = _status_from_error(exc)
            return DASTAttackResult(
                finding_id=config.finding_id,
                attack_succeeded=False,
                confidence=0.0,
                verification_status=status,
                proof_of_exploit=None,
                evidence=[],
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
            evidence = parsed.evidence if parsed else []
            return DASTAttackResult(
                finding_id=config.finding_id,
                attack_succeeded=True,
                confidence=0.95,
                verification_status="confirmed_exploitable",
                proof_of_exploit=None,
                evidence=evidence,
                matched_at=parsed.matched_at if parsed else target_url,
                endpoint=parsed.endpoint if parsed else _base_url(target_url),
                template_id=parsed.template_id if parsed else None,
                severity=parsed.severity if parsed else None,
                cve_ids=parsed.cve_ids if parsed else None,
                cwe_ids=parsed.cwe_ids if parsed else None,
            )

        status = (
            "attempted_not_reproduced"
            if config.endpoint_mapping_confidence >= 0.45
            else "inconclusive_mapping"
        )
        confidence = 0.6 if status == "attempted_not_reproduced" else 0.35
        return DASTAttackResult(
            finding_id=config.finding_id,
            attack_succeeded=False,
            confidence=confidence,
            verification_status=status,
            proof_of_exploit=None,
            evidence=["ZAP active scan completed with no matching alerts."],
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
            if finding.is_false_positive:
                continue

            finding_id = f"{finding.rule_id}:{finding.file_path}:{finding.line_start}"
            dast_result = result_map.get(finding_id)

            if dast_result:
                finding.dast_verification_status = dast_result.verification_status
                if dast_result.attack_succeeded:
                    finding.confirmed_exploitable = True
                    finding.is_false_positive = False
                    finding.ai_confidence = min(1.0, finding.ai_confidence + 0.2)
                    finding.dast_matched_at = dast_result.matched_at
                    finding.dast_endpoint = dast_result.endpoint
                    finding.dast_curl_command = dast_result.proof_of_exploit
                    finding.dast_evidence = dast_result.evidence
                    finding.dast_cve_ids = dast_result.cve_ids
                    finding.dast_cwe_ids = dast_result.cwe_ids
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
    if exc.kind == "timeout":
        return "error_timeout"
    blocked = _detect_blocking_status(str(exc))
    if blocked:
        return blocked
    return "error_tooling"


def _detect_blocking_status(output: str) -> Optional[str]:
    text = output.lower()
    if "429" in text or "rate limit" in text or "too many requests" in text:
        return "blocked_rate_limit"
    if "401" in text or "403" in text or "unauthorized" in text or "forbidden" in text:
        return "blocked_auth_required"
    return None
