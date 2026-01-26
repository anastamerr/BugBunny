"""
Targeted DAST Runner - Attacks specific SAST findings.

Unlike blind DAST that scans entire apps, this targets specific
vulnerabilities found by SAST to confirm exploitability.

Workflow:
1. Takes SAST findings as input (after AI triage)
2. Maps each finding to attack configuration (endpoint, parameter, vuln type)
3. Runs Nuclei with targeted tags for each finding
4. Returns results showing which findings are confirmed exploitable
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

from ...config import get_settings
from .route_parser import RouteParser
from .types import DASTAttackConfig, DASTAttackResult, TriagedFinding

logger = logging.getLogger(__name__)


class TargetedDASTRunner:
    """
    Executes targeted DAST attacks based on SAST findings.

    Instead of blindly scanning an entire application, this runner:
    1. Takes SAST findings (e.g., SQL injection in line 45)
    2. Maps to endpoint (e.g., /api/users?id=X)
    3. Generates attack config (SQLi payloads for that endpoint)
    4. Runs Nuclei with targeted tags
    5. Returns confirmation of exploitability
    """

    def __init__(
        self,
        nuclei_path: str = "nuclei",
        timeout: int = 60,
        auth_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
    ) -> None:
        self.nuclei_path = nuclei_path
        self.timeout = timeout
        self.settings = get_settings()
        self.last_error: str | None = None
        self.auth_headers = self._normalize_headers(auth_headers)
        self.cookies = cookies
        self.route_parser = RouteParser()

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
        """Check if Nuclei is installed."""
        return shutil.which(self.nuclei_path) is not None

    def _validate_nuclei(self) -> bool:
        """Ensure Nuclei is callable before running attacks."""
        if not self.is_available():
            self.last_error = (
                "Nuclei not found. Install: go install "
                "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            )
            return False
        try:
            result = subprocess.run(
                [self.nuclei_path, "-version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            self.last_error = f"Nuclei validation failed: {exc}"
            return False
        if result.returncode != 0:
            output = (result.stderr or result.stdout or "").strip()
            self.last_error = output or "Nuclei validation failed"
            return False
        return True

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
    ) -> List[DASTAttackResult]:
        """
        Attack each SAST finding to confirm exploitability.

        Args:
            target_base_url: Live app URL (e.g., https://app.example.com)
            sast_findings: Vulnerabilities found by SAST (after AI filtering)
            repo_path: Path to cloned repo (to map findings to endpoints)

        Returns:
            List of DAST results showing which findings are exploitable
        """
        self.last_error = None

        attack_configs: List[DASTAttackConfig] = []
        route_map = self._build_route_map(repo_path)

        # Generate attack configurations for non-false-positive findings
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

        if not self._validate_nuclei():
            error_message = self.last_error or "Nuclei validation failed"
            logger.warning(error_message)
            return [
                DASTAttackResult(
                    finding_id=config.finding_id,
                    attack_succeeded=False,
                    confidence=0.0,
                    verification_status="error_tooling",
                    proof_of_exploit=None,
                    evidence=[],
                    error=error_message,
                )
                for config in attack_configs
            ]

        logger.info(
            "Targeting %d SAST findings for DAST verification", len(attack_configs)
        )

        # Execute attacks with concurrency control
        semaphore = asyncio.Semaphore(3)  # Max 3 concurrent attacks

        async def run_with_semaphore(config: DASTAttackConfig) -> DASTAttackResult:
            async with semaphore:
                return await self._execute_attack(config)

        tasks = [run_with_semaphore(config) for config in attack_configs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results, handling any exceptions
        processed_results: List[DASTAttackResult] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                config = attack_configs[i]
                logger.error(
                    "DAST attack failed for %s: %s", config.finding_id, result
                )
                processed_results.append(
                    DASTAttackResult(
                        finding_id=config.finding_id,
                        attack_succeeded=False,
                        confidence=0.0,
                        verification_status="error_tooling",
                        proof_of_exploit=None,
                        evidence=[],
                        error=str(result),
                    )
                )
            else:
                processed_results.append(result)

        confirmed_count = sum(1 for r in processed_results if r.attack_succeeded)
        logger.info(
            "DAST verification complete: %d/%d findings confirmed exploitable",
            confirmed_count,
            len(processed_results),
        )

        return processed_results

    def _generate_attack_config(
        self,
        finding: TriagedFinding,
        base_url: str,
        repo_path: str,
        route_map: Optional[Dict[str, List[str]]] = None,
    ) -> Optional[DASTAttackConfig]:
        """
        Map SAST finding to DAST attack configuration.

        Examples:
        - SAST: "SQL injection in users.py line 45"
          -> DAST: Attack /api/users with SQLi payloads

        - SAST: "XSS in search_handler.js line 23"
          -> DAST: Attack /search?q=<payload>

        - SAST: "Command injection in upload.py line 67"
          -> DAST: Attack /upload with command payloads
        """
        rule_id = finding.rule_id.lower()
        rule_message = (finding.rule_message or "").lower()

        # Determine vulnerability type and appropriate templates
        vuln_type, tags_args = self._classify_vulnerability(rule_id, rule_message)

        if not vuln_type:
            return None

        # Map file path to endpoint
        endpoint, confidence = self._resolve_endpoint(
            finding.file_path,
            repo_path,
            route_map,
        )
        target_url = urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))

        # Extract parameter name from code context
        parameter = self._extract_parameter(finding)

        # Build finding ID from the finding attributes
        finding_id = f"{finding.rule_id}:{finding.file_path}:{finding.line_start}"

        return DASTAttackConfig(
            finding_id=finding_id,
            vuln_type=vuln_type,
            nuclei_templates=tags_args,
            target_endpoint=target_url,
            target_parameter=parameter,
            http_method=self._detect_http_method(finding),
            sast_rule_id=finding.rule_id,
            endpoint_mapping_confidence=confidence,
        )

    def _classify_vulnerability(
        self, rule_id: str, rule_message: str
    ) -> Tuple[Optional[str], List[str]]:
        """
        Map Semgrep rule to vulnerability type and Nuclei tag args.

        Returns: (vuln_type, nuclei_args)
        """
        combined_text = f"{rule_id} {rule_message}"

        classifications = [
            (
                ["sql", "sqli", "injection.sql"],
                "sqli",
                ["-tags", "sqli"],
            ),
            (
                ["xss", "cross-site-scripting", "cross_site_scripting"],
                "xss",
                ["-tags", "xss"],
            ),
            (
                ["command", "cmd-injection", "os-command", "exec", "shell"],
                "command-injection",
                ["-tags", "cmdi,command-injection"],
            ),
            (
                ["code-injection", "eval", "rce", "remote-code"],
                "code-injection",
                ["-tags", "rce,code-injection"],
            ),
            (
                ["path-traversal", "directory-traversal", "lfi", "file-inclusion"],
                "path-traversal",
                ["-tags", "lfi,path-traversal"],
            ),
            (
                ["xxe", "xml-external-entity"],
                "xxe",
                ["-tags", "xxe"],
            ),
            (
                ["ssrf", "server-side-request"],
                "ssrf",
                ["-tags", "ssrf"],
            ),
            (
                ["ssti", "template-injection", "server-side-template"],
                "ssti",
                ["-tags", "ssti"],
            ),
            (
                ["open-redirect", "unvalidated-redirect"],
                "open-redirect",
                ["-tags", "open-redirect"],
            ),
            (
                ["deserialization", "deserialize", "pickle", "yaml.load", "unserialize"],
                "deserialization",
                ["-tags", "deserialization"],
            ),
        ]

        for keywords, vuln_type, templates in classifications:
            if any(keyword in combined_text for keyword in keywords):
                return vuln_type, templates

        return None, []

    def _map_file_to_endpoint(self, file_path: str, repo_path: str) -> str:
        """
        Convert code file path to API endpoint.

        Examples:
        - api/routes/users.py -> /api/users
        - controllers/AuthController.java -> /auth
        - handlers/search_handler.go -> /search
        - src/routes/products/[id].tsx -> /products/:id

        This is heuristic-based. For production, parse route definitions.
        """
        # Remove repo path prefix
        rel_path = file_path.replace(repo_path, "").lstrip("/")

        # Common patterns for route files
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
                # Clean up the endpoint
                endpoint = endpoint.lower()
                endpoint = re.sub(r"_", "-", endpoint)
                # Handle Next.js style dynamic routes
                endpoint = re.sub(r"\[(\w+)\]", r":\1", endpoint)
                return endpoint

        # Fallback: extract meaningful part from filename
        filename = rel_path.split("/")[-1].rsplit(".", 1)[0]
        # Remove common suffixes
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
        """
        Extract vulnerable parameter name from code context.

        Example: request.args.get('id') -> 'id'
        """
        code = finding.code_snippet or ""
        context = finding.context_snippet or ""
        combined = f"{code} {context}"

        # Common parameter extraction patterns by framework
        patterns = [
            # Flask
            r"request\.args\.get\(['\"](\w+)['\"]",
            r"request\.form\.get\(['\"](\w+)['\"]",
            r"request\.values\.get\(['\"](\w+)['\"]",
            r"request\.json\.get\(['\"](\w+)['\"]",
            # Django
            r"request\.GET\.get\(['\"](\w+)['\"]",
            r"request\.POST\.get\(['\"](\w+)['\"]",
            r"request\.data\.get\(['\"](\w+)['\"]",
            # Express.js
            r"req\.query\.(\w+)",
            r"req\.body\.(\w+)",
            r"req\.params\.(\w+)",
            # FastAPI
            r"(\w+):\s*(?:str|int|float|bool)\s*=\s*Query",
            r"(\w+):\s*(?:str|int|float|bool)\s*=\s*Body",
            r"(\w+):\s*(?:str|int|float|bool)\s*=\s*Path",
            # Rails
            r"params\[:['\"]?(\w+)",
            # Spring
            r"@RequestParam.*?['\"](\w+)['\"]",
            r"@PathVariable.*?['\"](\w+)['\"]",
            # Generic patterns
            r"['\"](\w+)['\"]\s*[:\]]\s*request",
            r"get\(['\"](\w+)['\"]",
        ]

        for pattern in patterns:
            match = re.search(pattern, combined)
            if match:
                return match.group(1)

        # Try to extract from function name
        if finding.function_name:
            # Functions like get_user, update_user might suggest 'user' as param
            parts = finding.function_name.split("_")
            if len(parts) >= 2 and parts[0] in ["get", "update", "delete", "find"]:
                return parts[1]

        return "id"  # Default fallback

    def _detect_http_method(self, finding: TriagedFinding) -> str:
        """Detect HTTP method from code context."""
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

        return "GET"  # Default

    async def _execute_attack(self, config: DASTAttackConfig) -> DASTAttackResult:
        """
        Execute Nuclei attack with specific configuration.

        Returns result showing if attack succeeded.
        """
        logger.info(
            "DAST attacking %s for %s vulnerability",
            config.target_endpoint,
            config.vuln_type,
        )

        # Build Nuclei command
        cmd = [
            self.nuclei_path,
            "-u",
            config.target_endpoint,
            "-jsonl",
            "-silent",
            "-timeout",
            "10",
            "-rate-limit",
            "30",
            "-no-interactsh",  # Disable out-of-band testing for speed
        ]

        # Add tags / template args
        cmd.extend(config.nuclei_templates)

        # Add severity filter to focus on actual vulnerabilities
        cmd.extend(["-severity", "critical,high,medium"])

        # Add auth headers and cookies
        for header, value in self.auth_headers.items():
            cmd.extend(["-H", f"{header}: {value}"])
        if self.cookies and not _has_cookie_header(self.auth_headers):
            cmd.extend(["-H", f"Cookie: {self.cookies}"])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )

            output = stdout.decode(errors="ignore")
            stderr_text = stderr.decode(errors="ignore")

            if not output.strip():
                combined = f"{output}\n{stderr_text}".lower()
                blocked_status = _detect_blocking_status(combined)
                if blocked_status:
                    return DASTAttackResult(
                        finding_id=config.finding_id,
                        attack_succeeded=False,
                        confidence=0.35,
                        verification_status=blocked_status,
                        proof_of_exploit=None,
                        evidence=["Target blocked verification attempts."],
                        error=stderr_text.strip() or None,
                    )
                if proc.returncode not in (0, None):
                    error_detail = stderr_text.strip() or (
                        f"Nuclei exited with code {proc.returncode}"
                    )
                    return DASTAttackResult(
                        finding_id=config.finding_id,
                        attack_succeeded=False,
                        confidence=0.0,
                        verification_status="error_tooling",
                        proof_of_exploit=None,
                        evidence=[],
                        error=error_detail,
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
                    evidence=["Nuclei completed without confirmed vulnerabilities."],
                )

            # Parse JSONL output
            findings = []
            for line in output.strip().split("\n"):
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

            if findings:
                # Attack succeeded!
                first = findings[0]
                info = first.get("info", {})
                classification = info.get("classification", {})

                return DASTAttackResult(
                    finding_id=config.finding_id,
                    attack_succeeded=True,
                    confidence=0.99,  # Very high confidence
                    verification_status="confirmed_exploitable",
                    proof_of_exploit=first.get("curl-command"),
                    evidence=[f.get("matched-at", "") for f in findings],
                    matched_at=first.get("matched-at"),
                    endpoint=config.target_endpoint,
                    template_id=first.get("template-id"),
                    severity=info.get("severity"),
                    cve_ids=classification.get("cve-id", []),
                    cwe_ids=classification.get("cwe-id", []),
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
                evidence=["Nuclei completed but found no vulnerabilities"],
            )

        except asyncio.TimeoutError:
            logger.warning(
                "DAST attack timeout for %s after %ds",
                config.target_endpoint,
                self.timeout,
            )
            return DASTAttackResult(
                finding_id=config.finding_id,
                attack_succeeded=False,
                confidence=0.2,
                verification_status="error_timeout",
                proof_of_exploit=None,
                evidence=[],
                error=f"Timeout after {self.timeout}s",
            )
        except Exception as exc:
            logger.error(
                "DAST attack error for %s: %s", config.target_endpoint, exc
            )
            return DASTAttackResult(
                finding_id=config.finding_id,
                attack_succeeded=False,
                confidence=0.0,
                verification_status="error_tooling",
                proof_of_exploit=None,
                evidence=[],
                error=str(exc),
            )

    def map_results_to_findings(
        self,
        triaged_findings: List[TriagedFinding],
        dast_results: List[DASTAttackResult],
        repo_path: str,
    ) -> Tuple[List[TriagedFinding], int]:
        """
        Map DAST results back to triaged findings and update them.

        Returns:
            Tuple of (updated findings, count of confirmed exploitable)
        """
        # Build a mapping of finding_id to DAST result
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
                    # DAST confirmed the vulnerability is exploitable
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
                # Note: We mark all tested findings as dast_verified in the pipeline

        return triaged_findings, confirmed_count


def _has_cookie_header(headers: Dict[str, str]) -> bool:
    for key in headers.keys():
        if key.strip().lower() == "cookie":
            return True
    return False


def _detect_blocking_status(output: str) -> Optional[str]:
    text = output.lower()
    if "429" in text or "rate limit" in text or "too many requests" in text:
        return "blocked_rate_limit"
    if "401" in text or "403" in text or "unauthorized" in text or "forbidden" in text:
        return "blocked_auth_required"
    return None
