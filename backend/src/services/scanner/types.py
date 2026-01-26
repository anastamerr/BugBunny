from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class RawFinding:
    rule_id: str
    rule_message: str
    severity: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str


@dataclass
class CodeContext:
    snippet: str
    function_name: Optional[str]
    class_name: Optional[str]
    is_test_file: bool
    is_generated: bool
    imports: List[str]
    is_reachable: bool = True
    reachability_score: float = 1.0
    reachability_reason: str = ""
    entry_points: Optional[List[str]] = None
    call_path: Optional[List[str]] = None


@dataclass
class TriagedFinding:
    rule_id: str
    rule_message: str
    semgrep_severity: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    context_snippet: str
    function_name: Optional[str]
    class_name: Optional[str]
    is_test_file: bool
    is_generated: bool
    imports: List[str]
    is_false_positive: bool
    ai_severity: str
    ai_confidence: float
    ai_reasoning: str
    exploitability: str
    priority_score: Optional[int] = None
    confirmed_exploitable: bool = False
    is_reachable: bool = True
    reachability_score: float = 1.0
    reachability_reason: str = ""
    entry_points: Optional[List[str]] = None
    call_path: Optional[List[str]] = None
    dast_matched_at: Optional[str] = None
    dast_endpoint: Optional[str] = None
    dast_curl_command: Optional[str] = None
    dast_evidence: Optional[List[str]] = None
    dast_cve_ids: Optional[List[str]] = None
    dast_cwe_ids: Optional[List[str]] = None
    dast_verification_status: Optional[str] = None


@dataclass
class FindingGroup:
    key: str
    findings: List[TriagedFinding]


@dataclass
class DynamicFinding:
    template_id: str
    template_name: str
    severity: str
    matched_at: str
    endpoint: str
    curl_command: str
    evidence: List[str]
    description: str
    remediation: str
    cve_ids: List[str]
    cwe_ids: List[str]


@dataclass
class DependencyFinding:
    cve_id: str
    package_name: str
    installed_version: str
    fixed_version: str
    severity: str
    description: str
    cvss_score: Optional[float]
    target: Optional[str] = None


@dataclass
class DASTAttackConfig:
    """Configuration for attacking a specific SAST finding."""
    finding_id: str
    vuln_type: str  # "sqli", "xss", "command-injection", etc.
    vuln_keywords: List[str]  # Keywords to match ZAP alerts for this vulnerability
    target_endpoint: str  # Full URL to attack
    target_parameter: str  # Which parameter is vulnerable
    http_method: str = "GET"
    sast_rule_id: str = ""
    endpoint_mapping_confidence: float = 0.5  # Confidence in endpoint mapping


@dataclass
class DASTAttackResult:
    """Result of DAST attack on a specific SAST finding."""
    finding_id: str
    attack_succeeded: bool
    confidence: float  # 0.0-1.0
    verification_status: str  # One of: not_run, confirmed_exploitable, attempted_not_reproduced, blocked_auth_required, blocked_rate_limit, inconclusive_mapping, error_timeout, error_tooling
    proof_of_exploit: Optional[str] = None  # Curl command
    evidence: Optional[List[str]] = None  # ZAP alert evidence strings
    matched_at: Optional[str] = None
    endpoint: Optional[str] = None
    template_id: Optional[str] = None
    severity: Optional[str] = None
    cve_ids: Optional[List[str]] = None
    cwe_ids: Optional[List[str]] = None
    error: Optional[str] = None


@dataclass
class DependencyHealthFinding:
    package_name: str
    ecosystem: str
    status: str
    installed_version: Optional[str]
    latest_version: Optional[str]
    requirement: Optional[str]
    dependency_type: str
    file_path: str
    deprecation_reason: Optional[str]
    is_yanked: bool
    ai_severity: str
    ai_confidence: float
    ai_reasoning: str
    description: Optional[str] = None
    remediation: Optional[str] = None
