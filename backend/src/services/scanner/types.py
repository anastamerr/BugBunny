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
