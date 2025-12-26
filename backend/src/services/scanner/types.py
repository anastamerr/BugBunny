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


@dataclass
class FindingGroup:
    key: str
    findings: List[TriagedFinding]
