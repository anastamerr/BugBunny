from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Tuple

from ...config import get_settings
from ...services.intelligence.llm_service import LLMClient, get_llm_service
from .types import CodeContext, RawFinding, TriagedFinding


class AITriageEngine:
    def __init__(
        self,
        llm_client: LLMClient | None = None,
        max_concurrency: int = 3,
        timeout_seconds: float = 60.0,
    ) -> None:
        settings = get_settings()
        self.llm_client = llm_client or get_llm_service(settings)
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.timeout_seconds = timeout_seconds

    async def triage_finding(
        self, finding: RawFinding, context: CodeContext
    ) -> TriagedFinding:
        language = self._guess_language(finding.file_path)
        prompt = self._build_prompt(finding, context, language)
        response = await self._call_llm(prompt)
        data, parsed = self._parse_response(response)

        is_false_positive = (
            self._parse_bool(data.get("is_false_positive", False)) if parsed else False
        )
        ai_severity = self._normalize_severity(
            str(data.get("adjusted_severity") or data.get("ai_severity") or ""),
            finding.severity,
        )
        ai_confidence = (
            self._parse_confidence(data.get("confidence")) if parsed else 0.2
        )
        ai_reasoning = str(data.get("reasoning") or "").strip()
        exploitability = str(data.get("exploitability") or "").strip()

        ai_severity = self._apply_context_adjustments(
            ai_severity, context, is_false_positive
        )

        if not ai_reasoning:
            ai_reasoning = (
                "LLM response was unavailable or invalid; fallback to Semgrep severity."
            )
        if not exploitability:
            exploitability = "Not enough context to determine exploitability."

        return TriagedFinding(
            rule_id=finding.rule_id,
            rule_message=finding.rule_message,
            semgrep_severity=finding.severity,
            file_path=finding.file_path,
            line_start=finding.line_start,
            line_end=finding.line_end,
            code_snippet=finding.code_snippet,
            context_snippet=context.snippet or finding.code_snippet,
            function_name=context.function_name,
            class_name=context.class_name,
            is_test_file=context.is_test_file,
            is_generated=context.is_generated,
            imports=context.imports,
            is_false_positive=is_false_positive,
            ai_severity=ai_severity,
            ai_confidence=ai_confidence,
            ai_reasoning=ai_reasoning,
            exploitability=exploitability,
        )

    async def triage_batch(
        self, findings: List[Tuple[RawFinding, CodeContext]]
    ) -> List[TriagedFinding]:
        tasks = [self.triage_finding(finding, context) for finding, context in findings]
        return await asyncio.gather(*tasks)

    async def _call_llm(self, prompt: str) -> str:
        async with self.semaphore:
            try:
                return await asyncio.wait_for(
                    self.llm_client.generate(prompt, system=self._system_prompt()),
                    timeout=self.timeout_seconds,
                )
            except Exception:
                return ""

    def _system_prompt(self) -> str:
        return "You are a security expert reviewing static analysis findings."

    def _build_prompt(
        self, finding: RawFinding, context: CodeContext, language: str
    ) -> str:
        code_context = context.snippet or finding.code_snippet
        imports = ", ".join(context.imports[:10]) if context.imports else "none"
        function_name = context.function_name or "unknown"
        class_name = context.class_name or "none"
        return (
            "## Finding\n"
            f"- Rule: {finding.rule_id}\n"
            f"- Message: {finding.rule_message}\n"
            f"- Semgrep Severity: {finding.severity}\n"
            f"- File: {finding.file_path}:{finding.line_start}\n\n"
            "## Context Signals\n"
            f"- Function: {function_name}\n"
            f"- Class: {class_name}\n"
            f"- Test file: {context.is_test_file}\n"
            f"- Generated: {context.is_generated}\n"
            f"- Imports: {imports}\n\n"
            "## Code Context\n"
            f"```{language}\n"
            f"{code_context}\n"
            "```\n\n"
            "## Task\n"
            "Analyze this finding and respond in JSON:\n"
            "{\n"
            '  "is_false_positive": true/false,\n'
            '  "adjusted_severity": "critical|high|medium|low|info",\n'
            '  "confidence": 0.0-1.0,\n'
            '  "reasoning": "Brief explanation",\n'
            '  "exploitability": "How it could be exploited, or why not"\n'
            "}\n\n"
            "Consider:\n"
            "- Is the vulnerable code actually reachable?\n"
            "- Is there input validation elsewhere?\n"
            "- Is this a test file or example code?\n"
            "- Would exploitation require unlikely conditions?\n"
            "\n"
            "Severity guidance:\n"
            "- critical: unauthenticated RCE, auth bypass, or broad data loss\n"
            "- high: exploitable with auth or scoped data exposure\n"
            "- medium: limited impact, requires user interaction\n"
            "- low: hard to exploit, minor impact\n"
            "- info: test-only, generated code, or non-issue\n"
            "Do not default to high; pick the lowest realistic severity.\n"
        )

    def _parse_response(self, response: str) -> tuple[Dict, bool]:
        if not response:
            return {}, False
        text = response.strip()
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return {}, False
        payload = text[start : end + 1]
        try:
            return json.loads(payload), True
        except json.JSONDecodeError:
            return {}, False

    def _guess_language(self, file_path: str) -> str:
        ext = Path(file_path).suffix.lower()
        mapping = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".go": "go",
            ".java": "java",
        }
        return mapping.get(ext, "")

    def _normalize_severity(self, ai_severity: str, semgrep_severity: str) -> str:
        ai_severity = ai_severity.strip().lower()
        allowed = {"critical", "high", "medium", "low", "info"}
        if ai_severity in allowed:
            return ai_severity

        semgrep = semgrep_severity.upper()
        if semgrep == "ERROR":
            return "high"
        if semgrep == "WARNING":
            return "medium"
        return "low"

    def _parse_confidence(self, value: object) -> float:
        try:
            confidence = float(value)
        except (TypeError, ValueError):
            return 0.5
        return max(0.0, min(confidence, 1.0))

    def _parse_bool(self, value: object) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"true", "yes", "1"}
        if isinstance(value, (int, float)):
            return value != 0
        return False

    def _apply_context_adjustments(
        self, severity: str, context: CodeContext, is_false_positive: bool
    ) -> str:
        if is_false_positive:
            return "info"
        if context.is_test_file or context.is_generated:
            if severity in {"critical", "high"}:
                return "low"
            if severity == "medium":
                return "low"
        return severity
