from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from typing import Dict, List

from .types import RawFinding


class SemgrepRunner:
    def __init__(self, semgrep_path: str = "semgrep") -> None:
        self.semgrep_path = semgrep_path

    async def scan(self, repo_path: Path, languages: List[str]) -> List[RawFinding]:
        cmd = [
            self.semgrep_path,
            "--json",
            "--quiet",
            "--metrics",
            "off",
        ]

        rulesets = self.resolve_rulesets(languages)
        if rulesets:
            for ruleset in rulesets:
                cmd.extend(["--config", ruleset])
        else:
            cmd.extend(["--config", "auto"])

        cmd.append(str(repo_path))

        output = await asyncio.to_thread(self._run_command, cmd)
        try:
            parsed = json.loads(output)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Semgrep returned invalid JSON output") from exc

        return self._parse_results(parsed)

    def resolve_rulesets(self, languages: List[str]) -> List[str]:
        mapping = {
            "python": "p/python",
            "javascript": "p/javascript",
            "go": "p/golang",
            "java": "p/java",
        }
        return sorted({mapping[lang] for lang in languages if lang in mapping})

    def get_version(self) -> str | None:
        try:
            result = subprocess.run(
                [self.semgrep_path, "--version"],
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            return None

        if result.returncode != 0:
            return None

        output = (result.stdout or result.stderr or "").strip()
        return output or None

    def _run_command(self, cmd: List[str]) -> str:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("Semgrep CLI is not installed or not in PATH") from exc

        stdout = result.stdout or ""
        stderr = result.stderr or ""
        if result.returncode not in (0, 1):
            detail = stderr.strip() or stdout.strip() or "Unknown semgrep error"
            raise RuntimeError(f"Semgrep failed: {detail}")

        return stdout

    def _parse_results(self, json_output: Dict) -> List[RawFinding]:
        findings: List[RawFinding] = []
        for result in json_output.get("results", []):
            extra = result.get("extra") or {}
            start = result.get("start") or {}
            end = result.get("end") or {}

            findings.append(
                RawFinding(
                    rule_id=result.get("check_id", ""),
                    rule_message=extra.get("message", ""),
                    severity=str(extra.get("severity", "INFO")).upper(),
                    file_path=result.get("path", ""),
                    line_start=int(start.get("line", 1) or 1),
                    line_end=int(end.get("line", start.get("line", 1) or 1) or 1),
                    code_snippet=extra.get("lines", "") or "",
                )
            )

        return findings
