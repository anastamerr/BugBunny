from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List, Optional

from .reachability_analyzer import ReachabilityAnalyzer
from .types import CodeContext, RawFinding

logger = logging.getLogger(__name__)


class ContextExtractor:
    def __init__(self, enable_reachability: bool = True) -> None:
        self.enable_reachability = enable_reachability
        self._reachability_analyzer: Optional[ReachabilityAnalyzer] = None
        self._current_repo_path: Optional[Path] = None

    def _get_reachability_analyzer(self, repo_path: Path) -> ReachabilityAnalyzer:
        """Get or create reachability analyzer for the current repo."""
        if (
            self._reachability_analyzer is None
            or self._current_repo_path != repo_path
        ):
            self._reachability_analyzer = ReachabilityAnalyzer()
            self._current_repo_path = repo_path
        return self._reachability_analyzer

    def extract(
        self,
        repo_path: Path,
        finding: RawFinding,
        context_lines: int = 20,
    ) -> CodeContext:
        file_path = repo_path / finding.file_path
        try:
            content = file_path.read_text(errors="replace")
        except FileNotFoundError:
            return CodeContext(
                snippet="",
                function_name=None,
                class_name=None,
                is_test_file=self._is_test_file(finding.file_path),
                is_generated=False,
                imports=[],
            )

        lines = content.splitlines()
        line_count = len(lines)
        target_line = max(1, min(finding.line_start, line_count))
        start = max(0, target_line - context_lines - 1)
        end = min(line_count, finding.line_end + context_lines)
        snippet = "\n".join(lines[start:end])

        function_name = self._get_function_scope(lines, target_line)
        class_name = self._get_class_scope(lines, target_line)
        is_test_file = self._is_test_file(finding.file_path)
        is_generated = self._is_generated_file(lines)
        imports = self._extract_imports(lines)

        # Reachability analysis
        is_reachable = True
        reachability_score = 1.0
        reachability_reason = ""
        entry_points: Optional[List[str]] = None
        call_path: Optional[List[str]] = None

        if self.enable_reachability and not is_test_file:
            try:
                analyzer = self._get_reachability_analyzer(repo_path)
                result = analyzer.analyze(
                    repo_path=repo_path,
                    file_path=finding.file_path,
                    function_name=function_name,
                    class_name=class_name,
                    line_number=finding.line_start,
                )
                is_reachable = result.is_reachable
                reachability_score = result.reachability_score
                reachability_reason = result.reason
                entry_points = result.entry_points if result.entry_points else None
                call_path = result.call_path if result.call_path else None

                if not is_reachable:
                    logger.debug(
                        "Unreachable code detected: %s:%s - %s",
                        finding.file_path,
                        finding.line_start,
                        reachability_reason,
                    )
            except Exception as e:
                logger.warning("Reachability analysis failed: %s", str(e))

        return CodeContext(
            snippet=snippet,
            function_name=function_name,
            class_name=class_name,
            is_test_file=is_test_file,
            is_generated=is_generated,
            imports=imports,
            is_reachable=is_reachable,
            reachability_score=reachability_score,
            reachability_reason=reachability_reason,
            entry_points=entry_points,
            call_path=call_path,
        )

    def _get_function_scope(self, lines: List[str], target_line: int) -> Optional[str]:
        patterns = [
            re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("),
            re.compile(r"^\s*(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("),
            re.compile(
                r"^\s*(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:async\s+)?function\b"
            ),
            re.compile(
                r"^\s*(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:async\s+)?\("
            ),
            re.compile(
                r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\("
            ),
        ]

        for idx in range(target_line - 1, -1, -1):
            line = lines[idx]
            for pattern in patterns:
                match = pattern.match(line)
                if match:
                    return match.group(1)
        return None

    def _get_class_scope(self, lines: List[str], target_line: int) -> Optional[str]:
        pattern = re.compile(
            r"^\s*(?:export\s+)?(?:public\s+|private\s+|protected\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)"
        )
        for idx in range(target_line - 1, -1, -1):
            match = pattern.match(lines[idx])
            if match:
                return match.group(1)
        return None

    def _is_test_file(self, file_path: str) -> bool:
        lower = file_path.lower().replace("\\", "/")
        name = Path(lower).name
        if "__tests__" in lower or "/tests/" in lower:
            return True
        if name.startswith("test_"):
            return True
        if name.endswith("_test.py") or name.endswith("_test.go"):
            return True
        if name.endswith(".spec.js") or name.endswith(".spec.ts"):
            return True
        return False

    def _is_generated_file(self, lines: List[str]) -> bool:
        head = "\n".join(lines[:10]).lower()
        markers = [
            "@generated",
            "auto-generated",
            "autogenerated",
            "generated by",
            "do not edit",
        ]
        return any(marker in head for marker in markers)

    def _extract_imports(self, lines: List[str], limit: int = 30) -> List[str]:
        imports: List[str] = []
        import_patterns = [
            re.compile(r"^\s*import\s+"),
            re.compile(r"^\s*from\s+\S+\s+import\s+"),
            re.compile(r"^\s*require\("),
            re.compile(r"^\s*const\s+\S+\s*=\s*require\("),
        ]
        for line in lines:
            stripped = line.strip()
            for pattern in import_patterns:
                if pattern.match(stripped):
                    if stripped and stripped not in imports:
                        imports.append(stripped)
                    break
            if stripped.startswith("import ") and stripped not in imports:
                imports.append(stripped)
            if len(imports) >= limit:
                break
        return imports
