from __future__ import annotations

import asyncio
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..config import get_settings
from ..integrations.github_client import GitHubClient
from ..models import Finding, Scan
from .intelligence.llm_service import LLMClient, get_llm_service
from .scanner.repo_fetcher import RepoFetcher


@dataclass
class AutoFixResult:
    status: str
    patch: Optional[str] = None
    summary: Optional[str] = None
    confidence: Optional[float] = None
    pr_url: Optional[str] = None
    branch: Optional[str] = None
    error: Optional[str] = None


@dataclass
class FixPlaybook:
    name: str
    keywords: tuple[str, ...]
    languages: tuple[str, ...]
    guidance: str


class AutoFixService:
    def __init__(
        self,
        llm_client: LLMClient | None = None,
        git_path: str = "git",
        max_patch_lines: int = 160,
    ) -> None:
        settings = get_settings()
        self.llm_client = llm_client or get_llm_service(settings)
        self.repo_fetcher = RepoFetcher(git_path=git_path)
        self.git_path = git_path
        self.max_patch_lines = max_patch_lines

    async def generate_fix(
        self,
        *,
        finding: Finding,
        scan: Scan,
        github_token: Optional[str],
        create_pr: bool = False,
        regenerate: bool = False,
    ) -> AutoFixResult:
        eligibility_error = self._eligibility_error(finding)
        if eligibility_error:
            return AutoFixResult(status="failed", error=eligibility_error)

        category = self._select_playbook(finding)
        if category is None:
            return AutoFixResult(
                status="failed",
                error="Finding is not in the auto-fix allowlist.",
            )

        if create_pr and not github_token:
            return AutoFixResult(
                status="failed",
                error="GitHub token is required to open a PR.",
            )

        if not scan.repo_url:
            return AutoFixResult(
                status="failed",
                error="Scan repository URL is missing.",
            )

        repo_path = None
        try:
            repo_path, resolved_branch = await self.repo_fetcher.clone(
                scan.repo_url,
                branch=scan.branch,
                github_token=github_token,
            )
            if resolved_branch != scan.branch:
                scan.branch = resolved_branch

            target_file = repo_path / finding.file_path
            if not target_file.is_file():
                return AutoFixResult(
                    status="failed",
                    error="Finding file not found in repository clone.",
                )

            patch = None
            summary = None
            confidence = None

            if not regenerate and getattr(finding, "fix_patch", None):
                patch = finding.fix_patch
                summary = getattr(finding, "fix_summary", None)
                confidence = getattr(finding, "fix_confidence", None)
            else:
                context = self._build_context(target_file, finding)
                prompt = self._build_prompt(finding, category, context)
                response = await self._call_llm(prompt)
                if not response:
                    return AutoFixResult(
                        status="failed",
                        error="LLM is unavailable for auto-fix.",
                    )
                payload, parsed = self._parse_response(response)
                if not parsed:
                    return AutoFixResult(
                        status="failed",
                        error="LLM response was invalid or empty.",
                    )

                if not self._parse_bool(payload.get("fixable", False)):
                    reason = str(payload.get("reason") or payload.get("summary") or "")
                    reason = reason.strip() or "Fix is not safe to apply automatically."
                    return AutoFixResult(status="failed", error=reason)

                patch = str(payload.get("patch") or "").strip()
                summary = str(payload.get("summary") or "").strip() or None
                confidence = self._parse_confidence(payload.get("confidence"))

            if not patch:
                return AutoFixResult(
                    status="failed",
                    error="No patch was generated.",
                )

            validation_error = self._validate_patch(patch, finding.file_path)
            if validation_error:
                return AutoFixResult(status="failed", error=validation_error)

            apply_error = self._apply_patch(repo_path, patch)
            if apply_error:
                return AutoFixResult(status="failed", error=apply_error)

            applied_diff = self._get_diff(repo_path)
            if not applied_diff:
                return AutoFixResult(
                    status="failed",
                    error="Patch applied but produced no diff.",
                )

            branch_name = None
            pr_url = None

            if create_pr:
                branch_name = self._build_branch_name(finding)
                self._configure_git(repo_path)
                self._run_git(repo_path, ["checkout", "-b", branch_name])
                self._run_git(repo_path, ["add", "--", finding.file_path])
                commit_message = f"Fix {finding.rule_id} in {Path(finding.file_path).name}"
                self._run_git(repo_path, ["commit", "-m", commit_message])
                self._run_git(repo_path, ["push", "--set-upstream", "origin", branch_name])

                repo_full_name = self._extract_repo_full_name(scan.repo_url)
                if not repo_full_name:
                    return AutoFixResult(
                        status="failed",
                        error="Could not determine repo owner/name for PR.",
                    )

                pr_title = commit_message
                pr_body = self._build_pr_body(finding, summary, confidence, scan)
                pr_url, pr_number = await asyncio.to_thread(
                    self._create_pr,
                    repo_full_name,
                    github_token,
                    pr_title,
                    pr_body,
                    branch_name,
                    scan.branch,
                )
                if pr_number is not None:
                    comment = self._build_pr_comment(
                        finding, summary, confidence, applied_diff, scan
                    )
                    if comment:
                        try:
                            await asyncio.to_thread(
                                self._comment_on_pr,
                                repo_full_name,
                                github_token,
                                pr_number,
                                comment,
                            )
                        except Exception:
                            pass

            status = "pr_opened" if pr_url else "generated"
            return AutoFixResult(
                status=status,
                patch=applied_diff,
                summary=summary,
                confidence=confidence,
                pr_url=pr_url,
                branch=branch_name,
            )
        except Exception as exc:
            return AutoFixResult(status="failed", error=str(exc))
        finally:
            if repo_path:
                await self.repo_fetcher.cleanup(repo_path)

    def _select_playbook(self, finding: Finding) -> FixPlaybook | None:
        language = self._guess_language(finding.file_path)
        text = f"{finding.rule_id} {finding.rule_message}".lower()
        playbooks = self._playbooks()
        for playbook in playbooks:
            if language not in playbook.languages:
                continue
            if any(keyword in text for keyword in playbook.keywords):
                return playbook
        return None

    def _playbooks(self) -> tuple[FixPlaybook, ...]:
        return (
            FixPlaybook(
                name="sql_injection",
                keywords=("sql", "injection"),
                languages=("python",),
                guidance=(
                    "Use parameterized queries or ORM helpers; do not build SQL strings"
                    " by concatenating or interpolating user input."
                ),
            ),
            FixPlaybook(
                name="command_injection",
                keywords=("command", "shell", "subprocess", "exec"),
                languages=("python",),
                guidance=(
                    "Avoid shell=True; pass command arguments as a list and validate"
                    " user-provided values."
                ),
            ),
            FixPlaybook(
                name="ssrf",
                keywords=("ssrf", "server-side request", "request forgery", "url fetch"),
                languages=("python",),
                guidance=(
                    "Validate URLs against an allowlist and block private or local"
                    " network ranges before making outbound requests."
                ),
            ),
            FixPlaybook(
                name="path_traversal",
                keywords=("path", "traversal", "directory"),
                languages=("python",),
                guidance=(
                    "Join paths safely and ensure resolved paths stay within the"
                    " intended base directory."
                ),
            ),
            FixPlaybook(
                name="xss",
                keywords=(
                    "xss",
                    "cross-site",
                    "cross site",
                    "scripting",
                    "innerhtml",
                    "dangerouslysetinnerhtml",
                ),
                languages=("javascript", "typescript"),
                guidance=(
                    "Avoid injecting raw HTML; sanitize or escape user input, or use"
                    " safe rendering helpers instead of dangerouslySetInnerHTML."
                ),
            ),
        )

    def _eligibility_error(self, finding: Finding) -> Optional[str]:
        if getattr(finding, "finding_type", "sast") != "sast":
            return "Only SAST findings can be auto-fixed."
        if getattr(finding, "is_false_positive", False):
            return "False positives are not eligible for auto-fix."
        if getattr(finding, "is_test_file", False):
            return "Test files are excluded from auto-fix."
        if getattr(finding, "is_generated", False):
            return "Generated files are excluded from auto-fix."
        if not getattr(finding, "is_reachable", True):
            return "Unreachable code is excluded from auto-fix."
        confidence = getattr(finding, "ai_confidence", 0.0) or 0.0
        if confidence < 0.7:
            return "Finding confidence is below the auto-fix threshold."
        severity = (getattr(finding, "ai_severity", "") or "").lower()
        if severity not in {"critical", "high", "medium"}:
            return "Only medium or higher severity findings are auto-fixable."
        language = self._guess_language(finding.file_path)
        if language not in self._supported_languages():
            return "Auto-fix does not support this file type yet."
        return None

    def _supported_languages(self) -> set[str]:
        languages: set[str] = set()
        for playbook in self._playbooks():
            languages.update(playbook.languages)
        return languages

    def _build_context(self, file_path: Path, finding: Finding) -> str:
        try:
            content = file_path.read_text(errors="replace")
        except Exception:
            return finding.context_snippet or finding.code_snippet or ""

        lines = content.splitlines()
        start_line = max(1, int(getattr(finding, "line_start", 1) or 1))
        end_line = max(start_line, int(getattr(finding, "line_end", start_line) or start_line))
        window = 24
        start = max(1, start_line - window)
        end = min(len(lines), end_line + window)

        snippet_lines = []
        for idx in range(start, end + 1):
            line = lines[idx - 1]
            snippet_lines.append(f"{idx:4d}: {line}")
        return "\n".join(snippet_lines)

    def _build_prompt(self, finding: Finding, playbook: FixPlaybook, context: str) -> str:
        language = self._guess_language(finding.file_path)
        guidance = playbook.guidance
        rule_message = finding.rule_message or "n/a"
        severity = getattr(finding, "ai_severity", None) or finding.semgrep_severity

        return (
            "You are ScanGuard AutoFix, a senior security engineer generating minimal"
            " safe patches.\n"
            "Only produce fixes that are low-risk and localized.\n\n"
            "## Finding\n"
            f"- Rule: {finding.rule_id}\n"
            f"- Message: {rule_message}\n"
            f"- Severity: {severity}\n"
            f"- File: {finding.file_path}:{finding.line_start}-{finding.line_end}\n\n"
            "## Guidance\n"
            f"{guidance}\n\n"
            "## Code Context\n"
            f"```{language}\n{context}\n```\n\n"
            "## Constraints\n"
            f"- Only edit {finding.file_path}\n"
            f"- Patch must be <= {self.max_patch_lines} lines\n"
            "- Do not add new third-party dependencies\n"
            "- If a safe fix is unclear, set fixable=false\n\n"
            "## Response (JSON only)\n"
            "{\n"
            "  \"fixable\": true/false,\n"
            "  \"summary\": \"short fix summary\",\n"
            "  \"confidence\": 0.0-1.0,\n"
            "  \"patch\": \"unified diff\",\n"
            "  \"reason\": \"why this fix is safe or why not\"\n"
            "}\n"
        )

    async def _call_llm(self, prompt: str) -> str:
        if not await self.llm_client.is_available():
            return ""
        return await self.llm_client.generate(prompt, system=self._system_prompt())

    def _system_prompt(self) -> str:
        return (
            "You are ScanGuard AutoFix, a security engineer that outputs only valid JSON. "
            "If unsure, mark fixable=false."
        )

    def _parse_response(self, response: str) -> tuple[dict, bool]:
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

    def _parse_confidence(self, value: object) -> Optional[float]:
        try:
            confidence = float(value)
        except (TypeError, ValueError):
            return None
        return max(0.0, min(confidence, 1.0))

    def _parse_bool(self, value: object) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"true", "yes", "1"}
        if isinstance(value, (int, float)):
            return value != 0
        return False

    def _validate_patch(self, patch: str, expected_path: str) -> Optional[str]:
        patch_lines = patch.splitlines()
        if len(patch_lines) > self.max_patch_lines:
            return "Patch exceeds max allowed line count."

        normalized_expected = self._normalize_path(expected_path)
        file_paths = self._extract_patch_paths(patch)
        if not file_paths:
            return "Patch does not include a valid diff header."
        if len(set(file_paths)) != 1:
            return "Patch must touch exactly one file."

        target = next(iter(file_paths))
        if target != normalized_expected:
            return "Patch file does not match the finding file."
        if target.startswith("/") or ".." in target.split("/"):
            return "Patch file path is invalid."
        return None

    def _extract_patch_paths(self, patch: str) -> set[str]:
        paths: set[str] = set()
        for line in patch.splitlines():
            if line.startswith("diff --git "):
                parts = line.strip().split()
                if len(parts) >= 4:
                    left = self._strip_diff_prefix(parts[2])
                    right = self._strip_diff_prefix(parts[3])
                    if left == right:
                        paths.add(left)
            elif line.startswith("--- "):
                left = self._strip_diff_prefix(line.split(" ", 1)[1].strip())
                if left and left != "/dev/null":
                    paths.add(left)
            elif line.startswith("+++ "):
                right = self._strip_diff_prefix(line.split(" ", 1)[1].strip())
                if right and right != "/dev/null":
                    paths.add(right)
        return {self._normalize_path(path) for path in paths if path}

    def _strip_diff_prefix(self, path: str) -> str:
        if path.startswith("a/") or path.startswith("b/"):
            return path[2:]
        return path

    def _apply_patch(self, repo_path: Path, patch: str) -> Optional[str]:
        result = subprocess.run(
            [self.git_path, "-C", str(repo_path), "apply", "--whitespace=nowarn", "-"],
            input=patch,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            return detail or "Failed to apply patch."
        return None

    def _get_diff(self, repo_path: Path) -> Optional[str]:
        result = subprocess.run(
            [self.git_path, "-C", str(repo_path), "diff", "--patch"],
            capture_output=True,
            text=True,
            check=False,
        )
        output = (result.stdout or "").strip()
        return output or None

    def _configure_git(self, repo_path: Path) -> None:
        self._run_git(repo_path, ["config", "user.name", "ScanGuard AI"])
        self._run_git(repo_path, ["config", "user.email", "scanguard-ai@users.noreply.github.com"])

    def _run_git(self, repo_path: Path, args: list[str]) -> None:
        result = subprocess.run(
            [self.git_path, "-C", str(repo_path), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(detail or "Git command failed.")

    def _build_branch_name(self, finding: Finding) -> str:
        short_id = str(getattr(finding, "id", ""))[:8] or "fix"
        rule = re.sub(r"[^a-z0-9]+", "-", finding.rule_id.lower()).strip("-")
        rule = rule[:24] if rule else "finding"
        return f"scanguard/fix-{rule}-{short_id}"

    def _create_pr(
        self,
        repo_full_name: str,
        github_token: Optional[str],
        title: str,
        body: str,
        head: str,
        base: str,
    ) -> tuple[str, Optional[int]]:
        client = GitHubClient(token=github_token or "")
        try:
            return client.create_pull_request(
                repo_full_name,
                title=title,
                body=body,
                head=head,
                base=base,
            )
        finally:
            client.close()

    def _comment_on_pr(
        self,
        repo_full_name: str,
        github_token: Optional[str],
        pr_number: int,
        body: str,
    ) -> None:
        client = GitHubClient(token=github_token or "")
        try:
            client.create_issue_comment(
                repo_full_name,
                issue_number=pr_number,
                body=body,
            )
        finally:
            client.close()

    def _build_pr_body(self, finding: Finding, summary: Optional[str], confidence: Optional[float], scan: Scan) -> str:
        confidence_text = f"{round(confidence * 100)}%" if confidence is not None else "n/a"
        summary_text = summary or "Automated fix generated by ScanGuard AI."
        return (
            "## Summary\n"
            f"{summary_text}\n\n"
            "## Finding\n"
            f"- Rule: {finding.rule_id}\n"
            f"- Severity: {getattr(finding, 'ai_severity', None) or finding.semgrep_severity}\n"
            f"- File: {finding.file_path}:{finding.line_start}\n"
            f"- Scan: {scan.id}\n"
            f"- Finding: {finding.id}\n\n"
            "## Confidence\n"
            f"- Fix confidence: {confidence_text}\n\n"
            "_Generated by ScanGuard AI._"
        )

    def _build_pr_comment(
        self,
        finding: Finding,
        summary: Optional[str],
        confidence: Optional[float],
        diff_text: Optional[str],
        scan: Scan,
    ) -> Optional[str]:
        if not diff_text:
            return None
        summary_text = summary or "AutoFix patch preview."
        confidence_text = f"{round(confidence * 100)}%" if confidence is not None else "n/a"
        diff_block, truncated = self._truncate_diff(diff_text)
        truncated_note = "\n\n(Truncated for brevity.)" if truncated else ""
        return (
            "## ScanGuard AutoFix Patch\n"
            f"{summary_text}\n\n"
            f"- Finding: {finding.rule_id} ({finding.file_path}:{finding.line_start})\n"
            f"- Scan: {scan.id}\n"
            f"- Confidence: {confidence_text}\n\n"
            "```diff\n"
            f"{diff_block}\n"
            "```"
            f"{truncated_note}"
        )

    def _truncate_diff(self, diff_text: str) -> tuple[str, bool]:
        max_lines = 160
        max_chars = 4000
        lines = diff_text.splitlines()
        truncated = False
        if len(lines) > max_lines:
            lines = lines[:max_lines]
            truncated = True
        diff_block = "\n".join(lines)
        if len(diff_block) > max_chars:
            diff_block = diff_block[:max_chars]
            truncated = True
        return diff_block, truncated

    def _guess_language(self, file_path: str) -> str:
        ext = Path(file_path).suffix.lower()
        mapping = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
        }
        return mapping.get(ext, "")

    def _normalize_path(self, value: str) -> str:
        return value.replace("\\", "/")

    def _extract_repo_full_name(self, value: str | None) -> Optional[str]:
        if not value:
            return None

        if value.startswith("http://") or value.startswith("https://"):
            try:
                _, path = value.split("://", 1)
                parts = path.split("/", 1)
                if len(parts) == 2:
                    path_part = parts[1].strip("/")
                    segments = [s for s in path_part.split("/") if s]
                    if len(segments) >= 2:
                        return f"{segments[0]}/{segments[1]}"
            except ValueError:
                return None

        match = re.search(r":(?P<owner>[^/]+)/(?P<repo>[^/]+)$", value)
        if match:
            owner = match.group("owner")
            repo = match.group("repo")
            if owner and repo:
                return f"{owner}/{repo}"

        return None
