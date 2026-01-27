from __future__ import annotations

import json
import hashlib
import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


class SemgrepError(RuntimeError):
    pass


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SastFindingData:
    rule_id: str
    message: str
    severity: str
    file_path: str
    line_start: int
    line_end: int
    cwe_ids: List[int]
    fingerprint: str
    raw: Dict[str, Any]


class SemgrepRunner:
    def __init__(self, semgrep_path: str = "semgrep") -> None:
        self.semgrep_path = semgrep_path

    def _local_available(self) -> bool:
        return shutil.which(self.semgrep_path) is not None

    def _docker_available(self) -> bool:
        return shutil.which("docker") is not None

    def run(
        self,
        repo_path: Path,
        *,
        config: str,
        timeout_seconds: int,
        docker_image: Optional[str] = None,
    ) -> List[SastFindingData]:
        if self._local_available():
            cmd = self._build_local_cmd(repo_path, config)
            try:
                output = self._run_cmd(cmd, timeout_seconds)
                return parse_semgrep_output(output)
            except SemgrepError as exc:
                if docker_image and self._docker_available():
                    logger.warning(
                        "Local Semgrep failed (%s). Falling back to Docker image %s.",
                        exc,
                        docker_image,
                    )
                    cmd = self._build_docker_cmd(repo_path, config, docker_image)
                    output = self._run_cmd(cmd, timeout_seconds)
                    return parse_semgrep_output(output)
                raise

        if docker_image and self._docker_available():
            cmd = self._build_docker_cmd(repo_path, config, docker_image)
            output = self._run_cmd(cmd, timeout_seconds)
            return parse_semgrep_output(output)

        raise SemgrepError(
            "Semgrep CLI is not available. Install semgrep or enable Docker for the semgrep image."
        )

    def _build_local_cmd(self, repo_path: Path, config: str) -> List[str]:
        normalized = _normalize_config_path(repo_path, config, docker_mode=False)
        cmd = [
            self.semgrep_path,
            "--json",
            "--quiet",
        ]
        cmd.extend(_metrics_args(normalized))
        cmd.extend(["--config", normalized, str(repo_path)])
        return cmd

    def _build_docker_cmd(
        self, repo_path: Path, config: str, docker_image: str
    ) -> List[str]:
        normalized = _normalize_config_path(repo_path, config, docker_mode=True)
        repo_abs = repo_path.resolve()
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{repo_abs}:/src",
            "-w",
            "/src",
            docker_image,
            "semgrep",
            "--json",
            "--quiet",
        ]
        cmd.extend(_metrics_args(normalized))
        cmd.extend(["--config", normalized, "/src"])
        return cmd

    def _run_cmd(self, cmd: List[str], timeout_seconds: int) -> str:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout_seconds,
            )
        except FileNotFoundError as exc:
            raise SemgrepError("Semgrep CLI or Docker is not available") from exc
        except subprocess.TimeoutExpired as exc:
            raise SemgrepError(f"Semgrep timed out after {timeout_seconds}s") from exc

        stdout = result.stdout or ""
        stderr = result.stderr or ""
        if result.returncode not in (0, 1):
            detail = stderr.strip() or stdout.strip() or "Unknown semgrep error"
            raise SemgrepError(f"Semgrep failed: {detail}")

        return stdout


def _normalize_config_path(repo_path: Path, config: str, *, docker_mode: bool) -> str:
    value = (config or "auto").strip() or "auto"
    if value == "auto":
        return "auto"

    path = Path(value)
    if path.is_absolute():
        if not path.exists():
            return value
        if docker_mode:
            try:
                relative = path.relative_to(repo_path)
            except ValueError:
                raise SemgrepError(
                    "Semgrep config must be inside the repo when using Docker."
                ) from None
            return f"/src/{relative.as_posix()}"
        return str(path)

    candidate = repo_path / value
    if candidate.exists():
        return f"/src/{value}" if docker_mode else str(candidate)

    return value


def _metrics_args(normalized_config: str) -> List[str]:
    if normalized_config == "auto":
        logger.info("Semgrep config set to auto; leaving metrics enabled.")
        return []
    return ["--metrics", "off"]


def parse_semgrep_output(output: str) -> List[SastFindingData]:
    try:
        parsed = json.loads(output or "{}")
    except json.JSONDecodeError as exc:
        raise SemgrepError("Semgrep returned invalid JSON output") from exc

    findings: List[SastFindingData] = []
    for result in parsed.get("results", []) or []:
        extra = result.get("extra") or {}
        start = result.get("start") or {}
        end = result.get("end") or {}

        rule_id = str(result.get("check_id") or "")
        message = str(extra.get("message") or "")
        severity = str(extra.get("severity") or "INFO").upper()
        file_path = str(result.get("path") or "")
        line_start = int(start.get("line") or 1)
        line_end = int(end.get("line") or line_start)
        cwe_ids = _extract_cwe_ids(extra.get("metadata") or {})
        fingerprint = str(extra.get("fingerprint") or "")
        if not fingerprint:
            fingerprint = _stable_fingerprint(
                rule_id, file_path, line_start, line_end, message
            )
        findings.append(
            SastFindingData(
                rule_id=rule_id,
                message=message,
                severity=severity,
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                cwe_ids=cwe_ids,
                fingerprint=fingerprint,
                raw=result,
            )
        )
    return findings


def _stable_fingerprint(
    rule_id: str, file_path: str, line_start: int, line_end: int, message: str
) -> str:
    payload = f"{rule_id}:{file_path}:{line_start}:{line_end}:{message}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _extract_cwe_ids(metadata: Dict[str, Any]) -> List[int]:
    cwe_value = metadata.get("cwe") or metadata.get("cwe_id") or []
    if not cwe_value:
        return []
    values: List[Any]
    if isinstance(cwe_value, list):
        values = cwe_value
    else:
        values = [cwe_value]

    cwe_ids: List[int] = []
    for item in values:
        if item is None:
            continue
        text = str(item)
        digits = "".join(ch for ch in text if ch.isdigit())
        if not digits:
            continue
        try:
            cwe_ids.append(int(digits))
        except ValueError:
            continue
    return sorted(set(cwe_ids))
