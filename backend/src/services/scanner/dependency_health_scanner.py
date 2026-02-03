from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import quote

import httpx
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from ...config import get_settings
from ...services.intelligence.llm_service import LLMClient, get_llm_service
from .types import DependencyHealthFinding

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore


@dataclass
class DependencySpec:
    name: str
    ecosystem: str
    specifier: Optional[str]
    version: Optional[str]
    dependency_type: str
    file_path: str
    display: Optional[str] = None


class DependencyHealthScanner:
    def __init__(
        self,
        llm_client: LLMClient | None = None,
        max_concurrency: int = 6,
        registry_timeout_seconds: float = 10.0,
    ) -> None:
        settings = get_settings()
        self.use_llm = bool(settings.dependency_health_use_llm)
        self.llm_client = llm_client or get_llm_service(settings)
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.registry_timeout_seconds = registry_timeout_seconds

    async def scan(self, repo_path: Path) -> list[DependencyHealthFinding]:
        specs = self._collect_specs(repo_path)
        if not specs:
            return []

        async with httpx.AsyncClient(timeout=self.registry_timeout_seconds) as client:
            npm_meta = await self._fetch_npm_metadata(
                client, {spec.name for spec in specs if spec.ecosystem == "npm"}
            )
            pypi_meta = await self._fetch_pypi_metadata(
                client, {spec.name for spec in specs if spec.ecosystem == "pypi"}
            )

        findings: list[DependencyHealthFinding] = []
        for spec in specs:
            if spec.ecosystem == "npm":
                meta = npm_meta.get(spec.name)
                finding = self._evaluate_npm(spec, meta)
            else:
                meta = pypi_meta.get(spec.name.lower())
                finding = self._evaluate_pypi(spec, meta)
            if finding:
                findings.append(finding)

        if self.use_llm:
            findings = await self._apply_llm(findings)

        return findings

    def _collect_specs(self, repo_path: Path) -> list[DependencySpec]:
        specs: list[DependencySpec] = []
        specs.extend(self._collect_npm_specs(repo_path))
        specs.extend(self._collect_python_specs(repo_path))
        return self._dedupe_specs(specs)

    def _collect_npm_specs(self, repo_path: Path) -> list[DependencySpec]:
        specs: list[DependencySpec] = []
        for package_path in self._iter_files(repo_path, "package.json"):
            data = self._load_json(package_path)
            if not isinstance(data, dict):
                continue
            lock_path = self._resolve_lock_path(package_path.parent)
            lock_data = self._load_json(lock_path) if lock_path else None
            version_map = self._extract_npm_lock_versions(lock_data)
            relative = self._relative_path(repo_path, package_path)
            for dep_type, key in (
                ("runtime", "dependencies"),
                ("dev", "devDependencies"),
                ("optional", "optionalDependencies"),
                ("peer", "peerDependencies"),
            ):
                deps = data.get(key) or {}
                if not isinstance(deps, dict):
                    continue
                for name, requirement in deps.items():
                    if not name or not isinstance(name, str):
                        continue
                    requirement_text = str(requirement) if requirement is not None else ""
                    specs.append(
                        DependencySpec(
                            name=name,
                            ecosystem="npm",
                            specifier=requirement_text or None,
                            version=version_map.get(name),
                            dependency_type=dep_type,
                            file_path=relative,
                            display=self._format_display(name, requirement_text),
                        )
                    )
        return specs

    def _collect_python_specs(self, repo_path: Path) -> list[DependencySpec]:
        specs: list[DependencySpec] = []
        for req_path in self._iter_requirements_files(repo_path):
            specs.extend(self._parse_requirements_file(repo_path, req_path))
        for pyproject_path in self._iter_files(repo_path, "pyproject.toml"):
            specs.extend(self._parse_pyproject(repo_path, pyproject_path))
        return specs

    async def _fetch_npm_metadata(
        self, client: httpx.AsyncClient, names: Iterable[str]
    ) -> dict[str, Optional[dict]]:
        results: dict[str, Optional[dict]] = {}

        async def fetch(name: str) -> None:
            encoded = quote(name, safe="")
            url = f"https://registry.npmjs.org/{encoded}"
            async with self.semaphore:
                try:
                    response = await client.get(url)
                except httpx.RequestError:
                    results[name] = None
                    return
            if response.status_code != 200:
                results[name] = None
                return
            try:
                results[name] = response.json()
            except ValueError:
                results[name] = None

        await asyncio.gather(*[fetch(name) for name in names])
        return results

    async def _fetch_pypi_metadata(
        self, client: httpx.AsyncClient, names: Iterable[str]
    ) -> dict[str, Optional[dict]]:
        results: dict[str, Optional[dict]] = {}

        async def fetch(name: str) -> None:
            normalized = name.lower()
            url = f"https://pypi.org/pypi/{normalized}/json"
            async with self.semaphore:
                try:
                    response = await client.get(url)
                except httpx.RequestError:
                    results[normalized] = None
                    return
            if response.status_code != 200:
                results[normalized] = None
                return
            try:
                results[normalized] = response.json()
            except ValueError:
                results[normalized] = None

        await asyncio.gather(*[fetch(name) for name in names])
        return results

    def _evaluate_npm(
        self, spec: DependencySpec, meta: Optional[dict]
    ) -> Optional[DependencyHealthFinding]:
        if not meta:
            return None
        versions = meta.get("versions") or {}
        dist_tags = meta.get("dist-tags") or {}
        latest = dist_tags.get("latest")
        installed = spec.version or self._extract_exact_npm_version(spec.specifier)
        deprecated_reason = None
        status = None

        if installed and installed in versions:
            deprecated_reason = versions.get(installed, {}).get("deprecated")
            if deprecated_reason:
                status = "deprecated"

        if status is None:
            if installed and latest and self._compare_semver(installed, latest) < 0:
                status = "outdated"
            elif spec.specifier and latest:
                satisfies = self._npm_spec_satisfies(spec.specifier, latest)
                if satisfies is False:
                    status = "outdated"

        if not status:
            return None

        severity = self._base_severity(status, deprecated_reason, is_yanked=False)
        reasoning = self._build_reasoning(
            status=status,
            installed=installed,
            latest=latest,
            deprecation_reason=deprecated_reason,
            is_yanked=False,
        )
        description = self._build_description(
            spec=spec,
            status=status,
            installed=installed,
            latest=latest,
            deprecation_reason=deprecated_reason,
            is_yanked=False,
        )
        remediation = self._build_remediation(status, latest)

        return DependencyHealthFinding(
            package_name=spec.name,
            ecosystem="npm",
            status=status,
            installed_version=installed,
            latest_version=latest,
            requirement=spec.specifier,
            dependency_type=spec.dependency_type,
            file_path=spec.file_path,
            deprecation_reason=deprecated_reason,
            is_yanked=False,
            ai_severity=severity,
            ai_confidence=0.75 if status == "deprecated" else 0.45,
            ai_reasoning=reasoning,
            description=description,
            remediation=remediation,
        )

    def _evaluate_pypi(
        self, spec: DependencySpec, meta: Optional[dict]
    ) -> Optional[DependencyHealthFinding]:
        if not meta:
            return None
        info = meta.get("info") or {}
        releases = meta.get("releases") or {}
        latest = info.get("version")
        classifiers = info.get("classifiers") or []
        inactive = any(
            str(item).startswith("Development Status :: 7 - Inactive")
            for item in classifiers
        )

        installed = spec.version or self._extract_exact_pypi_version(spec.specifier)
        status = None
        deprecation_reason = None
        is_yanked = False

        if installed and installed in releases:
            is_yanked, deprecation_reason = self._is_yanked_release(
                releases.get(installed) or []
            )
            if is_yanked:
                status = "deprecated"

        if status is None and inactive:
            status = "deprecated"
            deprecation_reason = "Project marked inactive in PyPI classifiers."

        if status is None:
            if installed and latest and self._compare_versions(installed, latest) < 0:
                status = "outdated"
            elif spec.specifier and latest:
                satisfies = self._pypi_spec_satisfies(spec.specifier, latest)
                if satisfies is False:
                    status = "outdated"

        if not status:
            return None

        severity = self._base_severity(status, deprecation_reason, is_yanked)
        reasoning = self._build_reasoning(
            status=status,
            installed=installed,
            latest=latest,
            deprecation_reason=deprecation_reason,
            is_yanked=is_yanked,
        )
        description = self._build_description(
            spec=spec,
            status=status,
            installed=installed,
            latest=latest,
            deprecation_reason=deprecation_reason,
            is_yanked=is_yanked,
        )
        remediation = self._build_remediation(status, latest)

        return DependencyHealthFinding(
            package_name=spec.name,
            ecosystem="pypi",
            status=status,
            installed_version=installed,
            latest_version=latest,
            requirement=spec.specifier,
            dependency_type=spec.dependency_type,
            file_path=spec.file_path,
            deprecation_reason=deprecation_reason,
            is_yanked=is_yanked,
            ai_severity=severity,
            ai_confidence=0.75 if status == "deprecated" else 0.45,
            ai_reasoning=reasoning,
            description=description,
            remediation=remediation,
        )

    async def _apply_llm(
        self, findings: list[DependencyHealthFinding]
    ) -> list[DependencyHealthFinding]:
        try:
            if not await self.llm_client.is_available():
                return findings
        except Exception:
            return findings

        targets = [finding for finding in findings if finding.status == "deprecated"]
        if not targets:
            return findings

        async def enrich(finding: DependencyHealthFinding) -> None:
            prompt = self._build_llm_prompt(finding)
            response = await self._call_llm(prompt)
            data = self._parse_llm_response(response)
            if not data:
                return
            severity = self._normalize_ai_severity(
                str(data.get("adjusted_severity") or data.get("ai_severity") or "")
            )
            if severity:
                finding.ai_severity = severity
            confidence = self._parse_confidence(data.get("confidence"))
            if confidence is not None:
                finding.ai_confidence = confidence
            reasoning = str(data.get("reasoning") or "").strip()
            if reasoning:
                finding.ai_reasoning = reasoning

        await asyncio.gather(*[enrich(item) for item in targets])
        return findings

    async def _call_llm(self, prompt: str) -> str:
        async with self.semaphore:
            try:
                return await asyncio.wait_for(
                    self.llm_client.generate(prompt, system=self._llm_system_prompt()),
                    timeout=30.0,
                )
            except Exception:
                return ""

    def _llm_system_prompt(self) -> str:
        return (
            "You are BugBunny, a dependency risk analyst.\n"
            "Assess deprecated or yanked dependencies for operational risk.\n"
            "Return only valid JSON."
        )

    def _build_llm_prompt(self, finding: DependencyHealthFinding) -> str:
        return (
            "## Dependency Finding\n"
            f"- Ecosystem: {finding.ecosystem}\n"
            f"- Package: {finding.package_name}\n"
            f"- Status: {finding.status}\n"
            f"- Installed: {finding.installed_version or 'unknown'}\n"
            f"- Latest: {finding.latest_version or 'unknown'}\n"
            f"- Dependency type: {finding.dependency_type}\n"
            f"- File: {finding.file_path}\n"
            f"- Deprecated reason: {finding.deprecation_reason or 'none'}\n"
            f"- Yanked: {finding.is_yanked}\n\n"
            "## Task\n"
            "Return JSON:\n"
            "{\n"
            '  "adjusted_severity": "critical|high|medium|low|info",\n'
            '  "confidence": 0.0-1.0,\n'
            '  "reasoning": "Brief explanation"\n'
            "}\n"
        )

    def _parse_llm_response(self, response: str) -> dict | None:
        if not response:
            return None
        text = response.strip()
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        payload = text[start : end + 1]
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    def _normalize_ai_severity(self, value: str) -> Optional[str]:
        value = value.strip().lower()
        if value in {"critical", "high", "medium", "low", "info"}:
            return value
        return None

    def _parse_confidence(self, value: object) -> Optional[float]:
        try:
            confidence = float(value)
        except (TypeError, ValueError):
            return None
        return max(0.0, min(confidence, 1.0))

    def _build_reasoning(
        self,
        *,
        status: str,
        installed: Optional[str],
        latest: Optional[str],
        deprecation_reason: Optional[str],
        is_yanked: bool,
    ) -> str:
        if status == "deprecated":
            reason = deprecation_reason or "Registry flagged this package/version as deprecated."
            if is_yanked:
                reason = f"Yanked release. {reason}".strip()
            return reason
        if installed and latest:
            return f"Installed version {installed} is behind latest {latest}."
        return "Dependency is behind the latest available release."

    def _build_description(
        self,
        *,
        spec: DependencySpec,
        status: str,
        installed: Optional[str],
        latest: Optional[str],
        deprecation_reason: Optional[str],
        is_yanked: bool,
    ) -> str:
        parts = [f"{spec.ecosystem} dependency {spec.name}"]
        if installed:
            parts.append(f"installed {installed}")
        if latest:
            parts.append(f"latest {latest}")
        if status == "deprecated":
            parts.append("marked deprecated")
            if is_yanked:
                parts.append("(yanked)")
            if deprecation_reason:
                parts.append(f"reason: {deprecation_reason}")
        else:
            parts.append("is outdated")
        return ". ".join(part.strip() for part in parts if part).strip(". ")

    def _build_remediation(self, status: str, latest: Optional[str]) -> str:
        if latest:
            return f"Upgrade to {latest}."
        if status == "deprecated":
            return "Replace with a maintained alternative."
        return "Update to a supported version."

    def _base_severity(
        self, status: str, reason: Optional[str], is_yanked: bool
    ) -> str:
        if status == "outdated":
            return "low"
        lowered = (reason or "").lower()
        high_keywords = [
            "security",
            "vulnerab",
            "rce",
            "remote",
            "exploit",
            "critical",
            "eol",
            "end of life",
            "unsupported",
            "unmaintained",
        ]
        if is_yanked or any(term in lowered for term in high_keywords):
            return "high"
        return "medium"

    def _extract_exact_npm_version(self, specifier: Optional[str]) -> Optional[str]:
        if not specifier:
            return None
        raw = specifier.strip()
        if raw and re.fullmatch(r"v?\d+(\.\d+){0,2}([-+].+)?", raw):
            return raw.lstrip("v")
        return None

    def _extract_exact_pypi_version(self, specifier: Optional[str]) -> Optional[str]:
        if not specifier:
            return None
        try:
            spec = SpecifierSet(specifier)
        except Exception:
            return None
        items = list(spec)
        if len(items) != 1:
            return None
        item = items[0]
        if item.operator == "==" and "*" not in item.version:
            return item.version
        return None

    def _compare_versions(self, left: str, right: str) -> int:
        left_v = self._safe_version(left)
        right_v = self._safe_version(right)
        if not left_v or not right_v:
            return 0
        if left_v < right_v:
            return -1
        if left_v > right_v:
            return 1
        return 0

    def _safe_version(self, value: str) -> Optional[Version]:
        try:
            return Version(value)
        except InvalidVersion:
            return None

    def _pypi_spec_satisfies(self, specifier: str, latest: str) -> Optional[bool]:
        try:
            spec = SpecifierSet(specifier)
            version = Version(latest)
        except (InvalidVersion, Exception):
            return None
        if not spec:
            return True
        return version in spec

    def _npm_spec_satisfies(self, specifier: str, latest: str) -> Optional[bool]:
        specifier = specifier.strip()
        if not specifier or specifier in {"*", "latest"}:
            return True
        if "||" in specifier:
            return None
        exact = self._extract_exact_npm_version(specifier)
        if exact:
            return self._compare_semver(exact, latest) == 0
        if specifier.startswith("^") or specifier.startswith("~"):
            lower = specifier[1:]
            upper = self._upper_bound_from_prefix(lower, caret=specifier.startswith("^"))
            return self._semver_in_range(latest, lower, upper)
        if self._has_range_operators(specifier):
            constraints = self._parse_npm_constraints(specifier)
            if constraints is None:
                return None
            return all(self._eval_constraint(latest, op, ver) for op, ver in constraints)
        return None

    def _has_range_operators(self, specifier: str) -> bool:
        return any(op in specifier for op in [">", "<", "="])

    def _parse_npm_constraints(
        self, specifier: str
    ) -> Optional[list[tuple[str, str]]]:
        constraints: list[tuple[str, str]] = []
        tokens = specifier.replace(",", " ").split()
        for token in tokens:
            match = re.match(r"(>=|<=|>|<|=)?\s*(.+)", token)
            if not match:
                return None
            op = match.group(1) or "="
            version = match.group(2).lstrip("v")
            if not version or "x" in version or "*" in version:
                return None
            constraints.append((op, version))
        return constraints

    def _eval_constraint(self, latest: str, operator: str, version: str) -> bool:
        cmp_val = self._compare_semver(latest, version)
        if operator == ">":
            return cmp_val > 0
        if operator == ">=":
            return cmp_val >= 0
        if operator == "<":
            return cmp_val < 0
        if operator == "<=":
            return cmp_val <= 0
        return cmp_val == 0

    def _upper_bound_from_prefix(self, base: str, caret: bool) -> Optional[str]:
        parsed = self._parse_semver(base)
        if not parsed:
            return None
        major, minor, patch, _ = parsed
        if caret:
            if major > 0:
                return f"{major + 1}.0.0"
            if minor > 0:
                return f"0.{minor + 1}.0"
            return f"0.0.{patch + 1}"
        return f"{major}.{minor + 1}.0"

    def _semver_in_range(
        self, value: str, lower: Optional[str], upper: Optional[str]
    ) -> Optional[bool]:
        if lower and self._compare_semver(value, lower) < 0:
            return False
        if upper and self._compare_semver(value, upper) >= 0:
            return False
        return True

    def _compare_semver(self, left: str, right: str) -> int:
        left_parsed = self._parse_semver(left)
        right_parsed = self._parse_semver(right)
        if not left_parsed or not right_parsed:
            return 0
        if left_parsed[:3] != right_parsed[:3]:
            return (left_parsed[:3] > right_parsed[:3]) - (
                left_parsed[:3] < right_parsed[:3]
            )
        return self._compare_prerelease(left_parsed[3], right_parsed[3])

    def _parse_semver(
        self, value: str
    ) -> Optional[tuple[int, int, int, tuple]]:
        if not value:
            return None
        cleaned = value.strip().lstrip("v").split("+", 1)[0]
        main, _, prerelease = cleaned.partition("-")
        parts = main.split(".")
        try:
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            patch = int(parts[2]) if len(parts) > 2 else 0
        except (ValueError, IndexError):
            return None
        pre_parts = (
            tuple(self._parse_prerelease_part(part) for part in prerelease.split("."))
            if prerelease
            else ()
        )
        return major, minor, patch, pre_parts

    def _parse_prerelease_part(self, value: str) -> tuple[int, str | int]:
        if value.isdigit():
            return (0, int(value))
        return (1, value)

    def _compare_prerelease(self, left: tuple, right: tuple) -> int:
        if not left and not right:
            return 0
        if not left:
            return 1
        if not right:
            return -1
        for l_part, r_part in zip(left, right):
            if l_part == r_part:
                continue
            return (l_part > r_part) - (l_part < r_part)
        return (len(left) > len(right)) - (len(left) < len(right))

    def _iter_requirements_files(self, repo_path: Path) -> Iterable[Path]:
        for path in repo_path.rglob("requirements*.txt"):
            if self._should_skip(path):
                continue
            yield path

    def _parse_requirements_file(
        self, repo_path: Path, path: Path
    ) -> list[DependencySpec]:
        specs: list[DependencySpec] = []
        dep_type = "dev" if "dev" in path.name.lower() else "runtime"
        seen: set[Path] = set()

        def parse_file(file_path: Path) -> None:
            if file_path in seen or not file_path.is_file():
                return
            seen.add(file_path)
            current_relative = self._relative_path(repo_path, file_path)
            for line in file_path.read_text(
                encoding="utf-8", errors="ignore"
            ).splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                stripped = stripped.split("#", 1)[0].strip()
                if not stripped:
                    continue
                if stripped.startswith("-r") or stripped.startswith("--requirement"):
                    parts = stripped.split(maxsplit=1)
                    if len(parts) == 2:
                        include_path = (file_path.parent / parts[1]).resolve()
                        parse_file(include_path)
                    continue
                if stripped.startswith("-e") or stripped.startswith("--editable"):
                    parts = stripped.split(maxsplit=1)
                    stripped = parts[1] if len(parts) == 2 else ""
                if stripped.startswith("-"):
                    continue
                try:
                    req = Requirement(stripped)
                except Exception:
                    continue
                if not req.name or req.url:
                    continue
                specifier = str(req.specifier) if req.specifier else None
                version = self._extract_exact_pypi_version(specifier)
                specs.append(
                    DependencySpec(
                        name=req.name,
                        ecosystem="pypi",
                        specifier=specifier,
                        version=version,
                        dependency_type=dep_type,
                        file_path=current_relative,
                        display=stripped,
                    )
                )

        parse_file(path)
        return specs

    def _parse_pyproject(
        self, repo_path: Path, path: Path
    ) -> list[DependencySpec]:
        specs: list[DependencySpec] = []
        data = self._load_toml(path)
        if not isinstance(data, dict):
            return specs

        relative = self._relative_path(repo_path, path)
        poetry_lock = self._load_poetry_lock(path.parent)

        project = data.get("project") or {}
        if isinstance(project, dict):
            deps = project.get("dependencies") or []
            specs.extend(
                self._parse_python_dependency_list(
                    deps, "runtime", relative, poetry_lock
                )
            )
            optional = project.get("optional-dependencies") or {}
            if isinstance(optional, dict):
                for values in optional.values():
                    specs.extend(
                        self._parse_python_dependency_list(
                            values, "optional", relative, poetry_lock
                        )
                    )

        tool = data.get("tool") or {}
        poetry = tool.get("poetry") or {}
        if isinstance(poetry, dict):
            for dep_type, key in (
                ("runtime", "dependencies"),
                ("dev", "dev-dependencies"),
            ):
                items = poetry.get(key) or {}
                specs.extend(
                    self._parse_poetry_table(items, dep_type, relative, poetry_lock)
                )
            groups = poetry.get("group") or {}
            if isinstance(groups, dict):
                for group in groups.values():
                    if not isinstance(group, dict):
                        continue
                    items = group.get("dependencies") or {}
                    specs.extend(
                        self._parse_poetry_table(
                            items, "dev", relative, poetry_lock
                        )
                    )

        return specs

    def _parse_python_dependency_list(
        self,
        values: Any,
        dep_type: str,
        file_path: str,
        poetry_lock: dict[str, str],
    ) -> list[DependencySpec]:
        specs: list[DependencySpec] = []
        if not isinstance(values, list):
            return specs
        for entry in values:
            if not isinstance(entry, str):
                continue
            try:
                req = Requirement(entry)
            except Exception:
                continue
            if not req.name or req.name.lower() == "python" or req.url:
                continue
            specifier = str(req.specifier) if req.specifier else None
            version = poetry_lock.get(req.name.lower()) or self._extract_exact_pypi_version(
                specifier
            )
            specs.append(
                DependencySpec(
                    name=req.name,
                    ecosystem="pypi",
                    specifier=specifier,
                    version=version,
                    dependency_type=dep_type,
                    file_path=file_path,
                    display=entry,
                )
            )
        return specs

    def _parse_poetry_table(
        self,
        values: Any,
        dep_type: str,
        file_path: str,
        poetry_lock: dict[str, str],
    ) -> list[DependencySpec]:
        specs: list[DependencySpec] = []
        if not isinstance(values, dict):
            return specs
        for name, entry in values.items():
            if name.lower() == "python":
                continue
            current_type = dep_type
            if isinstance(entry, str):
                spec_raw = entry
            elif isinstance(entry, dict):
                spec_raw = entry.get("version") or ""
                if entry.get("optional") is True:
                    current_type = "optional"
            else:
                continue
            specifier = self._normalize_poetry_specifier(str(spec_raw).strip())
            version = poetry_lock.get(name.lower()) or self._extract_exact_pypi_version(
                specifier
            )
            specs.append(
                DependencySpec(
                    name=name,
                    ecosystem="pypi",
                    specifier=specifier,
                    version=version,
                    dependency_type=current_type,
                    file_path=file_path,
                    display=self._format_display(name, spec_raw),
                )
            )
        return specs

    def _normalize_poetry_specifier(self, value: str) -> Optional[str]:
        if not value or value in {"*", "latest"}:
            return None
        if re.fullmatch(r"v?\d+(\.\d+)*", value):
            return f"=={value.lstrip('v')}"
        if value.startswith("^"):
            lower = value[1:]
            upper = self._upper_bound_from_prefix(lower, caret=True)
            if upper:
                return f">={lower},<{upper}"
            return f">={lower}"
        if value.startswith("~"):
            lower = value[1:]
            upper = self._upper_bound_from_prefix(lower, caret=False)
            if upper:
                return f">={lower},<{upper}"
            return f">={lower}"
        return value

    def _load_poetry_lock(self, root: Path) -> dict[str, str]:
        lock_path = root / "poetry.lock"
        data = self._load_toml(lock_path)
        if not isinstance(data, dict):
            return {}
        packages = data.get("package") or []
        if not isinstance(packages, list):
            return {}
        mapping: dict[str, str] = {}
        for entry in packages:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").lower()
            version = str(entry.get("version") or "")
            if name and version:
                mapping[name] = version
        return mapping

    def _is_yanked_release(self, files: list) -> tuple[bool, Optional[str]]:
        if not files:
            return False, None
        reasons = []
        all_yanked = True
        for entry in files:
            if not isinstance(entry, dict):
                continue
            yanked = bool(entry.get("yanked"))
            if not yanked:
                all_yanked = False
            reason = entry.get("yanked_reason")
            if reason:
                reasons.append(str(reason))
        if not all_yanked:
            return False, None
        reason_text = reasons[0] if reasons else "Release is yanked on PyPI."
        return True, reason_text

    def _dedupe_specs(self, specs: list[DependencySpec]) -> list[DependencySpec]:
        deduped: dict[tuple[str, str, str], DependencySpec] = {}
        for spec in specs:
            key = (spec.ecosystem, spec.name, spec.file_path)
            current = deduped.get(key)
            if current is None:
                deduped[key] = spec
            elif not current.version and spec.version:
                deduped[key] = spec
        return list(deduped.values())

    def _iter_files(self, repo_path: Path, filename: str) -> Iterable[Path]:
        for path in repo_path.rglob(filename):
            if self._should_skip(path):
                continue
            yield path

    def _should_skip(self, path: Path) -> bool:
        skip_dirs = {
            ".git",
            "node_modules",
            "dist",
            "build",
            "vendor",
            ".venv",
            "__pycache__",
            ".tox",
            ".eggs",
        }
        return any(part in skip_dirs for part in path.parts)

    def _resolve_lock_path(self, root: Path) -> Optional[Path]:
        for name in ("package-lock.json", "npm-shrinkwrap.json"):
            candidate = root / name
            if candidate.is_file():
                return candidate
        return None

    def _extract_npm_lock_versions(self, data: Any) -> dict[str, str]:
        if not isinstance(data, dict):
            return {}
        versions: dict[str, str] = {}
        packages = data.get("packages")
        if isinstance(packages, dict):
            for key, entry in packages.items():
                if not key.startswith("node_modules/"):
                    continue
                name = key.replace("node_modules/", "")
                if not isinstance(entry, dict):
                    continue
                version = entry.get("version")
                if name and isinstance(version, str):
                    versions[name] = version
        dependencies = data.get("dependencies")
        if isinstance(dependencies, dict):
            for name, entry in dependencies.items():
                if name in versions:
                    continue
                if isinstance(entry, dict):
                    version = entry.get("version")
                    if isinstance(version, str):
                        versions[name] = version
        return versions

    def _load_json(self, path: Optional[Path]) -> Optional[dict]:
        if not path or not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            return None

    def _load_toml(self, path: Optional[Path]) -> Optional[dict]:
        if not path or not path.is_file():
            return None
        try:
            content = path.read_bytes()
            return tomllib.loads(content.decode("utf-8", errors="ignore"))
        except Exception:
            return None

    def _relative_path(self, repo_path: Path, path: Path) -> str:
        try:
            return str(path.relative_to(repo_path))
        except ValueError:
            return str(path)

    def _format_display(self, name: str, version: str) -> str:
        version = str(version or "").strip()
        if version:
            return f"{name}@{version}"
        return name
