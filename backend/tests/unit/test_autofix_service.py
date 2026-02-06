from __future__ import annotations

import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.services.autofix_service import AutoFixService


class DummyLLM:
    async def is_available(self) -> bool:
        return False

    async def generate(self, prompt: str, system: str | None = None) -> str:
        return ""


class DummyFetcher:
    def __init__(self, repo_path: Path) -> None:
        self.repo_path = repo_path

    async def clone(
        self,
        repo_url: str,
        branch: str = "main",
        github_token: str | None = None,
    ) -> tuple[Path, str]:
        return self.repo_path, branch

    async def cleanup(self, repo_path: Path) -> None:
        return None


def _make_finding(*, patch: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        finding_type="sast",
        is_false_positive=False,
        is_test_file=False,
        is_generated=False,
        is_reachable=True,
        ai_confidence=0.95,
        ai_severity="high",
        semgrep_severity="ERROR",
        file_path="app.py",
        line_start=1,
        line_end=1,
        rule_id="sql-injection",
        rule_message="Possible SQL injection",
        context_snippet="",
        code_snippet="",
        fix_patch=patch,
        fix_summary="Use parameterized queries",
        fix_confidence=0.92,
    )


def _make_scan(repo_url: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        repo_url=repo_url,
        branch="main",
    )


def test_extract_repo_full_name_supports_common_git_formats():
    service = AutoFixService(llm_client=DummyLLM())

    assert service._extract_repo_full_name("https://github.com/acme/widgets.git") == "acme/widgets"
    assert service._extract_repo_full_name("https://github.com/acme/widgets") == "acme/widgets"
    assert service._extract_repo_full_name("git@github.com:acme/widgets.git") == "acme/widgets"
    assert service._extract_repo_full_name("ssh://git@github.com/acme/widgets.git") == "acme/widgets"
    assert service._extract_repo_full_name("acme/widgets.git") == "acme/widgets"


@pytest.mark.asyncio
async def test_generate_fix_create_pr_uses_normalized_repo_name(tmp_path):
    patch = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1 +1 @@\n"
        "-print('unsafe')\n"
        "+print('safe')\n"
    )
    finding = _make_finding(patch=patch)
    scan = _make_scan("https://github.com/acme/widgets.git")

    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "app.py").write_text("print('unsafe')\n", encoding="utf-8")

    service = AutoFixService(llm_client=DummyLLM())
    service.repo_fetcher = DummyFetcher(repo_path)
    service._apply_patch = lambda _repo_path, _patch: None  # type: ignore[method-assign]
    service._get_diff = lambda _repo_path: patch  # type: ignore[method-assign]
    service._configure_git = lambda _repo_path: None  # type: ignore[method-assign]
    service._run_git = lambda _repo_path, _args: None  # type: ignore[method-assign]
    service._comment_on_pr = lambda *_args, **_kwargs: None  # type: ignore[method-assign]

    captured: dict[str, str] = {}

    def _fake_create_pr(
        repo_full_name: str,
        github_token: str | None,
        title: str,
        body: str,
        head: str,
        base: str,
    ) -> tuple[str, int]:
        captured["repo_full_name"] = repo_full_name
        captured["base"] = base
        return "https://github.com/acme/widgets/pull/123", 123

    service._create_pr = _fake_create_pr  # type: ignore[method-assign]

    result = await service.generate_fix(
        finding=finding,
        scan=scan,
        github_token="ghp_test",
        create_pr=True,
        regenerate=False,
    )

    assert result.status == "pr_opened"
    assert result.pr_url == "https://github.com/acme/widgets/pull/123"
    assert captured["repo_full_name"] == "acme/widgets"
    assert captured["base"] == "main"
