from __future__ import annotations

from pathlib import Path

from src.services.scanner.reachability_analyzer import ReachabilityAnalyzer


def _write(repo: Path, name: str, content: str) -> None:
    path = repo / name
    path.write_text(content, encoding="utf-8")


def test_python_reachability_detects_entry_point(tmp_path_factory) -> None:
    repo = tmp_path_factory.mktemp("repo")
    _write(
        repo,
        "app.py",
        "\n".join(
            [
                "from fastapi import FastAPI",
                "app = FastAPI()",
                "",
                "def target():",
                "    return 1",
                "",
                "def helper():",
                "    return target()",
                "",
                "@app.get('/items')",
                "def handler():",
                "    return helper()",
            ]
        ),
    )

    analyzer = ReachabilityAnalyzer()
    result = analyzer.analyze(
        repo_path=repo,
        file_path="app.py",
        function_name="target",
        class_name=None,
        line_number=4,
    )

    assert result.is_reachable is True
    assert result.reachability_score == 1.0
    assert result.entry_points


def test_python_reachability_unknown_when_target_has_no_callers(
    tmp_path_factory,
) -> None:
    repo = tmp_path_factory.mktemp("repo")
    _write(
        repo,
        "app.py",
        "\n".join(
            [
                "from fastapi import FastAPI",
                "app = FastAPI()",
                "",
                "def target():",
                "    return 1",
                "",
                "def helper():",
                "    return 2",
                "",
                "@app.get('/items')",
                "def handler():",
                "    return helper()",
            ]
        ),
    )

    analyzer = ReachabilityAnalyzer()
    result = analyzer.analyze(
        repo_path=repo,
        file_path="app.py",
        function_name="target",
        class_name=None,
        line_number=4,
    )

    assert result.is_reachable is True
    assert result.reachability_score == 0.5
    assert "No callers found" in result.reason


def test_js_reachability_detects_entry_point(tmp_path_factory) -> None:
    repo = tmp_path_factory.mktemp("repo")
    _write(
        repo,
        "app.js",
        "\n".join(
            [
                "export async function handler(req, res) {",
                "  helper();",
                "}",
                "",
                "function helper() {",
                "  target();",
                "}",
                "",
                "function target() {",
                "  return 1;",
                "}",
            ]
        ),
    )

    analyzer = ReachabilityAnalyzer()
    result = analyzer.analyze(
        repo_path=repo,
        file_path="app.js",
        function_name="target",
        class_name=None,
        line_number=9,
    )

    assert result.is_reachable is True
    assert result.reachability_score == 1.0
    assert result.entry_points
