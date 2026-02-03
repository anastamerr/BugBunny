from types import SimpleNamespace

import pytest

from src.services.scanner.semgrep_runner import SemgrepRunner


def test_parse_results_maps_fields():
    runner = SemgrepRunner()
    payload = {
        "results": [
            {
                "check_id": "rule-1",
                "extra": {"message": "msg", "severity": "warning", "lines": "code"},
                "path": "app.py",
                "start": {"line": 5},
                "end": {"line": 7},
            }
        ]
    }

    findings = runner._parse_results(payload)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "rule-1"
    assert finding.rule_message == "msg"
    assert finding.severity == "WARNING"
    assert finding.file_path == "app.py"
    assert finding.line_start == 5
    assert finding.line_end == 7
    assert finding.code_snippet == "code"


def test_resolve_configs_includes_local_and_rulesets(tmp_path):
    config_path = tmp_path / ".semgrep.yml"
    config_path.write_text("rules: []", encoding="utf-8")

    runner = SemgrepRunner()
    configs = runner.resolve_configs(tmp_path, ["python", "javascript"])

    assert str(config_path) in configs
    assert "p/python" in configs
    assert "p/javascript" in configs


def test_format_config_labels_marks_local_paths(tmp_path):
    config_path = tmp_path / ".semgrep.yml"
    config_path.write_text("rules: []", encoding="utf-8")

    runner = SemgrepRunner()
    labels = runner.format_config_labels(tmp_path, [str(config_path), "p/python"])

    assert "local:.semgrep.yml" in labels
    assert "p/python" in labels


def test_run_command_raises_when_missing_binary(monkeypatch):
    runner = SemgrepRunner()

    def fake_run(*args, **kwargs):
        raise FileNotFoundError("semgrep not found")

    monkeypatch.setattr("src.services.scanner.semgrep_runner.subprocess.run", fake_run)

    with pytest.raises(RuntimeError, match="Semgrep CLI is not installed"):
        runner._run_command(["semgrep", "--version"])
