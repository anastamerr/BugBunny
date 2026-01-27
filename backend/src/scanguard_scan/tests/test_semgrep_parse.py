import json

from src.scanguard_scan.runners.semgrep_runner import parse_semgrep_output


def test_parse_semgrep_output_extracts_cwe_ids():
    payload = {
        "results": [
            {
                "check_id": "python.lang.security.sql.injection",
                "path": "app.py",
                "start": {"line": 10},
                "end": {"line": 12},
                "extra": {
                    "message": "SQL injection",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-89", 89]},
                },
            }
        ]
    }

    findings = parse_semgrep_output(json.dumps(payload))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "python.lang.security.sql.injection"
    assert finding.severity == "ERROR"
    assert finding.cwe_ids == [89]
    assert finding.file_path == "app.py"
