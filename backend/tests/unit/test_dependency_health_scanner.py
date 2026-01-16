from pathlib import Path

from src.services.scanner.dependency_health_scanner import (
    DependencyHealthScanner,
    DependencySpec,
)


def test_collect_specs_reads_requirements_and_package_json(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\nflask>=2.0\n", encoding="utf-8"
    )

    package_json = tmp_path / "package.json"
    package_json.write_text(
        '{"dependencies": {"lodash": "^4.17.0"}, "devDependencies": {"jest": "^29.0.0"}}',
        encoding="utf-8",
    )

    package_lock = tmp_path / "package-lock.json"
    package_lock.write_text(
        '{"packages": {"node_modules/lodash": {"version": "4.17.21"}, '
        '"node_modules/jest": {"version": "29.6.1"}}}',
        encoding="utf-8",
    )

    scanner = DependencyHealthScanner()
    specs = scanner._collect_specs(tmp_path)

    names = {(spec.ecosystem, spec.name) for spec in specs}
    assert ("pypi", "requests") in names
    assert ("npm", "lodash") in names
    assert ("npm", "jest") in names


def test_evaluate_pypi_marks_outdated() -> None:
    scanner = DependencyHealthScanner()
    spec = DependencySpec(
        name="requests",
        ecosystem="pypi",
        specifier="==1.0.0",
        version="1.0.0",
        dependency_type="runtime",
        file_path="requirements.txt",
    )
    meta = {
        "info": {"version": "2.0.0", "classifiers": []},
        "releases": {"1.0.0": []},
    }

    finding = scanner._evaluate_pypi(spec, meta)

    assert finding is not None
    assert finding.status == "outdated"
    assert finding.ai_severity == "low"
