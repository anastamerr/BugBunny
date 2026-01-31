import uuid
from pathlib import Path

import pytest

from src.models import Finding, Scan
from src.services.scanner import scan_pipeline
from src.services.scanner.types import CodeContext, RawFinding, TriagedFinding


class DummySio:
    async def emit(self, *args, **kwargs):  # noqa: ANN001
        return None


class DummyFetcher:
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path

    async def clone(self, repo_url, branch="main", github_token=None):  # noqa: ANN001
        return self.repo_path, branch

    def analyze_repo(self, repo_path):  # noqa: ANN001
        return ["python"], 1

    async def cleanup(self, repo_path):  # noqa: ANN001
        return None


class DummyRunner:
    def resolve_configs(self, repo_path, languages):  # noqa: ANN001
        return []

    def format_config_labels(self, repo_path, configs):  # noqa: ANN001
        return []

    def get_version(self):
        return "1.0.0"

    async def scan(self, repo_path, languages):  # noqa: ANN001
        return [
            RawFinding(
                rule_id="rule-1",
                rule_message="msg",
                severity="ERROR",
                file_path="app.py",
                line_start=1,
                line_end=1,
                code_snippet="print('hi')",
            )
        ]


class DummyExtractor:
    def extract(self, repo_path, finding):  # noqa: ANN001
        return CodeContext(
            snippet="print('hi')",
            function_name="handler",
            class_name=None,
            is_test_file=False,
            is_generated=False,
            imports=["import os"],
        )


class DummyTriage:
    async def triage_batch(self, pairs):  # noqa: ANN001
        return [
            TriagedFinding(
                rule_id="rule-1",
                rule_message="msg",
                semgrep_severity="ERROR",
                file_path="app.py",
                line_start=1,
                line_end=1,
                code_snippet="print('hi')",
                context_snippet="print('hi')",
                function_name="handler",
                class_name=None,
                is_test_file=False,
                is_generated=False,
                imports=["import os"],
                is_false_positive=False,
                ai_severity="high",
                ai_confidence=0.9,
                ai_reasoning="real issue",
                exploitability="remote",
            )
        ]


class DummyAggregator:
    def __init__(self, pinecone):  # noqa: ANN001
        return None

    async def process(self, findings):  # noqa: ANN001
        return findings

    def calculate_priority(self, finding):  # noqa: ANN001
        return 77


class DummyDAST:
    def __init__(self):
        self.last_error = None

    def is_available(self):
        return False

    async def scan(self, target_url, auth_headers=None, cookies=None, progress_cb=None):  # noqa: ANN001
        return []


class DummyDependencyScanner:
    def is_available(self):
        return False

    async def scan(self, repo_path):  # noqa: ANN001
        return []


class DummyDependencyHealthScanner:
    async def scan(self, repo_path):  # noqa: ANN001
        return []


@pytest.mark.asyncio
async def test_run_scan_pipeline_persists_findings(db_sessionmaker, tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    monkeypatch.setattr(scan_pipeline, "RepoFetcher", lambda: DummyFetcher(repo_path))
    monkeypatch.setattr(scan_pipeline, "SemgrepRunner", DummyRunner)
    monkeypatch.setattr(scan_pipeline, "ContextExtractor", DummyExtractor)
    monkeypatch.setattr(scan_pipeline, "AITriageEngine", DummyTriage)
    monkeypatch.setattr(scan_pipeline, "FindingAggregator", DummyAggregator)
    monkeypatch.setattr(scan_pipeline, "DASTRunner", DummyDAST)
    monkeypatch.setattr(scan_pipeline, "DependencyScanner", DummyDependencyScanner)
    monkeypatch.setattr(
        scan_pipeline, "DependencyHealthScanner", DummyDependencyHealthScanner
    )
    monkeypatch.setattr(scan_pipeline, "sio", DummySio())
    monkeypatch.setattr(scan_pipeline, "_get_pinecone", lambda: None)
    monkeypatch.setattr(scan_pipeline, "SessionLocal", lambda: db_sessionmaker())

    scan_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session = db_sessionmaker()
    session.add(
        Scan(
            id=scan_id,
            user_id=user_id,
            repo_url="https://example.com/repo",
            branch="main",
            scan_type="sast",
            status="pending",
            trigger="manual",
        )
    )
    session.commit()
    session.close()

    await scan_pipeline.run_scan_pipeline(
        scan_id=scan_id,
        repo_url="https://example.com/repo",
        branch="main",
        scan_type="sast",
        target_url=None,
    )

    verify = db_sessionmaker()
    scan = verify.query(Scan).filter(Scan.id == scan_id).first()
    findings = verify.query(Finding).filter(Finding.scan_id == scan_id).all()
    verify.close()

    assert scan is not None
    assert scan.status == "completed"
    assert scan.total_findings == 1
    assert scan.filtered_findings == 1
    assert scan.semgrep_version == "1.0.0"
    assert len(findings) == 1
    assert findings[0].priority_score == 77


@pytest.mark.asyncio
async def test_dast_verification_persisted_before_zap(db_sessionmaker, monkeypatch):
    scan_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session = db_sessionmaker()
    session.add(
        Scan(
            id=scan_id,
            user_id=user_id,
            repo_url=None,
            branch="main",
            scan_type="dast",
            target_url="https://example.com",
            commit_sha="deadbeef",
            status="pending",
            trigger="manual",
        )
    )
    session.commit()
    session.close()

    status_at_zap = {}

    class DummyVerifier:
        async def verify_deployment(self, target_url, expected_sha):  # noqa: ANN001
            return "commit_mismatch", "mismatch"

    class DummyDAST:
        def __init__(self):
            self.last_error = None

        def is_available(self):
            return True

        async def scan(self, target_url, auth_headers=None, cookies=None, progress_cb=None):  # noqa: ANN001
            verify = db_sessionmaker()
            scan = verify.query(Scan).filter(Scan.id == scan_id).first()
            status_at_zap["value"] = scan.dast_verification_status if scan else None
            verify.close()
            return []

    monkeypatch.setattr(scan_pipeline, "CommitVerifier", DummyVerifier)
    monkeypatch.setattr(scan_pipeline, "DASTRunner", DummyDAST)
    monkeypatch.setattr(scan_pipeline, "sio", DummySio())
    monkeypatch.setattr(scan_pipeline, "SessionLocal", lambda: db_sessionmaker())

    await scan_pipeline.run_scan_pipeline(
        scan_id=scan_id,
        repo_url=None,
        branch="main",
        scan_type="dast",
        target_url="https://example.com",
    )

    assert status_at_zap["value"] == "commit_mismatch"


@pytest.mark.asyncio
async def test_dast_manual_url_sets_unverified_before_zap(db_sessionmaker, monkeypatch):
    scan_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session = db_sessionmaker()
    session.add(
        Scan(
            id=scan_id,
            user_id=user_id,
            repo_url=None,
            branch="main",
            scan_type="dast",
            target_url="https://example.com",
            commit_sha=None,
            status="pending",
            trigger="manual",
        )
    )
    session.commit()
    session.close()

    status_at_zap = {}

    class DummyVerifier:
        async def verify_deployment(self, target_url, expected_sha):  # noqa: ANN001
            raise AssertionError("verify_deployment should not be called without commit_sha")

    class DummyDAST:
        def __init__(self):
            self.last_error = None

        def is_available(self):
            return True

        async def scan(self, target_url, auth_headers=None, cookies=None, progress_cb=None):  # noqa: ANN001
            verify = db_sessionmaker()
            scan = verify.query(Scan).filter(Scan.id == scan_id).first()
            status_at_zap["value"] = scan.dast_verification_status if scan else None
            verify.close()
            return []

    monkeypatch.setattr(scan_pipeline, "CommitVerifier", DummyVerifier)
    monkeypatch.setattr(scan_pipeline, "DASTRunner", DummyDAST)
    monkeypatch.setattr(scan_pipeline, "sio", DummySio())
    monkeypatch.setattr(scan_pipeline, "SessionLocal", lambda: db_sessionmaker())

    await scan_pipeline.run_scan_pipeline(
        scan_id=scan_id,
        repo_url=None,
        branch="main",
        scan_type="dast",
        target_url="https://example.com",
    )

    assert status_at_zap["value"] == "unverified_url"


@pytest.mark.asyncio
async def test_dast_failure_keeps_verification_status(db_sessionmaker, monkeypatch):
    scan_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session = db_sessionmaker()
    session.add(
        Scan(
            id=scan_id,
            user_id=user_id,
            repo_url=None,
            branch="main",
            scan_type="dast",
            target_url="https://example.com",
            commit_sha="deadbeef",
            status="pending",
            trigger="manual",
        )
    )
    session.commit()
    session.close()

    class DummyVerifier:
        async def verify_deployment(self, target_url, expected_sha):  # noqa: ANN001
            return "verified", "ok"

    class DummyDAST:
        def __init__(self):
            self.last_error = None

        def is_available(self):
            return True

        async def scan(self, target_url, auth_headers=None, cookies=None, progress_cb=None):  # noqa: ANN001
            raise RuntimeError("zap failed")

    monkeypatch.setattr(scan_pipeline, "CommitVerifier", DummyVerifier)
    monkeypatch.setattr(scan_pipeline, "DASTRunner", DummyDAST)
    monkeypatch.setattr(scan_pipeline, "sio", DummySio())
    monkeypatch.setattr(scan_pipeline, "SessionLocal", lambda: db_sessionmaker())

    await scan_pipeline.run_scan_pipeline(
        scan_id=scan_id,
        repo_url=None,
        branch="main",
        scan_type="dast",
        target_url="https://example.com",
    )

    verify = db_sessionmaker()
    scan = verify.query(Scan).filter(Scan.id == scan_id).first()
    verify.close()

    assert scan is not None
    assert scan.dast_verification_status == "verified"


@pytest.mark.asyncio
async def test_dast_upgrades_unverified_before_zap(db_sessionmaker, monkeypatch):
    scan_id = uuid.uuid4()
    user_id = uuid.uuid4()
    session = db_sessionmaker()
    session.add(
        Scan(
            id=scan_id,
            user_id=user_id,
            repo_url=None,
            branch="main",
            scan_type="dast",
            target_url="https://example.com",
            commit_sha="deadbeef",
            dast_verification_status="unverified_url",
            status="pending",
            trigger="manual",
        )
    )
    session.commit()
    session.close()

    called = {"verify": False}
    status_at_zap = {}

    class DummyVerifier:
        async def verify_deployment(self, target_url, expected_sha):  # noqa: ANN001
            called["verify"] = True
            return "verified", "ok"

    class DummyDAST:
        def __init__(self):
            self.last_error = None

        def is_available(self):
            return True

        async def scan(self, target_url, auth_headers=None, cookies=None, progress_cb=None):  # noqa: ANN001
            verify = db_sessionmaker()
            scan = verify.query(Scan).filter(Scan.id == scan_id).first()
            status_at_zap["value"] = scan.dast_verification_status if scan else None
            verify.close()
            return []

    monkeypatch.setattr(scan_pipeline, "CommitVerifier", DummyVerifier)
    monkeypatch.setattr(scan_pipeline, "DASTRunner", DummyDAST)
    monkeypatch.setattr(scan_pipeline, "sio", DummySio())
    monkeypatch.setattr(scan_pipeline, "SessionLocal", lambda: db_sessionmaker())

    await scan_pipeline.run_scan_pipeline(
        scan_id=scan_id,
        repo_url=None,
        branch="main",
        scan_type="dast",
        target_url="https://example.com",
    )

    assert called["verify"] is True
    assert status_at_zap["value"] == "verified"
