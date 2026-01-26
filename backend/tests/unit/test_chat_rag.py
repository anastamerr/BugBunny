from datetime import datetime, timezone
import uuid

from src.api.deps import CurrentUser
from src.api.routes import chat as chat_routes
from src.models import BugReport, Scan
from src.schemas.chat import ChatRequest


class _Match:
    def __init__(self, match_id, score, metadata=None):
        self.id = match_id
        self.score = score
        self.metadata = metadata or {}


def test_repo_scoped_bug_retrieval_filter_applied(db_sessionmaker, monkeypatch):
    session = db_sessionmaker()
    user_id = uuid.uuid4()
    scan = Scan(
        id=uuid.uuid4(),
        user_id=user_id,
        repo_url="https://github.com/acme/widgets",
        branch="main",
        scan_type="sast",
        status="completed",
        trigger="manual",
    )
    session.add(scan)
    session.commit()

    class FakePinecone:
        def __init__(self):
            self.bug_filter = None
            self.memory_filter = None

        def find_similar_bugs(self, title, description, top_k=5, metadata_filter=None):  # noqa: ANN001
            self.bug_filter = metadata_filter
            return []

        def find_project_memory(self, text, top_k=5, metadata_filter=None):  # noqa: ANN001
            self.memory_filter = metadata_filter
            return []

    fake = FakePinecone()
    monkeypatch.setattr(chat_routes, "_get_pinecone_safe", lambda: fake)

    payload = ChatRequest(message="What should we fix first?")
    current_user = CurrentUser(id=user_id, email="tester@example.com")
    chat_routes._prepare_chat_prompt(payload, session, current_user)

    assert fake.bug_filter == {"repo_full_name": {"$eq": "acme/widgets"}}

    session.close()


def test_chat_prompt_includes_project_memory_sections(db_sessionmaker, monkeypatch):
    session = db_sessionmaker()
    user_id = uuid.uuid4()
    scan = Scan(
        id=uuid.uuid4(),
        user_id=user_id,
        repo_url="https://github.com/acme/widgets",
        branch="main",
        scan_type="sast",
        status="completed",
        trigger="manual",
    )
    bug = BugReport(
        bug_id="GH-123",
        source="github",
        title="Login fails on retry",
        description="User sees 500 after retrying login",
        created_at=datetime.now(timezone.utc),
        classified_type="bug",
        classified_component="auth",
        classified_severity="high",
        confidence_score=0.9,
        status="new",
    )
    session.add(scan)
    session.add(bug)
    session.commit()
    session.refresh(bug)

    bug_match = _Match(str(bug.id), 0.91)
    memory_match = _Match(
        "mem-1",
        0.8,
        metadata={
            "doc_type": "scan_summary",
            "summary": "Scan summary for acme/widgets with 3 high findings.",
            "severity": "high",
            "scan_id": str(scan.id),
        },
    )

    class FakePinecone:
        def find_similar_bugs(self, title, description, top_k=5, metadata_filter=None):  # noqa: ANN001
            return [bug_match]

        def find_project_memory(self, text, top_k=5, metadata_filter=None):  # noqa: ANN001
            return [memory_match]

    monkeypatch.setattr(chat_routes, "_get_pinecone_safe", lambda: FakePinecone())

    payload = ChatRequest(message="Summarize what to focus on.")
    current_user = CurrentUser(id=user_id, email="tester@example.com")
    context, _system, _prompt, _focus = chat_routes._prepare_chat_prompt(
        payload, session, current_user
    )

    assert "SEMANTIC BUG MATCHES" in context
    assert "PROJECT MEMORY" in context
    assert "Scan summary for acme/widgets" in context

    session.close()
