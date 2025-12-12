from unittest.mock import MagicMock


def test_find_duplicates_filters_by_threshold_and_ids():
    pinecone = MagicMock()
    match_ok = MagicMock(id="1", score=0.9, metadata={"title": "t"})
    match_low = MagicMock(id="2", score=0.5, metadata={})
    match_self = MagicMock(id="self", score=0.99, metadata={})
    pinecone.find_similar_bugs.return_value = [match_ok, match_low, match_self]

    from src.services.bug_triage.duplicate_detector import DuplicateDetector

    detector = DuplicateDetector(pinecone)
    duplicates = detector.find_duplicates("self", "a", "b")

    assert len(duplicates) == 1
    assert duplicates[0]["bug_id"] == "1"


def test_register_bug_upserts_vector():
    pinecone = MagicMock()

    from src.services.bug_triage.duplicate_detector import DuplicateDetector

    detector = DuplicateDetector(pinecone)

    bug = MagicMock()
    bug.id = "uuid"
    bug.title = "Title"
    bug.description = "Desc"
    bug.status = "new"
    bug.created_at.isoformat.return_value = "2025-01-01T00:00:00Z"
    bug.classified_component = "backend"
    bug.classified_severity = "high"

    detector.register_bug(bug)

    pinecone.upsert_bug.assert_called_once()

