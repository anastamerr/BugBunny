from unittest.mock import MagicMock

import pytest

from src.services.scanner.finding_aggregator import FindingAggregator
from src.services.scanner.types import TriagedFinding


def _make_finding(**overrides) -> TriagedFinding:
    data = {
        "rule_id": "rule-1",
        "rule_message": "msg",
        "semgrep_severity": "ERROR",
        "file_path": "app.py",
        "line_start": 1,
        "line_end": 1,
        "code_snippet": "print('hi')",
        "context_snippet": "print('hi')",
        "function_name": None,
        "class_name": None,
        "is_test_file": False,
        "is_generated": False,
        "imports": [],
        "is_false_positive": False,
        "ai_severity": "high",
        "ai_confidence": 0.9,
        "ai_reasoning": "reason",
        "exploitability": "remote",
    }
    data.update(overrides)
    return TriagedFinding(**data)


@pytest.mark.asyncio
async def test_process_includes_false_positives_and_sorts():
    aggregator = FindingAggregator()
    keep = _make_finding(rule_id="keep", is_false_positive=False)
    drop = _make_finding(rule_id="drop", is_false_positive=True)

    results = await aggregator.process([drop, keep])

    assert len(results) == 2
    assert results[0].rule_id == "keep"
    assert results[0].priority_score is not None
    assert results[1].is_false_positive is True


@pytest.mark.asyncio
async def test_deduplicate_skips_similar_findings():
    pinecone = MagicMock()
    pinecone.find_similar_patterns.side_effect = [
        [MagicMock(score=0.95)],
        [],
    ]
    aggregator = FindingAggregator(pinecone, duplicate_threshold=0.9)
    first = _make_finding(rule_id="r1")
    second = _make_finding(rule_id="r2")

    results = await aggregator._deduplicate([first, second])

    assert results == [second]
    pinecone.upsert_pattern.assert_called_once()


def test_calculate_priority_penalizes_unreachable_code():
    aggregator = FindingAggregator()
    reachable = _make_finding(is_reachable=True, reachability_score=1.0)
    unreachable = _make_finding(is_reachable=False, reachability_score=0.0)

    score_reachable = aggregator.calculate_priority(reachable)
    score_unreachable = aggregator.calculate_priority(unreachable)

    assert score_unreachable < score_reachable
