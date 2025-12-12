from datetime import datetime, timedelta
from unittest.mock import MagicMock


def make_bug_incident(hours_after: float):
    incident = MagicMock()
    incident.timestamp = datetime.utcnow()
    incident.table_name = "user_transactions"
    incident.affected_columns = ["user_id"]
    incident.incident_type = "SCHEMA_DRIFT"
    incident.severity = "CRITICAL"

    bug = MagicMock()
    bug.created_at = incident.timestamp + timedelta(hours=hours_after)
    bug.title = "Dashboard shows $0 revenue"
    bug.description = "user_transactions user_id schema drift"
    bug.classified_component = "analytics_dashboard"
    bug.classified_severity = "critical"

    return bug, incident


def test_temporal_score_immediate_max():
    from src.services.correlation.temporal_matcher import TemporalMatcher

    matcher = TemporalMatcher(MagicMock())
    bug, incident = make_bug_incident(0.5)
    assert matcher._temporal_score(bug, incident) == 1.0


def test_temporal_score_delayed_reduced():
    from src.services.correlation.temporal_matcher import TemporalMatcher

    matcher = TemporalMatcher(MagicMock())
    bug, incident = make_bug_incident(3)
    score = matcher._temporal_score(bug, incident)
    assert 0.5 < score < 0.7


def test_temporal_score_too_old_zero():
    from src.services.correlation.temporal_matcher import TemporalMatcher

    matcher = TemporalMatcher(MagicMock())
    bug, incident = make_bug_incident(30)
    assert matcher._temporal_score(bug, incident) == 0.0

