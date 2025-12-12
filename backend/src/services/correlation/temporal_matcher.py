from __future__ import annotations

from datetime import timedelta
from typing import List, Tuple

from sqlalchemy.orm import Session

from ...models import BugReport, DataIncident
from ..pipeline_monitor.lineage_graph import DataLineageGraph


class TemporalMatcher:
    def __init__(self, db: Session):
        self.db = db

    def find_correlated_incidents(
        self, bug: BugReport, window_hours: int = 24
    ) -> List[Tuple[DataIncident, float]]:
        incidents = (
            self.db.query(DataIncident)
            .filter(
                DataIncident.timestamp >= bug.created_at - timedelta(hours=window_hours),
                DataIncident.timestamp <= bug.created_at,
                DataIncident.status.in_(["ACTIVE", "INVESTIGATING"]),
            )
            .all()
        )

        correlations: List[Tuple[DataIncident, float]] = []
        for incident in incidents:
            score = self.calculate_correlation_score(bug, incident)
            if score > 0.3:
                correlations.append((incident, score))

        return sorted(correlations, key=lambda x: x[1], reverse=True)

    def calculate_correlation_score(self, bug: BugReport, incident: DataIncident) -> float:
        scores = {
            "temporal": self._temporal_score(bug, incident),
            "component": self._component_score(bug, incident),
            "keyword": self._keyword_score(bug, incident),
            "severity": self._severity_alignment_score(bug, incident),
        }

        weights = {"temporal": 0.35, "component": 0.35, "keyword": 0.20, "severity": 0.10}
        total = sum(scores[k] * weights[k] for k in scores)
        return min(total, 1.0)

    def _temporal_score(self, bug: BugReport, incident: DataIncident) -> float:
        time_diff = (bug.created_at - incident.timestamp).total_seconds() / 3600

        if time_diff < 0:
            return 0.0
        if time_diff <= 1:
            return 1.0
        if time_diff <= 2:
            return 0.9 - (time_diff - 1) * 0.2
        if time_diff <= 6:
            return 0.7 - (time_diff - 2) * 0.1
        if time_diff <= 24:
            return 0.3 - (time_diff - 6) * 0.015
        return 0.0

    def _component_score(self, bug: BugReport, incident: DataIncident) -> float:
        lineage = DataLineageGraph()
        bug_component = bug.classified_component

        if not bug_component:
            return 0.3

        if lineage.is_downstream(bug_component, incident.table_name):
            return 1.0

        tables = lineage.get_tables_for_component(bug_component)
        if incident.table_name in tables:
            return 0.8

        return 0.0

    def _keyword_score(self, bug: BugReport, incident: DataIncident) -> float:
        incident_keywords = set()
        incident_keywords.add(incident.table_name.lower())
        for col in incident.affected_columns or []:
            incident_keywords.add(col.lower())
        if incident.incident_type:
            incident_keywords.add(str(incident.incident_type).lower().replace("_", " "))

        bug_text = f"{bug.title} {bug.description or ''}".lower()
        matches = sum(1 for kw in incident_keywords if kw in bug_text)

        if matches >= 3:
            return 1.0
        if matches >= 2:
            return 0.7
        if matches >= 1:
            return 0.4
        return 0.0

    def _severity_alignment_score(self, bug: BugReport, incident: DataIncident) -> float:
        severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        incident_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        bug_sev = severity_map.get(bug.classified_severity or "medium", 2)
        inc_sev = incident_map.get(incident.severity or "MEDIUM", 2)

        if inc_sev >= 3 and bug_sev >= 3:
            return 1.0
        if abs(inc_sev - bug_sev) <= 1:
            return 0.7
        return 0.3

