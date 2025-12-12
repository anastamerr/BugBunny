from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from ...models import BugReport, DataIncident


class BugClusterer:
    def __init__(self, db):
        self.db = db

    def cluster_by_root_cause(self, bugs: List[BugReport]) -> Dict[str, List[BugReport]]:
        clusters: Dict[str, List[BugReport]] = defaultdict(list)

        for bug in bugs:
            if bug.correlated_incident_id:
                key = str(bug.correlated_incident_id)
            else:
                key = "uncorrelated"
            clusters[key].append(bug)

        return dict(clusters)

    def get_cluster_summary(self, incident_id: str) -> Dict:
        bugs = (
            self.db.query(BugReport)
            .filter(BugReport.correlated_incident_id == incident_id)
            .all()
        )
        incident = self.db.query(DataIncident).get(incident_id)

        return {
            "incident": incident,
            "bug_count": len(bugs),
            "bugs": bugs,
            "components_affected": list(set(b.classified_component for b in bugs)),
            "total_reporters": len(set(b.reporter for b in bugs)),
            "resolution_impact": f"Fixing this incident will resolve {len(bugs)} bug reports",
        }

    def propagate_resolution(self, incident_id: str, resolution_notes: str) -> int:
        bugs = (
            self.db.query(BugReport)
            .filter(BugReport.correlated_incident_id == incident_id)
            .all()
        )

        for bug in bugs:
            bug.status = "resolved"
            bug.resolution_notes = (
                f"Resolved via data incident fix: {resolution_notes}"
            )

        self.db.commit()
        return len(bugs)

