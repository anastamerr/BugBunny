from __future__ import annotations

import uuid
from datetime import datetime
from typing import Dict, List, Optional

from ...models import DataIncident


class IncidentGenerator:
    def __init__(self, db, lineage_graph):
        self.db = db
        self.lineage = lineage_graph

    def generate_incident(
        self,
        table_name: str,
        validation_result: Dict,
        anomaly_result: Optional[Dict] = None,
    ) -> DataIncident:
        incident_type = self._classify_incident(validation_result, anomaly_result)
        severity = self._calculate_severity(incident_type, validation_result, anomaly_result)
        affected_columns = self._extract_affected_columns(validation_result)
        downstream = self.lineage.get_downstream_systems(table_name)
        details = self._build_details(validation_result, anomaly_result)

        incident = DataIncident(
            incident_id=f"DI-{datetime.utcnow().strftime('%Y-%m-%d')}-{uuid.uuid4().hex[:6]}",
            timestamp=datetime.utcnow(),
            table_name=table_name,
            incident_type=incident_type,
            severity=severity,
            details=details,
            affected_columns=affected_columns,
            anomaly_score=anomaly_result.get("score", 0) if anomaly_result else 0,
            downstream_systems=downstream,
            status="ACTIVE",
        )

        self.db.add(incident)
        self.db.commit()
        return incident

    def _classify_incident(self, validation: Dict, anomaly: Optional[Dict]) -> str:
        failures = validation.get("failures", [])

        for failure in failures:
            exp_type = failure["expectation_type"]

            if "column_to_exist" in exp_type:
                return "SCHEMA_DRIFT"
            if "not_be_null" in exp_type:
                return "NULL_SPIKE"
            if "row_count" in exp_type:
                return "VOLUME_ANOMALY"

        if anomaly and anomaly.get("is_anomaly"):
            anomalous = anomaly.get("anomalous_metrics", {})
            if "freshness_hours" in anomalous:
                return "FRESHNESS"
            if "row_count" in anomalous:
                return "VOLUME_ANOMALY"
            return "DISTRIBUTION_DRIFT"

        return "VALIDATION_FAILURE"

    def _calculate_severity(
        self, incident_type: str, validation: Dict, anomaly: Optional[Dict]
    ) -> str:
        type_severity = {
            "SCHEMA_DRIFT": "CRITICAL",
            "NULL_SPIKE": "HIGH",
            "VOLUME_ANOMALY": "HIGH",
            "FRESHNESS": "MEDIUM",
            "DISTRIBUTION_DRIFT": "MEDIUM",
            "VALIDATION_FAILURE": "LOW",
        }

        base = type_severity.get(incident_type, "LOW")

        if anomaly and anomaly.get("score", 0) > 0.8:
            if base == "MEDIUM":
                return "HIGH"
            if base == "HIGH":
                return "CRITICAL"

        return base

    def _extract_affected_columns(self, validation: Dict) -> List[str]:
        columns = set()
        for failure in validation.get("failures", []):
            col = failure.get("column")
            if col:
                columns.add(col)
        return list(columns)

    def _build_details(self, validation: Dict, anomaly: Optional[Dict]) -> Dict:
        return {
            "validation": {
                "total_expectations": validation["statistics"]["total"],
                "failed_expectations": validation["statistics"]["unsuccessful"],
                "failures": validation.get("failures", []),
            },
            "anomaly": anomaly or {},
            "generated_at": datetime.utcnow().isoformat(),
        }

