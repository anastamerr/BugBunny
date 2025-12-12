from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Optional

import numpy as np
from sklearn.ensemble import GradientBoostingRegressor

from ...models import DataIncident
from ..pipeline_monitor.lineage_graph import DataLineageGraph


class PredictionEngine:
    def __init__(self, db, pinecone=None):
        self.db = db
        self.pinecone = pinecone
        self.model: Optional[GradientBoostingRegressor] = None
        self._train_model()

    def _train_model(self) -> None:
        patterns = self.db.execute(
            """
            SELECT
                i.incident_type,
                i.severity,
                i.anomaly_score,
                COUNT(b.id) as bug_count
            FROM data_incidents i
            LEFT JOIN bug_reports b ON b.correlated_incident_id = i.id
            WHERE i.timestamp > :start
            GROUP BY i.id, i.incident_type, i.severity, i.anomaly_score
            """,
            {"start": datetime.utcnow() - timedelta(days=90)},
        ).fetchall()

        if len(patterns) < 10:
            return

        type_map = {
            "SCHEMA_DRIFT": 4,
            "NULL_SPIKE": 3,
            "VOLUME_ANOMALY": 3,
            "FRESHNESS": 2,
            "DISTRIBUTION_DRIFT": 2,
            "VALIDATION_FAILURE": 1,
        }
        sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        X: List[List[float]] = []
        y: List[int] = []
        for p in patterns:
            X.append(
                [
                    type_map.get(p.incident_type, 1),
                    sev_map.get(p.severity, 1),
                    float(p.anomaly_score or 0.5),
                ]
            )
            y.append(int(p.bug_count))

        self.model = GradientBoostingRegressor(n_estimators=50, random_state=42)
        self.model.fit(np.array(X), np.array(y))

    def predict_bugs(self, incident: DataIncident) -> Dict:
        if self.model is None:
            return self._rule_based_prediction(incident)

        type_map = {
            "SCHEMA_DRIFT": 4,
            "NULL_SPIKE": 3,
            "VOLUME_ANOMALY": 3,
            "FRESHNESS": 2,
            "DISTRIBUTION_DRIFT": 2,
            "VALIDATION_FAILURE": 1,
        }
        sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        X = np.array(
            [
                [
                    type_map.get(incident.incident_type, 1),
                    sev_map.get(incident.severity, 1),
                    float(incident.anomaly_score or 0.5),
                ]
            ]
        )
        predicted_count = max(0, int(self.model.predict(X)[0]))

        similar = self._find_similar_incidents(incident)
        predicted_components = self._predict_affected_components(incident, similar)

        return {
            "predicted_bug_count": predicted_count,
            "predicted_components": predicted_components,
            "confidence": self._calculate_confidence(incident),
            "prediction_window_hours": 6,
            "recommendation": self._generate_recommendation(predicted_count, incident),
        }

    def _rule_based_prediction(self, incident: DataIncident) -> Dict:
        base_counts = {
            "SCHEMA_DRIFT": 5,
            "NULL_SPIKE": 3,
            "VOLUME_ANOMALY": 2,
            "FRESHNESS": 1,
            "DISTRIBUTION_DRIFT": 2,
            "VALIDATION_FAILURE": 1,
        }

        count = float(base_counts.get(incident.incident_type, 1))
        if incident.severity == "CRITICAL":
            count *= 2
        elif incident.severity == "HIGH":
            count *= 1.5

        downstream = incident.downstream_systems or DataLineageGraph().get_downstream_systems(
            incident.table_name
        )

        return {
            "predicted_bug_count": int(count),
            "predicted_components": downstream[:3],
            "confidence": 0.6,
            "prediction_window_hours": 6,
            "recommendation": f"Expect ~{int(count)} bug reports in the next 6 hours",
        }

    def _find_similar_incidents(self, incident: DataIncident) -> List[DataIncident]:
        # Simple heuristic: past incidents of same type/severity in last 90 days
        start = datetime.utcnow() - timedelta(days=90)
        return (
            self.db.query(DataIncident)
            .filter(
                DataIncident.timestamp >= start,
                DataIncident.incident_type == incident.incident_type,
                DataIncident.severity == incident.severity,
            )
            .limit(20)
            .all()
        )

    def _predict_affected_components(
        self, incident: DataIncident, similar: List[DataIncident]
    ) -> List[str]:
        components: List[str] = []
        for inc in similar:
            if inc.downstream_systems:
                components.extend(list(inc.downstream_systems))

        if not components:
            components = list(
                incident.downstream_systems
                or DataLineageGraph().get_downstream_systems(incident.table_name)
            )

        # return top unique components
        seen = set()
        unique = []
        for c in components:
            if c not in seen:
                unique.append(c)
                seen.add(c)
        return unique[:5]

    def _calculate_confidence(self, incident: DataIncident) -> float:
        base = 0.75 if self.model is not None else 0.6
        if incident.anomaly_score:
            base += min(float(incident.anomaly_score), 1.0) * 0.1
        return min(base, 0.95)

    def _generate_recommendation(
        self, predicted_count: int, incident: DataIncident
    ) -> str:
        downstream = incident.downstream_systems or []
        if predicted_count >= 5:
            return (
                f"HIGH ALERT: Expect {predicted_count}+ bug reports. "
                f"Consider proactive communication to affected teams: {', '.join(downstream)}"
            )
        if predicted_count >= 2:
            return (
                f"MODERATE: Expect {predicted_count} bug reports. "
                f"Monitor {', '.join(downstream)} closely."
            )
        return "LOW: Expect minimal bug reports. Standard monitoring sufficient."

