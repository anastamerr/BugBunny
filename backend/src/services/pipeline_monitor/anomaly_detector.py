from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Tuple

import numpy as np
from pyod.models.iforest import IForest
from pyod.models.knn import KNN
from sqlalchemy.orm import Session


class _SimpleEnsemble:
    def __init__(self, detectors):
        self.detectors = detectors

    def fit(self, X: np.ndarray) -> "_SimpleEnsemble":
        for d in self.detectors:
            d.fit(X)
        return self

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        scores = np.vstack([d.decision_function(X) for d in self.detectors])
        return scores.mean(axis=0)

    def predict(self, X: np.ndarray) -> np.ndarray:
        preds = np.vstack([d.predict(X) for d in self.detectors])
        votes = (preds == 1).sum(axis=0) >= (len(self.detectors) / 2)
        return votes.astype(int)


class AnomalyDetector:
    def __init__(self, db: Session):
        self.db = db
        self.models: Dict[str, _SimpleEnsemble] = {}

    def compute_metrics(self, table_name: str) -> Dict[str, float]:
        query = f"""
            SELECT
                COUNT(*) as row_count,
                COUNT(*) FILTER (WHERE user_id IS NULL) * 100.0 / NULLIF(COUNT(*), 0) as null_rate_user_id,
                COUNT(*) FILTER (WHERE transaction_amount IS NULL) * 100.0 / NULLIF(COUNT(*), 0) as null_rate_amount,
                AVG(transaction_amount) as avg_amount,
                STDDEV(transaction_amount) as std_amount,
                MAX(transaction_date) as latest_record
            FROM {table_name}
        """
        result = self.db.execute(query).fetchone()

        return {
            "row_count": result.row_count,
            "null_rate_user_id": result.null_rate_user_id or 0,
            "null_rate_amount": result.null_rate_amount or 0,
            "avg_amount": float(result.avg_amount or 0),
            "std_amount": float(result.std_amount or 0),
            "freshness_hours": self._compute_freshness(result.latest_record),
        }

    def _compute_freshness(self, latest_record: datetime) -> float:
        if latest_record is None:
            return 999.0
        delta = datetime.utcnow() - latest_record
        return delta.total_seconds() / 3600

    def get_historical_metrics(self, table_name: str, days: int = 30) -> List[Dict]:
        query = """
            SELECT metrics, recorded_at
            FROM metrics_history
            WHERE table_name = :table_name
            AND recorded_at > :start_date
            ORDER BY recorded_at
        """
        results = self.db.execute(
            query,
            {
                "table_name": table_name,
                "start_date": datetime.utcnow() - timedelta(days=days),
            },
        ).fetchall()

        return [{"metrics": r.metrics, "timestamp": r.recorded_at} for r in results]

    def train_model(self, table_name: str):
        historical = self.get_historical_metrics(table_name)
        if len(historical) < 10:
            return None

        features = []
        for record in historical:
            m = record["metrics"]
            features.append(
                [
                    m["row_count"],
                    m["null_rate_user_id"],
                    m["null_rate_amount"],
                    m["avg_amount"],
                    m["freshness_hours"],
                ]
            )

        X = np.array(features)

        detectors = [
            IForest(contamination=0.1, random_state=42),
            KNN(contamination=0.1),
        ]
        model = _SimpleEnsemble(detectors).fit(X)

        self.models[table_name] = model
        return model

    def detect_anomaly(
        self, table_name: str, metrics: Dict
    ) -> Tuple[bool, float, Dict]:
        if table_name not in self.models:
            self.train_model(table_name)

        model = self.models.get(table_name)
        if model is None:
            return False, 0.0, {}

        X = np.array(
            [
                [
                    metrics["row_count"],
                    metrics["null_rate_user_id"],
                    metrics["null_rate_amount"],
                    metrics["avg_amount"],
                    metrics["freshness_hours"],
                ]
            ]
        )

        score = model.decision_function(X)[0]
        is_anomaly = model.predict(X)[0] == 1
        anomalous_metrics = self._identify_anomalous_metrics(table_name, metrics)

        return is_anomaly, float(score), anomalous_metrics

    def _identify_anomalous_metrics(self, table_name: str, metrics: Dict) -> Dict:
        historical = self.get_historical_metrics(table_name)
        if len(historical) < 5:
            return {}

        anomalies: Dict[str, Dict] = {}
        for key in [
            "row_count",
            "null_rate_user_id",
            "null_rate_amount",
            "freshness_hours",
        ]:
            values = [h["metrics"][key] for h in historical]
            mean = float(np.mean(values))
            std = float(np.std(values) or 1)
            z_score = (metrics[key] - mean) / std

            if abs(z_score) > 3:
                anomalies[key] = {
                    "current": metrics[key],
                    "mean": mean,
                    "std": std,
                    "z_score": z_score,
                    "direction": "high" if z_score > 0 else "low",
                }

        return anomalies
