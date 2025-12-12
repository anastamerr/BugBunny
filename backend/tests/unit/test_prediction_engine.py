from unittest.mock import MagicMock


def test_rule_based_prediction_boosts_for_critical():
    from src.services.intelligence.prediction_engine import PredictionEngine

    engine = PredictionEngine.__new__(PredictionEngine)
    engine.model = None
    engine.db = MagicMock()

    incident = MagicMock()
    incident.incident_type = "SCHEMA_DRIFT"
    incident.severity = "CRITICAL"
    incident.anomaly_score = 0.9
    incident.downstream_systems = ["analytics_dashboard"]
    incident.table_name = "user_transactions"

    out = PredictionEngine._rule_based_prediction(engine, incident)
    assert out["predicted_bug_count"] >= 8


def test_predict_bugs_uses_model():
    from src.services.intelligence.prediction_engine import PredictionEngine

    engine = PredictionEngine.__new__(PredictionEngine)
    engine.db = MagicMock()
    engine.model = MagicMock()
    engine.model.predict.return_value = [3]
    engine._find_similar_incidents = MagicMock(return_value=[])
    engine._predict_affected_components = MagicMock(return_value=["user_api"])
    engine._calculate_confidence = MagicMock(return_value=0.8)
    engine._generate_recommendation = MagicMock(return_value="rec")

    incident = MagicMock()
    incident.incident_type = "NULL_SPIKE"
    incident.severity = "HIGH"
    incident.anomaly_score = 0.6
    incident.downstream_systems = ["user_api"]

    out = PredictionEngine.predict_bugs(engine, incident)
    assert out["predicted_bug_count"] == 3
    assert out["predicted_components"] == ["user_api"]

