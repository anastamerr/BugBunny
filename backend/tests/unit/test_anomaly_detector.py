from datetime import datetime, timedelta
from unittest.mock import MagicMock


def test_compute_metrics_returns_expected_fields():
    db = MagicMock()
    row = MagicMock(
        row_count=100,
        null_rate_user_id=None,
        null_rate_amount=2.5,
        avg_amount=10,
        std_amount=1.2,
        latest_record=None,
    )
    db.execute.return_value.fetchone.return_value = row

    from src.services.pipeline_monitor.anomaly_detector import AnomalyDetector

    detector = AnomalyDetector(db)
    metrics = detector.compute_metrics("user_transactions")

    assert metrics["row_count"] == 100
    assert metrics["null_rate_user_id"] == 0
    assert metrics["null_rate_amount"] == 2.5
    assert metrics["freshness_hours"] == 999.0


def test_detect_anomaly_without_model_returns_false():
    db = MagicMock()

    from src.services.pipeline_monitor.anomaly_detector import AnomalyDetector

    detector = AnomalyDetector(db)
    detector.train_model = MagicMock(return_value=None)

    is_anom, score, details = detector.detect_anomaly(
        "t",
        {
            "row_count": 1,
            "null_rate_user_id": 0,
            "null_rate_amount": 0,
            "avg_amount": 0,
            "freshness_hours": 0,
        },
    )

    assert is_anom is False
    assert score == 0.0
    assert details == {}


def test_identify_anomalous_metrics_flags_outlier():
    db = MagicMock()

    from src.services.pipeline_monitor.anomaly_detector import AnomalyDetector

    detector = AnomalyDetector(db)
    historical = []
    base_metrics = {
        "row_count": 100,
        "null_rate_user_id": 1,
        "null_rate_amount": 1,
        "avg_amount": 10,
        "freshness_hours": 1,
    }
    now = datetime.utcnow()
    for i in range(5):
        historical.append(
            {"metrics": base_metrics, "timestamp": now - timedelta(hours=i)}
        )
    detector.get_historical_metrics = MagicMock(return_value=historical)

    anomalies = detector._identify_anomalous_metrics(
        "t",
        {
            **base_metrics,
            "row_count": 1000,
        },
    )

    assert "row_count" in anomalies

