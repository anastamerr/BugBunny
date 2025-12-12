from unittest.mock import MagicMock


def make_generator():
    db = MagicMock()
    lineage = MagicMock()
    lineage.get_downstream_systems.return_value = ["analytics_dashboard"]

    from src.services.pipeline_monitor.incident_generator import IncidentGenerator

    return IncidentGenerator(db, lineage)


def test_classify_incident_schema_drift():
    gen = make_generator()
    validation = {"failures": [{"expectation_type": "expect_column_to_exist"}]}
    assert gen._classify_incident(validation, None) == "SCHEMA_DRIFT"


def test_classify_incident_null_spike():
    gen = make_generator()
    validation = {"failures": [{"expectation_type": "expect_column_values_to_not_be_null"}]}
    assert gen._classify_incident(validation, None) == "NULL_SPIKE"


def test_calculate_severity_boosts_for_high_anomaly_score():
    gen = make_generator()
    validation = {"statistics": {"total": 1, "unsuccessful": 1}}
    anomaly = {"score": 0.9}
    assert gen._calculate_severity("FRESHNESS", validation, anomaly) == "HIGH"


def test_build_details_includes_validation_and_anomaly():
    gen = make_generator()
    validation = {"statistics": {"total": 2, "unsuccessful": 1}, "failures": []}
    anomaly = {"is_anomaly": False}
    details = gen._build_details(validation, anomaly)
    assert "validation" in details
    assert details["anomaly"] == anomaly

