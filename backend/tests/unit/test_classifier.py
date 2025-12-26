from unittest.mock import MagicMock


def test_classify_returns_confidence():
    from src.services.bug_triage.classifier import BugClassifier

    classifier = BugClassifier.__new__(BugClassifier)
    classifier.encoder = MagicMock()
    classifier.encoder.encode.return_value = [[0.0]]

    classifier.type_classifier = MagicMock()
    classifier.component_classifier = MagicMock()
    classifier.severity_classifier = MagicMock()

    classifier.type_classifier.predict_proba.return_value = [[0.9, 0.1]]
    classifier.component_classifier.predict_proba.return_value = [[0.2, 0.8]]
    classifier.severity_classifier.predict_proba.return_value = [[0.3, 0.7]]

    classifier.type_encoder = MagicMock()
    classifier.component_encoder = MagicMock()
    classifier.severity_encoder = MagicMock()

    classifier.type_encoder.inverse_transform.return_value = ["bug"]
    classifier.component_encoder.inverse_transform.return_value = ["backend"]
    classifier.severity_encoder.inverse_transform.return_value = ["high"]

    out = BugClassifier.classify(classifier, "title", "desc")

    assert out["type"] == "bug"
    assert out["component"] == "backend"
    assert out["severity"] == "high"
    assert out["overall_confidence"] > 0

