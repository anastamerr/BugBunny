from src.scanguard_scan.runners.zap_runner import parse_zap_alert


def test_parse_zap_alert_basic_fields():
    alert = {
        "pluginId": "40018",
        "alert": "SQL Injection",
        "risk": "High",
        "confidence": "High",
        "url": "http://example.com/login",
        "param": "username",
        "evidence": "You have an error in your SQL syntax",
        "cweid": "89",
    }

    parsed = parse_zap_alert(alert)

    assert parsed is not None
    assert parsed.plugin_id == "40018"
    assert parsed.name == "SQL Injection"
    assert parsed.risk == "high"
    assert parsed.url == "http://example.com/login"
    assert parsed.param == "username"
    assert parsed.cwe_id == 89
