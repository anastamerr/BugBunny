from src.services.bug_triage.auto_router import AutoRouter


def test_route_bug_component_map():
    router = AutoRouter()
    out = router.route_bug({"component": "frontend", "component_confidence": 0.9})
    assert out["team"] == "frontend_team"
    assert out["priority_boost"] is False


def test_calculate_priority_from_severity():
    router = AutoRouter()
    assert router.calculate_priority("high") == "P1"

