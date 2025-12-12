from src.services.bug_triage.auto_router import AutoRouter


def test_route_bug_data_related_high_corr():
    router = AutoRouter()
    out = router.route_bug({"component": "frontend"}, True, correlation_score=0.8)
    assert out["team"] == "data_engineering"
    assert out["priority_boost"] is True


def test_route_bug_component_map():
    router = AutoRouter()
    out = router.route_bug({"component": "frontend", "component_confidence": 0.9}, False)
    assert out["team"] == "frontend_team"
    assert out["priority_boost"] is False


def test_calculate_priority_boosts_for_data_related():
    router = AutoRouter()
    assert router.calculate_priority("high", True, correlation_score=0.9) == "P0"

