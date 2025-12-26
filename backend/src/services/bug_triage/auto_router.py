from __future__ import annotations

from typing import Dict


class AutoRouter:
    """Routes bugs to appropriate teams based on classification."""

    COMPONENT_TEAM_MAP = {
        "frontend": "frontend_team",
        "backend": "backend_team",
        "mobile": "mobile_team",
        "analytics": "analytics_team",
        "ml": "ml_team",
        "infrastructure": "platform_team",
        "data": "data_engineering",
        # Lineage-aligned components
        "analytics_dashboard": "analytics_team",
        "user_api": "backend_team",
        "mobile_app": "mobile_team",
        "recommendation_model": "ml_team",
        "search_service": "backend_team",
        "inventory_api": "backend_team",
        "personalization_service": "ml_team",
    }

    def route_bug(self, classification: Dict) -> Dict:
        component = classification.get("component", "backend")
        team = self.COMPONENT_TEAM_MAP.get(component, "backend_team")

        return {
            "team": team,
            "reason": f"Classified as {component} issue",
            "confidence": classification.get("component_confidence", 0.5),
            "priority_boost": False,
        }

    def calculate_priority(self, severity: str) -> str:
        base_priority = {
            "critical": "P0",
            "high": "P1",
            "medium": "P2",
            "low": "P3",
        }

        return base_priority.get(severity, "P2")
