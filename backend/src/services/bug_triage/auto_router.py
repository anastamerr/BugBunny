from __future__ import annotations

from typing import Dict, Optional


class AutoRouter:
    """Routes bugs to appropriate teams based on classification and correlation."""

    COMPONENT_TEAM_MAP = {
        "frontend": "frontend_team",
        "backend": "backend_team",
        "mobile": "mobile_team",
        "analytics": "analytics_team",
        "ml": "ml_team",
        "infrastructure": "platform_team",
        "data": "data_engineering",
    }

    def route_bug(
        self,
        classification: Dict,
        is_data_related: bool,
        correlation_score: Optional[float] = None,
    ) -> Dict:
        if is_data_related and correlation_score and correlation_score > 0.7:
            return {
                "team": "data_engineering",
                "reason": "Bug is highly correlated with a data pipeline incident",
                "confidence": correlation_score,
                "priority_boost": True,
            }

        component = classification.get("component", "backend")
        team = self.COMPONENT_TEAM_MAP.get(component, "backend_team")

        return {
            "team": team,
            "reason": f"Classified as {component} issue",
            "confidence": classification.get("component_confidence", 0.5),
            "priority_boost": False,
        }

    def calculate_priority(
        self,
        severity: str,
        is_data_related: bool,
        correlation_score: Optional[float] = None,
    ) -> str:
        base_priority = {
            "critical": "P0",
            "high": "P1",
            "medium": "P2",
            "low": "P3",
        }

        priority = base_priority.get(severity, "P2")

        if is_data_related and correlation_score and correlation_score > 0.7:
            if priority == "P1":
                priority = "P0"
            elif priority == "P2":
                priority = "P1"

        return priority

