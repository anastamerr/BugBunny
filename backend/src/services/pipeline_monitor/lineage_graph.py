from __future__ import annotations

from typing import List


class DataLineageGraph:
    """Simple lineage graph for demo purposes."""

    LINEAGE = {
        "user_transactions": {
            "downstream": [
                "analytics_dashboard",
                "user_api",
                "mobile_app",
                "recommendation_model",
            ],
            "owners": ["data_engineering"],
            "criticality": "HIGH",
            "refresh_frequency_hours": 1,
        },
        "user_profiles": {
            "downstream": ["user_api", "mobile_app", "personalization_service"],
            "owners": ["data_engineering"],
            "criticality": "HIGH",
            "refresh_frequency_hours": 24,
        },
        "product_catalog": {
            "downstream": [
                "search_service",
                "recommendation_model",
                "inventory_api",
            ],
            "owners": ["data_engineering"],
            "criticality": "MEDIUM",
            "refresh_frequency_hours": 6,
        },
    }

    COMPONENT_TO_TABLES = {
        "analytics_dashboard": ["user_transactions", "aggregated_metrics"],
        "user_api": ["user_transactions", "user_profiles"],
        "mobile_app": ["user_transactions", "user_profiles"],
        "recommendation_model": ["user_transactions", "product_catalog"],
        "search_service": ["product_catalog"],
        "personalization_service": ["user_profiles"],
    }

    def get_downstream_systems(self, table_name: str) -> List[str]:
        return self.LINEAGE.get(table_name, {}).get("downstream", [])

    def get_tables_for_component(self, component: str) -> List[str]:
        return self.COMPONENT_TO_TABLES.get(component, [])

    def is_downstream(self, component: str, table: str) -> bool:
        downstream = self.get_downstream_systems(table)
        return component in downstream

