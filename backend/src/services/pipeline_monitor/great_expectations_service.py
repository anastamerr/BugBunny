from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

import great_expectations as gx
from great_expectations.core import ExpectationSuite


class GreatExpectationsService:
    def __init__(self, connection_string: str):
        self.context = gx.get_context()
        self.connection_string = connection_string
        self._setup_datasource()

    def _setup_datasource(self) -> None:
        self.datasource = self.context.sources.add_or_update_postgres(
            name="databug_source", connection_string=self.connection_string
        )

    def create_expectation_suite(self, table_name: str) -> ExpectationSuite:
        suite_name = f"{table_name}_suite"
        suite = self.context.add_or_update_expectation_suite(suite_name)

        expectations = [
            {
                "expectation_type": "expect_table_row_count_to_be_between",
                "kwargs": {"min_value": 1},
            }
        ]

        for exp in expectations:
            suite.add_expectation(
                expectation_configuration=gx.core.ExpectationConfiguration(**exp)
            )

        return suite

    def add_column_expectations(self, suite_name: str, column: str, config: dict) -> None:
        suite = self.context.get_expectation_suite(suite_name)

        if config.get("not_null", False):
            suite.add_expectation(
                gx.core.ExpectationConfiguration(
                    expectation_type="expect_column_values_to_not_be_null",
                    kwargs={"column": column},
                )
            )

        if "value_set" in config:
            suite.add_expectation(
                gx.core.ExpectationConfiguration(
                    expectation_type="expect_column_values_to_be_in_set",
                    kwargs={"column": column, "value_set": config["value_set"]},
                )
            )

        if "min_value" in config or "max_value" in config:
            suite.add_expectation(
                gx.core.ExpectationConfiguration(
                    expectation_type="expect_column_values_to_be_between",
                    kwargs={
                        "column": column,
                        "min_value": config.get("min_value"),
                        "max_value": config.get("max_value"),
                    },
                )
            )

        if "regex" in config:
            suite.add_expectation(
                gx.core.ExpectationConfiguration(
                    expectation_type="expect_column_values_to_match_regex",
                    kwargs={"column": column, "regex": config["regex"]},
                )
            )

        self.context.save_expectation_suite(suite)

    def create_demo_suites(self) -> None:
        for table_name, table_config in DEMO_TABLE_CONFIGS.items():
            suite = self.create_expectation_suite(table_name)
            for column_name, column_cfg in table_config.get("columns", {}).items():
                self.add_column_expectations(suite.expectation_suite_name, column_name, column_cfg)

            row_count_cfg = table_config.get("row_count")
            if row_count_cfg:
                suite.add_expectation(
                    gx.core.ExpectationConfiguration(
                        expectation_type="expect_table_row_count_to_be_between",
                        kwargs={
                            "min_value": row_count_cfg.get("min"),
                            "max_value": row_count_cfg.get("max"),
                        },
                    )
                )
                self.context.save_expectation_suite(suite)

    def validate_table(self, table_name: str) -> Dict[str, Any]:
        suite_name = f"{table_name}_suite"

        asset = self.datasource.add_table_asset(name=table_name, table_name=table_name)
        batch_request = asset.build_batch_request()

        checkpoint = self.context.add_or_update_checkpoint(
            name=f"{table_name}_checkpoint",
            validations=[
                {
                    "batch_request": batch_request,
                    "expectation_suite_name": suite_name,
                }
            ],
        )

        results = checkpoint.run()
        return self._parse_results(results, table_name)

    def _parse_results(self, results: Any, table_name: str) -> Dict[str, Any]:
        validation_result = list(results.run_results.values())[0]

        success = validation_result["success"]
        statistics = validation_result["statistics"]

        failures = []
        for result in validation_result["results"]:
            if not result["success"]:
                failures.append(
                    {
                        "expectation_type": result["expectation_config"][
                            "expectation_type"
                        ],
                        "column": result["expectation_config"]["kwargs"].get("column"),
                        "details": result["result"],
                    }
                )

        return {
            "table": table_name,
            "timestamp": datetime.utcnow().isoformat(),
            "success": success,
            "statistics": {
                "successful": statistics["successful_expectations"],
                "unsuccessful": statistics["unsuccessful_expectations"],
                "total": statistics["evaluated_expectations"],
            },
            "failures": failures,
        }


DEMO_TABLE_CONFIGS = {
    "user_transactions": {
        "columns": {
            "user_id": {"not_null": True},
            "transaction_amount": {"not_null": True, "min_value": 0},
            "transaction_date": {"not_null": True},
            "status": {
                "not_null": True,
                "value_set": ["completed", "pending", "failed"],
            },
        },
        "row_count": {"min": 100, "max": 1000000},
    },
    "user_profiles": {
        "columns": {
            "user_id": {"not_null": True},
            "email": {
                "not_null": True,
                "regex": r"^[\w\.-]+@[\w\.-]+\.\w+$",
            },
            "created_at": {"not_null": True},
        }
    },
    "product_catalog": {
        "columns": {
            "product_id": {"not_null": True},
            "name": {"not_null": True},
            "price": {"not_null": True, "min_value": 0},
        }
    },
}

