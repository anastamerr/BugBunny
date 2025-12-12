from unittest.mock import MagicMock, patch


@patch("src.services.pipeline_monitor.great_expectations_service.gx")
def test_create_expectation_suite_adds_default_expectation(mock_gx):
    mock_context = MagicMock()
    mock_context.sources.add_or_update_postgres.return_value = MagicMock()
    mock_suite = MagicMock()
    mock_context.add_or_update_expectation_suite.return_value = mock_suite
    mock_gx.get_context.return_value = mock_context
    mock_gx.core.ExpectationConfiguration.side_effect = lambda **kwargs: kwargs

    from src.services.pipeline_monitor.great_expectations_service import (
        GreatExpectationsService,
    )

    service = GreatExpectationsService("postgresql://example")
    suite = service.create_expectation_suite("users")

    assert suite == mock_suite
    assert mock_suite.add_expectation.called


@patch("src.services.pipeline_monitor.great_expectations_service.gx")
def test_validate_table_runs_checkpoint(mock_gx):
    mock_context = MagicMock()
    mock_ds = MagicMock()
    mock_asset = MagicMock()
    mock_checkpoint = MagicMock()

    mock_context.sources.add_or_update_postgres.return_value = mock_ds
    mock_ds.add_table_asset.return_value = mock_asset
    mock_asset.build_batch_request.return_value = {"batch": "req"}
    mock_context.add_or_update_checkpoint.return_value = mock_checkpoint
    mock_checkpoint.run.return_value = MagicMock(run_results={})
    mock_gx.get_context.return_value = mock_context

    from src.services.pipeline_monitor.great_expectations_service import (
        GreatExpectationsService,
    )

    service = GreatExpectationsService("postgresql://example")
    service._parse_results = MagicMock(return_value={"success": True})

    out = service.validate_table("users")
    mock_checkpoint.run.assert_called_once()
    service._parse_results.assert_called_once()
    assert out["success"] is True


@patch("src.services.pipeline_monitor.great_expectations_service.gx")
def test_parse_results_success(mock_gx):
    mock_context = MagicMock()
    mock_context.sources.add_or_update_postgres.return_value = MagicMock()
    mock_gx.get_context.return_value = mock_context

    from src.services.pipeline_monitor.great_expectations_service import (
        GreatExpectationsService,
    )

    service = GreatExpectationsService("postgresql://example")

    validation = {
        "success": True,
        "statistics": {
            "successful_expectations": 1,
            "unsuccessful_expectations": 0,
            "evaluated_expectations": 1,
        },
        "results": [],
    }
    results = MagicMock(run_results={"x": validation})
    parsed = service._parse_results(results, "users")
    assert parsed["success"] is True
    assert parsed["failures"] == []


@patch("src.services.pipeline_monitor.great_expectations_service.gx")
def test_parse_results_failure_collects_failures(mock_gx):
    mock_context = MagicMock()
    mock_context.sources.add_or_update_postgres.return_value = MagicMock()
    mock_gx.get_context.return_value = mock_context

    from src.services.pipeline_monitor.great_expectations_service import (
        GreatExpectationsService,
    )

    service = GreatExpectationsService("postgresql://example")

    validation = {
        "success": False,
        "statistics": {
            "successful_expectations": 0,
            "unsuccessful_expectations": 1,
            "evaluated_expectations": 1,
        },
        "results": [
            {
                "success": False,
                "expectation_config": {
                    "expectation_type": "expect_column_values_to_not_be_null",
                    "kwargs": {"column": "email"},
                },
                "result": {"unexpected_count": 2},
            }
        ],
    }
    results = MagicMock(run_results={"x": validation})
    parsed = service._parse_results(results, "users")
    assert parsed["success"] is False
    assert len(parsed["failures"]) == 1
    assert parsed["failures"][0]["column"] == "email"

