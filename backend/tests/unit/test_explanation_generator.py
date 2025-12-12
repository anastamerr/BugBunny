from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.mark.asyncio
async def test_generate_root_cause_explanation_calls_llm():
    llm = AsyncMock()
    llm.generate.return_value = "explanation"

    from src.services.intelligence.explanation_generator import ExplanationGenerator

    gen = ExplanationGenerator(llm)
    bug = MagicMock(title="t", description="d", classified_component="backend", classified_severity="high", created_at="now")
    incident = MagicMock(incident_type="SCHEMA_DRIFT", table_name="users", affected_columns=["id"], severity="CRITICAL", timestamp="then", details={})

    out = await gen.generate_root_cause_explanation(bug, incident, 0.9)
    assert out == "explanation"
    llm.generate.assert_called_once()

