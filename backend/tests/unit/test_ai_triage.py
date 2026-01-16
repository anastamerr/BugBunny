import pytest

from src.services.scanner.ai_triage import AITriageEngine
from src.services.scanner.types import CodeContext, RawFinding


class DummyLLM:
    async def generate(self, prompt, system=None):  # noqa: ANN001
        return (
            '{"is_false_positive": false, "adjusted_severity": "high", '
            '"confidence": 0.8, "reasoning": "Issue confirmed", '
            '"exploitability": "remote input"}'
        )


class BadLLM:
    async def generate(self, prompt, system=None):  # noqa: ANN001
        return "not json"


@pytest.mark.asyncio
async def test_triage_applies_test_file_adjustment():
    engine = AITriageEngine(llm_client=DummyLLM(), max_concurrency=1)
    finding = RawFinding(
        rule_id="rule-1",
        rule_message="msg",
        severity="ERROR",
        file_path="tests/test_sample.py",
        line_start=3,
        line_end=3,
        code_snippet="eval(user_input)",
    )
    context = CodeContext(
        snippet="eval(user_input)",
        function_name="handler",
        class_name=None,
        is_test_file=True,
        is_generated=False,
        imports=[],
    )

    result = await engine.triage_finding(finding, context)

    assert result.ai_severity == "low"
    assert result.ai_confidence == 0.8
    assert result.ai_reasoning == "Issue confirmed"
    assert result.is_false_positive is False


@pytest.mark.asyncio
async def test_triage_falls_back_on_invalid_json():
    engine = AITriageEngine(llm_client=BadLLM(), max_concurrency=1)
    finding = RawFinding(
        rule_id="rule-1",
        rule_message="msg",
        severity="WARNING",
        file_path="app.py",
        line_start=1,
        line_end=1,
        code_snippet="print('hi')",
    )
    context = CodeContext(
        snippet="print('hi')",
        function_name=None,
        class_name=None,
        is_test_file=False,
        is_generated=False,
        imports=[],
    )

    result = await engine.triage_finding(finding, context)

    assert "LLM response was unavailable" in result.ai_reasoning
    assert result.ai_confidence == 0.2
