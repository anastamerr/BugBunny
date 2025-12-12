from __future__ import annotations

from typing import List

from ...models import BugReport, DataIncident
from .llm_service import OllamaService


class ExplanationGenerator:
    def __init__(self, llm: OllamaService):
        self.llm = llm

    async def generate_root_cause_explanation(
        self,
        bug: BugReport,
        incident: DataIncident,
        correlation_score: float,
    ) -> str:
        system_prompt = (
            "You are a data engineering expert helping to explain\n"
            "the root cause of software bugs. Be concise, technical, and actionable.\n"
            "Format your response in 3 parts:\n"
            "1. Root Cause: What happened\n"
            "2. Impact: How it caused the bug\n"
            "3. Suggested Fix: What to do"
        )

        prompt = f"""
        A bug report has been correlated with a data pipeline incident.

        BUG REPORT:
        - Title: {bug.title}
        - Description: {bug.description}
        - Component: {bug.classified_component}
        - Severity: {bug.classified_severity}
        - Reported: {bug.created_at}

        DATA INCIDENT:
        - Type: {incident.incident_type}
        - Table: {incident.table_name}
        - Affected Columns: {', '.join(incident.affected_columns or [])}
        - Severity: {incident.severity}
        - Time: {incident.timestamp}
        - Details: {incident.details}

        Correlation Score: {correlation_score:.0%}

        Explain the connection between this data incident and the bug report.
        """

        return await self.llm.generate(prompt, system_prompt)

    async def generate_cluster_summary(
        self, incident: DataIncident, bugs: List[BugReport]
    ) -> str:
        system_prompt = (
            "You are summarizing a group of related bug reports\n"
            "that were all caused by the same data incident. Be concise."
        )

        bug_summaries = "\n".join(
            [
                f"- {b.title} ({b.classified_component}, {b.classified_severity})"
                for b in bugs[:10]
            ]
        )

        prompt = f"""
        A data incident caused {len(bugs)} related bug reports:

        INCIDENT:
        - Type: {incident.incident_type}
        - Table: {incident.table_name}
        - Severity: {incident.severity}

        RELATED BUGS:
        {bug_summaries}

        Provide a brief summary of:
        1. The common root cause
        2. The blast radius (what was affected)
        3. Priority recommendation
        """

        return await self.llm.generate(prompt, system_prompt)

