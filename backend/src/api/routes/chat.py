from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ...api.deps import get_db
from ...config import get_settings
from ...models import BugIncidentCorrelation, BugReport, DataIncident
from ...schemas.chat import ChatRequest, ChatResponse
from ...services.intelligence.llm_service import get_llm_service

router = APIRouter(prefix="/chat", tags=["chat"])


def _build_context(
    bug: BugReport | None,
    incident: DataIncident | None,
    correlation: BugIncidentCorrelation | None,
) -> str:
    parts: list[str] = []

    if incident:
        parts.append(
            "\n".join(
                [
                    "DATA INCIDENT:",
                    f"- Table: {incident.table_name}",
                    f"- Type: {incident.incident_type}",
                    f"- Severity: {incident.severity}",
                    f"- Status: {incident.status}",
                    f"- Affected Columns: {', '.join(incident.affected_columns or [])}",
                    f"- Details: {incident.details or {}}",
                ]
            )
        )

    if bug:
        parts.append(
            "\n".join(
                [
                    "BUG REPORT:",
                    f"- Title: {bug.title}",
                    f"- Component: {bug.classified_component}",
                    f"- Severity: {bug.classified_severity}",
                    f"- Status: {bug.status}",
                    f"- Description: {bug.description or ''}",
                ]
            )
        )

    if correlation:
        parts.append(
            "\n".join(
                [
                    "CORRELATION:",
                    f"- Score: {correlation.correlation_score}",
                    f"- Explanation: {correlation.explanation or ''}",
                ]
            )
        )

    return "\n\n".join(parts).strip()


@router.post("", response_model=ChatResponse)
async def chat(payload: ChatRequest, db: Session = Depends(get_db)) -> ChatResponse:
    bug: BugReport | None = None
    incident: DataIncident | None = None
    correlation: BugIncidentCorrelation | None = None

    if payload.correlation_id is not None:
        correlation = (
            db.query(BugIncidentCorrelation)
            .filter(BugIncidentCorrelation.id == payload.correlation_id)
            .first()
        )
        if not correlation:
            raise HTTPException(status_code=404, detail="Correlation not found")

        bug = (
            db.query(BugReport).filter(BugReport.id == correlation.bug_id).first()
        )
        incident = (
            db.query(DataIncident)
            .filter(DataIncident.id == correlation.incident_id)
            .first()
        )

    if payload.bug_id is not None and bug is None:
        bug = db.query(BugReport).filter(BugReport.id == payload.bug_id).first()
        if not bug:
            raise HTTPException(status_code=404, detail="Bug not found")

    if payload.incident_id is not None and incident is None:
        incident = (
            db.query(DataIncident)
            .filter(DataIncident.id == payload.incident_id)
            .first()
        )
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

    context = _build_context(bug, incident, correlation)

    system = (
        "You are DataBug AI's assistant for bug triage and data incident response.\n"
        "Be concise, technical, and actionable.\n"
        "If needed context is missing, ask 1-2 clarifying questions."
    )
    prompt = (
        (f"{context}\n\n" if context else "")
        + f"USER QUESTION:\n{payload.message}\n\n"
        "Answer with:\n"
        "1) Root cause hypothesis\n"
        "2) Evidence in the provided context\n"
        "3) Next best action\n"
    )

    settings = get_settings()
    llm = get_llm_service(settings)

    try:
        if not await llm.is_available():
            fallback = (
                "LLM is unavailable. Configure OPEN_ROUTER_API_KEY or start Ollama.\n"
                + (f"\nContext:\n{context}\n" if context else "")
            ).strip()
            return ChatResponse(response=fallback, used_llm=False, model=None)

        text = await llm.generate(prompt, system=system)
        return ChatResponse(response=text, used_llm=True, model=llm.model)
    except Exception as exc:
        fallback = (
            f"LLM request failed: {type(exc).__name__}. "
            "Check your LLM provider settings and retry.\n"
            + (f"\nContext:\n{context}\n" if context else "")
        ).strip()
        return ChatResponse(response=fallback, used_llm=False, model=None)
