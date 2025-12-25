from __future__ import annotations

from functools import lru_cache
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ...api.deps import get_db
from ...config import get_settings
from ...integrations.pinecone_client import PineconeService
from ...models import BugReport, Finding, Scan
from ...schemas.chat import ChatRequest, ChatResponse
from ...services.intelligence.llm_service import get_llm_service

router = APIRouter(prefix="/chat", tags=["chat"])


def _truncate(text: str, max_len: int = 500) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _bug_brief(bug: BugReport) -> str:
    return (
        f"- {bug.id} | {bug.created_at} | {bug.classified_severity} "
        f"{bug.classified_component} | status={bug.status} | {bug.title}"
    )


def _scan_brief(scan: Scan) -> str:
    return (
        f"- {scan.id} | {scan.created_at} | status={scan.status} | "
        f"{scan.repo_url}@{scan.branch} | findings={scan.total_findings} "
        f"filtered={scan.filtered_findings}"
    )


def _finding_brief(finding: Finding) -> str:
    severity = finding.ai_severity or finding.semgrep_severity
    return (
        f"- {finding.id} | {severity} | {finding.file_path}:{finding.line_start} | "
        f"{finding.rule_id} | status={finding.status}"
    )


@lru_cache
def _get_pinecone_safe() -> Optional[PineconeService]:
    try:
        return PineconeService()
    except Exception:
        return None


def _priority_order_query(q):
    # Highest priority first: unresolved, severity, recency.
    from sqlalchemy import case, desc

    severity_rank = case(
        (BugReport.classified_severity == "critical", 4),
        (BugReport.classified_severity == "high", 3),
        (BugReport.classified_severity == "medium", 2),
        (BugReport.classified_severity == "low", 1),
        else_=0,
    )
    status_rank = case((BugReport.status == "resolved", 0), else_=1)

    return q.order_by(
        desc(status_rank),
        desc(severity_rank),
        BugReport.created_at.desc(),
    )


def _finding_order_query(q):
    from sqlalchemy import case, desc

    priority_rank = case((Finding.priority_score.is_(None), 0), else_=1)
    return q.order_by(
        desc(priority_rank),
        desc(Finding.priority_score),
        Finding.created_at.desc(),
    )


def _build_context(
    bug: BugReport | None,
    scan: Scan | None,
    finding: Finding | None,
    *,
    recent_bugs: list[BugReport],
    bug_queue: list[BugReport],
    semantic_bugs: list[BugReport],
    recent_scans: list[Scan],
    finding_queue: list[Finding],
    scan_findings: list[Finding],
) -> str:
    parts: list[str] = []

    snapshot = "\n".join(
        [
            "PLATFORM SNAPSHOT:",
            f"- Recent scans shown: {len(recent_scans)}",
            f"- Top findings shown: {len(finding_queue)}",
            f"- Recent bugs shown: {len(recent_bugs)}",
            f"- High-priority bugs shown: {len(bug_queue)}",
            f"- Semantic-matched bugs shown: {len(semantic_bugs)}",
        ]
    )
    parts.append(snapshot)

    if recent_scans:
        parts.append("RECENT SCANS:\n" + "\n".join(_scan_brief(s) for s in recent_scans))

    if finding_queue:
        parts.append(
            "TOP FINDINGS:\n" + "\n".join(_finding_brief(f) for f in finding_queue)
        )

    if recent_bugs:
        parts.append("RECENT BUGS:\n" + "\n".join(_bug_brief(b) for b in recent_bugs))

    if bug_queue:
        parts.append("HIGH-PRIORITY BUG QUEUE:\n" + "\n".join(_bug_brief(b) for b in bug_queue))

    if scan:
        parts.append(
            "\n".join(
                [
                    "FOCUS SCAN:",
                    f"- Repo: {scan.repo_url}",
                    f"- Branch: {scan.branch}",
                    f"- Status: {scan.status}",
                    f"- Findings: {scan.total_findings}",
                    f"- Filtered: {scan.filtered_findings}",
                ]
            )
        )

    if scan_findings:
        parts.append(
            "FOCUS SCAN FINDINGS:\n"
            + "\n".join(_finding_brief(f) for f in scan_findings)
        )

    if finding:
        parts.append(
            "\n".join(
                [
                    "FOCUS FINDING:",
                    f"- Rule: {finding.rule_id}",
                    f"- Severity: {finding.ai_severity or finding.semgrep_severity}",
                    f"- File: {finding.file_path}:{finding.line_start}",
                    f"- Status: {finding.status}",
                    f"- Reasoning: {_truncate(finding.ai_reasoning or '')}",
                ]
            )
        )

    if bug:
        parts.append(
            "\n".join(
                [
                    "FOCUS BUG:",
                    f"- Title: {bug.title}",
                    f"- Component: {bug.classified_component}",
                    f"- Severity: {bug.classified_severity}",
                    f"- Status: {bug.status}",
                    f"- Description: {_truncate(bug.description or '')}",
                ]
            )
        )

    if semantic_bugs:
        parts.append(
            "SEMANTICALLY RELEVANT BUGS (from embeddings):\n"
            + "\n".join(_bug_brief(b) for b in semantic_bugs)
        )

    return "\n\n".join(parts).strip()


@router.post("", response_model=ChatResponse)
async def chat(payload: ChatRequest, db: Session = Depends(get_db)) -> ChatResponse:
    bug: BugReport | None = None
    scan: Scan | None = None
    finding: Finding | None = None

    if payload.bug_id is not None and bug is None:
        bug = db.query(BugReport).filter(BugReport.id == payload.bug_id).first()
        if not bug:
            raise HTTPException(status_code=404, detail="Bug not found")

    if payload.scan_id is not None and scan is None:
        scan = db.query(Scan).filter(Scan.id == payload.scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

    if payload.finding_id is not None and finding is None:
        finding = db.query(Finding).filter(Finding.id == payload.finding_id).first()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

    if finding is not None and scan is None:
        scan = db.query(Scan).filter(Scan.id == finding.scan_id).first()

    # If user didn't provide specific IDs, we still want the assistant to be useful
    # by attaching recent platform context and a "focus" bug.
    recent_bugs = (
        db.query(BugReport).order_by(BugReport.created_at.desc()).limit(5).all()
    )

    if bug is None:
        bug = db.query(BugReport).order_by(BugReport.created_at.desc()).first()

    # High-priority bug queue (enterprise triage default).
    bug_q = _priority_order_query(db.query(BugReport)).limit(8).all()

    recent_scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(5).all()
    finding_q = (
        _finding_order_query(
            db.query(Finding).filter(Finding.is_false_positive.is_(False))
        )
        .limit(8)
        .all()
    )
    scan_findings: list[Finding] = []
    if scan is not None:
        scan_findings = (
            _finding_order_query(
                db.query(Finding).filter(
                    Finding.scan_id == scan.id,
                    Finding.is_false_positive.is_(False),
                )
            )
            .limit(8)
            .all()
        )

    # Semantic retrieval: pull relevant bugs for the user's question (optional).
    semantic_bugs: list[BugReport] = []
    pinecone = _get_pinecone_safe()
    if pinecone is not None and payload.message.strip():
        try:
            matches = pinecone.find_similar_bugs(payload.message, "", top_k=5)
            ids: list[uuid.UUID] = []
            for m in matches or []:
                mid = getattr(m, "id", None)
                if isinstance(mid, str):
                    try:
                        ids.append(uuid.UUID(mid))
                    except ValueError:
                        continue
            if ids:
                semantic_bugs = (
                    db.query(BugReport)
                    .filter(BugReport.id.in_(ids))
                    .all()
                )
        except Exception:
            semantic_bugs = []

    context = _build_context(
        bug,
        scan,
        finding,
        recent_bugs=recent_bugs,
        bug_queue=bug_q,
        semantic_bugs=semantic_bugs,
        recent_scans=recent_scans,
        finding_queue=finding_q,
        scan_findings=scan_findings,
    )

    system = (
        "You are ScanGuard AI, an enterprise-grade assistant for security findings and bug triage.\n"
        "Use ONLY the provided platform context. Be concise, technical, and actionable.\n"
        "Do not ask for context if the snapshot already includes bugs; instead make the best recommendation.\n"
        "If something critical is missing, ask at most 1-2 specific questions."
    )
    prompt = (
        (f"{context}\n\n" if context else "")
        + f"USER QUESTION:\n{payload.message}\n\n"
        "Answer with:\n"
        "1) Root cause hypothesis (with confidence)\n"
        "2) Evidence from context (bullets)\n"
        "3) Impacted users/components\n"
        "4) Triage plan (next best actions + owners)\n"
        "5) Prioritization (top 3 findings/bugs from the queue, if relevant)\n"
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
