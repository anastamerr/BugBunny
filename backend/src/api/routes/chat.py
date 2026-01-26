from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
from typing import AsyncGenerator, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
import httpx
from sqlalchemy.orm import Session

from ...api.deps import CurrentUser, get_current_user, get_db
from ...config import get_settings
from ...integrations.pinecone_client import PineconeService
from ...models import BugReport, Finding, Scan
from ...schemas.chat import ChatRequest, ChatResponse
from ...services.intelligence.llm_service import (
    OllamaService,
    OpenRouterService,
    get_llm_service,
)
from ...services.scanner.project_memory import extract_repo_full_name, redact_text

router = APIRouter(prefix="/chat", tags=["chat"])

BUG_SEMANTIC_TOP_K = 5
BUG_SEMANTIC_SCORE_THRESHOLD = 0.72
PROJECT_MEMORY_TOP_K = 6
PROJECT_MEMORY_SCORE_THRESHOLD = 0.68
MAX_SECTION_CHARS = 1200


def _truncate(text: str, max_len: int = 500) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _guess_language(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    mapping = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
        ".java": "java",
    }
    return mapping.get(ext, "")


def _code_block(code: str, language: str = "") -> str:
    if not code:
        return "n/a"
    return f"```{language}\n{code}\n```"


def _format_list(items: list[str] | None, empty_label: str = "none") -> str:
    if not items:
        return empty_label
    return ", ".join(items)


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


def _repo_context_from_bug(bug: BugReport | None) -> dict[str, str]:
    if bug is None:
        return {}
    labels = bug.labels if isinstance(bug.labels, dict) else {}
    repo_full_name = None
    repo_url = None
    if isinstance(labels, dict):
        repo_full_name = labels.get("repo") or labels.get("repo_full_name")
        repo_url = labels.get("repo_url")
    if not repo_full_name and isinstance(bug.bug_id, str):
        if bug.bug_id.startswith("gh:") and "#" in bug.bug_id:
            repo_full_name = bug.bug_id.split("gh:", 1)[1].split("#", 1)[0]
    if not repo_url and repo_full_name:
        repo_url = f"https://github.com/{repo_full_name}"
    context = {}
    if repo_full_name:
        context["repo_full_name"] = repo_full_name
    if repo_url:
        context["repo_url"] = repo_url
    return context


def _repo_context_from_scan(scan: Scan | None) -> dict[str, str]:
    if scan is None:
        return {}
    repo_url = scan.repo_url
    repo_full_name = extract_repo_full_name(repo_url)
    context = {}
    if repo_full_name:
        context["repo_full_name"] = repo_full_name
    if repo_url:
        context["repo_url"] = repo_url
    return context


def _build_repo_filter(context: dict[str, str]) -> dict | None:
    if not context:
        return None
    if context.get("repo_full_name"):
        return {"repo_full_name": {"$eq": context["repo_full_name"]}}
    if context.get("repo_url"):
        return {"repo_url": {"$eq": context["repo_url"]}}
    return None


def _build_project_memory_filter(
    repo_filter: dict | None,
    scan: Scan | None,
    finding: Finding | None,
) -> dict | None:
    if not repo_filter:
        return None
    scoped = dict(repo_filter)
    if scan is not None:
        scoped["scan_id"] = {"$eq": str(scan.id)}
        return scoped
    if finding is not None:
        if finding.rule_id:
            scoped["rule_id"] = {"$eq": finding.rule_id}
        elif finding.endpoint:
            scoped["endpoint"] = {"$eq": finding.endpoint}
        elif finding.file_path:
            scoped["file_path"] = {"$eq": finding.file_path}
    return scoped


def _score_ok(match: object, threshold: float) -> bool:
    score = getattr(match, "score", None)
    try:
        return float(score or 0.0) >= threshold
    except Exception:
        return False


def _cap_lines(lines: list[str], max_chars: int) -> list[str]:
    capped: list[str] = []
    total = 0
    for line in lines:
        line_len = len(line) + 1
        if total + line_len > max_chars:
            break
        capped.append(line)
        total += line_len
    return capped


def _cap_bug_list(bugs: list[BugReport], max_chars: int) -> list[BugReport]:
    lines = [_bug_brief(b) for b in bugs]
    capped = _cap_lines(lines, max_chars)
    return bugs[: len(capped)]


def _project_memory_brief(match: object) -> str:
    metadata = getattr(match, "metadata", None) or {}
    summary = metadata.get("summary") or metadata.get("text") or ""
    summary = redact_text(str(summary))
    summary = _truncate(summary, 260)
    doc_type = metadata.get("doc_type") or "memory"
    severity = metadata.get("severity") or "n/a"
    scan_id = metadata.get("scan_id") or "n/a"
    score = getattr(match, "score", None)
    score_label = "n/a"
    if score is not None:
        try:
            score_label = f"{float(score):.2f}"
        except Exception:
            score_label = "n/a"
    return f"- [{doc_type}] severity={severity} scan={scan_id} score={score_label} :: {summary}"


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
    project_memory: list[str],
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
            f"- Project memory matches shown: {len(project_memory)}",
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
            "SEMANTIC BUG MATCHES:\n"
            + "\n".join(_bug_brief(b) for b in semantic_bugs)
        )

    if project_memory:
        parts.append("PROJECT MEMORY:\n" + "\n".join(project_memory))

    return "\n\n".join(parts).strip()


def _build_focus_context(
    bug: BugReport | None,
    scan: Scan | None,
    finding: Finding | None,
    *,
    scan_findings: list[Finding],
    project_memory: list[str],
) -> str:
    parts: list[str] = []

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
                    f"- Languages: {_format_list(scan.detected_languages)}",
                    f"- Rulesets: {_format_list(scan.rulesets, 'auto')}",
                    f"- Files scanned: {scan.scanned_files or 'n/a'}",
                    f"- Semgrep: {scan.semgrep_version or 'n/a'}",
                ]
            )
        )

    if scan_findings and not finding:
        parts.append(
            "FOCUS SCAN FINDINGS:\n"
            + "\n".join(_finding_brief(f) for f in scan_findings)
        )

    if finding:
        language = _guess_language(finding.file_path)
        code = finding.context_snippet or finding.code_snippet or ""
        parts.append(
            "\n".join(
                [
                    "FOCUS FINDING:",
                    f"- Rule: {finding.rule_id}",
                    f"- Message: {finding.rule_message or ''}",
                    f"- Semgrep severity: {finding.semgrep_severity}",
                    f"- AI severity: {finding.ai_severity or finding.semgrep_severity}",
                    f"- Confidence: {finding.ai_confidence}",
                    f"- File: {finding.file_path}:{finding.line_start}-{finding.line_end}",
                    f"- Function: {finding.function_name or 'n/a'}",
                    f"- Class: {finding.class_name or 'n/a'}",
                    f"- Test file: {finding.is_test_file}",
                    f"- Generated: {finding.is_generated}",
                    f"- Imports: {_format_list(finding.imports)}",
                    f"- Status: {finding.status}",
                    f"- Priority: {finding.priority_score if finding.priority_score is not None else 'n/a'}",
                    f"- Reasoning: {finding.ai_reasoning or ''}",
                    f"- Exploitability: {finding.exploitability or ''}",
                    "CODE:",
                    _code_block(code, language),
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
                    f"- Description: {bug.description or ''}",
                ]
            )
        )

    if project_memory:
        parts.append("PROJECT MEMORY:\n" + "\n".join(project_memory))

    return "\n\n".join(part for part in parts if part).strip()


def _prepare_chat_prompt(
    payload: ChatRequest,
    db: Session,
    current_user: CurrentUser,
) -> tuple[str, str, str, bool]:
    bug: BugReport | None = None
    scan: Scan | None = None
    finding: Finding | None = None

    focus_bug = payload.bug_id is not None
    focus_finding = payload.finding_id is not None
    focus_scan = payload.scan_id is not None and not focus_finding
    focus_mode = focus_bug or focus_finding or focus_scan

    if payload.bug_id is not None and bug is None:
        bug = db.query(BugReport).filter(BugReport.id == payload.bug_id).first()
        if not bug:
            raise HTTPException(status_code=404, detail="Bug not found")

    if payload.scan_id is not None and scan is None:
        scan = (
            db.query(Scan)
            .filter(Scan.id == payload.scan_id, Scan.user_id == current_user.id)
            .first()
        )
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

    if payload.finding_id is not None and finding is None:
        finding = (
            db.query(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .filter(Finding.id == payload.finding_id, Scan.user_id == current_user.id)
            .first()
        )
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

    if finding is not None and scan is None:
        scan = (
            db.query(Scan)
            .filter(Scan.id == finding.scan_id, Scan.user_id == current_user.id)
            .first()
        )

    # If user didn't provide specific IDs, we still want the assistant to be useful
    # by attaching recent platform context and a "focus" bug.
    recent_bugs: list[BugReport] = []
    bug_q: list[BugReport] = []
    recent_scans: list[Scan] = []
    finding_q: list[Finding] = []
    scan_findings: list[Finding] = []

    if not focus_mode:
        recent_bugs = (
            db.query(BugReport).order_by(BugReport.created_at.desc()).limit(5).all()
        )
        if bug is None:
            bug = db.query(BugReport).order_by(BugReport.created_at.desc()).first()

        # High-priority bug queue (enterprise triage default).
        bug_q = _priority_order_query(db.query(BugReport)).limit(8).all()

        recent_scans = (
            db.query(Scan)
            .filter(Scan.user_id == current_user.id)
            .order_by(Scan.created_at.desc())
            .limit(5)
            .all()
        )
        finding_q = (
            _finding_order_query(
                db.query(Finding)
                .join(Scan, Finding.scan_id == Scan.id)
                .filter(
                    Finding.is_false_positive.is_(False),
                    Scan.user_id == current_user.id,
                )
            )
            .limit(8)
            .all()
        )

    if scan is not None and focus_scan:
        scan_findings = (
            _finding_order_query(
                db.query(Finding)
                .join(Scan, Finding.scan_id == Scan.id)
                .filter(
                    Finding.scan_id == scan.id,
                    Finding.is_false_positive.is_(False),
                    Scan.user_id == current_user.id,
                )
            )
            .limit(8)
            .all()
        )

    repo_context: dict[str, str] = {}
    if scan is not None:
        repo_context = _repo_context_from_scan(scan)
    if not repo_context and bug is not None:
        repo_context = _repo_context_from_bug(bug)
    if not repo_context and recent_scans:
        repo_context = _repo_context_from_scan(recent_scans[0])

    repo_filter = _build_repo_filter(repo_context)

    pinecone = _get_pinecone_safe()

    # Semantic retrieval: pull relevant bugs for the user's question (optional).
    semantic_bugs: list[BugReport] = []
    if not focus_mode and pinecone is not None and payload.message.strip():
        try:
            matches = pinecone.find_similar_bugs(
                payload.message,
                "",
                top_k=BUG_SEMANTIC_TOP_K,
                metadata_filter=repo_filter,
            )
            matches = [m for m in matches or [] if _score_ok(m, BUG_SEMANTIC_SCORE_THRESHOLD)]
            matches = matches[:BUG_SEMANTIC_TOP_K]
            ids: list[uuid.UUID] = []
            for m in matches:
                mid = getattr(m, "id", None)
                if isinstance(mid, str):
                    try:
                        ids.append(uuid.UUID(mid))
                    except ValueError:
                        continue
            if ids:
                semantic_bugs = db.query(BugReport).filter(BugReport.id.in_(ids)).all()
                semantic_bugs = _cap_bug_list(semantic_bugs, MAX_SECTION_CHARS)
        except Exception:
            semantic_bugs = []

    project_memory: list[str] = []
    if pinecone is not None and repo_filter and payload.message.strip():
        try:
            memory_filter = repo_filter
            if focus_mode:
                memory_filter = _build_project_memory_filter(repo_filter, scan, finding)
            matches = pinecone.find_project_memory(
                payload.message,
                top_k=PROJECT_MEMORY_TOP_K,
                metadata_filter=memory_filter,
            )
            matches = [m for m in matches or [] if _score_ok(m, PROJECT_MEMORY_SCORE_THRESHOLD)]
            matches = matches[:PROJECT_MEMORY_TOP_K]
            memory_lines = [_project_memory_brief(m) for m in matches]
            project_memory = _cap_lines(memory_lines, MAX_SECTION_CHARS)
        except Exception:
            project_memory = []

    if focus_mode:
        context = _build_focus_context(
            bug,
            scan,
            finding,
            scan_findings=scan_findings,
            project_memory=project_memory,
        )
    else:
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
            project_memory=project_memory,
        )

    system = (
        "You are ScanGuard AI, an enterprise-grade assistant for security findings and bug triage.\n"
        "Use ONLY the provided platform context. Be concise, technical, and actionable.\n"
        "Respond in Markdown.\n"
        "If a focus finding is provided, answer only about that issue and avoid unrelated queue items.\n"
        "If the user asks for code suggestions, provide minimal, safe patches with file paths.\n"
        "If something critical is missing, ask at most 1-2 specific questions."
    )

    if focus_mode:
        prompt = (
            (f"{context}\n\n" if context else "")
            + f"USER QUESTION:\n{payload.message}\n\n"
            "Answer with:\n"
            "1) Summary (what is happening)\n"
            "2) Risk/impact (or why this is likely a false positive)\n"
            "3) Recommended fix (include code suggestions only if requested)\n"
            "4) Validation steps\n"
        )
    else:
        prompt = (
            (f"{context}\n\n" if context else "")
            + f"USER QUESTION:\n{payload.message}\n\n"
            "Answer with:\n"
            "1) Root cause hypothesis (with confidence)\n"
            "2) Evidence from context (bullets)\n"
            "3) Impacted users/components\n"
            "4) Triage plan (next best actions + owners)\n"
            "5) Prioritization (top 3 findings/bugs from the queue, if relevant)\n"
            "Rank items individually based on exploitability and context.\n"
        )

    return context, system, prompt, focus_mode


def _sse_format(message: str) -> str:
    if message == "":
        return "data:\n\n"
    lines = message.splitlines() or [""]
    payload = "".join(f"data: {line}\n" for line in lines)
    return f"{payload}\n"


async def _stream_openrouter(
    client: httpx.AsyncClient,
    settings,
    prompt: str,
    system: str,
) -> AsyncGenerator[str, None]:
    messages: list[dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    headers: dict[str, str] = {
        "Authorization": f"Bearer {settings.open_router_api_key}",
        "Content-Type": "application/json",
    }
    if settings.open_router_site_url:
        headers["HTTP-Referer"] = settings.open_router_site_url
    if settings.open_router_app_name:
        headers["X-Title"] = settings.open_router_app_name

    async with client.stream(
        "POST",
        f"{settings.open_router_base_url.rstrip('/')}/chat/completions",
        headers=headers,
        json={
            "model": settings.open_router_model,
            "messages": messages,
            "temperature": 0.2,
            "stream": True,
        },
    ) as response:
        response.raise_for_status()
        async for line in response.aiter_lines():
            if not line:
                continue
            if not line.startswith("data:"):
                continue
            data = line[5:].lstrip()
            if data == "[DONE]":
                break
            try:
                payload = json.loads(data)
            except json.JSONDecodeError:
                continue
            choices = payload.get("choices")
            if not isinstance(choices, list) or not choices:
                continue
            choice = choices[0] if isinstance(choices[0], dict) else {}
            delta = choice.get("delta") or {}
            chunk = delta.get("content")
            if isinstance(chunk, str) and chunk:
                yield chunk


async def _stream_ollama(
    client: httpx.AsyncClient,
    settings,
    prompt: str,
    system: str,
) -> AsyncGenerator[str, None]:
    async with client.stream(
        "POST",
        f"{settings.ollama_host.rstrip('/')}/api/generate",
        json={
            "model": settings.ollama_model,
            "prompt": prompt,
            "system": system,
            "stream": True,
        },
    ) as response:
        response.raise_for_status()
        async for line in response.aiter_lines():
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            chunk = payload.get("response")
            if isinstance(chunk, str) and chunk:
                yield chunk
            if payload.get("done"):
                break


@router.post("/stream")
async def chat_stream(
    payload: ChatRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    context, system, prompt, _focus_mode = _prepare_chat_prompt(
        payload, db, current_user
    )
    settings = get_settings()
    llm = get_llm_service(settings)

    llm_available = await llm.is_available()
    headers = {
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "X-LLM-Provider": getattr(llm, "provider", "unknown"),
    }
    if hasattr(llm, "model"):
        headers["X-LLM-Model"] = llm.model
    headers["X-LLM-Used"] = "true" if llm_available else "false"

    async def event_stream() -> AsyncGenerator[str, None]:
        if not llm_available:
            fallback = (
                "LLM is unavailable. Configure OPEN_ROUTER_API_KEY or start Ollama.\n"
                + (f"\nContext:\n{context}\n" if context else "")
            ).strip()
            yield _sse_format(fallback)
            yield _sse_format("[DONE]")
            return

        async with httpx.AsyncClient(timeout=None) as client:
            try:
                if isinstance(llm, OpenRouterService):
                    async for chunk in _stream_openrouter(
                        client, settings, prompt, system
                    ):
                        yield _sse_format(chunk)
                elif isinstance(llm, OllamaService):
                    async for chunk in _stream_ollama(client, settings, prompt, system):
                        yield _sse_format(chunk)
                else:
                    text = await llm.generate(prompt, system=system)
                    if text:
                        yield _sse_format(text)
                yield _sse_format("[DONE]")
            except Exception as exc:
                fallback = (
                    f"LLM request failed: {type(exc).__name__}. "
                    "Check your LLM provider settings and retry.\n"
                    + (f"\nContext:\n{context}\n" if context else "")
                ).strip()
                yield _sse_format(fallback)
                yield _sse_format("[DONE]")

    return StreamingResponse(event_stream(), media_type="text/event-stream", headers=headers)


@router.post("", response_model=ChatResponse)
async def chat(
    payload: ChatRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ChatResponse:
    context, system, prompt, _focus_mode = _prepare_chat_prompt(
        payload, db, current_user
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
