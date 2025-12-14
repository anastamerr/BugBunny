from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import re
from typing import Iterable

from sqlalchemy.orm import Session

from ...models import BugPrediction, BugReport, DataIncident, IncidentAction, ResolutionPattern
from ..bug_triage.auto_router import AutoRouter
from ..pipeline_monitor.lineage_graph import DataLineageGraph


_STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "from",
    "this",
    "that",
    "into",
    "when",
    "then",
    "over",
    "under",
    "after",
    "before",
    "fails",
    "failing",
    "failure",
    "error",
    "errors",
    "null",
    "none",
    "data",
    "pipeline",
    "incident",
    "bug",
    "report",
    "reports",
    "service",
    "api",
    "dashboard",
    "users",
    "user",
    "table",
    "column",
}


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _unique_preserve(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _resolve_owner_teams(incident: DataIncident) -> list[str]:
    lineage = DataLineageGraph()
    owners = lineage.LINEAGE.get(incident.table_name, {}).get("owners", [])
    if isinstance(owners, list) and owners:
        return [str(o) for o in owners if o]
    return ["data_engineering"]


def _stakeholder_teams_from_downstream(incident: DataIncident) -> list[str]:
    router = AutoRouter()
    teams: list[str] = []
    for component in incident.downstream_systems or []:
        if not component:
            continue
        teams.append(router.COMPONENT_TEAM_MAP.get(component, "backend_team"))
    return _unique_preserve(teams)


def _template_actions(incident: DataIncident, prediction: BugPrediction | None) -> list[dict]:
    owner_teams = _resolve_owner_teams(incident)
    stakeholders = _stakeholder_teams_from_downstream(incident)
    primary_owner = owner_teams[0] if owner_teams else None

    downstream = incident.downstream_systems or DataLineageGraph().get_downstream_systems(
        incident.table_name
    )
    downstream_label = ", ".join(downstream) if downstream else "unknown"

    prediction_line = None
    if prediction is not None:
        confidence = (
            f"{int(round((prediction.confidence or 0.0) * 100))}%"
            if prediction.confidence is not None
            else "n/a"
        )
        prediction_line = (
            f"Prediction: ~{prediction.predicted_bug_count} bugs in next "
            f"{prediction.prediction_window_hours}h (confidence {confidence})."
        )

    common = [
        {
            "title": "Confirm blast radius",
            "description": f"Identify downstream systems impacted: {downstream_label}.",
            "owner_team": primary_owner,
            "sort_order": 10,
        },
        {
            "title": "Notify stakeholders",
            "description": (
                "Send an update to impacted teams and set a response channel. "
                + (f"Stakeholders: {', '.join(stakeholders)}." if stakeholders else "")
            ).strip(),
            "owner_team": primary_owner,
            "sort_order": 20,
        },
    ]

    if incident.severity == "CRITICAL":
        common.insert(
            0,
            {
                "title": "Page on-call + open incident bridge",
                "description": "Treat as P0. Assign incident commander and start updates cadence.",
                "owner_team": primary_owner,
                "sort_order": 0,
            },
        )

    type_specific: list[dict] = []
    itype = str(incident.incident_type)

    if itype == "SCHEMA_DRIFT":
        type_specific = [
            {
                "title": "Diff schema and identify breaking change",
                "description": "Compare upstream schema versions and locate the change that introduced drift.",
                "owner_team": primary_owner,
                "sort_order": 30,
            },
            {
                "title": "Patch transformation + backfill",
                "description": "Update transforms/mappings and backfill the impacted window.",
                "owner_team": primary_owner,
                "sort_order": 40,
            },
        ]
    elif itype == "NULL_SPIKE":
        type_specific = [
            {
                "title": "Identify null source + timeframe",
                "description": "Pinpoint upstream job or input causing the null spike.",
                "owner_team": primary_owner,
                "sort_order": 30,
            },
            {
                "title": "Add guardrails",
                "description": "Add null-threshold expectation and quarantine bad records.",
                "owner_team": primary_owner,
                "sort_order": 40,
            },
        ]
    elif itype == "VOLUME_ANOMALY":
        type_specific = [
            {
                "title": "Validate ingestion volume + partitions",
                "description": "Check missing/duplicate partitions and upstream ingestion throughput.",
                "owner_team": primary_owner,
                "sort_order": 30,
            },
            {
                "title": "Re-run for completeness",
                "description": "Reprocess the affected window and confirm counts stabilize.",
                "owner_team": primary_owner,
                "sort_order": 40,
            },
        ]
    elif itype == "FRESHNESS":
        type_specific = [
            {
                "title": "Check job SLA + scheduler state",
                "description": "Validate upstream job is running and confirm dependency chain.",
                "owner_team": primary_owner,
                "sort_order": 30,
            },
            {
                "title": "Restore freshness + prevent recurrence",
                "description": "Re-run missing job and add freshness expectation / alert.",
                "owner_team": primary_owner,
                "sort_order": 40,
            },
        ]
    elif itype == "DISTRIBUTION_DRIFT":
        type_specific = [
            {
                "title": "Validate distribution shift root cause",
                "description": "Check upstream input changes, feature pipelines, and recent releases.",
                "owner_team": primary_owner,
                "sort_order": 30,
            },
            {
                "title": "Rebaseline or hotfix",
                "description": "Decide whether to rebaseline expected distribution or roll back a change.",
                "owner_team": primary_owner,
                "sort_order": 40,
            },
        ]
    elif itype == "VALIDATION_FAILURE":
        type_specific = [
            {
                "title": "Inspect validation results",
                "description": "Review Great Expectations output and identify failing checks.",
                "owner_team": primary_owner,
                "sort_order": 30,
            },
            {
                "title": "Quarantine + fix upstream",
                "description": "Block downstream propagation; remediate upstream data and re-run.",
                "owner_team": primary_owner,
                "sort_order": 40,
            },
        ]

    if prediction_line:
        common.append(
            {
                "title": "Prepare for bug surge",
                "description": prediction_line,
                "owner_team": primary_owner,
                "sort_order": 25,
            }
        )

    return common + type_specific


def ensure_incident_actions(db: Session, incident: DataIncident) -> list[IncidentAction]:
    existing = (
        db.query(IncidentAction)
        .filter(IncidentAction.incident_id == incident.id)
        .order_by(IncidentAction.sort_order.asc().nullslast(), IncidentAction.created_at.asc())
        .all()
    )
    if existing:
        return existing

    prediction = (
        db.query(BugPrediction)
        .filter(BugPrediction.incident_id == incident.id)
        .order_by(BugPrediction.created_at.desc())
        .first()
    )

    pattern = (
        db.query(ResolutionPattern)
        .filter(
            ResolutionPattern.incident_type == str(incident.incident_type),
            ResolutionPattern.affected_table == incident.table_name,
        )
        .first()
    )

    templates = _template_actions(incident, prediction)
    if pattern and pattern.resolution_action:
        eta = (
            f" Historically resolves in ~{pattern.resolution_time_avg:.1f}h."
            if pattern.resolution_time_avg
            else ""
        )
        templates.insert(
            1,
            {
                "title": "Apply proven fix",
                "description": f"Previous resolution: {pattern.resolution_action}.{eta}".strip(),
                "owner_team": _resolve_owner_teams(incident)[0],
                "sort_order": 5,
            },
        )

    actions: list[IncidentAction] = []
    for item in templates:
        actions.append(
            IncidentAction(
                incident_id=incident.id,
                title=item["title"],
                description=item.get("description"),
                owner_team=item.get("owner_team"),
                status="todo",
                source="generated",
                sort_order=item.get("sort_order"),
            )
        )

    db.add_all(actions)
    db.commit()

    return (
        db.query(IncidentAction)
        .filter(IncidentAction.incident_id == incident.id)
        .order_by(IncidentAction.sort_order.asc().nullslast(), IncidentAction.created_at.asc())
        .all()
    )


def extract_symptom_keywords(bugs: list[BugReport], *, max_keywords: int = 12) -> list[str]:
    text = " ".join([b.title or "" for b in bugs] + [b.description or "" for b in bugs])
    tokens = re.findall(r"[a-zA-Z][a-zA-Z0-9_]{2,}", text.lower())
    tokens = [t for t in tokens if t not in _STOPWORDS]
    counts = Counter(tokens)
    return [w for w, _c in counts.most_common(max_keywords)]


def upsert_resolution_pattern(
    db: Session, incident: DataIncident, *, related_bugs: list[BugReport]
) -> ResolutionPattern:
    if not incident.resolved_at:
        incident.resolved_at = _now_utc()

    started_at = _as_utc(incident.timestamp) if incident.timestamp else None
    resolved_at = _as_utc(incident.resolved_at) if incident.resolved_at else None

    duration_hours = (
        (resolved_at - started_at).total_seconds() / 3600
        if started_at and resolved_at
        else None
    )

    existing = (
        db.query(ResolutionPattern)
        .filter(
            ResolutionPattern.incident_type == str(incident.incident_type),
            ResolutionPattern.affected_table == incident.table_name,
        )
        .first()
    )

    keywords = extract_symptom_keywords(related_bugs)
    action_text = (incident.resolution_notes or "").strip() or None

    if existing:
        n = int(existing.occurrence_count or 0) + 1
        existing.occurrence_count = n
        existing.last_seen = incident.resolved_at

        if action_text:
            existing.resolution_action = action_text

        if duration_hours is not None:
            prev = float(existing.resolution_time_avg or 0.0)
            existing.resolution_time_avg = (prev * (n - 1) + float(duration_hours)) / n

        if keywords:
            prev_kw = existing.symptom_keywords or []
            if not isinstance(prev_kw, list):
                prev_kw = []
            existing.symptom_keywords = _unique_preserve([*prev_kw, *keywords])[:20]

        db.add(existing)
        db.commit()
        db.refresh(existing)
        return existing

    pattern = ResolutionPattern(
        incident_type=str(incident.incident_type),
        affected_table=incident.table_name,
        symptom_keywords=keywords,
        resolution_action=action_text,
        resolution_time_avg=float(duration_hours) if duration_hours is not None else None,
        occurrence_count=1,
        last_seen=incident.resolved_at,
        embedding_id=None,
    )
    db.add(pattern)
    db.commit()
    db.refresh(pattern)
    return pattern


def build_postmortem_markdown(
    incident: DataIncident,
    *,
    related_bugs: list[BugReport],
    actions: list[IncidentAction],
    prediction: BugPrediction | None,
    resolution_pattern: ResolutionPattern | None,
) -> str:
    title = f"{incident.incident_id} — {incident.incident_type} on {incident.table_name}"

    started = _as_utc(incident.timestamp) if incident.timestamp else None
    resolved = _as_utc(incident.resolved_at) if incident.resolved_at else None
    duration = None
    if started and resolved:
        duration = int(round((resolved - started).total_seconds() / 60))

    predicted = prediction.predicted_bug_count if prediction else None
    predicted_window = prediction.prediction_window_hours if prediction else None
    predicted_conf = prediction.confidence if prediction else None

    bug_lines = []
    for bug in related_bugs[:20]:
        bug_lines.append(
            f"- {bug.id} | {bug.classified_severity} {bug.classified_component} | "
            f"status={bug.status} | {bug.title}"
        )

    action_lines = []
    for action in actions:
        box = "x" if action.status == "done" else " "
        owner = f" @{action.owner_team}" if action.owner_team else ""
        desc = f" — {action.description}" if action.description else ""
        action_lines.append(f"- [{box}] {action.title}{owner}{desc}")

    downstream = incident.downstream_systems or []
    cols = incident.affected_columns or []

    parts: list[str] = []
    parts.append(f"# Postmortem: {title}")
    parts.append("")
    parts.append("## Summary")
    parts.append(f"- Severity: {incident.severity}")
    parts.append(f"- Status: {incident.status}")
    parts.append(f"- Start: {started.isoformat() if started else 'n/a'}")
    parts.append(f"- Resolved: {resolved.isoformat() if resolved else 'n/a'}")
    parts.append(f"- Duration: {f'{duration} min' if duration is not None else 'n/a'}")
    parts.append("")
    parts.append("## Blast Radius")
    parts.append(
        f"- Downstream systems: {', '.join(downstream) if downstream else 'n/a'}"
    )
    parts.append(f"- Affected columns: {', '.join(cols) if cols else 'n/a'}")
    parts.append("")
    parts.append("## Prediction vs Actual")
    if predicted is None:
        parts.append("- Prediction: n/a")
    else:
        confidence = (
            f"{int(round((predicted_conf or 0.0) * 100))}%"
            if predicted_conf is not None
            else "n/a"
        )
        parts.append(
            f"- Prediction: {predicted} bugs in next {predicted_window}h (confidence {confidence})"
        )
    parts.append(f"- Actual correlated bugs so far: {len(related_bugs)}")
    parts.append("")
    parts.append("## Response Actions")
    parts.append("\n".join(action_lines) if action_lines else "- n/a")
    parts.append("")
    parts.append("## Related Bugs")
    parts.append("\n".join(bug_lines) if bug_lines else "- n/a")

    if incident.resolution_notes:
        parts.append("")
        parts.append("## Resolution Notes")
        parts.append(incident.resolution_notes.strip())

    if resolution_pattern and resolution_pattern.resolution_action:
        parts.append("")
        parts.append("## Resolution Intelligence")
        eta = (
            f"~{resolution_pattern.resolution_time_avg:.1f}h"
            if resolution_pattern.resolution_time_avg
            else "n/a"
        )
        parts.append(f"- Historical fix: {resolution_pattern.resolution_action}")
        parts.append(f"- Historical avg time to resolve: {eta}")

    return "\n".join(parts).strip() + "\n"
