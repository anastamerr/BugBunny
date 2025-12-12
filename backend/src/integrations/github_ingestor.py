from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from sqlalchemy.orm import Session

from ..models import BugIncidentCorrelation, BugReport, DataIncident
from ..services.bug_triage import AutoRouter, BugClassifier
from ..services.correlation.temporal_matcher import TemporalMatcher
from .github_client import parse_github_timestamp


def build_bug_id(repo_full_name: str, issue_number: int) -> str:
    return f"gh:{repo_full_name}#{issue_number}"


def issue_to_bug_fields(repo_full_name: str, issue: Dict[str, Any]) -> Dict[str, Any]:
    number = int(issue.get("number") or 0)
    title = str(issue.get("title") or "").strip()
    body = issue.get("body")
    description = str(body) if body is not None else None

    user = issue.get("user") or {}
    reporter = user.get("login")

    raw_labels = issue.get("labels") or []
    label_names = []
    for l in raw_labels:
        if isinstance(l, dict) and isinstance(l.get("name"), str):
            label_names.append(l["name"])
        elif isinstance(l, str):
            label_names.append(l)

    created_at = parse_github_timestamp(issue.get("created_at"))

    return {
        "bug_id": build_bug_id(repo_full_name, number),
        "source": "github",
        "title": title or f"GitHub Issue #{number}",
        "description": description,
        "created_at": created_at,
        "reporter": reporter,
        "labels": {
            "repo": repo_full_name,
            "number": number,
            "url": issue.get("html_url"),
            "labels": label_names,
            "state": issue.get("state"),
        },
    }


class GitHubIngestor:
    def __init__(
        self,
        *,
        classifier: Optional[BugClassifier] = None,
        auto_router: Optional[AutoRouter] = None,
    ):
        self.classifier = classifier or BugClassifier()
        self.auto_router = auto_router or AutoRouter()

    def upsert_issue(
        self,
        db: Session,
        *,
        repo_full_name: str,
        issue: Dict[str, Any],
        action: Optional[str] = None,
        auto_correlate: bool = True,
    ) -> Tuple[BugReport, bool, Optional[BugIncidentCorrelation], Optional[DataIncident]]:
        issue_state = str(issue.get("state") or "").lower().strip()
        fields = issue_to_bug_fields(repo_full_name, issue)

        bug = db.query(BugReport).filter(BugReport.bug_id == fields["bug_id"]).first()
        created = False
        if bug is None:
            created = True
            bug = BugReport(
                **{
                    k: v
                    for k, v in fields.items()
                    if v is not None or k in {"description", "reporter", "labels"}
                }
            )
            if bug.created_at is None:
                # fallback for missing/parse errors
                from datetime import datetime, timezone

                bug.created_at = datetime.now(timezone.utc)
            bug.status = "new"
            db.add(bug)
            db.commit()
            db.refresh(bug)
        else:
            for key, value in fields.items():
                if value is None and key in {"description", "reporter"}:
                    setattr(bug, key, None)
                elif value is not None:
                    setattr(bug, key, value)

            if issue_state == "closed":
                bug.status = "resolved"
                bug.resolution_notes = "Closed on GitHub"
            elif issue_state == "open" and bug.status == "resolved":
                bug.status = "new"
                bug.resolution_notes = None

            db.add(bug)
            db.commit()
            db.refresh(bug)

        if issue_state == "closed":
            bug.status = "resolved"
            bug.resolution_notes = "Closed on GitHub"
            db.add(bug)
            db.commit()
            db.refresh(bug)

        classification = self.classifier.classify(bug.title, bug.description or "")
        bug.classified_type = classification["type"]
        bug.classified_component = classification["component"]
        bug.classified_severity = classification["severity"]
        bug.confidence_score = classification["overall_confidence"]

        routing = self.auto_router.route_bug(
            classification,
            is_data_related=bug.is_data_related,
            correlation_score=bug.correlation_score,
        )
        bug.assigned_team = routing["team"]
        db.add(bug)
        db.commit()
        db.refresh(bug)

        corr: BugIncidentCorrelation | None = None
        incident: DataIncident | None = None

        if auto_correlate and action != "closed":
            matcher = TemporalMatcher(db)
            matches = matcher.find_correlated_incidents(bug)
            if matches:
                incident, score = matches[0]
                bug.is_data_related = True
                bug.correlated_incident_id = incident.id
                bug.correlation_score = score
                db.add(bug)
                db.commit()
                db.refresh(bug)

                existing = (
                    db.query(BugIncidentCorrelation)
                    .filter(
                        BugIncidentCorrelation.bug_id == bug.id,
                        BugIncidentCorrelation.incident_id == incident.id,
                    )
                    .first()
                )
                if existing:
                    existing.correlation_score = score
                    existing.temporal_score = matcher._temporal_score(bug, incident)
                    existing.component_score = matcher._component_score(bug, incident)
                    existing.keyword_score = matcher._keyword_score(bug, incident)
                    corr = existing
                else:
                    corr = BugIncidentCorrelation(
                        bug_id=bug.id,
                        incident_id=incident.id,
                        correlation_score=score,
                        temporal_score=matcher._temporal_score(bug, incident),
                        component_score=matcher._component_score(bug, incident),
                        keyword_score=matcher._keyword_score(bug, incident),
                        explanation=None,
                    )
                    db.add(corr)

                db.commit()
                if corr is not None:
                    db.refresh(corr)

        return bug, created, corr, incident
