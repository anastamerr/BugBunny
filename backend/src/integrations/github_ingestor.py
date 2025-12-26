from __future__ import annotations

import uuid
from functools import lru_cache
from typing import Any, Dict, Optional, Tuple

from sqlalchemy.orm import Session

from ..models import BugReport
from ..services.bug_triage import AutoRouter, BugClassifier, DuplicateDetector
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


@lru_cache
def _get_pinecone_service():
    from .pinecone_client import PineconeService

    return PineconeService()


def _get_duplicate_detector() -> Optional[DuplicateDetector]:
    try:
        return DuplicateDetector(_get_pinecone_service())
    except Exception:
        return None


class GitHubIngestor:
    def __init__(
        self,
        *,
        classifier: Optional[BugClassifier] = None,
        auto_router: Optional[AutoRouter] = None,
        duplicate_detector: Optional[DuplicateDetector] = None,
    ):
        self.classifier = classifier or BugClassifier()
        self.auto_router = auto_router or AutoRouter()
        self.duplicate_detector = duplicate_detector

    def upsert_issue(
        self,
        db: Session,
        *,
        repo_full_name: str,
        issue: Dict[str, Any],
        action: Optional[str] = None,
    ) -> Tuple[BugReport, bool]:
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

        routing = self.auto_router.route_bug(classification)
        bug.assigned_team = routing["team"]
        db.add(bug)
        db.commit()
        db.refresh(bug)

        duplicate_detector = self.duplicate_detector
        if duplicate_detector is None:
            duplicate_detector = _get_duplicate_detector()
            self.duplicate_detector = duplicate_detector

        if duplicate_detector is not None:
            try:
                duplicates = duplicate_detector.find_duplicates(
                    bug_id=str(bug.id),
                    title=bug.title,
                    description=bug.description or "",
                )

                if duplicates:
                    bug.is_duplicate = True
                    bug.duplicate_score = duplicates[0]["similarity_score"]
                    try:
                        bug.duplicate_of_id = uuid.UUID(duplicates[0]["bug_id"])
                    except ValueError:
                        bug.duplicate_of_id = None
                else:
                    bug.is_duplicate = False
                    bug.duplicate_score = None
                    bug.duplicate_of_id = None

                duplicate_detector.register_bug(bug)
                bug.embedding_id = str(bug.id)

                db.add(bug)
                db.commit()
                db.refresh(bug)
            except Exception:
                pass

        return bug, created

    def upsert_issue_comment(
        self,
        db: Session,
        *,
        repo_full_name: str,
        issue: Dict[str, Any],
        comment: Dict[str, Any],
        action: Optional[str] = None,
    ) -> Tuple[BugReport, bool]:
        bug, created = self.upsert_issue(
            db,
            repo_full_name=repo_full_name,
            issue=issue,
            action=None,
        )

        labels = dict(bug.labels) if isinstance(bug.labels, dict) else {}
        comment_id = comment.get("id")
        user = comment.get("user") or {}
        entry = {
            "id": comment_id,
            "user": user.get("login"),
            "body": comment.get("body"),
            "url": comment.get("html_url"),
            "created_at": comment.get("created_at"),
            "updated_at": comment.get("updated_at"),
        }

        comments_raw = labels.get("comments")
        comments: list[Any]
        if isinstance(comments_raw, list):
            comments = list(comments_raw)
        else:
            comments = []

        comments = [
            c
            for c in comments
            if not (isinstance(c, dict) and c.get("id") == comment_id)
        ]

        if (action or "").lower() != "deleted":
            comments.insert(0, entry)

        labels["comments"] = comments[:10]
        labels["last_comment"] = labels["comments"][0] if labels["comments"] else None
        bug.labels = labels

        db.add(bug)
        db.commit()
        db.refresh(bug)

        return bug, created
