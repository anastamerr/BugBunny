from __future__ import annotations

import re
from typing import Dict, List, Optional

from ...integrations.pinecone_client import PineconeService
from ...models import BugReport


class DuplicateDetector:
    def __init__(self, pinecone: PineconeService):
        self.pinecone = pinecone
        self.similarity_threshold = 0.85

    def find_duplicates(
        self,
        bug_id: str,
        title: str,
        description: str,
        exclude_ids: Optional[List[str]] = None,
    ) -> List[Dict]:
        matches = self.pinecone.find_similar_bugs(title, description, top_k=10)

        duplicates: List[Dict] = []
        for match in matches:
            if match.id == bug_id:
                continue
            if exclude_ids and match.id in exclude_ids:
                continue

            if match.score >= self.similarity_threshold:
                duplicates.append(
                    {
                        "bug_id": match.id,
                        "similarity_score": match.score,
                        "title": match.metadata.get("title"),
                        "status": match.metadata.get("status"),
                        "created_at": match.metadata.get("created_at"),
                    }
                )

        return duplicates

    def register_bug(self, bug: BugReport) -> None:
        repo_metadata = _extract_repo_metadata(bug)
        self.pinecone.upsert_bug(
            bug_id=str(bug.id),
            title=bug.title,
            description=bug.description or "",
            metadata={
                "title": bug.title,
                "status": bug.status,
                "created_at": bug.created_at.isoformat(),
                "component": bug.classified_component,
                "severity": bug.classified_severity,
                **repo_metadata,
            },
        )

    def get_duplicate_clusters(self) -> List[List[str]]:
        # Implementation for grouping duplicates (future work)
        return []


def _extract_repo_metadata(bug: BugReport) -> Dict[str, str]:
    repo_id = getattr(bug, "repo_id", None)
    labels = bug.labels if isinstance(bug.labels, dict) else {}

    repo_full_name = None
    repo_url = None

    if isinstance(labels, dict):
        repo_full_name = labels.get("repo") or labels.get("repo_full_name")
        repo_url = labels.get("repo_url")

    if not repo_full_name and isinstance(bug.bug_id, str):
        match = re.match(r"^gh:([^#]+)#\d+$", bug.bug_id.strip())
        if match:
            repo_full_name = match.group(1)

    if not repo_url and repo_full_name:
        repo_url = f"https://github.com/{repo_full_name}"

    metadata: Dict[str, str] = {}
    if repo_id:
        metadata["repo_id"] = str(repo_id)
    if repo_full_name:
        metadata["repo_full_name"] = str(repo_full_name)
    if repo_url:
        metadata["repo_url"] = str(repo_url)
    return metadata
