from __future__ import annotations

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
            },
        )

    def get_duplicate_clusters(self) -> List[List[str]]:
        # Implementation for grouping duplicates (future work)
        return []

