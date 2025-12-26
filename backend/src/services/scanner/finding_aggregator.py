from __future__ import annotations

import asyncio
import uuid
from typing import List, Optional

from ...integrations.pinecone_client import PineconeService
from .types import FindingGroup, TriagedFinding


class FindingAggregator:
    def __init__(
        self,
        pinecone: Optional[PineconeService] = None,
        duplicate_threshold: float = 0.9,
    ) -> None:
        self.pinecone = pinecone
        self.duplicate_threshold = duplicate_threshold

    async def process(self, findings: List[TriagedFinding]) -> List[TriagedFinding]:
        filtered = self._filter_false_positives(findings)
        _groups = self._group_related(filtered)
        deduped = await self._deduplicate(filtered)
        for finding in deduped:
            finding.priority_score = self.calculate_priority(finding)
        return sorted(
            deduped,
            key=lambda item: item.priority_score or 0,
            reverse=True,
        )

    def _filter_false_positives(
        self, findings: List[TriagedFinding]
    ) -> List[TriagedFinding]:
        return [finding for finding in findings if not finding.is_false_positive]

    def _group_related(self, findings: List[TriagedFinding]) -> List[FindingGroup]:
        groups: dict[str, List[TriagedFinding]] = {}
        for finding in findings:
            key = f"{finding.rule_id}:{finding.file_path}"
            groups.setdefault(key, []).append(finding)
        return [FindingGroup(key=key, findings=items) for key, items in groups.items()]

    async def _deduplicate(
        self, findings: List[TriagedFinding]
    ) -> List[TriagedFinding]:
        if not self.pinecone:
            return findings

        unique: List[TriagedFinding] = []

        for finding in findings:
            text = f"{finding.rule_id} {finding.rule_message} {finding.code_snippet}"
            try:
                matches = await asyncio.to_thread(
                    self.pinecone.find_similar_patterns, text, 3
                )
            except Exception:
                unique.append(finding)
                continue

            if any(match.score >= self.duplicate_threshold for match in matches):
                continue

            try:
                pattern_id = str(uuid.uuid4())
                await asyncio.to_thread(
                    self.pinecone.upsert_pattern,
                    pattern_id,
                    text,
                    {"rule_id": finding.rule_id, "file_path": finding.file_path},
                )
            except Exception:
                pass

            unique.append(finding)

        return unique

    def calculate_priority(self, finding: TriagedFinding) -> int:
        severity_weights = {
            "critical": 90,
            "high": 75,
            "medium": 55,
            "low": 35,
            "info": 10,
        }
        base = severity_weights.get(finding.ai_severity, 30)
        confidence = finding.ai_confidence or 0.5
        score = base * (0.5 + 0.5 * max(0.0, min(confidence, 1.0)))

        exploitability = (finding.exploitability or "").lower()
        if any(term in exploitability for term in ["not exploitable", "unlikely", "false positive"]):
            score -= 15
        if any(term in exploitability for term in ["remote", "arbitrary", "unauthenticated"]):
            score += 10
        if any(
            term in exploitability
            for term in [
                "requires authentication",
                "authenticated",
                "admin only",
                "local only",
                "user interaction",
            ]
        ):
            score -= 10

        if confidence < 0.35:
            score -= 10

        if finding.is_test_file or finding.is_generated:
            score -= 25

        return max(0, min(100, int(round(score))))

    def _calculate_priority(self, finding: TriagedFinding) -> int:
        return self.calculate_priority(finding)
