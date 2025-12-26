from __future__ import annotations

import re
import uuid
from typing import Dict, Iterable, List, Optional, Sequence, Set

from sqlalchemy.orm import Session

from ...integrations.pinecone_client import PineconeService
from ...models import BugReport


class BugCorrelationService:
    def __init__(self, pinecone: Optional[PineconeService] = None) -> None:
        self.pinecone = pinecone
        self.semantic_strong = 0.72
        self.semantic_floor = 0.62
        self.min_score = 0.55
        self.fallback_min_score = 0.42
        self.max_candidates = 40
        self.stop_words = {
            "the",
            "and",
            "for",
            "with",
            "this",
            "that",
            "from",
            "when",
            "where",
            "what",
            "how",
            "into",
            "onto",
            "your",
            "you",
            "our",
            "use",
            "using",
            "uses",
            "via",
        }

    def find_correlated(
        self,
        bug: BugReport,
        db: Session,
        *,
        top_k: int = 8,
    ) -> List[Dict]:
        seen: set[str] = {str(bug.id)}
        results: List[Dict] = []

        explicit = self._explicit_duplicates(bug, db)
        for related in explicit:
            results.append(self._build_result(related, score=1.0, relationship="duplicate"))
            seen.add(str(related.id))

        semantic_matches: Dict[str, float] = {}
        if self.pinecone is not None:
            try:
                matches = self.pinecone.find_similar_bugs(
                    bug.title, bug.description or "", top_k=self.max_candidates
                )
                for match in matches or []:
                    if not isinstance(match.id, str) or match.id in seen:
                        continue
                    semantic_matches[match.id] = float(match.score or 0.0)
            except Exception:
                semantic_matches = {}

        if semantic_matches:
            candidates = self._fetch_candidates(db, semantic_matches.keys())
            for candidate in candidates:
                if str(candidate.id) in seen:
                    continue
                match_score = semantic_matches.get(str(candidate.id))
                scored = self._score_candidate(bug, candidate, match_score)
                if scored is None:
                    continue
                results.append(scored)
        else:
            candidates = self._fallback_candidates(bug, db)
            for candidate in candidates:
                if str(candidate.id) in seen:
                    continue
                scored = self._score_candidate(bug, candidate, None, fallback=True)
                if scored is None:
                    continue
                results.append(scored)
        results.sort(key=lambda item: item["score"], reverse=True)
        return results[:top_k]

    def _explicit_duplicates(self, bug: BugReport, db: Session) -> List[BugReport]:
        related: List[BugReport] = []

        if bug.duplicate_of_id:
            parent = (
                db.query(BugReport)
                .filter(BugReport.id == bug.duplicate_of_id)
                .first()
            )
            if parent:
                related.append(parent)

            siblings = (
                db.query(BugReport)
                .filter(BugReport.duplicate_of_id == bug.duplicate_of_id)
                .all()
            )
            related.extend([b for b in siblings if b.id != bug.id])

        children = (
            db.query(BugReport)
            .filter(BugReport.duplicate_of_id == bug.id)
            .all()
        )
        related.extend(children)

        unique: Dict[str, BugReport] = {}
        for entry in related:
            unique[str(entry.id)] = entry
        return list(unique.values())

    def _fetch_candidates(
        self, db: Session, ids: Iterable[str]
    ) -> Sequence[BugReport]:
        parsed: List[uuid.UUID] = []
        for raw in ids:
            try:
                parsed.append(uuid.UUID(raw))
            except ValueError:
                continue
        if not parsed:
            return []
        return db.query(BugReport).filter(BugReport.id.in_(parsed)).all()

    def _fallback_candidates(self, bug: BugReport, db: Session) -> Sequence[BugReport]:
        query = db.query(BugReport).filter(BugReport.id != bug.id)
        if bug.classified_component:
            query = query.filter(BugReport.classified_component == bug.classified_component)
        return query.order_by(BugReport.created_at.desc()).limit(120).all()

    def _score_candidate(
        self,
        bug: BugReport,
        candidate: BugReport,
        semantic_score: Optional[float],
        *,
        fallback: bool = False,
    ) -> Optional[Dict]:
        text_overlap = self._text_overlap(bug, candidate)
        label_overlap = self._label_overlap(bug.labels, candidate.labels)
        component_match = self._bool_match(
            bug.classified_component, candidate.classified_component
        )
        severity_match = self._bool_match(
            bug.classified_severity, candidate.classified_severity
        )

        if semantic_score is not None:
            if not self._semantic_gate(
                semantic_score, text_overlap, label_overlap, component_match
            ):
                return None
        else:
            if not self._fallback_gate(text_overlap, label_overlap, component_match, severity_match):
                return None

        semantic_signal = semantic_score if semantic_score is not None else text_overlap
        score = (
            semantic_signal * 0.65
            + text_overlap * 0.15
            + component_match * 0.1
            + severity_match * 0.05
            + label_overlap * 0.05
        )
        min_score = self.fallback_min_score if fallback else self.min_score
        if score < min_score:
            return None

        return self._build_result(
            candidate,
            score=score,
            similarity_score=semantic_score,
            relationship="related",
        )

    def _semantic_gate(
        self,
        semantic_score: float,
        text_overlap: float,
        label_overlap: float,
        component_match: float,
    ) -> bool:
        if semantic_score >= self.semantic_strong:
            return True
        if semantic_score >= self.semantic_floor and (component_match or text_overlap >= 0.2):
            return True
        return label_overlap >= 0.3 and semantic_score >= 0.55

    def _fallback_gate(
        self,
        text_overlap: float,
        label_overlap: float,
        component_match: float,
        severity_match: float,
    ) -> bool:
        if text_overlap >= 0.25 or label_overlap >= 0.35:
            return True
        return component_match and severity_match and text_overlap >= 0.15

    def _build_result(
        self,
        bug: BugReport,
        *,
        score: float,
        similarity_score: Optional[float] = None,
        relationship: str = "related",
    ) -> Dict:
        return {
            "bug_id": str(bug.id),
            "score": round(score, 6),
            "similarity_score": round(similarity_score, 6)
            if similarity_score is not None
            else None,
            "title": bug.title,
            "status": bug.status,
            "created_at": bug.created_at.isoformat() if bug.created_at else None,
            "component": bug.classified_component,
            "severity": bug.classified_severity,
            "relationship": relationship,
        }

    def _text_overlap(self, bug: BugReport, candidate: BugReport) -> float:
        title_a = self._tokenize(bug.title or "")
        title_b = self._tokenize(candidate.title or "")
        desc_a = self._tokenize(bug.description or "")
        desc_b = self._tokenize(candidate.description or "")
        return max(self._jaccard(title_a, title_b), self._jaccard(desc_a, desc_b))

    def _label_overlap(self, left: object, right: object) -> float:
        return self._jaccard(self._labels(left), self._labels(right))

    def _labels(self, labels: object) -> Set[str]:
        raw: Iterable[str] = []
        if isinstance(labels, list):
            raw = [str(item) for item in labels if item]
        elif isinstance(labels, dict):
            nested = labels.get("labels")
            if isinstance(nested, list):
                raw = [str(item) for item in nested if item]
        return {item.strip().lower() for item in raw if item.strip()}

    def _tokenize(self, text: str) -> Set[str]:
        if not text:
            return set()
        tokens = re.findall(r"[a-z0-9]{3,}", text.lower())
        return {t for t in tokens if t not in self.stop_words}

    @staticmethod
    def _jaccard(left: Set[str], right: Set[str]) -> float:
        if not left or not right:
            return 0.0
        union = left | right
        if not union:
            return 0.0
        return len(left & right) / len(union)

    @staticmethod
    def _bool_match(left: Optional[str], right: Optional[str]) -> float:
        if left and right and left == right:
            return 1.0
        return 0.0
