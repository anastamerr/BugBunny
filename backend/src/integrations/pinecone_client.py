from __future__ import annotations

from typing import Any, Dict, List, Optional

from pinecone import Pinecone, ServerlessSpec
from sentence_transformers import SentenceTransformer

from ..config import get_settings


class PineconeService:
    def __init__(self):
        settings = get_settings()
        api_key = settings.pinecone_api_key
        if not api_key:
            raise RuntimeError("PINECONE_API_KEY is not set")

        self.pc = Pinecone(api_key=api_key)
        self.encoder = SentenceTransformer("all-MiniLM-L6-v2")
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        indexes = self.pc.list_indexes()
        existing = [idx.name for idx in indexes]

        if "scanguard-bugs" not in existing:
            self.pc.create_index(
                name="scanguard-bugs",
                dimension=384,
                metric="cosine",
                spec=ServerlessSpec(cloud="aws", region="us-east-1"),
            )

        if "scanguard-patterns" not in existing:
            self.pc.create_index(
                name="scanguard-patterns",
                dimension=384,
                metric="cosine",
                spec=ServerlessSpec(cloud="aws", region="us-east-1"),
            )

        self.bugs_index = self.pc.Index("scanguard-bugs")
        self.patterns_index = self.pc.Index("scanguard-patterns")

    def embed_text(self, text: str) -> List[float]:
        embedding = self.encoder.encode(text)
        if hasattr(embedding, "tolist"):
            return embedding.tolist()
        return list(embedding)

    def upsert_bug(
        self,
        bug_id: str,
        title: str,
        description: str,
        metadata: Dict[str, Any],
    ) -> str:
        text = f"{title} {description}"
        embedding = self.embed_text(text)

        self.bugs_index.upsert(
            vectors=[
                {
                    "id": bug_id,
                    "values": embedding,
                    "metadata": metadata,
                }
            ]
        )
        return bug_id

    def find_similar_bugs(
        self, title: str, description: str, top_k: int = 10
    ) -> List[Any]:
        text = f"{title} {description}"
        embedding = self.embed_text(text)

        results = self.bugs_index.query(
            vector=embedding, top_k=top_k, include_metadata=True
        )
        return results.matches

    def upsert_pattern(
        self,
        pattern_id: str,
        text: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        embedding = self.embed_text(text)
        self.patterns_index.upsert(
            vectors=[
                {
                    "id": pattern_id,
                    "values": embedding,
                    "metadata": metadata or {},
                }
            ]
        )
        return pattern_id

    def find_similar_patterns(
        self, text: str, top_k: int = 5
    ) -> List[Any]:
        embedding = self.embed_text(text)
        results = self.patterns_index.query(
            vector=embedding, top_k=top_k, include_metadata=True
        )
        return results.matches
