from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse


MAX_CLUSTER_DOCS = 20
MAX_SUMMARY_FINDINGS = 5
MAX_DOC_TEXT_CHARS = 900

REDACTION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"ghp_[A-Za-z0-9]{36,}"), "[REDACTED_GH_TOKEN]"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "[REDACTED_SLACK_TOKEN]"),
    (
        re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
        "[REDACTED_JWT]",
    ),
    (
        re.compile(r"(?is)-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----"),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (
        re.compile(
            r"(?i)\b(api|secret|token|key|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{8,})"
        ),
        r"\1=[REDACTED]",
    ),
)


@dataclass(frozen=True)
class ProjectMemoryDoc:
    doc_id: str
    text: str
    metadata: Dict[str, Any]


def redact_text(text: str) -> str:
    if not text:
        return ""
    redacted = text
    for pattern, replacement in REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def extract_repo_full_name(repo_url: Optional[str]) -> Optional[str]:
    if not repo_url:
        return None
    parsed = urlparse(repo_url)
    host = (parsed.netloc or "").lower()
    if "github.com" not in host:
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return None


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _severity_label(finding: Any) -> str:
    ai = getattr(finding, "ai_severity", None)
    if ai:
        return str(ai).lower()
    semgrep = getattr(finding, "semgrep_severity", None)
    mapping = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    return mapping.get(str(semgrep), "info")


def _severity_weight(label: str) -> int:
    weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return weights.get(label, 0)


def _infer_component(path_or_endpoint: Optional[str]) -> Optional[str]:
    if not path_or_endpoint:
        return None
    cleaned = path_or_endpoint.lstrip("/")
    if not cleaned:
        return None
    return cleaned.split("/")[0]


def _finding_key(finding: Any) -> Tuple[str, str]:
    rule_id = str(getattr(finding, "rule_id", "") or "unknown")
    location = (
        getattr(finding, "endpoint", None)
        or getattr(finding, "file_path", None)
        or "unknown"
    )
    return rule_id, str(location)


class ProjectMemoryBuilder:
    def __init__(
        self,
        *,
        max_cluster_docs: int = MAX_CLUSTER_DOCS,
        max_summary_findings: int = MAX_SUMMARY_FINDINGS,
        max_doc_chars: int = MAX_DOC_TEXT_CHARS,
    ) -> None:
        self.max_cluster_docs = max_cluster_docs
        self.max_summary_findings = max_summary_findings
        self.max_doc_chars = max_doc_chars

    def build_documents(self, scan: Any, findings: Sequence[Any]) -> List[ProjectMemoryDoc]:
        docs: List[ProjectMemoryDoc] = []
        summary = self._build_scan_summary(scan, findings)
        if summary:
            docs.append(summary)
        docs.extend(self._build_finding_clusters(scan, findings))
        return docs

    def upsert_for_scan(self, pinecone: Any, scan: Any, findings: Sequence[Any]) -> int:
        docs = self.build_documents(scan, findings)
        count = 0
        for doc in docs:
            pinecone.upsert_project_memory(doc.doc_id, doc.text, doc.metadata)
            count += 1
        return count

    def _build_scan_summary(self, scan: Any, findings: Sequence[Any]) -> Optional[ProjectMemoryDoc]:
        actionable = [f for f in findings if not getattr(f, "is_false_positive", False)]
        counts: Dict[str, int] = {}
        confirmed = 0
        for finding in actionable:
            label = _severity_label(finding)
            counts[label] = counts.get(label, 0) + 1
            if getattr(finding, "confirmed_exploitable", False):
                confirmed += 1

        ordered = sorted(
            actionable,
            key=lambda f: (_severity_weight(_severity_label(f)), getattr(f, "priority_score", 0)),
            reverse=True,
        )
        top_findings = ordered[: self.max_summary_findings]
        top_lines = []
        for finding in top_findings:
            loc = getattr(finding, "file_path", None) or getattr(finding, "endpoint", None) or "n/a"
            top_lines.append(
                f"- {finding.rule_id} @ {loc} ({_severity_label(finding)})"
            )

        repo_url = getattr(scan, "repo_url", None)
        repo_full_name = extract_repo_full_name(repo_url)
        created_at = getattr(scan, "created_at", None)
        created_label = _format_timestamp(created_at)

        summary = "\n".join(
            [
                f"Scan summary for {repo_full_name or repo_url or 'repo'} on {created_label}.",
                f"Totals: {getattr(scan, 'total_findings', 0)} signals, {getattr(scan, 'filtered_findings', 0)} actionable.",
                f"Severity counts: {counts or {'info': 0}}.",
                f"Confirmed exploitable: {confirmed}.",
                "Top findings:",
                *(top_lines or ["- none"]),
            ]
        )
        summary = _truncate(redact_text(summary), self.max_doc_chars)
        metadata = _base_metadata(scan, repo_full_name)
        metadata.update(
            {
                "doc_type": "scan_summary",
                "summary": summary,
                "severity": _dominant_severity(counts),
                "finding_count": len(actionable),
            }
        )
        doc_id = f"scan:{getattr(scan, 'id', uuid.uuid4())}"
        return ProjectMemoryDoc(doc_id=doc_id, text=summary, metadata=metadata)

    def _build_finding_clusters(
        self, scan: Any, findings: Sequence[Any]
    ) -> List[ProjectMemoryDoc]:
        actionable = [f for f in findings if not getattr(f, "is_false_positive", False)]
        clusters: Dict[Tuple[str, str], Dict[str, Any]] = {}

        for finding in actionable:
            rule_id, location = _finding_key(finding)
            key = (rule_id, location)
            entry = clusters.setdefault(
                key,
                {
                    "rule_id": rule_id,
                    "location": location,
                    "count": 0,
                    "severity": "info",
                    "component": _infer_component(location),
                    "endpoint": getattr(finding, "endpoint", None),
                    "file_path": getattr(finding, "file_path", None),
                    "cwe_ids": getattr(finding, "cwe_ids", None),
                },
            )
            entry["count"] += 1
            label = _severity_label(finding)
            if _severity_weight(label) > _severity_weight(entry["severity"]):
                entry["severity"] = label

        ordered = sorted(
            clusters.values(),
            key=lambda item: (_severity_weight(item["severity"]), item["count"]),
            reverse=True,
        )
        ordered = ordered[: self.max_cluster_docs]

        repo_url = getattr(scan, "repo_url", None)
        repo_full_name = extract_repo_full_name(repo_url)
        created_at = getattr(scan, "created_at", None)
        created_label = _format_timestamp(created_at)

        docs: List[ProjectMemoryDoc] = []
        for cluster in ordered:
            summary = (
                f"Finding cluster: {cluster['rule_id']} at {cluster['location']} "
                f"({cluster['count']} occurrences, severity {cluster['severity']}). "
                f"Last seen {created_label}."
            )
            summary = _truncate(redact_text(summary), self.max_doc_chars)
            metadata = _base_metadata(scan, repo_full_name)
            metadata.update(
                {
                    "doc_type": "finding_cluster",
                    "summary": summary,
                    "rule_id": cluster["rule_id"],
                    "file_path": cluster.get("file_path"),
                    "endpoint": cluster.get("endpoint"),
                    "severity": cluster["severity"],
                    "component": cluster.get("component"),
                    "finding_count": cluster["count"],
                    "cwe_ids": cluster.get("cwe_ids"),
                }
            )
            doc_id = f"cluster:{scan.id}:{_stable_cluster_id(cluster['rule_id'], cluster['location'])}"
            docs.append(ProjectMemoryDoc(doc_id=doc_id, text=summary, metadata=metadata))

        return docs


def _base_metadata(scan: Any, repo_full_name: Optional[str]) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {
        "scan_id": str(getattr(scan, "id", "")),
        "repo_url": getattr(scan, "repo_url", None),
        "created_at": _format_timestamp(getattr(scan, "created_at", None)),
    }
    repo_id = getattr(scan, "repo_id", None)
    if repo_id:
        metadata["repo_id"] = str(repo_id)
    if repo_full_name:
        metadata["repo_full_name"] = repo_full_name
    return metadata


def _dominant_severity(counts: Dict[str, int]) -> str:
    if not counts:
        return "info"
    return max(counts.items(), key=lambda item: (_severity_weight(item[0]), item[1]))[0]


def _format_timestamp(ts: Optional[datetime]) -> str:
    if not ts:
        return "n/a"
    try:
        return ts.isoformat()
    except Exception:
        return "n/a"


def _stable_cluster_id(rule_id: str, location: str) -> str:
    namespace = uuid.NAMESPACE_URL
    return str(uuid.uuid5(namespace, f"{rule_id}:{location}"))
