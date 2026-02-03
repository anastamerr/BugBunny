import type { Finding } from "../types";

const ZAP_EVIDENCE_URL_RE = /\b(url|param):[^\s]+/gi;

function normalizeValue(value?: string | null): string {
  return (value ?? "").trim().toLowerCase();
}

function normalizeEvidence(evidence: string[]): string {
  if (!evidence.length) return "";
  return evidence
    .map((item) => item.replace(ZAP_EVIDENCE_URL_RE, "$1:<redacted>").trim())
    .filter(Boolean)
    .join("|");
}

function extractFromEvidence(
  evidence: string[],
  field: "risk" | "confidence",
): string {
  const pattern = new RegExp(`${field}:(\\S+)`, "i");
  for (const item of evidence) {
    const match = item.match(pattern);
    if (match?.[1]) {
      return match[1].toLowerCase();
    }
  }
  return "";
}

function buildDastGroupKey(finding: Finding): string {
  const evidenceItems = (finding.evidence || []).filter(Boolean);
  const risk =
    extractFromEvidence(evidenceItems, "risk") ||
    normalizeValue(finding.semgrep_severity);
  const confidence = extractFromEvidence(evidenceItems, "confidence");
  const evidenceKey = normalizeEvidence(evidenceItems);
  return [
    normalizeValue(finding.rule_id),
    normalizeValue(finding.rule_message),
    risk,
    confidence,
    evidenceKey,
    normalizeValue(finding.remediation),
  ].join("||");
}

function extractUrl(finding: Finding): string | null {
  const candidate =
    finding.matched_at || finding.endpoint || finding.file_path || "";
  return candidate.trim() ? candidate : null;
}

export function groupFindingsForDisplay(findings: Finding[]) {
  const grouped: Finding[] = [];
  const dastGroups = new Map<
    string,
    {
      base: Finding;
      raw: Finding[];
      urls: Set<string>;
    }
  >();
  let rawDastCount = 0;

  for (const finding of findings) {
    if (finding.finding_type !== "dast") {
      grouped.push(finding);
      continue;
    }

    rawDastCount += 1;
    const key = buildDastGroupKey(finding);
    const existing = dastGroups.get(key);

    if (!existing) {
      dastGroups.set(key, {
        base: finding,
        raw: [finding],
        urls: new Set(),
      });
      grouped.push(finding);
    } else {
      existing.raw.push(finding);
    }

    const url = extractUrl(finding);
    if (url) {
      (existing ?? dastGroups.get(key))?.urls.add(url);
    }
  }

  const enriched = grouped.map((finding) => {
    if (finding.finding_type !== "dast") return finding;
    const key = buildDastGroupKey(finding);
    const group = dastGroups.get(key);
    if (!group) return finding;
    return {
      ...group.base,
      affected_urls: Array.from(group.urls),
      raw_findings: group.raw,
      raw_count: group.raw.length,
    } satisfies Finding;
  });

  return {
    items: enriched,
    rawDastCount,
    groupedDastCount: dastGroups.size,
  };
}
