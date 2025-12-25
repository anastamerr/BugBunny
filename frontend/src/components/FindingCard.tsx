import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

import type { Finding } from "../types";

type FindingCardProps = {
  finding: Finding;
  onUpdateStatus?: (id: string, status: "confirmed" | "dismissed") => void;
  isUpdating?: boolean;
};

const severityStyles: Record<string, string> = {
  critical: "badge border-rose-400/40 bg-rose-400/10 text-rose-200",
  high: "badge border-amber-400/40 bg-amber-400/10 text-amber-200",
  medium: "badge border-white/20 bg-white/10 text-white/80",
  low: "badge border-white/10 bg-white/5 text-white/70",
  info: "badge border-sky-400/40 bg-sky-400/10 text-sky-200",
};

const semgrepStyles: Record<string, string> = {
  ERROR: "badge border-amber-400/40 bg-amber-400/10 text-amber-200",
  WARNING: "badge border-white/20 bg-white/10 text-white/80",
  INFO: "badge border-white/10 bg-white/5 text-white/70",
};

function displayText(value?: string | null, fallback: string = "n/a") {
  if (!value) return fallback;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : fallback;
}

function formatConfidence(value?: number | null) {
  if (value === null || value === undefined) return "n/a";
  return `${Math.round(value * 100)}%`;
}

export function FindingCard({
  finding,
  onUpdateStatus,
  isUpdating = false,
}: FindingCardProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const aiSeverity = (finding.ai_severity || "info").toLowerCase();
  const aiBadgeClass = severityStyles[aiSeverity] || "badge";
  const semgrepBadgeClass = semgrepStyles[finding.semgrep_severity] || "badge";

  const meta = useMemo(() => {
    const parts: string[] = [];
    if (finding.function_name) parts.push(finding.function_name);
    if (finding.class_name) parts.push(finding.class_name);
    if (finding.is_test_file) parts.push("test");
    if (finding.is_generated) parts.push("generated");
    return parts;
  }, [finding]);

  const statusBadge =
    finding.status === "confirmed"
      ? "badge border-neon-mint/40 bg-neon-mint/10 text-neon-mint"
      : finding.status === "dismissed"
        ? "badge border-white/20 bg-white/10 text-white/80"
        : "badge";

  const shouldDisableConfirm = isUpdating || finding.status === "confirmed";
  const shouldDisableDismiss = isUpdating || finding.status === "dismissed";

  return (
    <div className="surface-solid p-5">
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="badge font-mono text-white/80">{finding.rule_id}</span>
            <span className={aiBadgeClass}>AI {aiSeverity}</span>
            <span className={semgrepBadgeClass}>
              Semgrep {finding.semgrep_severity}
            </span>
            <span className={statusBadge}>{finding.status}</span>
            {finding.is_false_positive ? (
              <span className="badge border-white/20 bg-white/10 text-white/60">
                false positive
              </span>
            ) : null}
            {finding.priority_score !== null && finding.priority_score !== undefined ? (
              <span className="badge font-mono text-white/70">
                score {finding.priority_score}
              </span>
            ) : null}
          </div>

          <div className="text-sm font-semibold text-white">
            {displayText(finding.rule_message, "No rule message provided.")}
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs text-white/60">
            <span className="font-mono">
              {finding.file_path}:{finding.line_start}
              {finding.line_end !== finding.line_start
                ? `-${finding.line_end}`
                : ""}
            </span>
            {meta.map((item) => (
              <span key={item} className="badge">
                {item}
              </span>
            ))}
            <span className="badge">confidence {formatConfidence(finding.ai_confidence)}</span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            className="btn-ghost"
            onClick={() => setIsExpanded((prev) => !prev)}
          >
            {isExpanded ? "Hide details" : "View details"}
          </button>
          <Link
            to={`/chat?scan_id=${finding.scan_id}&finding_id=${finding.id}`}
            className="btn-ghost"
          >
            Ask AI
          </Link>
          <button
            type="button"
            className="btn-primary"
            onClick={() => onUpdateStatus?.(finding.id, "confirmed")}
            disabled={shouldDisableConfirm}
          >
            {finding.status === "confirmed" ? "Confirmed" : "Confirm"}
          </button>
          <button
            type="button"
            className="btn-ghost"
            onClick={() => onUpdateStatus?.(finding.id, "dismissed")}
            disabled={shouldDisableDismiss}
          >
            {finding.status === "dismissed" ? "Dismissed" : "Dismiss"}
          </button>
        </div>
      </div>

      {isExpanded ? (
        <div className="mt-4 border-t border-white/10 pt-4">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div>
              <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                AI Reasoning
              </div>
              <p className="mt-2 text-sm text-white/80">
                {displayText(finding.ai_reasoning, "No AI reasoning provided.")}
              </p>
              <div className="mt-4 text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                Exploitability
              </div>
              <p className="mt-2 text-sm text-white/80">
                {displayText(finding.exploitability, "No exploitability notes.")}
              </p>
            </div>

            <div>
              <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                Code Context
              </div>
              <pre className="mt-2 max-h-72 overflow-auto rounded-card border border-white/10 bg-void p-3 text-xs text-white/80">
                {displayText(
                  finding.context_snippet || finding.code_snippet,
                  "No code snippet available.",
                )}
              </pre>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
