import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

import type { Finding } from "../types";

type FindingCardProps = {
  finding: Finding;
  onUpdateStatus?: (id: string, status: "confirmed" | "dismissed") => void;
  isUpdating?: boolean;
  onAutoFix?: (
    id: string,
    options: { createPr: boolean; regenerate?: boolean },
  ) => void;
  isAutoFixing?: boolean;
  autoFixAction?: "preview" | "pr" | null;
  autoFixError?: string | null;
};

const severityStyles: Record<string, string> = {
  critical: "badge border-rose-500/60 bg-rose-500/15 text-rose-200",
  high: "badge border-orange-400/50 bg-orange-400/15 text-orange-100",
  medium: "badge border-amber-300/50 bg-amber-300/15 text-amber-100",
  low: "badge border-emerald-300/50 bg-emerald-300/12 text-emerald-100",
  info: "badge border-sky-400/50 bg-sky-400/12 text-sky-100",
};

const semgrepStyles: Record<string, string> = {
  ERROR: "badge border-amber-400/40 bg-amber-400/10 text-amber-200",
  WARNING: "badge border-white/20 bg-white/10 text-white/80",
  INFO: "badge border-white/10 bg-white/5 text-white/70",
};

const fixStatusStyles: Record<string, string> = {
  generated: "badge border-sky-400/40 bg-sky-400/10 text-sky-200",
  pr_opened: "badge border-neon-mint/40 bg-neon-mint/10 text-neon-mint",
  failed: "badge border-rose-400/40 bg-rose-400/10 text-rose-200",
};

const dastStatusLabels: Record<string, string> = {
  confirmed_exploitable: "confirmed exploitable",
  not_confirmed: "not confirmed",
  inconclusive: "inconclusive",
  attempted_not_reproduced: "not confirmed",
  blocked_auth_required: "auth required",
  blocked_rate_limit: "rate limited",
  inconclusive_mapping: "inconclusive",
  bad_request: "bad request",
  error_timeout: "timeout",
  error_tooling: "DAST error",
  not_run: "SAST only (no DAST run)",
};

const dastStatusStyles: Record<string, string> = {
  confirmed_exploitable: "badge border-rose-500/60 bg-rose-500/15 text-rose-200 font-semibold",
  not_confirmed: "badge border-white/20 bg-white/10 text-white/80",
  inconclusive: "badge border-violet-400/40 bg-violet-400/10 text-violet-200",
  attempted_not_reproduced: "badge border-white/20 bg-white/10 text-white/80",
  blocked_auth_required: "badge border-violet-400/40 bg-violet-400/10 text-violet-200",
  blocked_rate_limit: "badge border-violet-400/40 bg-violet-400/10 text-violet-200",
  inconclusive_mapping: "badge border-violet-400/40 bg-violet-400/10 text-violet-200",
  bad_request: "badge border-violet-400/40 bg-violet-400/10 text-violet-200",
  error_timeout: "badge border-violet-400/40 bg-violet-400/10 text-violet-200",
  error_tooling: "badge border-violet-400/40 bg-violet-400/10 text-violet-200",
  not_run: "badge border-white/20 bg-white/10 text-white/70",
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

function formatList(values?: string[] | null, emptyLabel = "none") {
  if (!values || values.length === 0) return emptyLabel;
  return values.filter(Boolean).join(", ");
}

export function FindingCard({
  finding,
  onUpdateStatus,
  isUpdating = false,
  onAutoFix,
  isAutoFixing = false,
  autoFixAction = null,
  autoFixError = null,
}: FindingCardProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [showAffectedUrls, setShowAffectedUrls] = useState(false);
  const [copiedReasoning, setCopiedReasoning] = useState(false);

  const findingType = finding.finding_type || "sast";
  const isDast = findingType === "dast";
  const aiSeverity = (finding.ai_severity || "info").toLowerCase();
  const aiBadgeClass = severityStyles[aiSeverity] || "badge";
  const semgrepBadgeClass = semgrepStyles[finding.semgrep_severity] || "badge";
  const evidenceItems = useMemo(
    () => (finding.evidence || []).filter(Boolean),
    [finding.evidence],
  );
  const affectedUrls = useMemo(() => {
    if (finding.affected_urls && finding.affected_urls.length > 0) {
      return Array.from(new Set(finding.affected_urls.filter(Boolean)));
    }
    if (finding.raw_findings && finding.raw_findings.length > 0) {
      const urls = finding.raw_findings
        .map(
          (item) =>
            item.matched_at || item.endpoint || item.file_path || "",
        )
        .filter(Boolean);
      return Array.from(new Set(urls));
    }
    const fallback =
      finding.matched_at || finding.endpoint || finding.file_path || "";
    return fallback ? [fallback] : [];
  }, [finding]);
  const cveList = formatList(finding.cve_ids);
  const cweList = formatList(finding.cwe_ids);
  const hasDastEvidence =
    Boolean(finding.matched_at || finding.endpoint || finding.curl_command) ||
    evidenceItems.length > 0;
  const primaryMessage = isDast
    ? finding.description || finding.rule_message
    : finding.rule_message;
  const locationLabel = isDast
    ? displayText(
        finding.matched_at || finding.endpoint || finding.file_path,
        "n/a",
      )
    : `${finding.file_path}:${finding.line_start}${
        finding.line_end !== finding.line_start ? `-${finding.line_end}` : ""
      }`;
  const reasoningText = finding.ai_reasoning?.trim() ?? "";
  const reasoningDisplay = displayText(
    finding.ai_reasoning,
    "No AI reasoning provided.",
  );

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
  const fixStatus = finding.fix_status || null;
  const fixBadgeClass = fixStatus
    ? fixStatusStyles[fixStatus] || "badge"
    : "badge";
  const fixLabel =
    fixStatus === "generated"
      ? "fix ready"
      : fixStatus === "pr_opened"
        ? "fix PR opened"
        : fixStatus === "failed"
          ? "fix failed"
          : null;
  const fixPatch = finding.fix_patch;
  const fixSummary = finding.fix_summary;
  const fixConfidence =
    finding.fix_confidence !== null && finding.fix_confidence !== undefined
      ? Math.round(finding.fix_confidence * 100)
      : null;
  const currentFixError = autoFixError || finding.fix_error;
  const isGeneratingFix = isAutoFixing && autoFixAction === "preview";
  const isOpeningPr = isAutoFixing && autoFixAction === "pr";
  const fileExtension = finding.file_path
    ? finding.file_path.split(".").pop()?.toLowerCase()
    : undefined;
  const supportsAutoFix = Boolean(
    fileExtension && ["py", "js", "jsx", "ts", "tsx"].includes(fileExtension),
  );
  const canAutoFix =
    !isDast &&
    supportsAutoFix &&
    !finding.is_false_positive &&
    !finding.is_test_file &&
    !finding.is_generated &&
    (finding.ai_confidence ?? 0) >= 0.7 &&
    ["critical", "high", "medium"].includes(aiSeverity);
  const showGenerateFix = Boolean(onAutoFix) && canAutoFix;
  const showOpenPrAction =
    Boolean(onAutoFix) && canAutoFix && Boolean(fixPatch) && !finding.fix_pr_url;
  const dastStatus = finding.dast_verification_status || "not_run";
  const showDastStatus = !isDast && !finding.is_false_positive;
  const dastBadgeLabel = dastStatusLabels[dastStatus] || dastStatusLabels.not_run;
  const dastBadgeClass = dastStatusStyles[dastStatus] || "badge";

  const handleCopyReasoning = async () => {
    if (!reasoningText) return;
    try {
      await navigator.clipboard.writeText(reasoningText);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = reasoningText;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }
    setCopiedReasoning(true);
    window.setTimeout(() => setCopiedReasoning(false), 1500);
  };

  return (
    <div className="surface-solid p-5">
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="badge font-mono text-white/80">{finding.rule_id}</span>
            <span className="badge">{isDast ? "DAST" : "SAST"}</span>
            {isDast ? (
              <span className={aiBadgeClass}>DAST {aiSeverity}</span>
            ) : (
              <>
                <span className={aiBadgeClass}>AI {aiSeverity}</span>
                <span className={semgrepBadgeClass}>
                  Semgrep {finding.semgrep_severity}
                </span>
              </>
            )}
            <span className={statusBadge}>{finding.status}</span>
            {fixLabel ? (
              <span className={fixBadgeClass}>{fixLabel}</span>
            ) : null}
            {showDastStatus ? (
              <span className={dastBadgeClass}>{dastBadgeLabel}</span>
            ) : null}
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
            {displayText(primaryMessage, "No rule message provided.")}
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs text-white/60">
            <span className="font-mono">{locationLabel}</span>
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
          {showGenerateFix ? (
            <button
              type="button"
              className="btn-ghost"
              onClick={() =>
                onAutoFix?.(finding.id, {
                  createPr: false,
                  regenerate: Boolean(fixPatch),
                })
              }
              disabled={isAutoFixing}
            >
              {isGeneratingFix
                ? "Generating..."
                : fixPatch
                  ? "Regenerate Fix"
                  : "Generate Fix"}
            </button>
          ) : null}
          {showOpenPrAction ? (
            <button
              type="button"
              className="btn-ghost"
              onClick={() =>
                onAutoFix?.(finding.id, { createPr: true, regenerate: false })
              }
              disabled={isAutoFixing}
            >
              {isOpeningPr ? "Opening PR..." : "Open PR"}
            </button>
          ) : null}
          {finding.fix_pr_url ? (
            <a
              href={finding.fix_pr_url}
              target="_blank"
              rel="noreferrer"
              className="btn-ghost"
            >
              View PR
            </a>
          ) : null}
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
          {isDast ? (
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <div>
                <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                  DAST Summary
                </div>
                <p className="mt-2 text-sm text-white/80">
                  {displayText(
                    finding.description || finding.rule_message,
                    "No description provided.",
                  )}
                </p>
                {affectedUrls.length > 1 ? (
                  <div className="mt-4">
                    <button
                      type="button"
                      className="btn-ghost text-xs"
                      onClick={() => setShowAffectedUrls((prev) => !prev)}
                    >
                      {showAffectedUrls
                        ? "Hide affected URLs"
                        : `Affected URLs (${affectedUrls.length})`}
                    </button>
                    {showAffectedUrls ? (
                      <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-white/80">
                        {affectedUrls.map((url) => (
                          <li key={`${finding.id}-affected-${url}`}>{url}</li>
                        ))}
                      </ul>
                    ) : null}
                  </div>
                ) : null}
                <div className="mt-4 text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                  Remediation
                </div>
                <p className="mt-2 text-sm text-white/80">
                  {displayText(finding.remediation, "No remediation guidance.")}
                </p>
                <div className="mt-4 space-y-2 text-sm text-white/80">
                  <div>
                    <span className="text-white/60">Endpoint: </span>
                    {displayText(finding.endpoint, "n/a")}
                  </div>
                  <div>
                    <span className="text-white/60">Matched at: </span>
                    {displayText(finding.matched_at, "n/a")}
                  </div>
                  <div>
                    <span className="text-white/60">CVE: </span>
                    {cveList}
                  </div>
                  <div>
                    <span className="text-white/60">CWE: </span>
                    {cweList}
                  </div>
                </div>
                <div className="mt-4 flex items-center justify-between gap-3">
                  <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                    Analysis
                  </div>
                  <button
                    type="button"
                    className="btn-ghost text-xs"
                    onClick={handleCopyReasoning}
                    disabled={!reasoningText}
                  >
                    {copiedReasoning ? "Copied" : "Copy reasoning"}
                  </button>
                </div>
                <p className="mt-2 text-sm text-white/80">{reasoningDisplay}</p>
              </div>

              <div>
                <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                  Reproduction
                </div>
                <pre className="mt-2 max-h-48 overflow-auto rounded-card border border-white/10 bg-void p-3 text-xs text-white/80">
                  {displayText(
                    finding.curl_command,
                    "No curl command provided.",
                  )}
                </pre>
                <div className="mt-4 text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                  Evidence
                </div>
                {evidenceItems.length ? (
                  <ul className="mt-2 list-disc space-y-1 pl-4 text-xs text-white/80">
                    {evidenceItems.map((item, index) => (
                      <li key={`${finding.id}-evidence-${index}`}>{item}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="mt-2 text-sm text-white/70">
                    No evidence captured.
                  </p>
                )}
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <div>
                <div className="flex items-center justify-between gap-3">
                  <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                    AI Reasoning
                  </div>
                  <button
                    type="button"
                    className="btn-ghost text-xs"
                    onClick={handleCopyReasoning}
                    disabled={!reasoningText}
                  >
                    {copiedReasoning ? "Copied" : "Copy reasoning"}
                  </button>
                </div>
                <p className="mt-2 text-sm text-white/80">{reasoningDisplay}</p>
                <div className="mt-4 text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                  Exploitability
                </div>
                <p className="mt-2 text-sm text-white/80">
                  {displayText(
                    finding.exploitability,
                    "No exploitability notes.",
                  )}
                </p>
                {finding.description ? (
                  <>
                    <div className="mt-4 text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                      Details
                    </div>
                    <p className="mt-2 text-sm text-white/80">
                      {displayText(finding.description, "No details provided.")}
                    </p>
                  </>
                ) : null}
                {finding.remediation ? (
                  <>
                    <div className="mt-4 text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                      Remediation
                    </div>
                    <p className="mt-2 text-sm text-white/80">
                      {displayText(
                        finding.remediation,
                        "No remediation guidance.",
                      )}
                    </p>
                  </>
                ) : null}
                {fixSummary || currentFixError || fixStatus ? (
                  <>
                    <div className="mt-4 text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                      Auto Fix
                    </div>
                    {fixSummary ? (
                      <p className="mt-2 text-sm text-white/80">
                        {displayText(fixSummary, "Fix summary unavailable.")}
                      </p>
                    ) : null}
                    <div className="mt-2 text-sm text-white/70">
                      <span className="text-white/50">Status: </span>
                      {fixStatus || "not generated"}
                    </div>
                    {fixConfidence !== null ? (
                      <div className="mt-1 text-sm text-white/70">
                        <span className="text-white/50">Confidence: </span>
                        {fixConfidence}%
                      </div>
                    ) : null}
                    {currentFixError ? (
                      <div className="mt-2 text-sm text-rose-200">
                        {currentFixError}
                      </div>
                    ) : null}
                  </>
                ) : null}
                {hasDastEvidence ? (
                  <div className="mt-4">
                    <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                      DAST Evidence
                    </div>
                    <div className="mt-2 space-y-2 text-sm text-white/80">
                      {finding.endpoint ? (
                        <div>
                          <span className="text-white/60">Endpoint: </span>
                          {finding.endpoint}
                        </div>
                      ) : null}
                      {finding.matched_at ? (
                        <div>
                          <span className="text-white/60">Matched at: </span>
                          {finding.matched_at}
                        </div>
                      ) : null}
                      {(finding.cve_ids?.length ?? 0) > 0 ||
                      (finding.cwe_ids?.length ?? 0) > 0 ? (
                        <div>
                          <span className="text-white/60">CVE: </span>
                          {cveList} | <span className="text-white/60">CWE: </span>
                          {cweList}
                        </div>
                      ) : null}
                      {finding.curl_command ? (
                        <pre className="max-h-40 overflow-auto rounded-card border border-white/10 bg-void p-3 text-xs text-white/80">
                          {finding.curl_command}
                        </pre>
                      ) : null}
                      {evidenceItems.length ? (
                        <ul className="list-disc space-y-1 pl-4 text-xs text-white/80">
                          {evidenceItems.map((item, index) => (
                            <li key={`${finding.id}-evidence-${index}`}>
                              {item}
                            </li>
                          ))}
                        </ul>
                      ) : null}
                    </div>
                  </div>
                ) : null}
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
                {fixPatch ? (
                  <div className="mt-4">
                    <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                      Auto Fix Patch
                    </div>
                    <pre className="mt-2 max-h-72 overflow-auto rounded-card border border-white/10 bg-void p-3 text-xs text-white/80">
                      {fixPatch}
                    </pre>
                  </div>
                ) : null}
              </div>
            </div>
          )}
        </div>
      ) : null}
    </div>
  );
}
