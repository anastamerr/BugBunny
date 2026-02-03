import type { ReactNode } from "react";
import { useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { demoApi } from "../api/demo";
import { repositoriesApi } from "../api/repositories";
import { ApiError } from "../api/errors";
import { scansApi } from "../api/scans";
import type { Scan } from "../types";

// ============================================================================
// Constants & Types
// ============================================================================

type ScanType = "sast" | "dast" | "both";

const SCAN_TYPE_INFO: Record<ScanType, { label: string; description: string; icon: ReactNode }> = {
  sast: {
    label: "SAST",
    description: "Static code analysis with Semgrep",
    icon: (
      <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" />
      </svg>
    ),
  },
  dast: {
    label: "DAST",
    description: "Dynamic scan of a live target with OWASP ZAP",
    icon: (
      <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
      </svg>
    ),
  },
  both: {
    label: "Combined",
    description: "SAST + targeted DAST with correlation",
    icon: (
      <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
      </svg>
    ),
  },
};

const STATUS_CONFIG: Record<Scan["status"], { color: string; bgColor: string; label: string; isActive: boolean }> = {
  completed: { color: "text-neon-mint", bgColor: "bg-neon-mint", label: "Completed", isActive: false },
  failed: { color: "text-rose-400", bgColor: "bg-rose-400", label: "Failed", isActive: false },
  analyzing: { color: "text-amber-400", bgColor: "bg-amber-400", label: "Analyzing", isActive: true },
  scanning: { color: "text-sky-400", bgColor: "bg-sky-400", label: "Scanning", isActive: true },
  cloning: { color: "text-violet-400", bgColor: "bg-violet-400", label: "Cloning", isActive: true },
  pending: { color: "text-white/50", bgColor: "bg-white/50", label: "Pending", isActive: true },
};

const PAUSED_CONFIG = { color: "text-amber-300", bgColor: "bg-amber-300", label: "Paused", isActive: false };

// ============================================================================
// Utility Functions
// ============================================================================

function formatRepoName(url?: string | null): string {
  if (!url) return "DAST Target";
  try {
    const parsed = new URL(url);
    const parts = parsed.pathname.split("/").filter(Boolean);
    if (parts.length >= 2) {
      return `${parts[parts.length - 2]}/${parts[parts.length - 1]}`;
    }
  } catch {
    return url;
  }
  return url;
}

function formatDate(value?: string): string {
  if (!value) return "n/a";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return "n/a";

  const now = Date.now();
  const diffMs = now - dt.getTime();

  if (diffMs < 45_000) return "Just now";
  if (diffMs < 90_000) return "1m ago";

  const diffMins = Math.floor(diffMs / 60_000);
  if (diffMins < 60) return `${diffMins}m ago`;

  const diffHours = Math.floor(diffMs / 3_600_000);
  if (diffHours < 24) return `${diffHours}h ago`;

  const diffDays = Math.floor(diffMs / 86_400_000);
  if (diffDays < 7) return `${diffDays}d ago`;

  return dt.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function shortSha(sha?: string | null): string | null {
  if (!sha) return null;
  return sha.trim().slice(0, 7) || null;
}

function formatPhaseLabel(value?: string | null): string | null {
  if (!value) return null;
  const labels: Record<string, string> = {
    "sast.clone": "SAST - cloning",
    "sast.scan": "SAST - semgrep",
    "sast.analyze": "SAST - triage",
    "dast.deploy": "DAST - deploy",
    "dast.verify": "DAST - verify",
    "dast.spider": "DAST - spider",
    "dast.active_scan": "DAST - active scan",
    "dast.alerts": "DAST - alerts",
    "dast.targeted": "DAST - targeted",
    correlation: "Correlation",
  };
  return labels[value] || value.replace(/[_\.]/g, " ");
}

const DAST_VERIFICATION_LABELS: Record<string, string> = {
  verified: "DAST verified",
  unverified_url: "DAST unverified URL",
  commit_mismatch: "DAST commit mismatch",
  verification_error: "DAST verification error",
  not_applicable: "DAST not applicable",
};

const DAST_VERIFICATION_STYLES: Record<string, string> = {
  verified: "badge border-neon-mint/40 bg-neon-mint/10 text-neon-mint",
  unverified_url: "badge border-amber-400/40 bg-amber-400/10 text-amber-200",
  commit_mismatch: "badge border-rose-400/40 bg-rose-400/10 text-rose-200",
  verification_error: "badge border-rose-400/40 bg-rose-400/10 text-rose-200",
};

function getDastVerificationBadge(value?: string | null) {
  if (!value || value === "not_applicable") return null;
  return {
    label: DAST_VERIFICATION_LABELS[value] || `DAST ${value.replace(/[_\.]/g, " ")}`,
    className: DAST_VERIFICATION_STYLES[value] || "badge",
  };
}

function calculateNoiseReduction(scan: Scan): { percentage: number; filtered: number; total: number } {
  const total = scan.total_findings || 0;
  const filtered = scan.filtered_findings || 0;
  const percentage = total > 0 ? Math.round((1 - filtered / total) * 100) : 0;
  return { percentage, filtered, total };
}

function getProgressPercentage(status: Scan["status"]): number {
  switch (status) {
    case "pending": return 10;
    case "cloning": return 25;
    case "scanning": return 50;
    case "analyzing": return 75;
    case "completed": return 100;
    case "failed": return 100;
    default: return 0;
  }
}

function parseAuthHeaders(value: string): Record<string, string> | undefined {
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error("Auth headers must be valid JSON (e.g. {\"Authorization\":\"Bearer ...\"}).");
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error("Auth headers must be a JSON object.");
  }
  const headers: Record<string, string> = {};
  Object.entries(parsed as Record<string, unknown>).forEach(([key, val]) => {
    const headerKey = key.trim();
    if (!headerKey) return;
    if (val === null || val === undefined) return;
    headers[headerKey] = String(val);
  });
  return Object.keys(headers).length ? headers : undefined;
}

// ============================================================================
// Sub-Components
// ============================================================================

function StatusBadge({ status, isPaused }: { status: Scan["status"]; isPaused?: boolean }) {
  const config = isPaused ? PAUSED_CONFIG : STATUS_CONFIG[status];
  return (
    <div className="flex items-center gap-2">
      <span className={`status-dot ${config.bgColor} ${config.isActive ? "status-dot-pulse" : ""}`} />
      <span className={`text-xs font-medium ${config.color}`}>{config.label}</span>
    </div>
  );
}

function ScanTypeBadge({ type }: { type: ScanType }) {
  const badges = [];
  if (type === "sast" || type === "both") {
    badges.push(
      <span key="sast" className="badge border-sky-400/30 bg-sky-400/10 text-sky-300">
        SAST
      </span>
    );
  }
  if (type === "dast" || type === "both") {
    badges.push(
      <span key="dast" className="badge border-violet-400/30 bg-violet-400/10 text-violet-300">
        DAST
      </span>
    );
  }
  return <div className="flex items-center gap-1">{badges}</div>;
}

function ProgressBar({ status, isPaused }: { status: Scan["status"]; isPaused?: boolean }) {
  const percentage = getProgressPercentage(status);
  const config = isPaused ? PAUSED_CONFIG : STATUS_CONFIG[status];

  if (status === "completed" || status === "failed") return null;

  return (
    <div className="progress-bar">
      <div
        className={`progress-bar-fill ${config.bgColor}`}
        style={{ width: `${percentage}%` }}
      />
    </div>
  );
}

function StatCard({ value, label, trend }: { value: string | number; label: string; trend?: "up" | "down" }) {
  return (
    <div className="stat-card">
      <div className="flex items-center gap-2">
        <span className="stat-value">{value}</span>
        {trend && (
          <span className={trend === "up" ? "text-neon-mint" : "text-rose-400"}>
            {trend === "up" ? "+" : "-"}
          </span>
        )}
      </div>
      <span className="stat-label">{label}</span>
    </div>
  );
}

function EmptyState({ onCreateScan }: { onCreateScan: () => void }) {
  return (
    <div className="empty-state surface-solid">
      <svg className="empty-state-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
      </svg>
      <h3 className="empty-state-title">No scans yet</h3>
      <p className="empty-state-description">
        Start your first security scan to identify vulnerabilities in your code or live applications.
      </p>
      <button type="button" className="btn-primary" onClick={onCreateScan}>
        Create Your First Scan
      </button>
    </div>
  );
}

function ScanCard({
  scan,
  onDelete,
  isDeleting,
}: {
  scan: Scan;
  onDelete?: (scanId: string) => void;
  isDeleting?: boolean;
}) {
  const headline = scan.repo_url ? formatRepoName(scan.repo_url) : scan.target_url || "DAST Scan";
  const { percentage, filtered, total } = calculateNoiseReduction(scan);
  const isPaused = Boolean(scan.is_paused);
  const isActive = isPaused || STATUS_CONFIG[scan.status].isActive;
  const phaseLabel = formatPhaseLabel(scan.phase);
  const phaseMessage = scan.phase_message?.trim();
  const verificationBadge = getDastVerificationBadge(scan.dast_verification_status);
  const updatedAt = scan.updated_at || scan.created_at;
  const updatedLabel = formatDate(updatedAt);
  const updatedTitle = updatedAt ? new Date(updatedAt).toLocaleString() : undefined;
  const canDelete =
    scan.status === "pending" ||
    scan.is_paused ||
    scan.status === "completed" ||
    scan.status === "failed";

  return (
    <div className="scan-card">
      {isActive && <ProgressBar status={scan.status} isPaused={isPaused} />}

      <div className="scan-card-header">
        <div className="flex items-center gap-3">
          <StatusBadge status={scan.status} isPaused={isPaused} />
          <ScanTypeBadge type={scan.scan_type} />
          {scan.trigger === "webhook" && (
            <span className="badge border-amber-400/30 bg-amber-400/10 text-amber-300">
              Webhook
            </span>
          )}
          {verificationBadge && scan.scan_type !== "sast" ? (
            <span className={verificationBadge.className}>
              {verificationBadge.label}
            </span>
          ) : null}
        </div>
        <span className="text-xs text-white/40" title={updatedTitle}>
          Updated {updatedLabel}
        </span>
      </div>

      <div className="scan-card-body">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="min-w-0 flex-1">
            <h3 className="truncate text-lg font-semibold text-white">{headline}</h3>

            <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-white/50">
              {scan.branch && scan.scan_type !== "dast" && (
                <span className="flex items-center gap-1">
                  <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
                  </svg>
                  {scan.branch}
                </span>
              )}
              {shortSha(scan.commit_sha) && (
                <span className="font-mono">{shortSha(scan.commit_sha)}</span>
              )}
              {scan.pr_number && (
                <span className="flex items-center gap-1">
                  <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
                  </svg>
                  PR #{scan.pr_number}
                </span>
              )}
              {scan.target_url && (
                <span className="flex items-center gap-1 truncate max-w-[200px]">
                  <svg className="h-3.5 w-3.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
                  </svg>
                  <span className="truncate">{scan.target_url}</span>
                </span>
              )}
              {phaseLabel && isActive && (
                <span className="flex items-center gap-1">
                  <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6l4 2" />
                    <circle cx="12" cy="12" r="9" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                  <span className="truncate">
                    {phaseLabel}
                    {phaseMessage ? ` - ${phaseMessage}` : ""}
                  </span>
                </span>
              )}
            </div>

            {scan.error_message && (
              <p className="mt-2 text-xs text-rose-300">{scan.error_message}</p>
            )}
          </div>

          <div className="flex items-center gap-6">
            {scan.status === "completed" && total > 0 && (
              <div className="flex items-center gap-4">
                <div className="text-right">
                  <div className="text-2xl font-bold text-white">{filtered}</div>
                  <div className="text-xs text-white/50">Real Issues</div>
                </div>
                <div className="h-10 w-px bg-white/10" />
                <div className="text-right">
                  <div className="flex items-center gap-1">
                    <span className="text-2xl font-bold text-neon-mint">{percentage}%</span>
                  </div>
                  <div className="text-xs text-white/50">Noise Filtered</div>
                </div>
              </div>
            )}

            {scan.status === "completed" && total === 0 && (
              <div className="flex items-center gap-2 text-neon-mint">
                <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span className="text-sm font-medium">No issues found</span>
              </div>
            )}

            {onDelete ? (
              <button
                type="button"
                className="btn-ghost text-rose-300 hover:text-rose-200"
                onClick={() => {
                  if (!canDelete || isDeleting) return;
                  const confirmed = window.confirm(
                    "Delete this scan and all its findings? This cannot be undone.",
                  );
                  if (confirmed) {
                    onDelete(scan.id);
                  }
                }}
                disabled={!canDelete || isDeleting}
                title={
                  canDelete
                    ? "Delete this scan and its findings"
                    : "Delete is available when pending, paused, completed, or failed"
                }
              >
                {isDeleting ? "Deleting..." : "Delete"}
              </button>
            ) : null}

            <Link
              to={`/scans/${scan.id}`}
              className="btn-ghost flex items-center gap-2"
            >
              View Details
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
              </svg>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

function NewScanForm({
  scanType,
  setScanType,
  repoUrl,
  setRepoUrl,
  branch,
  setBranch,
  dependencyHealthEnabled,
  setDependencyHealthEnabled,
  targetUrl,
  setTargetUrl,
  dastConsent,
  setDastConsent,
  dastAuthHeaders,
  setDastAuthHeaders,
  dastCookies,
  setDastCookies,
  selectedRepoId,
  setSelectedRepoId,
  repos,
  onSubmit,
  onSubmitSaved,
  isLoading,
  errorMessage,
}: {
  scanType: ScanType;
  setScanType: (type: ScanType) => void;
  repoUrl: string;
  setRepoUrl: (url: string) => void;
  branch: string;
  setBranch: (branch: string) => void;
  dependencyHealthEnabled: boolean;
  setDependencyHealthEnabled: (enabled: boolean) => void;
  targetUrl: string;
  setTargetUrl: (url: string) => void;
  dastConsent: boolean;
  setDastConsent: (consent: boolean) => void;
  dastAuthHeaders: string;
  setDastAuthHeaders: (headers: string) => void;
  dastCookies: string;
  setDastCookies: (cookies: string) => void;
  selectedRepoId: string;
  setSelectedRepoId: (id: string) => void;
  repos: Array<{ id: string; repo_url: string; repo_full_name?: string | null }>;
  onSubmit: () => void;
  onSubmitSaved: () => void;
  isLoading: boolean;
  errorMessage: string | null;
}) {
  const [mode, setMode] = useState<"quick" | "saved">("quick");
  const [touched, setTouched] = useState({
    repo: false,
    target: false,
    consent: false,
    selectedRepo: false,
  });

  const repoMissing = scanType !== "dast" && mode === "quick" && !repoUrl.trim();
  const selectedRepoMissing =
    scanType !== "dast" && mode === "saved" && !selectedRepoId;
  const targetMissing = scanType !== "sast" && !targetUrl.trim();
  const consentMissing = scanType !== "sast" && !dastConsent;

  const showRepoError = repoMissing && touched.repo;
  const showSelectedRepoError = selectedRepoMissing && touched.selectedRepo;
  const showTargetError = targetMissing && touched.target;
  const showConsentError = consentMissing && touched.consent;

  const markTouched = (field: keyof typeof touched) => {
    setTouched((prev) => ({ ...prev, [field]: true }));
  };

  const canSubmit = useMemo(() => {
    if (isLoading) return false;

    if (scanType !== "sast" && (!targetUrl.trim() || !dastConsent)) {
      return false;
    }

    if (mode === "quick") {
      if (scanType !== "dast" && !repoUrl.trim()) return false;
    } else {
      if (scanType !== "dast" && !selectedRepoId) return false;
    }

    return true;
  }, [isLoading, scanType, targetUrl, dastConsent, mode, repoUrl, selectedRepoId]);

  return (
    <div className="surface-solid overflow-hidden">
      {/* Header */}
      <div className="border-b border-white/10 bg-white/[0.02] px-6 py-4">
        <h2 className="text-lg font-semibold text-white">New Security Scan</h2>
        <p className="mt-1 text-sm text-white/50">
          Choose your scan type and configure the target
        </p>
      </div>

      <div className="p-6 space-y-6">
        {/* Scan Type Selection */}
        <div>
          <label className="block text-xs font-semibold uppercase tracking-widest text-white/50 mb-3">
            Scan Type
          </label>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {(Object.keys(SCAN_TYPE_INFO) as ScanType[]).map((type) => {
              const info = SCAN_TYPE_INFO[type];
              const isSelected = scanType === type;
              return (
                <button
                  key={type}
                  type="button"
                  onClick={() => setScanType(type)}
                  className={`flex items-center gap-3 rounded-card border-2 p-4 text-left transition-all duration-200 ${
                    isSelected
                      ? "border-neon-mint bg-neon-mint/5 shadow-lg shadow-neon-mint/10"
                      : "border-white/10 bg-white/[0.02] hover:border-white/20 hover:bg-white/[0.04]"
                  }`}
                >
                  <div className={`rounded-xl p-2 ${isSelected ? "bg-neon-mint/20 text-neon-mint" : "bg-white/10 text-white/60"}`}>
                    {info.icon}
                  </div>
                  <div>
                    <div className={`font-semibold ${isSelected ? "text-neon-mint" : "text-white"}`}>
                      {info.label}
                    </div>
                    <div className="text-xs text-white/50">{info.description}</div>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* DAST Target URL (shown when DAST is involved) */}
        {scanType !== "sast" && (
          <div className="rounded-card border border-violet-400/20 bg-violet-400/5 p-4">
            <label className="block text-xs font-semibold uppercase tracking-widest text-violet-300 mb-2">
              Live Target URL
            </label>
            <div className="input-group">
              <svg className="input-icon h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
              </svg>
              <input
                className={`input input-with-icon w-full ${
                  showTargetError ? "border-rose-400 focus:border-rose-400" : ""
                }`}
                placeholder="https://app.example.com"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                onBlur={() => markTouched("target")}
                aria-invalid={showTargetError}
              />
            </div>
            {showTargetError ? (
              <p className="mt-2 text-xs text-rose-200">
                Target URL is required for DAST scans.
              </p>
            ) : null}
            <label className="mt-3 flex items-start gap-3 cursor-pointer group">
              <input
                type="checkbox"
                className="checkbox mt-0.5"
                checked={dastConsent}
                onChange={(e) => {
                  setDastConsent(e.target.checked);
                  if (e.target.checked) {
                    setTouched((prev) => ({ ...prev, consent: true }));
                  }
                }}
                onBlur={() => markTouched("consent")}
              />
              <span className="text-sm text-white/70 group-hover:text-white/90 transition-colors">
                I confirm I am authorized to run security testing on this target
              </span>
            </label>
            {showConsentError ? (
              <p className="mt-2 text-xs text-rose-200">
                Authorization is required before running DAST.
              </p>
            ) : (
              <p className="mt-2 text-xs text-white/50">
                Required for DAST. Only scan systems you own or have explicit
                permission to test.
              </p>
            )}
            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-widest text-violet-300/80 mb-2">
                  Auth Headers (JSON, optional)
                </label>
                <textarea
                  className="input-textarea min-h-[96px] w-full font-mono text-xs leading-relaxed"
                  placeholder='{"Authorization":"Bearer <token>"}'
                  value={dastAuthHeaders}
                  onChange={(e) => setDastAuthHeaders(e.target.value)}
                />
                <p className="mt-2 text-xs text-white/40">
                  Stored for this scan only. Valid JSON object required.
                </p>
              </div>
              <div>
                <label className="block text-xs font-semibold uppercase tracking-widest text-violet-300/80 mb-2">
                  Cookies (optional)
                </label>
                <input
                  className="input w-full font-mono text-xs"
                  placeholder="session=abc123; token=xyz"
                  value={dastCookies}
                  onChange={(e) => setDastCookies(e.target.value)}
                />
                <p className="mt-2 text-xs text-white/40">
                  Added as a Cookie header for DAST requests.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Repository Selection (shown when SAST is involved) */}
        {scanType !== "dast" && (
          <div>
            <div className="flex items-center gap-2 mb-3">
              <label className="text-xs font-semibold uppercase tracking-widest text-white/50">
                Repository Source
              </label>
              <div className="segmented-control">
                <button
                  type="button"
                  className="segmented-control-item"
                  data-active={mode === "quick"}
                  onClick={() => setMode("quick")}
                >
                  URL
                </button>
                <button
                  type="button"
                  className="segmented-control-item"
                  data-active={mode === "saved"}
                  onClick={() => setMode("saved")}
                >
                  Saved
                </button>
              </div>
            </div>

            {mode === "quick" ? (
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="block text-xs font-medium text-white/50 mb-2">Repository URL</label>
                  <div className="input-group">
                    <svg className="input-icon h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244" />
                    </svg>
                    <input
                      className={`input input-with-icon w-full ${
                        showRepoError ? "border-rose-400 focus:border-rose-400" : ""
                      }`}
                      placeholder="https://github.com/org/repo"
                      value={repoUrl}
                      onChange={(e) => setRepoUrl(e.target.value)}
                      onBlur={() => markTouched("repo")}
                      aria-invalid={showRepoError}
                    />
                  </div>
                  {showRepoError ? (
                    <p className="mt-2 text-xs text-rose-200">
                      Repository URL is required for SAST scans.
                    </p>
                  ) : null}
                </div>
                <div>
                  <label className="block text-xs font-medium text-white/50 mb-2">Branch</label>
                  <div className="input-group">
                    <svg className="input-icon h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
                    </svg>
                    <input
                      className="input input-with-icon w-full"
                      placeholder="main"
                      value={branch}
                      onChange={(e) => setBranch(e.target.value)}
                    />
                  </div>
                </div>
              </div>
            ) : (
              <div>
                <label className="block text-xs font-medium text-white/50 mb-2">Select Repository</label>
                <select
                  className="select w-full"
                  value={selectedRepoId}
                  onChange={(e) => {
                    setSelectedRepoId(e.target.value);
                    if (e.target.value) {
                      setTouched((prev) => ({ ...prev, selectedRepo: true }));
                    }
                  }}
                  onBlur={() => markTouched("selectedRepo")}
                  aria-invalid={showSelectedRepoError}
                >
                  <option value="">Choose a saved repository...</option>
                  {repos.map((repo) => (
                    <option key={repo.id} value={repo.id}>
                      {repo.repo_full_name || formatRepoName(repo.repo_url)}
                    </option>
                  ))}
                </select>
                {showSelectedRepoError ? (
                  <p className="mt-2 text-xs text-rose-200">
                    Select a repository to run SAST scans.
                  </p>
                ) : null}
                <div className="mt-2 flex items-center justify-between text-xs text-white/40">
                  <span>Manage your saved repositories</span>
                  <Link to="/repos" className="text-neon-mint hover:text-neon-mint/80 transition-colors">
                    Edit list ->
                  </Link>
                </div>
              </div>
            )}
          </div>
        )}

        {scanType !== "dast" && (
          <div className="rounded-card border border-sky-400/20 bg-sky-400/5 p-4">
            <label className="block text-xs font-semibold uppercase tracking-widest text-sky-300 mb-2">
              Dependency Health
            </label>
            <label className="flex items-start gap-3 cursor-pointer group">
              <input
                type="checkbox"
                className="checkbox mt-0.5"
                checked={dependencyHealthEnabled}
                onChange={(e) => setDependencyHealthEnabled(e.target.checked)}
              />
              <span className="text-sm text-white/70 group-hover:text-white/90 transition-colors">
                Detect deprecated or outdated npm and Python dependencies
              </span>
            </label>
          </div>
        )}

        {/* Error Message */}
        {errorMessage && (
          <div className="flex items-center gap-2 rounded-card border border-rose-400/30 bg-rose-400/10 px-4 py-3 text-sm text-rose-200">
            <svg className="h-5 w-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
            </svg>
            {errorMessage}
          </div>
        )}

        {/* Submit Button */}
        <button
          type="button"
          className="btn-primary w-full py-3 text-base"
          onClick={mode === "saved" ? onSubmitSaved : onSubmit}
          disabled={!canSubmit}
        >
          {isLoading ? (
            <span className="flex items-center gap-2">
              <svg className="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
              Starting Scan...
            </span>
          ) : (
            <span className="flex items-center gap-2">
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
              </svg>
              Start {SCAN_TYPE_INFO[scanType].label} Scan
            </span>
          )}
        </button>
      </div>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export default function Scans() {
  const queryClient = useQueryClient();

  // Form State
  const [scanType, setScanType] = useState<ScanType>("sast");
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("main");
  const [dependencyHealthEnabled, setDependencyHealthEnabled] = useState(true);
  const [selectedRepoId, setSelectedRepoId] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [dastConsent, setDastConsent] = useState(false);
  const [dastAuthHeaders, setDastAuthHeaders] = useState("");
  const [dastCookies, setDastCookies] = useState("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // UI State
  const [showNewScan, setShowNewScan] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<Scan["status"] | "all">("all");
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const newScanRef = useRef<HTMLDivElement | null>(null);

  // Data Fetching
  const { data, isLoading, error } = useQuery({
    queryKey: ["scans"],
    queryFn: () => scansApi.list(),
    refetchInterval: (query) => {
      const scans = Array.isArray(query.state.data) ? query.state.data : [];
      return scans.some((scan) =>
        ["pending", "cloning", "scanning", "analyzing"].includes(scan.status)
      )
        ? 5000
        : false;
    },
  });
  const isAuthError = error instanceof ApiError && error.status === 401;

  const { data: repos } = useQuery({
    queryKey: ["repos"],
    queryFn: () => repositoriesApi.list(),
  });

  // Mutations
  const createScan = useMutation({
    mutationFn: async () => {
      const trimmedRepo = repoUrl.trim();
      const trimmedBranch = branch.trim() || "main";
      const trimmedTarget = targetUrl.trim();
      const trimmedCookies = dastCookies.trim();
      const authHeaders =
        scanType !== "sast" ? parseAuthHeaders(dastAuthHeaders) : undefined;
      const cookies =
        scanType !== "sast" && trimmedCookies ? trimmedCookies : undefined;

      if (scanType !== "dast" && !trimmedRepo) {
        throw new Error("Repository URL is required.");
      }
      if (scanType !== "sast" && !trimmedTarget) {
        throw new Error("Target URL is required for DAST.");
      }
      if (scanType !== "sast" && !dastConsent) {
        throw new Error("Please confirm authorization for DAST scans.");
      }

      return scansApi.create({
        repo_url: scanType !== "dast" ? trimmedRepo : undefined,
        branch: scanType !== "dast" ? trimmedBranch : undefined,
        scan_type: scanType,
        dependency_health_enabled: scanType !== "dast" ? dependencyHealthEnabled : undefined,
        target_url: scanType !== "sast" ? trimmedTarget : undefined,
        dast_consent: scanType !== "sast" ? dastConsent : undefined,
        dast_auth_headers: authHeaders,
        dast_cookies: cookies,
      });
    },
    onSuccess: async () => {
      setErrorMessage(null);
      setRepoUrl("");
      setDastAuthHeaders("");
      setDastCookies("");
      setShowNewScan(false);
      await queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (error) => {
      setErrorMessage(error instanceof Error ? error.message : "Failed to trigger scan.");
    },
  });

  const createSavedScan = useMutation({
    mutationFn: async () => {
      if (!selectedRepoId) throw new Error("Select a saved repository.");
      const trimmedTarget = targetUrl.trim();
      const trimmedCookies = dastCookies.trim();
      const authHeaders =
        scanType !== "sast" ? parseAuthHeaders(dastAuthHeaders) : undefined;
      const cookies =
        scanType !== "sast" && trimmedCookies ? trimmedCookies : undefined;
      if (scanType !== "sast" && !trimmedTarget) {
        throw new Error("Target URL is required for DAST.");
      }
      if (scanType !== "sast" && !dastConsent) {
        throw new Error("Please confirm authorization for DAST scans.");
      }
      return scansApi.create({
        repo_id: selectedRepoId,
        scan_type: scanType,
        dependency_health_enabled: scanType !== "dast" ? dependencyHealthEnabled : undefined,
        target_url: scanType !== "sast" ? trimmedTarget : undefined,
        dast_consent: scanType !== "sast" ? dastConsent : undefined,
        dast_auth_headers: authHeaders,
        dast_cookies: cookies,
      });
    },
    onSuccess: async () => {
      setErrorMessage(null);
      setDastAuthHeaders("");
      setDastCookies("");
      setShowNewScan(false);
      await queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (error) => {
      setErrorMessage(error instanceof Error ? error.message : "Failed to trigger scan.");
    },
  });

  const injectDemo = useMutation({
    mutationFn: () => demoApi.injectScan(),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  const deleteScan = useMutation({
    mutationFn: async (scanId: string) => {
      await scansApi.delete(scanId);
    },
    onMutate: (scanId) => {
      setDeleteError(null);
      setDeletingId(scanId);
    },
    onError: (err) => {
      setDeleteError(
        err instanceof Error ? err.message : "Failed to delete scan.",
      );
    },
    onSettled: async () => {
      setDeletingId(null);
      await queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  // Computed Values
  const scans = useMemo(() => {
    let items = Array.isArray(data) ? data : [];

    // Filter by search
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      items = items.filter((scan) =>
        formatRepoName(scan.repo_url).toLowerCase().includes(query) ||
        scan.target_url?.toLowerCase().includes(query) ||
        scan.branch?.toLowerCase().includes(query)
      );
    }

    // Filter by status
    if (statusFilter !== "all") {
      items = items.filter((scan) => scan.status === statusFilter);
    }

    // Sort by created_at descending (newest first)
    items = [...items].sort((a, b) =>
      new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    );

    return items;
  }, [data, searchQuery, statusFilter]);

  const repoList = Array.isArray(repos) ? repos : [];

  const stats = useMemo(() => {
    const allScans = Array.isArray(data) ? data : [];
    const completed = allScans.filter((s) => s.status === "completed");
    const active = allScans.filter((s) => STATUS_CONFIG[s.status].isActive);
    const totalFiltered = completed.reduce((sum, s) => sum + (s.total_findings - s.filtered_findings), 0);
    const avgReduction = completed.length > 0
      ? Math.round(
          completed.reduce((sum, s) => {
            const { percentage } = calculateNoiseReduction(s);
            return sum + percentage;
          }, 0) / completed.length
        )
      : 0;

    return {
      total: allScans.length,
      active: active.length,
      completed: completed.length,
      totalFiltered,
      avgReduction,
    };
  }, [data]);

  const focusNewScanForm = () => {
    requestAnimationFrame(() => {
      newScanRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      const firstField = newScanRef.current?.querySelector(
        "input, select, textarea, button",
      ) as HTMLElement | null;
      firstField?.focus();
    });
  };

  const handleToggleNewScan = () => {
    const next = !showNewScan;
    setShowNewScan(next);
    if (next) {
      focusNewScanForm();
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="surface-solid p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-white">
              Security Scans
            </h1>
            <p className="mt-1 text-sm text-white/50">
              AI-powered vulnerability detection with intelligent noise reduction
            </p>
          </div>
          <button
            type="button"
            className={showNewScan ? "btn-ghost" : "btn-primary"}
            onClick={handleToggleNewScan}
          >
            {showNewScan ? (
              <>
                <svg className="mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
                Cancel
              </>
            ) : (
              <>
                <svg className="mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
                </svg>
                New Scan
              </>
            )}
          </button>
        </div>

        {/* Stats */}
        <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-5">
          <StatCard value={stats.total} label="Total Scans" />
          <StatCard value={stats.active} label="In Progress" />
          <StatCard value={stats.completed} label="Completed" />
          <StatCard value={stats.totalFiltered} label="FPs Filtered" />
          <StatCard value={`${stats.avgReduction}%`} label="Avg Reduction" />
        </div>
      </div>

      {/* New Scan Form */}
      {showNewScan && (
        <div ref={newScanRef}>
          <NewScanForm
            scanType={scanType}
            setScanType={setScanType}
            repoUrl={repoUrl}
            setRepoUrl={setRepoUrl}
            branch={branch}
            setBranch={setBranch}
            dependencyHealthEnabled={dependencyHealthEnabled}
            setDependencyHealthEnabled={setDependencyHealthEnabled}
            targetUrl={targetUrl}
            setTargetUrl={setTargetUrl}
            dastConsent={dastConsent}
            setDastConsent={setDastConsent}
            dastAuthHeaders={dastAuthHeaders}
            setDastAuthHeaders={setDastAuthHeaders}
            dastCookies={dastCookies}
            setDastCookies={setDastCookies}
            selectedRepoId={selectedRepoId}
            setSelectedRepoId={setSelectedRepoId}
            repos={repoList}
            onSubmit={() => createScan.mutate()}
            onSubmitSaved={() => createSavedScan.mutate()}
            isLoading={createScan.isPending || createSavedScan.isPending}
            errorMessage={errorMessage}
          />
        </div>
      )}

      {/* Demo Dataset */}
      {scans.length === 0 && !isLoading && (
        <div className="surface-solid p-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <div className="text-sm font-medium text-white">Try with demo data</div>
              <div className="text-xs text-white/50">
                Seed a pre-scanned repo with 12 real issues and 75 false positives
              </div>
            </div>
            <button
              type="button"
              className="btn-ghost"
              onClick={() => injectDemo.mutate()}
              disabled={injectDemo.isPending}
            >
              {injectDemo.isPending ? "Seeding..." : "Load Demo"}
            </button>
          </div>
        </div>
      )}

      {/* Error State */}
      {error && (
        <div className="surface-solid flex items-center gap-3 p-4 text-rose-200">
          <svg className="h-5 w-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
          </svg>
          <div className="text-sm">
            <div>
              {error instanceof Error ? error.message : "Unable to load scans."}
            </div>
            {isAuthError ? (
              <div className="mt-1 text-xs text-rose-100/80">
                Sign in to load scan history.
              </div>
            ) : null}
          </div>
        </div>
      )}

      {deleteError && (
        <div className="surface-solid flex items-center gap-3 p-4 text-rose-200">
          <svg className="h-5 w-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
          </svg>
          <span className="text-sm">{deleteError}</span>
        </div>
      )}

      {/* Filters & Search */}
      {scans.length > 0 && (
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap items-center gap-2">
            <input
              type="text"
              className="search-input w-full sm:w-64"
              placeholder="Search scans..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            <select
              className="select"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as Scan["status"] | "all")}
            >
              <option value="all">All Status</option>
              <option value="completed">Completed</option>
              <option value="scanning">In Progress</option>
              <option value="failed">Failed</option>
            </select>
          </div>
          <div className="text-xs text-white/40">
            Showing {scans.length} scan{scans.length !== 1 ? "s" : ""}
          </div>
        </div>
      )}

      {/* Loading State */}
      {isLoading && (
        <div className="space-y-4">
          {Array.from({ length: 3 }).map((_, index) => (
            <div key={`skeleton-${index}`} className="scan-card animate-pulse">
              <div className="scan-card-header">
                <div className="flex items-center gap-3">
                  <div className="h-4 w-20 rounded-pill bg-white/10" />
                  <div className="h-4 w-12 rounded-pill bg-white/10" />
                </div>
                <div className="h-3 w-16 rounded-pill bg-white/5" />
              </div>
              <div className="scan-card-body">
                <div className="h-6 w-48 rounded-pill bg-white/10" />
                <div className="mt-3 h-4 w-32 rounded-pill bg-white/5" />
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Scan List */}
      {!isLoading && scans.length > 0 && (
        <div className="space-y-4">
          {scans.map((scan) => (
            <ScanCard
              key={scan.id}
              scan={scan}
              onDelete={(scanId) => deleteScan.mutate(scanId)}
              isDeleting={deleteScan.isPending && deletingId === scan.id}
            />
          ))}
        </div>
      )}

      {/* Empty State */}
      {!isLoading && !error && scans.length === 0 && !showNewScan && (
        <EmptyState
          onCreateScan={() => {
            setShowNewScan(true);
            focusNewScanForm();
          }}
        />
      )}
    </div>
  );
}
