import type { Scan } from "../types";

// ── Finding severity badges ───────────────────────────────────────────

export const severityStyles: Record<string, string> = {
  critical: "badge border-rose-500/60 bg-rose-500/15 text-rose-200",
  high: "badge border-orange-400/50 bg-orange-400/15 text-orange-100",
  medium: "badge border-amber-300/50 bg-amber-300/15 text-amber-100",
  low: "badge border-emerald-300/50 bg-emerald-300/12 text-emerald-100",
  info: "badge border-sky-400/50 bg-sky-400/12 text-sky-100",
};

export function getSeverityClass(severity?: string | null): string {
  const key = (severity || "").toLowerCase();
  return severityStyles[key] || "badge";
}

// ── Scan status config ────────────────────────────────────────────────

export const STATUS_CONFIG: Record<
  Scan["status"],
  { color: string; bgColor: string; label: string; isActive: boolean }
> = {
  completed: { color: "text-neon-mint", bgColor: "bg-neon-mint", label: "Completed", isActive: false },
  failed: { color: "text-rose-400", bgColor: "bg-rose-400", label: "Failed", isActive: false },
  analyzing: { color: "text-amber-400", bgColor: "bg-amber-400", label: "Analyzing", isActive: true },
  scanning: { color: "text-sky-400", bgColor: "bg-sky-400", label: "Scanning", isActive: true },
  cloning: { color: "text-violet-400", bgColor: "bg-violet-400", label: "Cloning", isActive: true },
  pending: { color: "text-white/50", bgColor: "bg-white/50", label: "Pending", isActive: true },
};

export const PAUSED_CONFIG = {
  color: "text-amber-300",
  bgColor: "bg-amber-300",
  label: "Paused",
  isActive: false,
};

/**
 * Get the badge class for a scan status.
 */
export function scanStatusClass(status: Scan["status"]): string {
  switch (status) {
    case "completed":
      return "badge border-neon-mint/40 bg-neon-mint/10 text-neon-mint";
    case "failed":
      return "badge border-rose-400/40 bg-rose-400/10 text-rose-200";
    case "analyzing":
      return "badge border-amber-400/40 bg-amber-400/10 text-amber-200";
    case "scanning":
    case "cloning":
      return "badge border-sky-400/40 bg-sky-400/10 text-sky-200";
    case "pending":
    default:
      return "badge";
  }
}

// ── DAST verification badges ──────────────────────────────────────────

export const DAST_VERIFICATION_LABELS: Record<string, string> = {
  verified: "DAST verified",
  unverified_url: "DAST unverified URL",
  commit_mismatch: "DAST commit mismatch",
  verification_error: "DAST verification error",
  not_applicable: "DAST not applicable",
};

export const DAST_VERIFICATION_STYLES: Record<string, string> = {
  verified: "badge border-neon-mint/40 bg-neon-mint/10 text-neon-mint",
  unverified_url: "badge border-amber-400/40 bg-amber-400/10 text-amber-200",
  commit_mismatch: "badge border-rose-400/40 bg-rose-400/10 text-rose-200",
  verification_error: "badge border-rose-400/40 bg-rose-400/10 text-rose-200",
};

export function getDastVerificationBadge(value?: string | null) {
  if (!value || value === "not_applicable") return null;
  return {
    label:
      DAST_VERIFICATION_LABELS[value] ||
      `DAST ${value.replace(/[_.]/g, " ")}`,
    className: DAST_VERIFICATION_STYLES[value] || "badge",
  };
}

// ── Phase labels ──────────────────────────────────────────────────────

export const PHASE_LABELS: Record<string, string> = {
  "sast.clone": "SAST - Cloning",
  "sast.scan": "SAST - Semgrep",
  "sast.analyze": "SAST - AI triage",
  "dast.deploy": "DAST - Deploy",
  "dast.verify": "DAST - Verification",
  "dast.spider": "DAST - Spider",
  "dast.active_scan": "DAST - Active scan",
  "dast.alerts": "DAST - Alerts",
  "dast.targeted": "DAST - Targeted checks",
  correlation: "Correlation",
  completed: "Completed",
  failed: "Failed",
};

export function formatPhase(value?: string | null): string | null {
  if (!value) return null;
  return PHASE_LABELS[value] || value.replace(/[_.]/g, " ");
}
