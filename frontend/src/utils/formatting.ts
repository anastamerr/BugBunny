/**
 * Extract a display-friendly "owner/repo" from a full GitHub URL.
 * Falls back to the raw URL if parsing fails, or to `fallback` if provided.
 */
export function formatRepoName(
  url?: string | null,
  fallback?: string | null,
): string {
  if (fallback) return fallback;
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

/**
 * Smart relative-time formatter.
 * Returns "Just now", "3m ago", "2h ago", "5d ago", or a short date for older entries.
 */
export function formatRelativeDate(value?: string | null): string {
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

/**
 * Full locale date-time string, safe against bad input.
 */
export function formatDate(value?: string | null): string {
  if (!value) return "n/a";
  const dt = new Date(value);
  return Number.isNaN(dt.getTime()) ? "n/a" : dt.toLocaleString();
}

/**
 * Clock-only time string (HH:MM).
 */
export function formatClock(value?: Date | null): string {
  if (!value) return "n/a";
  return value.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/**
 * Truncate a SHA to 7 chars.
 */
export function shortSha(value?: string | null): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  return trimmed.length ? trimmed.slice(0, 7) : null;
}

/**
 * Join an array of strings for display, with a configurable empty label.
 */
export function formatList(
  values?: string[] | null,
  emptyLabel = "none",
): string {
  if (!values || values.length === 0) return emptyLabel;
  return values.filter(Boolean).join(", ");
}
