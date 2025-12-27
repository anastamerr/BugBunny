import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { scansApi } from "../api/scans";
import { FindingCard } from "../components/FindingCard";
import type { Finding, Scan } from "../types";

function statusClass(status: Scan["status"]) {
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

function formatDate(value?: string) {
  if (!value) return "n/a";
  const dt = new Date(value);
  return Number.isNaN(dt.getTime()) ? "n/a" : dt.toLocaleString();
}

function formatReduction(scan: Scan) {
  if (!scan.total_findings) return "No findings yet";
  const ratio =
    scan.total_findings > 0
      ? 1 - scan.filtered_findings / scan.total_findings
      : 0;
  const pct = Math.round(Math.max(0, Math.min(1, ratio)) * 100);
  return `${scan.total_findings} -> ${scan.filtered_findings} (${pct}% filtered)`;
}

function shortSha(value?: string | null) {
  if (!value) return null;
  const trimmed = value.trim();
  return trimmed.length ? trimmed.slice(0, 7) : null;
}

function formatList(values?: string[] | null, emptyLabel = "none") {
  if (!values || values.length === 0) return emptyLabel;
  return values.join(", ");
}

export default function ScanDetail() {
  const { id } = useParams();
  const queryClient = useQueryClient();
  const [includeFalsePositives, setIncludeFalsePositives] = useState(false);
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const [updateError, setUpdateError] = useState<string | null>(null);

  const {
    data: scan,
    isLoading,
    error: scanError,
    refetch: refetchScan,
  } = useQuery({
    queryKey: ["scans", id],
    queryFn: () => scansApi.getById(id as string),
    enabled: Boolean(id),
    refetchInterval: (query) =>
      query.state.data &&
      ["pending", "cloning", "scanning", "analyzing"].includes(query.state.data.status)
        ? 8000
        : false,
  });

  const {
    data: findings,
    isLoading: findingsLoading,
    error: findingsError,
    refetch: refetchFindings,
  } = useQuery({
    queryKey: ["findings", id, includeFalsePositives],
    queryFn: () =>
      scansApi.getFindings(id as string, {
        include_false_positives: includeFalsePositives,
      }),
    enabled: Boolean(id),
    refetchInterval:
      scan && ["pending", "cloning", "scanning", "analyzing"].includes(scan.status)
        ? 8000
        : false,
  });

  const updateFinding = useMutation({
    mutationFn: async (payload: {
      id: string;
      status: "confirmed" | "dismissed";
    }) => scansApi.updateFinding(payload.id, { status: payload.status }),
    onMutate: ({ id: findingId }) => {
      setUpdatingId(findingId);
      setUpdateError(null);
    },
    onError: (err) => {
      setUpdateError(
        err instanceof Error ? err.message : "Failed to update finding status."
      );
    },
    onSettled: async () => {
      setUpdatingId(null);
      await queryClient.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  const stats = useMemo(() => {
    const total = scan?.total_findings ?? 0;
    const filtered = scan?.filtered_findings ?? 0;
    const ratio = total ? 1 - filtered / total : 0;
    const pct = Math.round(Math.max(0, Math.min(1, ratio)) * 100);
    return { total, filtered, pct };
  }, [scan]);

  const isDastEnabled = scan?.scan_type !== "sast";
  const headline = scan?.repo_url || scan?.target_url || "DAST scan";

  const telemetry = useMemo(() => {
    const detectedLanguages = formatList(
      scan?.detected_languages,
      "none detected"
    );
    const rulesets = formatList(scan?.rulesets, "auto");
    const scannedFiles =
      scan?.scanned_files === null || scan?.scanned_files === undefined
        ? "n/a"
        : String(scan.scanned_files);
    const semgrepVersion = scan?.semgrep_version || "n/a";
    const hasTelemetry =
      scan?.detected_languages != null ||
      scan?.rulesets != null ||
      scan?.scanned_files != null ||
      scan?.semgrep_version != null;
    return {
      detectedLanguages,
      rulesets,
      scannedFiles,
      semgrepVersion,
      hasTelemetry,
    };
  }, [scan]);

  const progressSteps: Scan["status"][] = [
    "pending",
    "cloning",
    "scanning",
    "analyzing",
    "completed",
  ];
  const progressIndex = scan ? progressSteps.indexOf(scan.status) : -1;
  const progressPercent =
    progressIndex >= 0
      ? Math.round((progressIndex / (progressSteps.length - 1)) * 100)
      : 0;
  const showProgress = scan
    ? ["pending", "cloning", "scanning", "analyzing"].includes(scan.status)
    : false;
  const progressWidth = showProgress ? Math.max(5, progressPercent) : 0;
  const scanErrorMessage =
    scanError instanceof Error ? scanError.message : "Unable to load scan.";
  const findingsErrorMessage =
    findingsError instanceof Error
      ? findingsError.message
      : "Unable to load findings.";

  if (!id) {
    return (
      <div className="space-y-6">
        <div className="surface-solid p-6">
          <h1 className="text-2xl font-extrabold tracking-tight text-white">
            Scan
          </h1>
          <p className="mt-1 text-sm text-white/60">Missing scan id.</p>
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="surface-solid animate-pulse p-6">
          <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
            <div className="min-w-0 space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <div className="h-5 w-16 rounded-pill bg-white/10" />
                <div className="h-5 w-12 rounded-pill bg-white/5" />
                <div className="h-5 w-20 rounded-pill bg-white/10" />
                <div className="h-5 w-28 rounded-pill bg-white/10" />
              </div>
              <div className="h-6 w-80 rounded-pill bg-white/10" />
              <div className="h-3 w-48 rounded-pill bg-white/5" />
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <div className="h-9 w-20 rounded-pill bg-white/10" />
              <div className="h-9 w-20 rounded-pill bg-white/10" />
              <div className="h-9 w-16 rounded-pill bg-white/5" />
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {Array.from({ length: 3 }).map((_, index) => (
            <div
              key={`scan-stat-skeleton-${index}`}
              className="surface-solid animate-pulse p-5"
            >
              <div className="h-3 w-28 rounded-pill bg-white/5" />
              <div className="mt-3 h-6 w-16 rounded-pill bg-white/10" />
            </div>
          ))}
        </div>

        <div className="surface-solid animate-pulse p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="space-y-2">
              <div className="h-4 w-24 rounded-pill bg-white/10" />
              <div className="h-3 w-44 rounded-pill bg-white/5" />
            </div>
            <div className="h-4 w-36 rounded-pill bg-white/10" />
          </div>
        </div>

        <div className="space-y-4">
          {Array.from({ length: 2 }).map((_, index) => (
            <div
              key={`finding-skeleton-${index}`}
              className="surface-solid animate-pulse p-5"
            >
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="h-5 w-20 rounded-pill bg-white/10" />
                  <div className="h-5 w-16 rounded-pill bg-white/10" />
                  <div className="h-5 w-16 rounded-pill bg-white/5" />
                </div>
                <div className="h-4 w-64 rounded-pill bg-white/10" />
                <div className="h-3 w-40 rounded-pill bg-white/5" />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (scanError || !scan) {
    return (
      <div className="space-y-6">
        <div className="surface-solid p-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h1 className="text-2xl font-extrabold tracking-tight text-white">
                Scan
              </h1>
              <p className="mt-1 text-sm text-white/60">
                {scanError ? scanErrorMessage : "Scan not found."}
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {scanError ? (
                <button
                  type="button"
                  className="btn-ghost"
                  onClick={() => refetchScan()}
                >
                  Retry
                </button>
              ) : null}
              <Link to="/scans" className="btn-ghost">
                Back to Scans
              </Link>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="surface-solid p-6">
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className={statusClass(scan.status)}>{scan.status}</span>
              <span className="badge">{scan.trigger}</span>
              {scan.scan_type !== "dast" ? (
                <span className="badge">SAST</span>
              ) : null}
              {scan.scan_type !== "sast" ? (
                <span className="badge">DAST</span>
              ) : null}
              {scan.scan_type !== "dast" ? (
                <span className="badge">branch {scan.branch}</span>
              ) : null}
              <span className="badge">{formatReduction(scan)}</span>
              {scan.pr_number ? (
                <span className="badge">PR #{scan.pr_number}</span>
              ) : null}
              {shortSha(scan.commit_sha) ? (
                <span className="badge font-mono text-white/70">
                  {shortSha(scan.commit_sha)}
                </span>
              ) : null}
            </div>
            <h1 className="mt-3 break-all text-2xl font-extrabold tracking-tight text-white">
              {headline}
            </h1>
            {scan.repo_url && scan.target_url ? (
              <div className="mt-2 space-y-1 text-xs text-white/60">
                {scan.repo_url ? (
                  <div>
                    Repo: <span className="text-white/80">{scan.repo_url}</span>
                  </div>
                ) : null}
                {scan.target_url ? (
                  <div>
                    Target:{" "}
                    <span className="text-white/80">{scan.target_url}</span>
                  </div>
                ) : null}
              </div>
            ) : null}
            <p className="mt-1 text-sm text-white/60">
              Started {formatDate(scan.created_at)}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Link to={`/chat?scan_id=${scan.id}`} className="btn-primary">
              Ask AI
            </Link>
            {scan.pr_url ? (
              <a
                href={scan.pr_url}
                target="_blank"
                rel="noreferrer"
                className="btn-ghost"
              >
                Open PR
              </a>
            ) : null}
            {scan.commit_url ? (
              <a
                href={scan.commit_url}
                target="_blank"
                rel="noreferrer"
                className="btn-ghost"
              >
                View Commit
              </a>
            ) : null}
            <Link to="/scans" className="btn-ghost">
              Back
            </Link>
          </div>
        </div>
        {scan.error_message ? (
          <div className="mt-4 text-sm text-rose-200">{scan.error_message}</div>
        ) : null}
        {showProgress ? (
          <div className="mt-4">
            <div className="flex items-center justify-between text-xs text-white/60">
              <span>Progress</span>
              <span className="capitalize">{scan.status}</span>
            </div>
            <div className="mt-2 h-2 w-full rounded-pill bg-white/10">
              <div
                className="h-2 rounded-pill bg-neon-mint"
                style={{ width: `${progressWidth}%` }}
              />
            </div>
          </div>
        ) : null}
      </div>

      <div
        className={`grid grid-cols-1 gap-4 ${
          isDastEnabled ? "md:grid-cols-4" : "md:grid-cols-3"
        }`}
      >
        <div className="surface-solid p-5">
          <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
            Total Findings
          </div>
          <div className="mt-2 text-2xl font-extrabold text-white">
            {stats.total}
          </div>
        </div>
        <div className="surface-solid p-5">
          <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
            Filtered Issues
          </div>
          <div className="mt-2 text-2xl font-extrabold text-white">
            {stats.filtered}
          </div>
        </div>
        <div className="surface-solid p-5">
          <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
            Noise Reduction
          </div>
          <div className="mt-2 text-2xl font-extrabold text-white">
            {stats.pct}%
          </div>
        </div>
        {isDastEnabled ? (
          <div className="surface-solid p-5">
            <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
              DAST Findings
            </div>
            <div className="mt-2 text-2xl font-extrabold text-white">
              {scan?.dast_findings ?? 0}
            </div>
          </div>
        ) : null}
      </div>

      {telemetry.hasTelemetry ? (
        <div className="surface-solid p-5">
          <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
            Scan Evidence
          </div>
          <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
            <div>
              <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                Files Scanned
              </div>
              <div className="mt-2 text-sm font-semibold text-white">
                {telemetry.scannedFiles}
              </div>
            </div>
            <div>
              <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                Languages
              </div>
              <div className="mt-2 text-sm text-white/80">
                {telemetry.detectedLanguages}
              </div>
            </div>
            <div>
              <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                Rulesets
              </div>
              <div className="mt-2 text-sm text-white/80">
                {telemetry.rulesets}
              </div>
            </div>
            <div>
              <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                Semgrep Version
              </div>
              <div className="mt-2 text-sm text-white/80">
                {telemetry.semgrepVersion}
              </div>
            </div>
          </div>
        </div>
      ) : null}

      <div className="surface-solid p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-white">Findings</h2>
            <p className="mt-1 text-sm text-white/60">
              AI-reviewed findings ordered by exploitability.
            </p>
          </div>
          <label className="flex items-center gap-2 text-sm text-white/70">
            <input
              type="checkbox"
              className="h-4 w-4 rounded border-white/20 bg-void text-neon-mint"
              checked={includeFalsePositives}
              onChange={(event) => setIncludeFalsePositives(event.target.checked)}
            />
            Include false positives
          </label>
        </div>
      </div>

      {updateError ? (
        <div className="surface-solid p-4 text-sm text-rose-200">
          {updateError}
        </div>
      ) : null}

      {findingsError ? (
        <div className="surface-solid p-4 text-sm text-rose-200">
          <div>{findingsErrorMessage}</div>
          <button
            type="button"
            className="btn-ghost mt-3"
            onClick={() => refetchFindings()}
          >
            Retry
          </button>
        </div>
      ) : null}

      {findingsLoading ? (
        <div className="space-y-4">
          {Array.from({ length: 2 }).map((_, index) => (
            <div
              key={`finding-loading-${index}`}
              className="surface-solid animate-pulse p-5"
            >
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="h-5 w-20 rounded-pill bg-white/10" />
                  <div className="h-5 w-16 rounded-pill bg-white/10" />
                  <div className="h-5 w-16 rounded-pill bg-white/5" />
                </div>
                <div className="h-4 w-64 rounded-pill bg-white/10" />
                <div className="h-3 w-40 rounded-pill bg-white/5" />
              </div>
            </div>
          ))}
        </div>
      ) : null}

      <div className="space-y-4">
        {(findings || []).map((finding: Finding) => (
          <FindingCard
            key={finding.id}
            finding={finding}
            isUpdating={updateFinding.isPending && updatingId === finding.id}
            onUpdateStatus={(findingId, status) =>
              updateFinding.mutate({ id: findingId, status })
            }
          />
        ))}

        {!findingsLoading && !findingsError && (findings || []).length === 0 ? (
          <div className="surface-solid p-6 text-sm text-white/60">
            {scan.status === "completed"
              ? "No findings for this scan."
              : "Scan is still running. Findings will appear here once analysis completes."}
          </div>
        ) : null}
      </div>
    </div>
  );
}
