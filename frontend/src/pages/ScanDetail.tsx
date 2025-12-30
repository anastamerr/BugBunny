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
  const [autoFixing, setAutoFixing] = useState<{
    id: string;
    action: "preview" | "pr";
  } | null>(null);
  const [autoFixErrors, setAutoFixErrors] = useState<
    Record<string, string | null>
  >({});
  const [isDownloadingReport, setIsDownloadingReport] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);

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

  const autofixFinding = useMutation({
    mutationFn: async (payload: {
      id: string;
      createPr: boolean;
      regenerate?: boolean;
    }) =>
      scansApi.autofixFinding(payload.id, {
        create_pr: payload.createPr,
        regenerate: payload.regenerate,
      }),
    onMutate: ({ id: findingId, createPr }) => {
      setAutoFixing({ id: findingId, action: createPr ? "pr" : "preview" });
      setAutoFixErrors((prev) => ({ ...prev, [findingId]: null }));
    },
    onSuccess: (data) => {
      if (data.error) {
        setAutoFixErrors((prev) => ({ ...prev, [data.finding.id]: data.error }));
      }
    },
    onError: (err, payload) => {
      setAutoFixErrors((prev) => ({
        ...prev,
        [payload.id]:
          err instanceof Error ? err.message : "Failed to generate auto-fix.",
      }));
    },
    onSettled: async () => {
      setAutoFixing(null);
      await queryClient.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  const handleDownloadReport = async () => {
    if (!scan) return;
    setIsDownloadingReport(true);
    setReportError(null);
    try {
      const blob = await scansApi.downloadReport(scan.id);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `scan-report-${scan.id}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setReportError(
        err instanceof Error ? err.message : "Failed to generate PDF report."
      );
    } finally {
      setIsDownloadingReport(false);
    }
  };

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
              {scan.scan_type !== "dast" &&
              scan.dependency_health_enabled === false ? (
                <span className="badge">dependency health off</span>
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
            <button
              type="button"
              className="inline-flex items-center gap-2 rounded-pill border border-neon-mint/30 bg-neon-mint/10 px-4 py-2 text-sm font-semibold text-neon-mint transition-all duration-200 hover:border-neon-mint/50 hover:bg-neon-mint/20 disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:border-neon-mint/30 disabled:hover:bg-neon-mint/10"
              onClick={handleDownloadReport}
              disabled={scan.status !== "completed" || isDownloadingReport}
              title={scan.status !== "completed" ? "Report available after scan completes" : "Download PDF report"}
            >
              {isDownloadingReport ? (
                <svg
                  className="h-4 w-4 animate-spin"
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                >
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                  />
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  />
                </svg>
              ) : (
                <svg
                  className="h-4 w-4"
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                  strokeWidth={2}
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m.75 12l3 3m0 0l3-3m-3 3v-6m-1.5-9H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"
                  />
                </svg>
              )}
              {isDownloadingReport ? "Generating..." : "PDF Report"}
            </button>
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

      {reportError ? (
        <div className="surface-solid p-4 text-sm text-rose-200">
          {reportError}
        </div>
      ) : null}

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
            isAutoFixing={
              autofixFinding.isPending && autoFixing?.id === finding.id
            }
            autoFixAction={
              autoFixing?.id === finding.id ? autoFixing.action : null
            }
            autoFixError={autoFixErrors[finding.id] ?? null}
            onUpdateStatus={(findingId, status) =>
              updateFinding.mutate({ id: findingId, status })
            }
            onAutoFix={(findingId, options) =>
              autofixFinding.mutate({
                id: findingId,
                createPr: options.createPr,
                regenerate: options.regenerate,
              })
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
