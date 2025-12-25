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

export default function ScanDetail() {
  const { id } = useParams();
  const queryClient = useQueryClient();
  const [includeFalsePositives, setIncludeFalsePositives] = useState(false);
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  const {
    data: scan,
    isLoading,
    error,
  } = useQuery({
    queryKey: ["scans", id],
    queryFn: () => scansApi.getById(id as string),
    enabled: Boolean(id),
  });

  const {
    data: findings,
    isLoading: findingsLoading,
  } = useQuery({
    queryKey: ["findings", id, includeFalsePositives],
    queryFn: () =>
      scansApi.getFindings(id as string, {
        include_false_positives: includeFalsePositives,
      }),
    enabled: Boolean(id),
  });

  const updateFinding = useMutation({
    mutationFn: async (payload: {
      id: string;
      status: "confirmed" | "dismissed";
    }) => scansApi.updateFinding(payload.id, { status: payload.status }),
    onMutate: ({ id: findingId }) => {
      setUpdatingId(findingId);
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
        <div className="surface-solid p-6">
          <h1 className="text-2xl font-extrabold tracking-tight text-white">
            Scan
          </h1>
          <p className="mt-1 text-sm text-white/60">Loading...</p>
        </div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="space-y-6">
        <div className="surface-solid p-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h1 className="text-2xl font-extrabold tracking-tight text-white">
                Scan
              </h1>
              <p className="mt-1 text-sm text-white/60">Scan not found.</p>
            </div>
            <Link to="/scans" className="btn-ghost">
              Back to Scans
            </Link>
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
              <span className="badge">branch {scan.branch}</span>
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
              {scan.repo_url}
            </h1>
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
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
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
      </div>

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

      {findingsLoading ? (
        <div className="text-sm text-white/60">Loading findings...</div>
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

        {!findingsLoading && (findings || []).length === 0 ? (
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
