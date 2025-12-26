import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { repositoriesApi } from "../api/repositories";
import { scansApi } from "../api/scans";
import type { Scan } from "../types";

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

function formatRepoName(url: string) {
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

function formatDate(value?: string) {
  if (!value) return "n/a";
  const dt = new Date(value);
  return Number.isNaN(dt.getTime()) ? "n/a" : dt.toLocaleString();
}

function shortSha(sha?: string | null) {
  if (!sha) return null;
  const trimmed = sha.trim();
  return trimmed.length ? trimmed.slice(0, 7) : null;
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

export default function Scans() {
  const queryClient = useQueryClient();
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("main");
  const [selectedRepoId, setSelectedRepoId] = useState("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ["scans"],
    queryFn: () => scansApi.list(),
  });
  const { data: repos } = useQuery({
    queryKey: ["repos"],
    queryFn: () => repositoriesApi.list(),
  });

  const createScan = useMutation({
    mutationFn: async () => {
      const trimmedRepo = repoUrl.trim();
      const trimmedBranch = branch.trim() || "main";
      if (!trimmedRepo) {
        throw new Error("Repository URL is required.");
      }
      return scansApi.create({ repo_url: trimmedRepo, branch: trimmedBranch });
    },
    onSuccess: async () => {
      setErrorMessage(null);
      setRepoUrl("");
      await queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (error) => {
      if (error instanceof Error) {
        setErrorMessage(error.message);
      } else {
        setErrorMessage("Failed to trigger scan.");
      }
    },
  });

  const createSavedScan = useMutation({
    mutationFn: async () => {
      if (!selectedRepoId) {
        throw new Error("Select a saved repository.");
      }
      return scansApi.create({ repo_id: selectedRepoId });
    },
    onSuccess: async () => {
      setErrorMessage(null);
      await queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
    onError: (error) => {
      if (error instanceof Error) {
        setErrorMessage(error.message);
      } else {
        setErrorMessage("Failed to trigger scan.");
      }
    },
  });

  const scans = data || [];

  const summary = useMemo(() => {
    const completed = scans.filter((scan) => scan.status === "completed").length;
    const active = scans.filter((scan) =>
      ["pending", "cloning", "scanning", "analyzing"].includes(scan.status),
    ).length;
    return { total: scans.length, completed, active };
  }, [scans]);

  const listErrorMessage =
    error instanceof Error ? error.message : "Unable to load scans.";

  return (
    <div className="space-y-6">
      <div className="surface-solid p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-white">
              Scans
            </h1>
            <p className="mt-1 text-sm text-white/60">
              Run context-aware Semgrep scans and prioritize the real issues.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="badge">{summary.total} total</span>
            <span className="badge">{summary.active} active</span>
            <span className="badge">{summary.completed} completed</span>
          </div>
        </div>

        <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="rounded-card border border-white/10 bg-void p-4">
            <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
              Saved repositories
            </div>
            <select
              className="input mt-2 w-full"
              value={selectedRepoId}
              onChange={(event) => setSelectedRepoId(event.target.value)}
            >
              <option value="">Select repository</option>
              {(repos || []).map((repo) => (
                <option key={repo.id} value={repo.id}>
                  {repo.repo_full_name || formatRepoName(repo.repo_url)}
                </option>
              ))}
            </select>
            <div className="mt-3 flex items-center justify-between gap-2 text-xs text-white/50">
              <span>Manage list in Repositories.</span>
              <Link to="/repos" className="text-neon-mint hover:text-neon-mint/80">
                Edit list
              </Link>
            </div>
            <button
              type="button"
              className="btn-primary mt-4 w-full"
              onClick={() => createSavedScan.mutate()}
              disabled={createSavedScan.isPending || !selectedRepoId}
            >
              {createSavedScan.isPending ? "Starting..." : "Scan saved repo"}
            </button>
          </div>

          <div className="rounded-card border border-white/10 bg-void p-4">
            <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
              Quick scan
            </div>
            <div className="mt-3">
              <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                Repository URL
              </div>
              <input
                className="input mt-2 w-full"
                placeholder="https://github.com/org/repo"
                value={repoUrl}
                onChange={(event) => setRepoUrl(event.target.value)}
              />
            </div>
            <div className="mt-3">
              <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                Branch
              </div>
              <input
                className="input mt-2 w-full"
                placeholder="main"
                value={branch}
                onChange={(event) => setBranch(event.target.value)}
              />
            </div>
            <button
              type="button"
              className="btn-primary mt-4 w-full"
              onClick={() => createScan.mutate()}
              disabled={createScan.isPending || !repoUrl.trim()}
            >
              {createScan.isPending ? "Starting..." : "Scan repository"}
            </button>
          </div>
        </div>
        {errorMessage ? (
          <div className="mt-3 text-sm text-rose-200">{errorMessage}</div>
        ) : null}
      </div>

      {error ? (
        <div className="surface-solid p-4 text-sm text-rose-200">
          {listErrorMessage}
        </div>
      ) : null}

      {isLoading ? (
        <div className="space-y-4">
          {Array.from({ length: 3 }).map((_, index) => (
            <div
              key={`scan-skeleton-${index}`}
              className="surface-solid animate-pulse p-5"
            >
              <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                <div className="min-w-0 space-y-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="h-5 w-16 rounded-pill bg-white/10" />
                    <div className="h-5 w-12 rounded-pill bg-white/5" />
                    <div className="h-5 w-20 rounded-pill bg-white/10" />
                    <div className="h-5 w-28 rounded-pill bg-white/10" />
                  </div>
                  <div className="h-5 w-52 rounded-pill bg-white/10" />
                  <div className="h-3 w-72 rounded-pill bg-white/5" />
                </div>
                <div className="flex items-center gap-2">
                  <div className="h-3 w-20 rounded-pill bg-white/5" />
                  <div className="h-9 w-16 rounded-pill bg-white/10" />
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : null}

      <div className="space-y-4">
        {scans.map((scan) => (
          <div key={scan.id} className="surface-solid p-5">
            <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
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
                <div className="mt-3 text-lg font-semibold text-white">
                  {formatRepoName(scan.repo_url)}
                </div>
                <div className="mt-1 break-all text-xs text-white/60">
                  {scan.repo_url}
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <div className="text-xs text-white/60">
                  {formatDate(scan.created_at)}
                </div>
                <Link to={`/scans/${scan.id}`} className="btn-ghost">
                  View
                </Link>
              </div>
            </div>
            {scan.error_message ? (
              <div className="mt-3 text-xs text-rose-200">
                {scan.error_message}
              </div>
            ) : null}
          </div>
        ))}

        {scans.length === 0 && !isLoading && !error ? (
          <div className="surface-solid p-6 text-sm text-white/60">
            No scans yet. Trigger your first repository scan above.
          </div>
        ) : null}
      </div>
    </div>
  );
}
