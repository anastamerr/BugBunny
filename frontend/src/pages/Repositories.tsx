import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { repositoriesApi } from "../api/repositories";
import { scansApi } from "../api/scans";
import type { Repository } from "../types";

function formatRepoName(url: string, fallback?: string | null) {
  if (fallback) return fallback;
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

function isValidRepoInput(value: string) {
  if (!value) return false;
  if (value.includes("://")) {
    try {
      const parsed = new URL(value);
      return ["http:", "https:"].includes(parsed.protocol);
    } catch {
      return false;
    }
  }
  return /^[^/\s]+\/[^/\s]+$/.test(value);
}

export default function Repositories() {
  const queryClient = useQueryClient();
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("main");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  const { data, isLoading, error } = useQuery({
    queryKey: ["repos"],
    queryFn: () => repositoriesApi.list(),
  });

  const createRepo = useMutation({
    mutationFn: async () => {
      const trimmedRepo = repoUrl.trim();
      if (!trimmedRepo) {
        throw new Error("Repository URL is required.");
      }
      if (!isValidRepoInput(trimmedRepo)) {
        throw new Error("Enter a valid GitHub URL or owner/repo.");
      }
      return repositoriesApi.create({
        repo_url: trimmedRepo,
        default_branch: branch.trim() || "main",
      });
    },
    onSuccess: async () => {
      setRepoUrl("");
      setBranch("main");
      setErrorMessage(null);
      await queryClient.invalidateQueries({ queryKey: ["repos"] });
    },
    onError: (error) => {
      if (error instanceof Error) {
        setErrorMessage(error.message);
      } else {
        setErrorMessage("Failed to add repository.");
      }
    },
  });

  const removeRepo = useMutation({
    mutationFn: (repoId: string) => repositoriesApi.remove(repoId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["repos"] });
    },
  });

  const triggerScan = useMutation({
    mutationFn: (repo: Repository) =>
      scansApi.create({ repo_id: repo.id, branch: repo.default_branch }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  const repoValid = isValidRepoInput(repoUrl.trim());

  const repos = data || [];
  const filteredRepos = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return repos;
    return repos.filter((repo) => {
      const name = formatRepoName(repo.repo_url, repo.repo_full_name);
      const haystack = `${name} ${repo.repo_url} ${repo.default_branch}`.toLowerCase();
      return haystack.includes(normalized);
    });
  }, [repos, query]);

  return (
    <div className="space-y-6">
      <div className="surface-solid p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-white">
              Repositories
            </h1>
            <p className="mt-1 text-sm text-white/60">
              Save repositories to build a personalized scan watchlist.
            </p>
          </div>
        </div>

        <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-[1.5fr_0.8fr_auto] lg:items-end">
          <div>
            <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
              Repository URL
            </div>
            <input
              className="input mt-2 w-full"
              placeholder="https://github.com/org/repo"
              value={repoUrl}
              onChange={(event) => {
                setRepoUrl(event.target.value);
                setErrorMessage(null);
              }}
            />
          </div>
          <div>
            <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
              Default Branch
            </div>
            <input
              className="input mt-2 w-full"
              placeholder="main"
              value={branch}
              onChange={(event) => {
                setBranch(event.target.value);
                setErrorMessage(null);
              }}
            />
          </div>
          <button
            type="button"
            className="btn-primary h-11"
            onClick={() => createRepo.mutate()}
            disabled={createRepo.isPending || !repoValid}
          >
            {createRepo.isPending ? "Saving..." : "Add Repository"}
          </button>
        </div>
        <div className="mt-3 text-sm text-white/50">
          Add a full GitHub URL or an owner/repo slug.
        </div>
        {errorMessage ? (
          <div className="mt-2 text-sm text-rose-200">{errorMessage}</div>
        ) : null}
      </div>

      <div className="surface-solid p-5">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="text-sm font-semibold tracking-tight text-white">
            Saved repositories
          </div>
          <div className="flex flex-1 flex-col gap-3 md:flex-row md:items-center md:justify-end">
            <input
              className="search-input w-full md:max-w-sm"
              placeholder="Search repositories..."
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
            <div className="text-xs text-white/60">
              {filteredRepos.length} of {repos.length} shown
            </div>
          </div>
        </div>
      </div>

      {error ? (
        <div className="surface-solid p-4 text-sm text-rose-200">
          {error instanceof Error ? error.message : "Unable to load repositories."}
        </div>
      ) : null}

      <div className="space-y-4">
        {isLoading ? (
          <div className="surface-solid animate-pulse p-6">
            <div className="h-4 w-52 rounded-pill bg-white/10" />
            <div className="mt-3 h-3 w-72 rounded-pill bg-white/5" />
          </div>
        ) : null}

        {filteredRepos.map((repo) => (
          <div key={repo.id} className="surface-solid p-5">
            <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <div className="min-w-0">
                <div className="text-lg font-semibold text-white">
                  {formatRepoName(repo.repo_url, repo.repo_full_name)}
                </div>
                <div className="mt-1 break-all text-xs text-white/60">
                  {repo.repo_url}
                </div>
                <div className="mt-2 text-xs text-white/50">
                  Default branch: {repo.default_branch}
                </div>
                <div className="mt-1 text-[11px] text-white/40">
                  Updated {new Date(repo.updated_at).toLocaleString()}
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  className="btn-ghost"
                  onClick={() => triggerScan.mutate(repo)}
                  disabled={triggerScan.isPending}
                >
                  Scan now
                </button>
                <button
                  type="button"
                  className="btn-ghost text-rose-200 hover:text-rose-100"
                  onClick={() => removeRepo.mutate(repo.id)}
                  disabled={removeRepo.isPending}
                >
                  Remove
                </button>
              </div>
            </div>
          </div>
        ))}

        {repos.length === 0 && !isLoading && !error ? (
          <div className="surface-solid p-6 text-sm text-white/60">
            No repositories saved yet. Add one above to start tracking scans.
          </div>
        ) : null}
        {repos.length > 0 && filteredRepos.length === 0 && !isLoading && !error ? (
          <div className="surface-solid p-6 text-sm text-white/60">
            No repositories match this search.
          </div>
        ) : null}
      </div>
    </div>
  );
}
