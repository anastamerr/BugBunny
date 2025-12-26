import { useRef } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { bugsApi } from "../api/bugs";
import type { BugReport } from "../types";

type GitHubComment = {
  id?: string | number;
  user?: string;
  created_at?: string;
  url?: string;
  body?: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function getGitHubUrl(bug: BugReport): string | null {
  if (!isRecord(bug.labels)) return null;
  const url = bug.labels["url"];
  return typeof url === "string" && url.length ? url : null;
}

function getGitHubComments(bug: BugReport): GitHubComment[] {
  if (!isRecord(bug.labels)) return [];
  const comments = bug.labels["comments"];
  if (!Array.isArray(comments)) return [];

  return comments
    .filter(isRecord)
    .map((comment) => ({
      id:
        typeof comment["id"] === "string" || typeof comment["id"] === "number"
          ? (comment["id"] as string | number)
          : undefined,
      user: typeof comment["user"] === "string" ? (comment["user"] as string) : undefined,
      created_at:
        typeof comment["created_at"] === "string"
          ? (comment["created_at"] as string)
          : undefined,
      url: typeof comment["url"] === "string" ? (comment["url"] as string) : undefined,
      body: typeof comment["body"] === "string" ? (comment["body"] as string) : undefined,
    }));
}

function displayValue(value: unknown) {
  if (value === null || value === undefined) return "n/a";
  const text = String(value).trim();
  return text.length ? text : "n/a";
}

function safeDate(value?: string | null) {
  if (!value) return "n/a";
  const dt = new Date(value);
  return Number.isNaN(dt.getTime()) ? "n/a" : dt.toLocaleString();
}

function formatCorrelationMeta(meta: {
  status?: string | null;
  component?: string | null;
  severity?: string | null;
}) {
  const parts = [meta.status, meta.component, meta.severity]
    .map((item) => (typeof item === "string" ? item.trim() : ""))
    .filter(Boolean);
  return parts.length ? parts.join(" · ") : "n/a";
}

export default function BugDetail() {
  const { id } = useParams();
  const queryClient = useQueryClient();
  const workflowFormRef = useRef<HTMLFormElement | null>(null);

  const {
    data: bug,
    isLoading,
    error,
  } = useQuery({
    queryKey: ["bugs", id],
    queryFn: () => bugsApi.getById(id as string),
    enabled: Boolean(id),
  });

  const { data: correlations } = useQuery({
    queryKey: ["bugs", id, "correlations"],
    queryFn: () => bugsApi.getCorrelations(id as string),
    enabled: Boolean(id),
  });

  const updateBugMutation = useMutation({
    mutationFn: async (payload: Partial<BugReport>) => bugsApi.update(id as string, payload),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["bugs"] });
    },
  });

  async function onSaveWorkflow() {
    if (!bug || !workflowFormRef.current) return;
    const data = new FormData(workflowFormRef.current);
    const status = data.get("status");
    const assignedTeam = data.get("assigned_team");
    const notes = data.get("resolution_notes");

    const statusValue =
      status === "new" || status === "triaged" || status === "assigned" || status === "resolved"
        ? status
        : bug.status;
    const teamValue = typeof assignedTeam === "string" ? assignedTeam.trim() : "";
    const notesValue = typeof notes === "string" ? notes.trim() : "";

    await updateBugMutation.mutateAsync({
      status: statusValue,
      assigned_team: teamValue.length ? teamValue : undefined,
      resolution_notes: notesValue.length ? notesValue : null,
    });
  }

  if (!id) {
    return (
      <div className="space-y-6">
        <div className="surface-solid p-6">
          <h1 className="text-2xl font-extrabold tracking-tight text-white">Bug</h1>
          <p className="mt-1 text-sm text-white/60">Missing bug id.</p>
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="surface-solid p-6">
          <h1 className="text-2xl font-extrabold tracking-tight text-white">Bug</h1>
          <p className="mt-1 text-sm text-white/60">Loading...</p>
        </div>
      </div>
    );
  }

  if (error || !bug) {
    return (
      <div className="space-y-6">
        <div className="surface-solid p-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h1 className="text-2xl font-extrabold tracking-tight text-white">
                Bug
              </h1>
              <p className="mt-1 text-sm text-white/60">Bug not found.</p>
            </div>
            <Link to="/bugs" className="btn-ghost">
              Back to Bugs
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const githubUrl = getGitHubUrl(bug);
  const comments = getGitHubComments(bug);

  return (
    <div className="space-y-6">
      <div className="surface-solid p-6">
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="badge font-mono text-white/80">{bug.bug_id}</span>
              <span className="badge">{bug.source}</span>
              <span className="badge">{bug.classified_component}</span>
              <span className="badge">{bug.classified_severity}</span>
              <span className="badge">{bug.status}</span>
            </div>

            <h1 className="mt-3 truncate text-2xl font-extrabold tracking-tight text-white">
              {bug.title}
            </h1>
            <p className="mt-1 text-sm text-white/60">Created {safeDate(bug.created_at)}</p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {githubUrl ? (
              <a
                href={githubUrl}
                target="_blank"
                rel="noreferrer"
                className="btn-primary"
              >
                Open on GitHub
              </a>
            ) : null}
            <Link to="/bugs" className="btn-ghost">
              Back
            </Link>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="surface-solid p-6 lg:col-span-2">
          <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
            Description
          </div>
          <div className="mt-4 whitespace-pre-wrap text-sm text-white/80">
            {displayValue(bug.description) === "n/a"
              ? "No description provided."
              : displayValue(bug.description)}
          </div>
        </div>

        <div className="space-y-6">
          <div className="surface-solid p-6">
            <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
              Summary
            </div>
            <dl className="mt-4 grid grid-cols-2 gap-x-3 gap-y-3 text-sm">
              <dt className="text-white/60">Reporter</dt>
              <dd className="font-semibold text-white">
                {displayValue(bug.reporter)}
              </dd>

              <dt className="text-white/60">Team</dt>
              <dd className="font-semibold text-white">
                {displayValue(bug.assigned_team)}
              </dd>

              <dt className="text-white/60">Duplicate</dt>
              <dd className="font-semibold text-white">
                {bug.is_duplicate ? "Yes" : "No"}
              </dd>

              <dt className="text-white/60">Correlated</dt>
              <dd className="font-semibold text-white">
                {(correlations || []).length}
              </dd>
            </dl>

            {bug.duplicate_of_id ? (
              <div className="mt-5 text-sm text-white/80">
                Duplicate of{" "}
                <Link
                  to={`/bugs/${bug.duplicate_of_id}`}
                  className="font-mono text-neon-mint underline underline-offset-4 hover:opacity-80"
                >
                  {bug.duplicate_of_id}
                </Link>
              </div>
            ) : null}
          </div>

          <div className="surface-solid p-6">
            <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
              Workflow
            </div>

            <form ref={workflowFormRef} key={bug.id} className="mt-4 space-y-3">
              <div>
                <div className="text-xs font-semibold tracking-[0.2em] text-white/60">
                  Status
                </div>
                <select
                  className="input mt-2 w-full"
                  name="status"
                  defaultValue={bug.status}
                >
                  <option value="new">new</option>
                  <option value="triaged">triaged</option>
                  <option value="assigned">assigned</option>
                  <option value="resolved">resolved</option>
                </select>
              </div>

              <div>
                <div className="text-xs font-semibold tracking-[0.2em] text-white/60">
                  Assigned Team
                </div>
                <input
                  className="input mt-2 w-full"
                  name="assigned_team"
                  placeholder="e.g. data_engineering"
                  defaultValue={bug.assigned_team || ""}
                />
              </div>

              <div>
                <div className="text-xs font-semibold tracking-[0.2em] text-white/60">
                  Resolution Notes
                </div>
                <textarea
                  className="mt-2 min-h-[96px] w-full resize-y rounded-card border-2 border-white/10 bg-void px-4 py-3 text-sm text-white placeholder-white/30 outline-none transition-colors duration-200 ease-fluid focus:border-neon-mint"
                  name="resolution_notes"
                  placeholder="What fixed it? Links to PRs/runbooks/follow-ups..."
                  defaultValue={bug.resolution_notes || ""}
                />
              </div>

              <button
                type="button"
                className="btn-primary w-full"
                onClick={onSaveWorkflow}
                disabled={updateBugMutation.isPending}
              >
                {updateBugMutation.isPending ? "Saving..." : "Save"}
              </button>
            </form>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="surface-solid overflow-hidden">
          <div className="border-b border-white/10 bg-surface px-5 py-4 text-sm font-semibold tracking-tight text-white">
            Correlated Bugs
          </div>
          <div className="p-5">
            {(correlations || []).length === 0 ? (
              <div className="text-sm text-white/60">No correlated bugs found.</div>
            ) : (
              <div className="space-y-2 text-sm">
                {(correlations || []).slice(0, 10).map((match) => (
                  <div
                    key={match.bug_id}
                    className="flex items-center justify-between gap-4 rounded-card border border-white/10 bg-surface px-4 py-3 transition-colors duration-200 ease-fluid hover:border-neon-mint/40"
                  >
                    <div className="min-w-0">
                      <div className="truncate font-semibold text-white">
                        <Link
                          to={`/bugs/${match.bug_id}`}
                          className="underline decoration-white/20 underline-offset-4 hover:decoration-neon-mint/60 hover:text-neon-mint"
                        >
                          {match.title || match.bug_id}
                        </Link>
                      </div>
                      <div className="mt-1 text-xs text-white/60">
                        {formatCorrelationMeta(match)}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {match.relationship === "duplicate" ? (
                        <div className="badge text-white/80">dup</div>
                      ) : null}
                      <div className="badge font-mono text-white/80">
                        {(match.score ?? 0).toFixed(3)}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="surface-solid overflow-hidden">
          <div className="border-b border-white/10 bg-surface px-5 py-4 text-sm font-semibold tracking-tight text-white">
            GitHub Comments
          </div>
          <div className="p-5">
            {comments.length === 0 ? (
              <div className="text-sm text-white/60">No comments ingested.</div>
            ) : (
              <div className="space-y-3">
                {comments.slice(0, 20).map((comment, idx) => (
                  <div
                    key={String(comment.id ?? comment.url ?? idx)}
                    className="rounded-card border border-white/10 bg-surface p-4"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-white/60">
                      <div className="truncate">
                        {displayValue(comment.user)}
                        {comment.created_at ? ` - ${safeDate(comment.created_at)}` : ""}
                      </div>
                      {comment.url ? (
                        <a
                          href={String(comment.url)}
                          target="_blank"
                          rel="noreferrer"
                          className="text-neon-mint underline underline-offset-4 hover:opacity-80"
                        >
                          View
                        </a>
                      ) : null}
                    </div>
                    <div className="mt-3 whitespace-pre-wrap text-sm text-white/80">
                      {displayValue(comment.body)}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
