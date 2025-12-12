import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { bugsApi } from "../api/bugs";
import type { BugReport } from "../types";

function getGitHubUrl(bug: BugReport): string | null {
  const labels = bug.labels as any;
  if (!labels || typeof labels !== "object") return null;
  const url = labels.url;
  return typeof url === "string" && url.length ? url : null;
}

function getGitHubComments(bug: BugReport) {
  const labels = bug.labels as any;
  if (!labels || typeof labels !== "object") return [];
  const comments = labels.comments;
  return Array.isArray(comments) ? comments : [];
}

export default function BugDetail() {
  const { id } = useParams();

  const {
    data: bug,
    isLoading,
    error,
  } = useQuery({
    queryKey: ["bugs", id],
    queryFn: () => bugsApi.getById(id as string),
    enabled: Boolean(id),
  });

  const { data: duplicates } = useQuery({
    queryKey: ["bugs", id, "duplicates"],
    queryFn: () => bugsApi.getDuplicates(id as string),
    enabled: Boolean(id),
  });

  if (!id) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-semibold">Bug</h1>
        <div className="rounded-lg border bg-white p-4 text-sm text-gray-600">
          Missing bug id.
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-semibold">Bug</h1>
        <div className="text-sm text-gray-500">Loading...</div>
      </div>
    );
  }

  if (error || !bug) {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-semibold">Bug</h1>
          <Link to="/bugs" className="text-sm text-blue-600 hover:underline">
            Back to Bugs
          </Link>
        </div>
        <div className="rounded-lg border bg-white p-4 text-sm text-gray-600">
          Bug not found.
        </div>
      </div>
    );
  }

  const githubUrl = getGitHubUrl(bug);
  const comments = getGitHubComments(bug);

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold">{bug.title}</h1>
          <div className="text-sm text-gray-500">{bug.bug_id}</div>
        </div>
        <Link to="/bugs" className="text-sm text-blue-600 hover:underline">
          Back to Bugs
        </Link>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="rounded-lg border bg-white p-4 lg:col-span-2">
          <div className="space-y-3">
            <div className="text-xs font-semibold uppercase text-gray-500">
              Description
            </div>
            <div className="whitespace-pre-wrap text-sm text-gray-800">
              {bug.description || "—"}
            </div>
          </div>
        </div>

        <div className="rounded-lg border bg-white p-4">
          <div className="space-y-2 text-sm">
            <div className="text-xs font-semibold uppercase text-gray-500">
              Summary
            </div>
            <div className="grid grid-cols-2 gap-x-3 gap-y-2">
              <div className="text-gray-500">Source</div>
              <div className="font-medium">{bug.source}</div>

              <div className="text-gray-500">Created</div>
              <div className="font-medium">
                {new Date(bug.created_at).toLocaleString()}
              </div>

              <div className="text-gray-500">Reporter</div>
              <div className="font-medium">{bug.reporter || "—"}</div>

              <div className="text-gray-500">Component</div>
              <div className="font-medium">{bug.classified_component}</div>

              <div className="text-gray-500">Severity</div>
              <div className="font-medium">{bug.classified_severity}</div>

              <div className="text-gray-500">Team</div>
              <div className="font-medium">{bug.assigned_team || "—"}</div>

              <div className="text-gray-500">Status</div>
              <div className="font-medium">{bug.status}</div>

              <div className="text-gray-500">Duplicate</div>
              <div className="font-medium">
                {bug.is_duplicate ? "Yes" : "No"}
              </div>

              <div className="text-gray-500">Data-related</div>
              <div className="font-medium">{bug.is_data_related ? "Yes" : "No"}</div>

              <div className="text-gray-500">Correlation</div>
              <div className="font-medium">{bug.correlation_score ?? "—"}</div>
            </div>

            {githubUrl && (
              <div className="pt-2">
                <a
                  href={githubUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="text-blue-600 hover:underline"
                >
                  Open on GitHub
                </a>
              </div>
            )}

            {bug.duplicate_of_id && (
              <div className="pt-2 text-sm">
                Duplicate of{" "}
                <Link
                  to={`/bugs/${bug.duplicate_of_id}`}
                  className="text-blue-600 hover:underline"
                >
                  {bug.duplicate_of_id}
                </Link>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-lg border bg-white">
          <div className="border-b px-4 py-3 text-sm font-semibold">
            Duplicate Matches
          </div>
          <div className="p-4">
            {(duplicates || []).length === 0 ? (
              <div className="text-sm text-gray-500">No duplicates found.</div>
            ) : (
              <div className="space-y-2 text-sm">
                {(duplicates || []).slice(0, 10).map((d) => (
                  <div
                    key={d.bug_id}
                    className="flex items-center justify-between rounded-md border px-3 py-2"
                  >
                    <div className="min-w-0">
                      <div className="truncate font-medium">
                        <Link
                          to={`/bugs/${d.bug_id}`}
                          className="text-blue-600 hover:underline"
                        >
                          {d.title || d.bug_id}
                        </Link>
                      </div>
                      <div className="text-xs text-gray-500">{d.status || "—"}</div>
                    </div>
                    <div className="ml-3 shrink-0 font-mono text-xs text-gray-700">
                      {(d.similarity_score ?? 0).toFixed(3)}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="rounded-lg border bg-white">
          <div className="border-b px-4 py-3 text-sm font-semibold">
            GitHub Comments
          </div>
          <div className="p-4">
            {comments.length === 0 ? (
              <div className="text-sm text-gray-500">No comments ingested.</div>
            ) : (
              <div className="space-y-3">
                {comments.slice(0, 20).map((c: any) => (
                  <div key={String(c.id)} className="rounded-md border p-3">
                    <div className="flex items-center justify-between gap-3 text-xs text-gray-500">
                      <div className="truncate">
                        {c.user || "unknown"}
                        {c.created_at ? ` • ${new Date(c.created_at).toLocaleString()}` : ""}
                      </div>
                      {c.url ? (
                        <a
                          href={String(c.url)}
                          target="_blank"
                          rel="noreferrer"
                          className="shrink-0 text-blue-600 hover:underline"
                        >
                          View
                        </a>
                      ) : null}
                    </div>
                    <div className="mt-2 whitespace-pre-wrap text-sm text-gray-800">
                      {c.body || "—"}
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
