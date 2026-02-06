import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Bug } from "lucide-react";
import { Link } from "react-router-dom";

import { bugsApi } from "../api/bugs";
import { EmptyState } from "../components/ui/EmptyState";
import { LoadingState } from "../components/ui/LoadingState";
import { getSeverityClass } from "../utils/severity";

export default function Bugs() {
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const { data, isLoading, error } = useQuery({
    queryKey: ["bugs"],
    queryFn: () => bugsApi.getAll(),
  });

  const bugs = useMemo(() => data ?? [], [data]);
  const filtered = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return bugs.filter((bug) => {
      if (statusFilter !== "all" && bug.status !== statusFilter) {
        return false;
      }
      if (!normalized) return true;
      const haystack = [
        bug.title,
        bug.bug_id,
        bug.classified_component,
        bug.assigned_team || "",
        bug.classified_severity,
        bug.status,
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(normalized);
    });
  }, [bugs, query, statusFilter]);

  return (
    <div className="space-y-6">
      <div className="surface-solid p-6">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-white">
              Bugs
            </h1>
            <p className="mt-1 text-sm text-white/60">
              Automatically triaged and ordered by urgency.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs text-white/60">
            <span className="badge">{bugs.length} total</span>
            <span>
              Showing {filtered.length} {filtered.length === 1 ? "result" : "results"}
            </span>
          </div>
        </div>

        <div className="mt-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="flex-1">
            <input
              className="search-input w-full"
              placeholder="Search by title, component, or team..."
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>
          <div className="flex items-center gap-2">
            <select
              className="select"
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value)}
            >
              <option value="all">All statuses</option>
              <option value="new">new</option>
              <option value="triaged">triaged</option>
              <option value="assigned">assigned</option>
              <option value="resolved">resolved</option>
            </select>
            <button
              type="button"
              className="btn-ghost"
              onClick={() => {
                setQuery("");
                setStatusFilter("all");
              }}
              disabled={!query && statusFilter === "all"}
            >
              Clear
            </button>
          </div>
        </div>
      </div>

      {error ? (
        <div role="alert" className="surface-solid p-4 text-sm text-rose-200">
          {error instanceof Error ? error.message : "Unable to load bugs."}
        </div>
      ) : null}

      {isLoading ? (
        <div className="table-container">
          <table className="table min-w-[860px]">
            <thead>
              <tr>
                <th>Title</th>
                <th>Component</th>
                <th>Severity</th>
                <th>Team</th>
                <th>Status</th>
              </tr>
            </thead>
            <LoadingState variant="table" count={5} />
          </table>
        </div>
      ) : bugs.length === 0 && !error ? (
        <EmptyState
          icon={<Bug className="h-16 w-16" />}
          title="No bugs yet"
          description="Bugs will appear here once scans identify and triage issues."
          action={
            <Link to="/scans" className="btn-primary">
              Run a scan
            </Link>
          }
        />
      ) : (
        <div className="table-container">
          <table className="table min-w-[860px]">
            <thead>
              <tr>
                <th>Title</th>
                <th>Component</th>
                <th>Severity</th>
                <th>Team</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((bug) => (
                <tr key={bug.id}>
                  <td className="font-semibold text-white">
                    <Link
                      to={`/bugs/${bug.id}`}
                      className="underline decoration-white/20 underline-offset-4 hover:decoration-neon-mint/60 hover:text-neon-mint"
                    >
                      {bug.title}
                    </Link>
                  </td>
                  <td>{bug.classified_component}</td>
                  <td>
                    <span className={getSeverityClass(bug.classified_severity)}>
                      {bug.classified_severity}
                    </span>
                  </td>
                  <td className="text-white/70">{bug.assigned_team || "n/a"}</td>
                  <td>
                    <span className="badge">{bug.status}</span>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td className="py-8 text-center text-white/70" colSpan={5}>
                    No results match this filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
