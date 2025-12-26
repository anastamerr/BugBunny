import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { bugsApi } from "../api/bugs";

function severityClass(severity: string) {
  const normalized = String(severity || "").toUpperCase();
  if (normalized === "CRITICAL") {
    return "badge border-neon-mint/40 bg-neon-mint/10 text-neon-mint";
  }
  return "badge";
}

export default function Bugs() {
  const { data, isLoading } = useQuery({
    queryKey: ["bugs"],
    queryFn: () => bugsApi.getAll(),
  });

  return (
    <div className="space-y-6">
      <div className="surface-solid p-6">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-white">
              Bugs
            </h1>
            <p className="mt-1 text-sm text-white/60">
              Automatically triaged and ordered by urgency.
            </p>
          </div>
          <div className="badge">{(data || []).length} total</div>
        </div>
      </div>

      {isLoading && <div className="text-sm text-white/60">Loading...</div>}

      <div className="surface-solid overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[860px] text-sm">
            <thead className="bg-surface text-left text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
              <tr>
                <th className="px-4 py-3">Title</th>
                <th className="px-4 py-3">Component</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Team</th>
                <th className="px-4 py-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {(data || []).map((bug) => (
                <tr
                  key={bug.id}
                  className="border-t border-white/10 transition-colors duration-200 ease-fluid hover:bg-white/5"
                >
                  <td className="px-4 py-3 font-semibold text-white">
                    <Link
                      to={`/bugs/${bug.id}`}
                      className="underline decoration-white/20 underline-offset-4 hover:decoration-neon-mint/60 hover:text-neon-mint"
                    >
                      {bug.title}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-white/80">
                    {bug.classified_component}
                  </td>
                  <td className="px-4 py-3">
                    <span className={severityClass(bug.classified_severity)}>
                      {bug.classified_severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-white/60">
                    {bug.assigned_team || "n/a"}
                  </td>
                  <td className="px-4 py-3">
                    <span className="badge">{bug.status}</span>
                  </td>
                </tr>
              ))}
              {(data || []).length === 0 && !isLoading && (
                <tr>
                  <td className="px-4 py-8 text-center text-white/60" colSpan={5}>
                    No bugs yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
