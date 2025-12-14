import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { incidentsApi } from "../api/incidents";

function severityClass(severity: string) {
  const normalized = String(severity || "").toUpperCase();
  if (normalized === "CRITICAL") {
    return "badge border-neon-mint/40 bg-neon-mint/10 text-neon-mint";
  }
  return "badge";
}

function statusClass(status: string) {
  const normalized = String(status || "").toUpperCase();
  if (normalized === "ACTIVE") {
    return "badge border-neon-mint/40 bg-neon-mint/10 text-neon-mint";
  }
  return "badge";
}

export default function Incidents() {
  const { data, isLoading } = useQuery({
    queryKey: ["incidents"],
    queryFn: () => incidentsApi.getAll(),
  });

  return (
    <div className="space-y-6">
      <div className="surface-solid p-6">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-white">
              Incidents
            </h1>
            <p className="mt-1 text-sm text-white/60">
              Data pipeline incidents detected and tracked in real time.
            </p>
          </div>
          <div className="badge">{(data || []).length} total</div>
        </div>
      </div>

      {isLoading && <div className="text-sm text-white/60">Loading...</div>}

      <div className="surface-solid overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-sm">
            <thead className="bg-surface text-left text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
              <tr>
                <th className="px-4 py-3">Table</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Time</th>
              </tr>
            </thead>
            <tbody>
              {(data || []).map((incident) => (
                <tr
                  key={incident.id}
                  className="border-t border-white/10 transition-colors duration-200 ease-fluid hover:bg-white/5"
                >
                  <td className="px-4 py-3 font-semibold text-white">
                    <Link
                      to={`/incidents/${incident.id}`}
                      className="underline decoration-white/20 underline-offset-4 hover:decoration-neon-mint/60 hover:text-neon-mint"
                    >
                      {incident.table_name}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-white/80">
                    {incident.incident_type}
                  </td>
                  <td className="px-4 py-3">
                    <span className={severityClass(incident.severity)}>
                      {incident.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={statusClass(incident.status)}>
                      {incident.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-white/60">
                    {new Date(incident.timestamp).toLocaleString()}
                  </td>
                </tr>
              ))}
              {(data || []).length === 0 && !isLoading && (
                <tr>
                  <td className="px-4 py-8 text-center text-white/60" colSpan={5}>
                    No incidents yet.
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
