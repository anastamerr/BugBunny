import { Link } from "react-router-dom";

import type { DataIncident } from "../../types";

type Props = {
  incidents: DataIncident[];
};

function statusClass(status: string) {
  if (status === "ACTIVE") {
    return "badge border-neon-mint/40 bg-neon-mint/10 text-neon-mint";
  }
  return "badge";
}

export function IncidentFeed({ incidents }: Props) {
  return (
    <div className="surface-solid p-5">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div className="text-sm font-semibold tracking-tight text-white">
          Recent Incidents
        </div>
        <div className="badge border-neon-mint/40 bg-neon-mint/10 text-neon-mint">
          Live
        </div>
      </div>

      <div className="space-y-2">
        {incidents.length === 0 && (
          <div className="text-sm text-white/60">No incidents yet.</div>
        )}

        {incidents.map((incident) => (
          <Link
            key={incident.id}
            to={`/incidents/${incident.id}`}
            className="flex items-center justify-between gap-4 rounded-card border border-white/10 bg-surface px-4 py-3 transition-colors duration-200 ease-fluid hover:border-neon-mint/40"
          >
            <div className="min-w-0">
              <div className="truncate text-sm font-semibold text-white">
                {incident.table_name}
              </div>
              <div className="mt-1 text-xs font-medium text-white/60">
                {incident.incident_type} • {incident.severity}
              </div>
            </div>
            <span className={statusClass(incident.status)}>{incident.status}</span>
          </Link>
        ))}
      </div>
    </div>
  );
}
