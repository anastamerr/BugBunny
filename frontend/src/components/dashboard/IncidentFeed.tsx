import { DataIncident } from "../../types";

type Props = {
  incidents: DataIncident[];
};

export function IncidentFeed({ incidents }: Props) {
  return (
    <div className="rounded-lg border bg-white p-4 shadow-sm">
      <div className="mb-3 text-sm font-semibold">Recent Incidents</div>
      <div className="space-y-2">
        {incidents.length === 0 && (
          <div className="text-sm text-gray-500">No incidents yet.</div>
        )}
        {incidents.map((i) => (
          <div
            key={i.id}
            className="flex items-center justify-between rounded-md bg-gray-50 px-3 py-2"
          >
            <div>
              <div className="text-sm font-medium">{i.table_name}</div>
              <div className="text-xs text-gray-600">
                {i.incident_type} - {i.severity}
              </div>
            </div>
            <div className="text-xs text-gray-500">{i.status}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
