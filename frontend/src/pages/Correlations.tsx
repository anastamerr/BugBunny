import { useQuery } from "@tanstack/react-query";

import { correlationsApi } from "../api/correlations";

export default function Correlations() {
  const { data, isLoading } = useQuery({
    queryKey: ["correlations"],
    queryFn: () => correlationsApi.getAll(),
  });

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Correlations</h1>

      {isLoading && <div className="text-sm text-gray-500">Loading...</div>}

      <div className="space-y-2">
        {(data || []).map((c) => (
          <div key={c.id} className="rounded-lg border bg-white p-4 shadow-sm">
            <div className="text-sm font-semibold">{c.bug.title}</div>
            <div className="mt-1 text-xs text-gray-600">
              Incident: {c.incident.table_name} ({c.incident.incident_type}) -
              Score: {(c.correlation_score * 100).toFixed(0)}%
            </div>
            {c.explanation && (
              <div className="mt-2 text-sm text-gray-700">{c.explanation}</div>
            )}
          </div>
        ))}
        {(data || []).length === 0 && !isLoading && (
          <div className="text-sm text-gray-500">No correlations yet.</div>
        )}
      </div>
    </div>
  );
}
