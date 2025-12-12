import { useQuery } from "@tanstack/react-query";

import { api } from "../api/client";

type Prediction = {
  id: string;
  incident_id: string;
  predicted_bug_count: number;
  predicted_components?: string[];
  confidence?: number;
  prediction_window_hours?: number;
  created_at?: string;
};

export default function Predictions() {
  const { data, isLoading } = useQuery({
    queryKey: ["predictions"],
    queryFn: async () => {
      const resp = await api.get<Prediction[]>("/api/predictions");
      return resp.data;
    },
  });

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Predictions</h1>

      {isLoading && <div className="text-sm text-gray-500">Loading...</div>}

      <div className="space-y-2">
        {(data || []).map((p) => (
          <div key={p.id} className="rounded-lg border bg-white p-4 shadow-sm">
            <div className="text-sm font-semibold">
              {p.predicted_bug_count} predicted bugs
            </div>
            <div className="mt-1 text-xs text-gray-600">
              Window: {p.prediction_window_hours ?? 6}h - Confidence:{" "}
              {p.confidence ? `${Math.round(p.confidence * 100)}%` : "n/a"}
            </div>
            {p.predicted_components && (
              <div className="mt-1 text-xs">
                Components: {p.predicted_components.join(", ")}
              </div>
            )}
          </div>
        ))}
        {(data || []).length === 0 && !isLoading && (
          <div className="text-sm text-gray-500">No predictions yet.</div>
        )}
      </div>
    </div>
  );
}
