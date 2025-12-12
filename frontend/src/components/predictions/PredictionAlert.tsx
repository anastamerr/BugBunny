import { useQuery } from "@tanstack/react-query";

import { api } from "../../api/client";

type Prediction = {
  id: string;
  predicted_bug_count: number;
  predicted_components?: string[];
  confidence?: number;
  prediction_window_hours?: number;
  created_at?: string;
};

export function PredictionAlert() {
  const { data } = useQuery({
    queryKey: ["predictions"],
    queryFn: async () => {
      const resp = await api.get<Prediction[]>("/api/predictions");
      return resp.data;
    },
  });

  const latest = data?.[0];
  if (!latest) return null;

  return (
    <div className="rounded-lg border bg-indigo-50 p-4 text-indigo-900">
      <div className="text-sm font-semibold">Prediction Alert</div>
      <div className="mt-1 text-sm">
        Expect {latest.predicted_bug_count} bugs in the next{" "}
        {latest.prediction_window_hours ?? 6}h
      </div>
      {latest.predicted_components && (
        <div className="mt-1 text-xs">
          Components: {latest.predicted_components.join(", ")}
        </div>
      )}
    </div>
  );
}

