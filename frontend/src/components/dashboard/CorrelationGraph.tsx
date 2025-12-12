import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { correlationsApi } from "../../api/correlations";
import type { Correlation } from "../../types";

type Datum = {
  key: string;
  label: string;
  scorePct: number;
  bugTitle: string;
  incidentLabel: string;
};

function truncate(text: string, max: number) {
  return text.length > max ? `${text.slice(0, max - 3)}...` : text;
}

export function CorrelationGraph() {
  const { data, isLoading } = useQuery({
    queryKey: ["correlations"],
    queryFn: () => correlationsApi.getAll(),
  });

  const chartData = useMemo<Datum[]>(() => {
    const correlations = (data || []).slice(0, 8);
    return correlations.map((c: Correlation) => ({
      key: c.id,
      label: truncate(c.bug.title, 16),
      scorePct: Math.round((c.correlation_score || 0) * 100),
      bugTitle: c.bug.title,
      incidentLabel: `${c.incident.table_name} (${c.incident.incident_type})`,
    }));
  }, [data]);

  return (
    <div className="rounded-lg border bg-white p-4 shadow-sm">
      <div className="mb-3 text-sm font-semibold">Top Correlations</div>

      {isLoading && <div className="text-sm text-gray-500">Loading...</div>}

      {!isLoading && chartData.length === 0 && (
        <div className="text-sm text-gray-500">No correlations yet.</div>
      )}

      {!isLoading && chartData.length > 0 && (
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} margin={{ left: 0, right: 8 }}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="label" tick={{ fontSize: 12 }} interval={0} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 12 }} />
              <Tooltip
                formatter={(value: number) => [`${value}%`, "Score"]}
                labelFormatter={(_, payload) => {
                  const item = payload?.[0]?.payload as Datum | undefined;
                  return item
                    ? `${item.bugTitle} | ${item.incidentLabel}`
                    : "";
                }}
              />
              <Bar dataKey="scorePct" fill="#2563eb" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
