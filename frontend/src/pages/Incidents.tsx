import { useQuery } from "@tanstack/react-query";

import { incidentsApi } from "../api/incidents";

export default function Incidents() {
  const { data, isLoading } = useQuery({
    queryKey: ["incidents"],
    queryFn: () => incidentsApi.getAll(),
  });

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Incidents</h1>

      {isLoading && <div className="text-sm text-gray-500">Loading...</div>}

      <div className="rounded-lg border bg-white">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
            <tr>
              <th className="px-4 py-2">Table</th>
              <th className="px-4 py-2">Type</th>
              <th className="px-4 py-2">Severity</th>
              <th className="px-4 py-2">Status</th>
              <th className="px-4 py-2">Time</th>
            </tr>
          </thead>
          <tbody>
            {(data || []).map((i) => (
              <tr key={i.id} className="border-t">
                <td className="px-4 py-2 font-medium">{i.table_name}</td>
                <td className="px-4 py-2">{i.incident_type}</td>
                <td className="px-4 py-2">{i.severity}</td>
                <td className="px-4 py-2">{i.status}</td>
                <td className="px-4 py-2">
                  {new Date(i.timestamp).toLocaleString()}
                </td>
              </tr>
            ))}
            {(data || []).length === 0 && !isLoading && (
              <tr>
                <td className="px-4 py-6 text-center text-gray-500" colSpan={5}>
                  No incidents yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
