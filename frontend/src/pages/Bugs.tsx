import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { bugsApi } from "../api/bugs";

export default function Bugs() {
  const { data, isLoading } = useQuery({
    queryKey: ["bugs"],
    queryFn: () => bugsApi.getAll(),
  });

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Bugs</h1>

      {isLoading && <div className="text-sm text-gray-500">Loading...</div>}

      <div className="rounded-lg border bg-white">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 text-left text-xs uppercase text-gray-500">
            <tr>
              <th className="px-4 py-2">Title</th>
              <th className="px-4 py-2">Component</th>
              <th className="px-4 py-2">Severity</th>
              <th className="px-4 py-2">Team</th>
              <th className="px-4 py-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {(data || []).map((b) => (
              <tr key={b.id} className="border-t">
                <td className="px-4 py-2 font-medium">
                  <Link to={`/bugs/${b.id}`} className="hover:underline">
                    {b.title}
                  </Link>
                </td>
                <td className="px-4 py-2">{b.classified_component}</td>
                <td className="px-4 py-2">{b.classified_severity}</td>
                <td className="px-4 py-2">{b.assigned_team || "-"}</td>
                <td className="px-4 py-2">{b.status}</td>
              </tr>
            ))}
            {(data || []).length === 0 && !isLoading && (
              <tr>
                <td className="px-4 py-6 text-center text-gray-500" colSpan={5}>
                  No bugs yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
