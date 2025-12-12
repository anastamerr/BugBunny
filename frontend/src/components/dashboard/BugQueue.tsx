import type { BugReport } from "../../types";

type Props = {
  bugs: BugReport[];
};

export function BugQueue({ bugs }: Props) {
  return (
    <div className="rounded-lg border bg-white p-4 shadow-sm">
      <div className="mb-3 text-sm font-semibold">Bug Queue</div>
      <div className="space-y-2">
        {bugs.length === 0 && (
          <div className="text-sm text-gray-500">No new bugs.</div>
        )}
        {bugs.map((b) => (
          <div
            key={b.id}
            className="flex items-center justify-between rounded-md bg-gray-50 px-3 py-2"
          >
            <div>
              <div className="text-sm font-medium">{b.title}</div>
              <div className="text-xs text-gray-600">
                {b.classified_component} - {b.classified_severity}
              </div>
            </div>
            <div className="text-xs text-gray-500">{b.status}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
