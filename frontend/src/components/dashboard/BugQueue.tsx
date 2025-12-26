import { Link } from "react-router-dom";

import type { BugReport } from "../../types";

type Props = {
  bugs: BugReport[];
  title?: string;
  emptyLabel?: string;
};

export function BugQueue({ bugs, title = "Bug Queue", emptyLabel = "No new bugs." }: Props) {
  return (
    <div className="surface-solid p-5">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div className="text-sm font-semibold tracking-tight text-white">
          {title}
        </div>
        <div className="badge">{bugs.length} items</div>
      </div>

      <div className="space-y-2">
        {bugs.length === 0 && (
          <div className="text-sm text-white/60">{emptyLabel}</div>
        )}

        {bugs.map((bug) => (
          <Link
            key={bug.id}
            to={`/bugs/${bug.id}`}
            className="flex items-center justify-between gap-4 rounded-card border border-white/10 bg-surface px-4 py-3 transition-colors duration-200 ease-fluid hover:border-neon-mint/40"
          >
            <div className="min-w-0">
              <div className="truncate text-sm font-semibold text-white">
                {bug.title}
              </div>
              <div className="mt-1 text-xs font-medium text-white/60">
                {bug.classified_component} - {bug.classified_severity}
              </div>
            </div>
            <div className="badge">{bug.status}</div>
          </Link>
        ))}
      </div>
    </div>
  );
}
