import { useQuery } from "@tanstack/react-query";
import { Activity, Radar, ScanSearch, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";

import { bugsApi } from "../api/bugs";
import { scansApi } from "../api/scans";
import { BugQueue } from "../components/dashboard/BugQueue";
import { StatsCard } from "../components/dashboard/StatsCard";

function formatRepoName(url?: string | null) {
  if (!url) return "DAST target";
  try {
    const parsed = new URL(url);
    const parts = parsed.pathname.split("/").filter(Boolean);
    if (parts.length >= 2) {
      return `${parts[parts.length - 2]}/${parts[parts.length - 1]}`;
    }
  } catch {
    return url;
  }
  return url;
}

function formatReduction(total: number, filtered: number) {
  if (!total) return "0%";
  const ratio = 1 - filtered / total;
  return `${Math.round(Math.max(0, Math.min(1, ratio)) * 100)}%`;
}

export default function Dashboard() {
  const { data: bugs } = useQuery({
    queryKey: ["bugs"],
    queryFn: () => bugsApi.getAll(),
  });
  const { data: scans } = useQuery({
    queryKey: ["scans"],
    queryFn: () => scansApi.list(),
  });

  const bugList = bugs ?? [];
  const newBugs = bugList.filter((bug) => bug.status === "new");

  const scanList = scans ?? [];
  const activeScans = scanList.filter((scan) =>
    ["pending", "cloning", "scanning", "analyzing"].includes(scan.status),
  );
  const totalFindings = scanList.reduce(
    (acc, scan) => acc + (scan.total_findings || 0),
    0,
  );
  const filteredFindings = scanList.reduce(
    (acc, scan) => acc + (scan.filtered_findings || 0),
    0,
  );

  return (
    <div className="space-y-6">
      <div className="surface-solid relative overflow-hidden p-6">
        <div aria-hidden="true" className="pointer-events-none absolute inset-0">
          <div className="absolute -right-24 -top-24 h-72 w-72 rounded-full bg-neon-mint/10 blur-3xl" />
          <div className="absolute -bottom-24 -left-24 h-72 w-72 rounded-full bg-neon-mint/5 blur-3xl" />
        </div>

        <div className="relative flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
          <div className="min-w-0">
            <div className="inline-flex items-center gap-2 rounded-pill border border-neon-mint/40 bg-neon-mint/10 px-3 py-1 text-xs font-semibold tracking-[0.2em] text-neon-mint">
              SCANGUARD OPS
            </div>
            <h1 className="mt-3 text-3xl font-extrabold tracking-tight text-white">
              Dashboard
            </h1>
            <p className="mt-2 max-w-2xl text-sm text-white/60">
              Context-aware static analysis that cuts noise and surfaces real risk.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Link to="/scans" className="btn-primary">
              Run a Scan
            </Link>
            <Link to="/bugs" className="btn-ghost">
              View Bugs
            </Link>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        <StatsCard
          title="Total Scans"
          value={scanList.length}
          icon={<Radar className="h-4 w-4 text-neon-mint" />}
        />
        <StatsCard
          title="Active Scans"
          value={activeScans.length}
          icon={<Activity className="h-4 w-4 text-neon-mint" />}
        />
        <StatsCard
          title="Total Findings"
          value={totalFindings}
          subtitle="raw results"
          icon={<ScanSearch className="h-4 w-4 text-neon-mint" />}
        />
        <StatsCard
          title="Noise Reduction"
          value={formatReduction(totalFindings, filteredFindings)}
          subtitle={`${filteredFindings} real issues`}
          icon={<ShieldCheck className="h-4 w-4 text-neon-mint" />}
        />
      </div>

      <div className="surface-solid p-5">
        <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
          Why ScanGuard AI
        </div>
        <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-3">
          <div className="rounded-card border border-white/10 bg-void p-4">
            <div className="text-sm font-semibold text-white">Cut the noise</div>
            <p className="mt-2 text-sm text-white/60">
              Filter false positives so teams focus on real, exploitable issues.
            </p>
          </div>
          <div className="rounded-card border border-white/10 bg-void p-4">
            <div className="text-sm font-semibold text-white">
              Rank by exploitability
            </div>
            <p className="mt-2 text-sm text-white/60">
              Severity is adjusted by context, reachability, and confidence.
            </p>
          </div>
          <div className="rounded-card border border-white/10 bg-void p-4">
            <div className="text-sm font-semibold text-white">Prove with DAST</div>
            <p className="mt-2 text-sm text-white/60">
              Dynamic confirmation adds evidence and boosts confidence for top
              risks.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <div className="surface-solid p-5">
          <div className="flex items-center justify-between">
            <div className="text-sm font-semibold tracking-tight text-white">
              Recent Scans
            </div>
            <Link to="/scans" className="text-xs text-neon-mint">
              View all
            </Link>
          </div>
          <div className="mt-4 space-y-3 text-sm">
            {scanList.slice(0, 5).map((scan) => {
              const headline = scan.repo_url
                ? formatRepoName(scan.repo_url)
                : scan.target_url || "DAST scan";
              const scanScope =
                scan.scan_type === "dast"
                  ? scan.target_url || "DAST"
                  : scan.branch;

              return (
                <div
                  key={scan.id}
                  className="flex items-center justify-between gap-4 rounded-card border border-white/10 bg-surface px-4 py-3"
                >
                  <div className="min-w-0">
                    <div className="truncate font-semibold text-white">
                      {headline}
                    </div>
                    <div className="mt-1 text-xs text-white/60">
                      {scanScope} {"->"} {scan.status}
                    </div>
                  </div>
                  <Link to={`/scans/${scan.id}`} className="btn-ghost">
                    View
                  </Link>
                </div>
              );
            })}
            {scanList.length === 0 ? (
              <div className="text-sm text-white/60">No scans yet.</div>
            ) : null}
          </div>
        </div>

        <BugQueue title="New Bugs" emptyLabel="No new bugs." bugs={newBugs.slice(0, 5)} />
      </div>
    </div>
  );
}
