import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Bug, Clock, Database } from "lucide-react";

import { bugsApi } from "../api/bugs";
import { incidentsApi } from "../api/incidents";
import { BugQueue } from "../components/dashboard/BugQueue";
import { CorrelationGraph } from "../components/dashboard/CorrelationGraph";
import { IncidentFeed } from "../components/dashboard/IncidentFeed";
import { StatsCard } from "../components/dashboard/StatsCard";
import { PredictionAlert } from "../components/predictions/PredictionAlert";

export default function Dashboard() {
  const { data: incidents } = useQuery({
    queryKey: ["incidents"],
    queryFn: () => incidentsApi.getAll(),
  });
  const { data: bugs } = useQuery({
    queryKey: ["bugs"],
    queryFn: () => bugsApi.getAll(),
  });

  const activeIncidents =
    incidents?.filter((i) => i.status === "ACTIVE").length || 0;
  const unresolvedBugs = bugs?.filter((b) => b.status !== "resolved").length || 0;
  const dataRelatedBugs = bugs?.filter((b) => b.is_data_related).length || 0;
  const correlationRate = bugs?.length
    ? (dataRelatedBugs / bugs.length) * 100
    : 0;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">DataBug AI Dashboard</h1>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        <StatsCard
          title="Active Incidents"
          value={activeIncidents}
          icon={<AlertTriangle className="h-4 w-4 text-red-600" />}
        />
        <StatsCard
          title="Bug Queue"
          value={unresolvedBugs}
          icon={<Bug className="h-4 w-4 text-yellow-600" />}
        />
        <StatsCard
          title="Data-Related Bugs"
          value={`${correlationRate.toFixed(0)}%`}
          subtitle={`${dataRelatedBugs} of ${bugs?.length || 0}`}
          icon={<Database className="h-4 w-4 text-blue-600" />}
        />
        <StatsCard
          title="Avg Time to Root Cause"
          value="12 min"
          subtitle="Prev: 4.2 hrs"
          icon={<Clock className="h-4 w-4 text-green-600" />}
        />
      </div>

      <PredictionAlert />

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <div className="space-y-6">
          <IncidentFeed incidents={incidents?.slice(0, 5) || []} />
          <BugQueue bugs={bugs?.filter((b) => b.status === "new").slice(0, 5) || []} />
        </div>
        <CorrelationGraph />
      </div>
    </div>
  );
}
