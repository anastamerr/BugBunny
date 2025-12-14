import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { useWebSocket } from "../../hooks/useWebSocket";

export function RealtimeListener() {
  const queryClient = useQueryClient();
  const socket = useWebSocket();

  useEffect(() => {
    const invalidateIncidents = () =>
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
    const invalidateBugs = () =>
      queryClient.invalidateQueries({ queryKey: ["bugs"] });
    const invalidateCorrelations = () =>
      queryClient.invalidateQueries({ queryKey: ["correlations"] });
    const invalidatePredictions = () =>
      queryClient.invalidateQueries({ queryKey: ["predictions"] });

    socket.on("incident.created", invalidateIncidents);
    socket.on("incident.updated", invalidateIncidents);
    socket.on("incident.action.created", invalidateIncidents);
    socket.on("incident.action.updated", invalidateIncidents);
    socket.on("bug.created", invalidateBugs);
    socket.on("bug.updated", invalidateBugs);
    socket.on("correlation.created", invalidateCorrelations);
    socket.on("prediction.created", invalidatePredictions);

    return () => {
      socket.off("incident.created", invalidateIncidents);
      socket.off("incident.updated", invalidateIncidents);
      socket.off("incident.action.created", invalidateIncidents);
      socket.off("incident.action.updated", invalidateIncidents);
      socket.off("bug.created", invalidateBugs);
      socket.off("bug.updated", invalidateBugs);
      socket.off("correlation.created", invalidateCorrelations);
      socket.off("prediction.created", invalidatePredictions);
    };
  }, [queryClient, socket]);

  return null;
}
