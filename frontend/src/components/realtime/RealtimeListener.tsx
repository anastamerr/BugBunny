import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { useWebSocket } from "../../hooks/useWebSocket";

export function RealtimeListener() {
  const queryClient = useQueryClient();
  const socket = useWebSocket();

  useEffect(() => {
    const invalidateBugs = () =>
      queryClient.invalidateQueries({ queryKey: ["bugs"] });
    const invalidateScans = () =>
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    const invalidateFindings = () =>
      queryClient.invalidateQueries({ queryKey: ["findings"] });
    const handleScanCompleted = () => {
      invalidateScans();
      invalidateFindings();
    };

    socket.on("bug.created", invalidateBugs);
    socket.on("bug.updated", invalidateBugs);
    socket.on("scan.created", invalidateScans);
    socket.on("scan.updated", invalidateScans);
    socket.on("scan.completed", handleScanCompleted);
    socket.on("scan.failed", invalidateScans);
    socket.on("finding.updated", invalidateFindings);

    return () => {
      socket.off("bug.created", invalidateBugs);
      socket.off("bug.updated", invalidateBugs);
      socket.off("scan.created", invalidateScans);
      socket.off("scan.updated", invalidateScans);
      socket.off("scan.completed", handleScanCompleted);
      socket.off("scan.failed", invalidateScans);
      socket.off("finding.updated", invalidateFindings);
    };
  }, [queryClient, socket]);

  return null;
}
