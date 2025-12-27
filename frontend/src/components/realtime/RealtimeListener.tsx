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
    const setRealtimeStatus = (
      state: "connecting" | "connected" | "disconnected" | "error",
      message?: string,
    ) => {
      queryClient.setQueryData(["realtime-status"], {
        state,
        message,
        updatedAt: new Date().toISOString(),
      });
    };

    socket.on("bug.created", invalidateBugs);
    socket.on("bug.updated", invalidateBugs);
    socket.on("scan.created", invalidateScans);
    socket.on("scan.updated", invalidateScans);
    socket.on("scan.completed", handleScanCompleted);
    socket.on("scan.failed", invalidateScans);
    socket.on("finding.updated", invalidateFindings);
    socket.on("connect", () => setRealtimeStatus("connected"));
    socket.on("disconnect", () => setRealtimeStatus("disconnected"));
    socket.on("connect_error", (err: Error) =>
      setRealtimeStatus("error", err?.message),
    );
    socket.on("reconnect_attempt", () => setRealtimeStatus("connecting"));
    socket.on("reconnect_failed", () =>
      setRealtimeStatus("error", "Reconnection failed"),
    );

    if (!socket.connected) {
      setRealtimeStatus("connecting");
    }

    return () => {
      socket.off("bug.created", invalidateBugs);
      socket.off("bug.updated", invalidateBugs);
      socket.off("scan.created", invalidateScans);
      socket.off("scan.updated", invalidateScans);
      socket.off("scan.completed", handleScanCompleted);
      socket.off("scan.failed", invalidateScans);
      socket.off("finding.updated", invalidateFindings);
      socket.off("connect");
      socket.off("disconnect");
      socket.off("connect_error");
      socket.off("reconnect_attempt");
      socket.off("reconnect_failed");
    };
  }, [queryClient, socket]);

  return null;
}
