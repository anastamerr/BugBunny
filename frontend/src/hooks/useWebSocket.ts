import { useEffect, useMemo } from "react";
import { io, Socket } from "socket.io-client";

const WS_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

export function useWebSocket(path: string = "/ws"): Socket {
  const socket = useMemo(() => io(WS_URL, { path }), [path]);

  useEffect(() => {
    return () => {
      socket.disconnect();
    };
  }, [socket]);

  return socket;
}

