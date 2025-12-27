import { useEffect, useMemo } from "react";
import { io, Socket } from "socket.io-client";

const RAW_WS_URL =
  import.meta.env.VITE_WS_URL ||
  import.meta.env.VITE_API_URL ||
  "http://localhost:8000";
const WS_URL = RAW_WS_URL.replace(/\/api\/?$/, "");

export function useWebSocket(path: string = "/ws"): Socket {
  const socket = useMemo(
    () =>
      io(WS_URL, {
        path,
        transports: ["websocket", "polling"],
        reconnection: true,
        reconnectionDelayMax: 5000,
      }),
    [path],
  );

  useEffect(() => {
    return () => {
      socket.disconnect();
    };
  }, [socket]);

  return socket;
}

