import { useEffect, useMemo } from "react";
import { io, Socket } from "socket.io-client";

const RAW_WS_URL =
  import.meta.env.VITE_WS_URL ||
  import.meta.env.VITE_API_URL ||
  "http://localhost:8000";
const normalizeBaseUrl = (value: string) => {
  let current = value.trim();
  let next = current;

  do {
    current = next.replace(/\/+$/, "");
    next = current.replace(/\/(api|ws)$/i, "");
  } while (next !== current);

  return current;
};
const WS_URL = normalizeBaseUrl(RAW_WS_URL);
const normalizePath = (value: string) => {
  const trimmed = value.replace(/^\/+|\/+$/g, "");
  return `/${trimmed || "ws"}`;
};

export function useWebSocket(path: string = "/ws"): Socket {
  const socketPath = normalizePath(path);

  const socket = useMemo(
    () =>
      io(WS_URL, {
        path: socketPath,
        transports: ["polling", "websocket"],
        reconnection: true,
        reconnectionDelayMax: 5000,
      }),
    [socketPath],
  );

  useEffect(() => {
    const handleConnect = () => {
      console.info("[realtime] connected");
    };
    const handleConnectError = (err: Error) => {
      console.warn("[realtime] connect_error", err?.message ?? err);
    };
    const handleDisconnect = (reason: string) => {
      console.info("[realtime] disconnected", reason);
    };

    socket.on("connect", handleConnect);
    socket.on("connect_error", handleConnectError);
    socket.on("disconnect", handleDisconnect);

    return () => {
      socket.off("connect", handleConnect);
      socket.off("connect_error", handleConnectError);
      socket.off("disconnect", handleDisconnect);
      socket.disconnect();
    };
  }, [socket]);

  return socket;
}
