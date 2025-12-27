import { useQuery } from "@tanstack/react-query";

type RealtimeState = {
  state: "connecting" | "connected" | "disconnected" | "error";
  message?: string;
  updatedAt?: string;
};

const fallbackState: RealtimeState = { state: "connecting" };

const statusStyles: Record<RealtimeState["state"], string> = {
  connected: "badge border-neon-mint/40 bg-neon-mint/10 text-neon-mint",
  connecting: "badge border-amber-400/40 bg-amber-400/10 text-amber-200",
  disconnected: "badge border-white/20 bg-white/10 text-white/70",
  error: "badge border-rose-400/40 bg-rose-400/10 text-rose-200",
};

const statusLabel: Record<RealtimeState["state"], string> = {
  connected: "Live",
  connecting: "Connecting",
  disconnected: "Offline",
  error: "Error",
};

export function RealtimeStatus() {
  const { data } = useQuery({
    queryKey: ["realtime-status"],
    queryFn: () => fallbackState,
    initialData: fallbackState,
    staleTime: Infinity,
  });

  const status = data ?? fallbackState;
  const label = statusLabel[status.state] || "Connecting";
  const badgeClass = statusStyles[status.state] || "badge";

  return (
    <div className="rounded-card border border-white/10 bg-void p-3 text-xs text-white/70">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] uppercase tracking-[0.2em] text-white/50">
          Realtime
        </span>
        <span className={badgeClass}>{label}</span>
      </div>
      <div className="mt-2 text-xs text-white/60">
        Updates stream via <span className="font-mono text-white/80">/ws</span>
      </div>
      {status.message ? (
        <div className="mt-1 text-[11px] text-white/40">{status.message}</div>
      ) : null}
    </div>
  );
}
