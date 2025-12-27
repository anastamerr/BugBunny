import { UserCircle } from "lucide-react";
import { Link } from "react-router-dom";

export default function Settings() {
  return (
    <div className="space-y-6">
      <div className="surface-solid p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-white">
              Settings
            </h1>
            <p className="mt-1 text-sm text-white/60">
              Configure integrations, real-time updates, and AI triage.
            </p>
          </div>
          <Link
            to="/profile"
            className="btn-ghost h-11 w-11 justify-center p-0"
            aria-label="Profile"
          >
            <UserCircle className="h-5 w-5" />
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="surface-solid p-6">
          <div className="text-sm font-semibold tracking-tight text-white">
            Integrations
          </div>
          <p className="mt-1 text-sm text-white/60">
            User integrations live in Profile, while server-level defaults stay in{" "}
            <span className="font-mono text-white/80">backend/.env</span>.
          </p>

          <div className="mt-4 space-y-3 text-sm">
            <div className="flex items-start justify-between gap-4 rounded-card border border-white/10 bg-surface px-4 py-3">
              <div>
                <div className="font-semibold text-white">GitHub Webhooks</div>
                <div className="mt-1 text-xs text-white/60">
                  Trigger scans on push/PR and ingest issues when enabled.
                </div>
              </div>
              <span className="badge border-neon-mint/40 bg-neon-mint/10 text-neon-mint">
                Active
              </span>
            </div>

            <div className="flex items-start justify-between gap-4 rounded-card border border-white/10 bg-surface px-4 py-3">
              <div>
                <div className="font-semibold text-white">Realtime Events</div>
                <div className="mt-1 text-xs text-white/60">
                  Live UI refresh via Socket.IO.
                </div>
              </div>
              <span className="badge">/ws</span>
            </div>
          </div>
        </div>

        <div className="surface-solid p-6">
          <div className="text-sm font-semibold tracking-tight text-white">
            AI Provider
          </div>
          <p className="mt-1 text-sm text-white/60">
            Auto-selects the best available LLM provider for explanations and chat.
          </p>

          <div className="mt-4 space-y-3 text-sm">
            <div className="flex items-start justify-between gap-4 rounded-card border border-white/10 bg-surface px-4 py-3">
              <div>
                <div className="font-semibold text-white">OpenRouter</div>
                <div className="mt-1 text-xs text-white/60">
                  Cloud LLM routing via <span className="font-mono">OPEN_ROUTER_API_KEY</span>.
                </div>
              </div>
              <span className="badge">Optional</span>
            </div>

            <div className="flex items-start justify-between gap-4 rounded-card border border-white/10 bg-surface px-4 py-3">
              <div>
                <div className="font-semibold text-white">Ollama</div>
                <div className="mt-1 text-xs text-white/60">
                  Local inference (only if enabled).
                </div>
              </div>
              <span className="badge">Optional</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
