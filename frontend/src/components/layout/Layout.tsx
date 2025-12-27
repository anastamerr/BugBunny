import { NavLink, Outlet } from "react-router-dom";

import { RealtimeListener } from "../realtime/RealtimeListener";
import { RealtimeStatus } from "../realtime/RealtimeStatus";
import { useAuth } from "../../hooks/useAuth";

const navItems = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/scans", label: "Scans" },
  { to: "/repos", label: "Repositories" },
  { to: "/bugs", label: "Bugs" },
  { to: "/chat", label: "Chat" },
  { to: "/settings", label: "Settings" },
];

function linkClass(isActive: boolean) {
  return [
    "group flex items-center justify-between rounded-pill border border-white/10 px-4 py-2 text-sm font-semibold tracking-tight transition-colors duration-200 ease-fluid",
    isActive
      ? "active bg-neon-mint text-void border-transparent"
      : "text-white/80 hover:border-neon-mint/40 hover:bg-white/5 hover:text-white",
  ].join(" ");
}

export function Layout() {
  const { user, signOut } = useAuth();

  return (
    <div className="relative min-h-screen bg-void text-white">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 overflow-hidden"
      >
        <div className="absolute -top-48 left-1/2 h-[720px] w-[720px] -translate-x-1/2 rounded-full bg-neon-mint/10 blur-3xl" />
        <div className="absolute -bottom-52 left-0 h-[640px] w-[640px] rounded-full bg-neon-mint/5 blur-3xl" />
      </div>
      <RealtimeListener />
      <div className="relative mx-auto flex min-h-screen w-full max-w-7xl flex-col gap-4 p-4 lg:flex-row lg:gap-6 lg:p-6">
        <aside className="surface w-full p-4 lg:w-80">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-pill bg-neon-mint shadow-[0_0_28px_rgba(0,215,104,0.35)]" />
                <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                  ScanGuard AI
                </div>
              </div>
              <div className="mt-2 text-xl font-extrabold tracking-tight">
                Context-Aware Scanner
              </div>
              <div className="mt-1 text-sm text-white/60">
                Semgrep with LLM triage for exploitability-aware findings.
              </div>
            </div>
            <img
              src="/icon.png"
              alt="ScanGuard AI logo"
              className="h-10 w-10 rounded-card border border-white/10 bg-white/5 p-1.5"
            />
          </div>

          <nav className="mt-5 flex flex-wrap gap-2 lg:flex-col">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) => linkClass(isActive)}
              >
                <span className="truncate">{item.label}</span>
                <span className="h-1.5 w-1.5 rounded-pill bg-white/0 transition group-[.active]:bg-void/70" />
              </NavLink>
            ))}
          </nav>

          <div className="mt-5 rounded-card border border-white/10 bg-void p-3 text-xs text-white/70">
            <div className="text-[11px] uppercase tracking-[0.2em] text-white/50">
              Signed in
            </div>
            <div className="mt-1 truncate text-sm text-white/80">
              {user?.email ?? "unknown"}
            </div>
            <button
              type="button"
              className="btn-ghost mt-3 w-full justify-center text-xs"
              onClick={() => signOut()}
            >
              Sign out
            </button>
          </div>

          <div className="mt-5">
            <RealtimeStatus />
          </div>
        </aside>

        <main className="flex-1">
          <div className="surface min-h-[calc(100vh-2rem)] p-4 lg:min-h-[calc(100vh-3rem)] lg:p-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
