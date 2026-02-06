import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import {
  Bug,
  FolderGit2,
  LayoutDashboard,
  Menu,
  MessagesSquare,
  Radar,
  Settings,
  LogOut,
  X,
} from "lucide-react";

import { RealtimeListener } from "../realtime/RealtimeListener";
import { RealtimeStatus } from "../realtime/RealtimeStatus";
import { useAuth } from "../../hooks/useAuth";

const navItems = [
  { to: "/", label: "Dashboard", end: true, icon: <LayoutDashboard className="h-4 w-4" /> },
  { to: "/scans", label: "Scans", icon: <Radar className="h-4 w-4" /> },
  { to: "/repos", label: "Repositories", icon: <FolderGit2 className="h-4 w-4" /> },
  { to: "/bugs", label: "Bugs", icon: <Bug className="h-4 w-4" /> },
  { to: "/chat", label: "Chat", icon: <MessagesSquare className="h-4 w-4" /> },
  { to: "/settings", label: "Settings", icon: <Settings className="h-4 w-4" /> },
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
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Close sidebar on route change (mobile)
  const handleNavClick = () => setSidebarOpen(false);

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

      {/* Mobile top bar */}
      <div className="relative flex items-center justify-between border-b border-white/10 bg-void/80 px-4 py-3 backdrop-blur-sm lg:hidden">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-pill bg-neon-mint shadow-[0_0_20px_rgba(0,215,104,0.35)]" />
          <span className="text-xs font-semibold uppercase tracking-[0.2em] text-white/70">
            BugBunny
          </span>
        </div>
        <button
          type="button"
          className="btn-ghost h-9 w-9 justify-center p-0"
          onClick={() => setSidebarOpen(!sidebarOpen)}
          aria-label={sidebarOpen ? "Close navigation" : "Open navigation"}
          aria-expanded={sidebarOpen}
        >
          {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>

      {/* Mobile sidebar overlay */}
      {sidebarOpen ? (
        <div
          className="fixed inset-0 z-40 bg-void/60 backdrop-blur-sm lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      ) : null}

      <div className="relative mx-auto flex min-h-screen w-full max-w-7xl flex-col gap-4 p-4 lg:flex-row lg:gap-6 lg:p-6">
        <aside
          className={`surface shrink-0 p-4 lg:w-80 lg:block ${
            sidebarOpen
              ? "fixed inset-y-0 left-0 z-50 w-80 overflow-y-auto"
              : "hidden lg:block"
          }`}
        >
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-pill bg-neon-mint shadow-[0_0_28px_rgba(0,215,104,0.35)]" />
                <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/70">
                  BugBunny
                </div>
              </div>
              <div className="mt-2 text-xl font-extrabold tracking-tight">
                Context-Aware Scanner
              </div>
              <div className="mt-1 text-sm text-white/70">
                Semgrep with LLM triage for exploitability-aware findings.
              </div>
            </div>
            <img
              src="/icon.png"
              alt="BugBunny logo"
              className="h-10 w-10 rounded-card border border-white/10 bg-white/5 p-1.5"
            />
          </div>

          <nav aria-label="Main navigation" className="mt-5 flex flex-col gap-2">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                aria-label={item.label}
                className={({ isActive }) => linkClass(isActive)}
                onClick={handleNavClick}
              >
                <span className="flex items-center gap-2 truncate">
                  {item.icon}
                  <span className="truncate">{item.label}</span>
                </span>
                <span className="h-1.5 w-1.5 rounded-pill bg-white/0 transition group-[.active]:bg-void/70" />
              </NavLink>
            ))}
          </nav>

          <div className="mt-5 rounded-card border border-white/10 bg-void p-3 text-xs text-white/70">
            <div className="text-[11px] uppercase tracking-[0.2em] text-white/60">
              Signed in
            </div>
            <div className="mt-1 truncate text-sm text-white/80">
              {user?.email ?? "unknown"}
            </div>
            <button
              type="button"
              className="btn-ghost mt-3 w-full justify-center gap-2 text-xs"
              onClick={() => signOut()}
              aria-label="Sign out of your account"
            >
              <LogOut className="h-4 w-4" />
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
