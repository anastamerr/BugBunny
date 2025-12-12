import { NavLink, Outlet } from "react-router-dom";

import { RealtimeListener } from "../realtime/RealtimeListener";

const navItems = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/incidents", label: "Incidents" },
  { to: "/bugs", label: "Bugs" },
  { to: "/correlations", label: "Correlations" },
  { to: "/predictions", label: "Predictions" },
  { to: "/chat", label: "Chat" },
  { to: "/settings", label: "Settings" },
];

function linkClass(isActive: boolean) {
  return [
    "block rounded-md px-3 py-2 text-sm font-medium",
    isActive ? "bg-gray-900 text-white" : "text-gray-700 hover:bg-gray-100",
  ].join(" ");
}

export function Layout() {
  return (
    <div className="flex h-full bg-gray-50 text-gray-900">
      <RealtimeListener />
      <aside className="w-64 border-r bg-white p-4">
        <div className="mb-6 text-xl font-semibold">DataBug AI</div>
        <nav className="space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => linkClass(isActive)}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>

      <main className="flex-1 overflow-auto p-6">
        <Outlet />
      </main>
    </div>
  );
}
