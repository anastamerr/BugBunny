import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";

import { useAuth } from "../../hooks/useAuth";

export function isDevBypassEnabled() {
  return (
    String(import.meta.env.VITE_DEV_AUTH_BYPASS).toLowerCase() === "true" ||
    Boolean(import.meta.env.VITE_DEV_BEARER_TOKEN)
  );
}

export function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();
  const devBypass = isDevBypassEnabled();

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-void text-white">
        <div className="surface-solid px-6 py-4 text-sm text-white/70">
          Loading session…
        </div>
      </div>
    );
  }

  if (!user && !devBypass) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }

  return children;
}
