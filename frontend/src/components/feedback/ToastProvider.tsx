import type { ReactNode } from "react";
import { useEffect, useState } from "react";

import { subscribeToToasts } from "./toastBus";
import type { ToastItem } from "./toastBus";

const toneClasses: Record<ToastItem["tone"], string> = {
  info: "border-sky-400/40 bg-sky-400/10 text-sky-100",
  success: "border-neon-mint/40 bg-neon-mint/10 text-neon-mint",
  warning: "border-amber-400/40 bg-amber-400/10 text-amber-100",
  error: "border-rose-400/40 bg-rose-400/10 text-rose-200",
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  useEffect(() => {
    return subscribeToToasts((toast) => {
      setToasts((prev) => [...prev, toast]);
      window.setTimeout(() => {
        setToasts((prev) => prev.filter((item) => item.id !== toast.id));
      }, toast.duration);
    });
  }, []);

  const hasToasts = toasts.length > 0;

  return (
    <>
      {children}
      {hasToasts ? (
        <div
          aria-live="polite"
          role="status"
          className="fixed right-6 top-6 z-50 flex w-full max-w-sm flex-col gap-3"
        >
          {toasts.map((toast) => (
            <div
              key={toast.id}
              className={`rounded-card border px-4 py-3 text-sm shadow-lg shadow-black/30 ${toneClasses[toast.tone]}`}
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-sm font-semibold">{toast.title}</div>
                  {toast.message ? (
                    <div className="mt-1 text-xs text-white/70">
                      {toast.message}
                    </div>
                  ) : null}
                </div>
                <button
                  type="button"
                  className="btn-ghost text-xs"
                  onClick={() =>
                    setToasts((prev) => prev.filter((item) => item.id !== toast.id))
                  }
                >
                  Dismiss
                </button>
              </div>
            </div>
          ))}
        </div>
      ) : null}
    </>
  );
}
