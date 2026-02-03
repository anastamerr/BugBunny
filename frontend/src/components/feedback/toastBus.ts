export type ToastTone = "info" | "success" | "warning" | "error";

export type ToastItem = {
  id: string;
  title: string;
  message?: string;
  tone: ToastTone;
  duration: number;
};

type ToastListener = (toast: ToastItem) => void;

const listeners = new Set<ToastListener>();

const buildId = () => {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `toast-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
};

export function pushToast(payload: {
  title: string;
  message?: string;
  tone?: ToastTone;
  duration?: number;
}) {
  const toast: ToastItem = {
    id: buildId(),
    title: payload.title,
    message: payload.message,
    tone: payload.tone ?? "info",
    duration: payload.duration ?? 5000,
  };
  listeners.forEach((listener) => listener(toast));
  return toast.id;
}

export function subscribeToToasts(listener: ToastListener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
