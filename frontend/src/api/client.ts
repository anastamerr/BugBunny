import axios from "axios";

import { supabase } from "../lib/supabase";
import { ApiError, toApiError } from "./errors";
import { pushToast } from "../components/feedback/toastBus";

const rawApiBase = import.meta.env.VITE_API_URL || "http://localhost:8000";
export const API_BASE = rawApiBase.replace(/\/+$/, "");
const devBearerToken = (import.meta.env.VITE_DEV_BEARER_TOKEN as string | undefined)
  ?.trim();

export const api = axios.create({
  baseURL: API_BASE,
  headers: {
    "Content-Type": "application/json",
  },
});

async function resolveAuthToken(): Promise<string | undefined> {
  // In local dev, allow a manual bearer token without Supabase.
  if (devBearerToken) {
    return devBearerToken;
  }

  try {
    const { data, error } = await supabase.auth.getSession();
    if (error) {
      return undefined;
    }
    return data.session?.access_token;
  } catch {
    // Supabase may be unconfigured in local dev.
    return undefined;
  }
}

api.interceptors.request.use(async (config) => {
  const token = await resolveAuthToken();
  if (token) {
    config.headers.set("Authorization", `Bearer ${token}`);
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const apiError = toApiError(error);
    handleApiError(apiError);
    return Promise.reject(apiError);
  },
);

let lastErrorToastAt = 0;
let lastErrorMessage = "";

function handleApiError(error: ApiError) {
  if (typeof window === "undefined") return;

  if (error.status === 401) {
    pushToast({
      title: "Session expired",
      message: "Please sign in again.",
      tone: "warning",
      duration: 6000,
    });

    const current = `${window.location.pathname}${window.location.search}`;
    if (!window.location.pathname.startsWith("/login")) {
      const redirect = encodeURIComponent(current);
      window.location.href = `/login?redirect=${redirect}`;
    }
    return;
  }

  const isServerError = !error.status || error.status >= 500;
  if (!isServerError) return;

  const now = Date.now();
  if (lastErrorMessage === error.message && now - lastErrorToastAt < 4000) {
    return;
  }
  lastErrorMessage = error.message;
  lastErrorToastAt = now;

  pushToast({
    title: "Request failed",
    message: error.message,
    tone: "error",
    duration: 7000,
  });
}
