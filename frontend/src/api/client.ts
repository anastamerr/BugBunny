import axios from "axios";

import { supabase } from "../lib/supabase";
import { toApiError } from "./errors";

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
  (error) => Promise.reject(toApiError(error)),
);
