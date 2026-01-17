import axios from "axios";

import { supabase } from "../lib/supabase";
import { toApiError } from "./errors";

const rawApiBase = import.meta.env.VITE_API_URL || "http://localhost:8000";
export const API_BASE = rawApiBase.replace(/\/+$/, "");

export const api = axios.create({
  baseURL: API_BASE,
  headers: {
    "Content-Type": "application/json",
  },
});

api.interceptors.request.use(async (config) => {
  const { data } = await supabase.auth.getSession();
  const token = data.session?.access_token;
  if (token) {
    config.headers.set("Authorization", `Bearer ${token}`);
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => Promise.reject(toApiError(error)),
);
