import { API_BASE, api } from "./client";
import { supabase } from "../lib/supabase";

export type ChatRequest = {
  message: string;
  bug_id?: string;
  scan_id?: string;
  finding_id?: string;
};

export type ChatResponse = {
  response: string;
  used_llm: boolean;
  model?: string | null;
};

export const chatApi = {
  send: async (payload: ChatRequest) => {
    const { data } = await api.post<ChatResponse>("/api/chat", payload);
    return data;
  },
  stream: async (
    payload: ChatRequest,
    signal?: AbortSignal,
  ): Promise<Response> => {
    const { data } = await supabase.auth.getSession();
    const token = data.session?.access_token;
    return fetch(`${API_BASE}/api/chat/stream`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(payload),
      signal,
    });
  },
};

