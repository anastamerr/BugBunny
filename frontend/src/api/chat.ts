import { api } from "./client";

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
};

