import { api } from "./client";

export type ChatRequest = {
  message: string;
  incident_id?: string;
  bug_id?: string;
  correlation_id?: string;
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

