import { api } from "./client";
import type { BugReport } from "../types";

export type DuplicateMatch = {
  bug_id: string;
  similarity_score: number;
  title?: string;
  status?: string;
  created_at?: string;
};

export const bugsApi = {
  getAll: async (params?: { status?: string; is_data_related?: boolean }) => {
    const { data } = await api.get<BugReport[]>("/api/bugs", { params });
    return data;
  },

  getById: async (id: string) => {
    const { data } = await api.get<BugReport>(`/api/bugs/${id}`);
    return data;
  },

  getDuplicates: async (id: string) => {
    const { data } = await api.get<DuplicateMatch[]>(`/api/bugs/${id}/duplicates`);
    return data;
  },

  update: async (id: string, payload: Partial<BugReport>) => {
    const { data } = await api.patch<BugReport>(`/api/bugs/${id}`, payload);
    return data;
  },
};
