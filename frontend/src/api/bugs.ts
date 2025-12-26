import { api } from "./client";
import type { BugReport } from "../types";

export type DuplicateMatch = {
  bug_id: string;
  similarity_score: number;
  title?: string;
  status?: string;
  created_at?: string;
};

export type CorrelationMatch = {
  bug_id: string;
  score: number;
  similarity_score?: number | null;
  title?: string;
  status?: string;
  created_at?: string | null;
  component?: string | null;
  severity?: string | null;
  relationship?: "duplicate" | "related";
};

export const bugsApi = {
  getAll: async (params?: { status?: string; sort?: string; limit?: number }) => {
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

  getCorrelations: async (id: string) => {
    const { data } = await api.get<CorrelationMatch[]>(`/api/bugs/${id}/correlations`);
    return data;
  },

  update: async (id: string, payload: Partial<BugReport>) => {
    const { data } = await api.patch<BugReport>(`/api/bugs/${id}`, payload);
    return data;
  },
};
