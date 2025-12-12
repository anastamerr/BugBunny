import { api } from "./client";
import { BugReport } from "../types";

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
    const { data } = await api.get<BugReport[]>(
      `/api/bugs/${id}/duplicates`
    );
    return data;
  },
};

