import { api } from "./client";
import type { Correlation } from "../types";

export const correlationsApi = {
  getAll: async (params?: { bug_id?: string; incident_id?: string }) => {
    const { data } = await api.get<Correlation[]>("/api/correlations", {
      params,
    });
    return data;
  },

  getById: async (id: string) => {
    const { data } = await api.get<Correlation>(`/api/correlations/${id}`);
    return data;
  },
};
