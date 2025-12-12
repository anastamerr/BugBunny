import { api } from "./client";
import type { BugReport, DataIncident } from "../types";

export const incidentsApi = {
  getAll: async (params?: { status?: string; severity?: string }) => {
    const { data } = await api.get<DataIncident[]>("/api/incidents", { params });
    return data;
  },

  getById: async (id: string) => {
    const { data } = await api.get<DataIncident>(`/api/incidents/${id}`);
    return data;
  },

  getRelatedBugs: async (id: string) => {
    const { data } = await api.get<BugReport[]>(`/api/incidents/${id}/bugs`);
    return data;
  },
};
