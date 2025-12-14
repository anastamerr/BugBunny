import { api } from "./client";
import type { BugReport, DataIncident, IncidentAction, IncidentPostmortem } from "../types";

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

  update: async (id: string, payload: Partial<DataIncident>) => {
    const { data } = await api.patch<DataIncident>(`/api/incidents/${id}`, payload);
    return data;
  },

  getActions: async (id: string) => {
    const { data } = await api.get<IncidentAction[]>(`/api/incidents/${id}/actions`);
    return data;
  },

  createAction: async (
    id: string,
    payload: Pick<IncidentAction, "title"> &
      Partial<Pick<IncidentAction, "description" | "owner_team" | "status" | "sort_order">>
  ) => {
    const { data } = await api.post<IncidentAction>(
      `/api/incidents/${id}/actions`,
      payload
    );
    return data;
  },

  updateAction: async (
    incidentId: string,
    actionId: string,
    payload: Partial<Pick<IncidentAction, "title" | "description" | "owner_team" | "status" | "sort_order">>
  ) => {
    const { data } = await api.patch<IncidentAction>(
      `/api/incidents/${incidentId}/actions/${actionId}`,
      payload
    );
    return data;
  },

  getPostmortem: async (id: string) => {
    const { data } = await api.get<IncidentPostmortem>(
      `/api/incidents/${id}/postmortem`
    );
    return data;
  },
};
