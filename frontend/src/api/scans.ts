import { api } from "./client";
import type { Finding, Scan } from "../types";

export const scansApi = {
  create: async (payload: {
    repo_url?: string;
    repo_id?: string;
    branch?: string;
    scan_type?: "sast" | "dast" | "both";
    target_url?: string;
    dast_consent?: boolean;
  }) => {
    const { data } = await api.post<Scan>("/api/scans", payload);
    return data;
  },

  list: async () => {
    const { data } = await api.get<Scan[]>("/api/scans");
    return data;
  },

  getById: async (id: string) => {
    const { data } = await api.get<Scan>(`/api/scans/${id}`);
    return data;
  },

  getFindings: async (
    scanId: string,
    params?: { include_false_positives?: boolean },
  ) => {
    const { data } = await api.get<Finding[]>(
      `/api/scans/${scanId}/findings`,
      { params },
    );
    return data;
  },

  updateFinding: async (
    findingId: string,
    payload: { status: "new" | "confirmed" | "dismissed" },
  ) => {
    const { data } = await api.patch<Finding>(
      `/api/findings/${findingId}`,
      payload,
    );
    return data;
  },

  listFindings: async (params?: {
    scan_id?: string;
    status?: string;
    include_false_positives?: boolean;
    limit?: number;
  }) => {
    const { data } = await api.get<Finding[]>("/api/findings", { params });
    return data;
  },
};
