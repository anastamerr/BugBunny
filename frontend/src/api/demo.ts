import { api } from "./client";
import type { DemoInjectScanResponse } from "../types";

export const demoApi = {
  injectScan: async (payload?: {
    repo_url?: string;
    branch?: string;
    scan_type?: "sast" | "dast" | "both";
    target_url?: string;
    real_findings?: number;
    false_positives?: number;
  }) => {
    const { data } = await api.post<DemoInjectScanResponse>(
      "/api/demo/inject-scan",
      payload ?? {},
    );
    return data;
  },
};
