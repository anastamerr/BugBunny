import { api } from "./client";

export type ProfileSettings = {
  github_token_set: boolean;
  github_webhook_secret_set: boolean;
  github_allowlist: string[];
  enable_scan_push: boolean;
  enable_scan_pr: boolean;
  enable_issue_ingest: boolean;
  enable_issue_comment_ingest: boolean;
};

export type Profile = {
  user_id: string;
  email?: string | null;
  settings: ProfileSettings;
};

export type ProfileUpdate = {
  github_token?: string | null;
  github_webhook_secret?: string | null;
  github_allowlist?: string[];
  enable_scan_push?: boolean;
  enable_scan_pr?: boolean;
  enable_issue_ingest?: boolean;
  enable_issue_comment_ingest?: boolean;
};

export const profileApi = {
  get: async () => {
    const { data } = await api.get<Profile>("/api/profile");
    return data;
  },
  update: async (payload: ProfileUpdate) => {
    const { data } = await api.patch<Profile>("/api/profile", payload);
    return data;
  },
};
