import { api } from "./client";
import type { Repository } from "../types";

export const repositoriesApi = {
  list: async () => {
    const { data } = await api.get<Repository[]>("/api/repos");
    return data;
  },
  create: async (payload: { repo_url: string; default_branch?: string }) => {
    const { data } = await api.post<Repository>("/api/repos", payload);
    return data;
  },
  remove: async (id: string) => {
    await api.delete(`/api/repos/${id}`);
  },
};
