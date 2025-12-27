import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";

import { API_BASE } from "../api/client";
import { profileApi, type ProfileUpdate } from "../api/profile";
import { useAuth } from "../hooks/useAuth";

function parseAllowlist(value: string) {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export default function Profile() {
  const { user } = useAuth();
  const { data, isLoading, error } = useQuery({
    queryKey: ["profile"],
    queryFn: () => profileApi.get(),
  });

  const [githubToken, setGithubToken] = useState("");
  const [tokenTouched, setTokenTouched] = useState(false);
  const [webhookSecret, setWebhookSecret] = useState("");
  const [secretTouched, setSecretTouched] = useState(false);
  const [allowlist, setAllowlist] = useState("");
  const [allowlistTouched, setAllowlistTouched] = useState(false);
  const [initialized, setInitialized] = useState(false);
  const [flags, setFlags] = useState({
    enable_scan_push: true,
    enable_scan_pr: true,
    enable_issue_ingest: true,
    enable_issue_comment_ingest: true,
  });

  useEffect(() => {
    if (!data || initialized) return;
    setFlags({
      enable_scan_push: data.settings.enable_scan_push,
      enable_scan_pr: data.settings.enable_scan_pr,
      enable_issue_ingest: data.settings.enable_issue_ingest,
      enable_issue_comment_ingest: data.settings.enable_issue_comment_ingest,
    });
    setAllowlist(data.settings.github_allowlist.join("\n"));
    setAllowlistTouched(false);
    setInitialized(true);
  }, [data, initialized]);

  const updateProfile = useMutation({
    mutationFn: async () => {
      const payload: ProfileUpdate = {
        ...flags,
      };
      if (tokenTouched) {
        payload.github_token = githubToken;
      }
      if (secretTouched) {
        payload.github_webhook_secret = webhookSecret;
      }
      if (allowlistTouched) {
        payload.github_allowlist = parseAllowlist(allowlist);
      }
      return profileApi.update(payload);
    },
    onSuccess: (next) => {
      setGithubToken("");
      setWebhookSecret("");
      setTokenTouched(false);
      setSecretTouched(false);
      setAllowlist(next.settings.github_allowlist.join("\n"));
      setAllowlistTouched(false);
      setFlags({
        enable_scan_push: next.settings.enable_scan_push,
        enable_scan_pr: next.settings.enable_scan_pr,
        enable_issue_ingest: next.settings.enable_issue_ingest,
        enable_issue_comment_ingest: next.settings.enable_issue_comment_ingest,
      });
    },
  });

  const webhookUrl = `${API_BASE}/api/webhooks/github`;

  return (
    <div className="space-y-6">
      <div className="surface-solid p-6">
        <h1 className="text-2xl font-extrabold tracking-tight text-white">
          Profile
        </h1>
        <p className="mt-1 text-sm text-white/60">
          Manage your credentials and webhook preferences.
        </p>
      </div>

      {error ? (
        <div className="surface-solid p-4 text-sm text-rose-200">
          {error instanceof Error ? error.message : "Unable to load profile."}
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="surface-solid p-6">
          <div className="text-sm font-semibold tracking-tight text-white">
            Account
          </div>
          {isLoading ? (
            <div className="mt-4 space-y-2 text-xs text-white/50">
              <div className="h-4 w-32 rounded-pill bg-white/5" />
              <div className="h-4 w-64 rounded-pill bg-white/5" />
            </div>
          ) : (
            <div className="mt-4 space-y-3 text-sm text-white/70">
              <div>
                <div className="text-xs uppercase tracking-[0.2em] text-white/50">
                  Email
                </div>
                <div className="mt-1 text-white">{user?.email ?? "n/a"}</div>
              </div>
              <div>
                <div className="text-xs uppercase tracking-[0.2em] text-white/50">
                  JWT verified ID
                </div>
                <div className="mt-1 font-mono text-xs text-white/80">
                  {data?.user_id ?? "n/a"}
                </div>
              </div>
              <div>
                <div className="text-xs uppercase tracking-[0.2em] text-white/50">
                  Webhook URL
                </div>
                <div className="mt-1 break-all font-mono text-xs text-white/80">
                  {webhookUrl}
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="surface-solid p-6">
          <div className="text-sm font-semibold tracking-tight text-white">
            Webhook preferences
          </div>
          <div className="mt-4 space-y-3 text-sm text-white/70">
            <label className="flex items-center justify-between gap-3">
              <span>Trigger scans on push events</span>
              <input
                type="checkbox"
                checked={flags.enable_scan_push}
                onChange={(event) =>
                  setFlags((prev) => ({
                    ...prev,
                    enable_scan_push: event.target.checked,
                  }))
                }
              />
            </label>
            <label className="flex items-center justify-between gap-3">
              <span>Trigger scans on pull requests</span>
              <input
                type="checkbox"
                checked={flags.enable_scan_pr}
                onChange={(event) =>
                  setFlags((prev) => ({
                    ...prev,
                    enable_scan_pr: event.target.checked,
                  }))
                }
              />
            </label>
            <label className="flex items-center justify-between gap-3">
              <span>Ingest GitHub issues</span>
              <input
                type="checkbox"
                checked={flags.enable_issue_ingest}
                onChange={(event) =>
                  setFlags((prev) => ({
                    ...prev,
                    enable_issue_ingest: event.target.checked,
                  }))
                }
              />
            </label>
            <label className="flex items-center justify-between gap-3">
              <span>Ingest issue comments</span>
              <input
                type="checkbox"
                checked={flags.enable_issue_comment_ingest}
                onChange={(event) =>
                  setFlags((prev) => ({
                    ...prev,
                    enable_issue_comment_ingest: event.target.checked,
                  }))
                }
              />
            </label>
          </div>
        </div>
      </div>

      <div className="surface-solid p-6">
        <div className="text-sm font-semibold tracking-tight text-white">
          GitHub credentials
        </div>
        <p className="mt-1 text-sm text-white/60">
          Store credentials securely to scan private repositories and validate
          webhooks.
        </p>

        <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                GitHub token
              </label>
              {data?.settings.github_token_set ? (
                <span className="badge border-neon-mint/40 bg-neon-mint/10 text-neon-mint">
                  Saved
                </span>
              ) : null}
            </div>
            <div className="input-group">
              <svg
                className="input-icon h-4 w-4"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
                />
              </svg>
              <input
                className="input input-with-icon w-full"
                type="password"
                placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                value={githubToken}
                onChange={(event) => {
                  setGithubToken(event.target.value);
                  setTokenTouched(true);
                }}
              />
            </div>
            <p className="mt-2 text-xs text-white/40">
              Personal access token for private repository access
            </p>
            <button
              type="button"
              className="btn-ghost mt-3 text-xs"
              onClick={() => {
                setGithubToken("");
                setTokenTouched(true);
              }}
            >
              Clear token
            </button>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                Webhook secret
              </label>
              {data?.settings.github_webhook_secret_set ? (
                <span className="badge border-neon-mint/40 bg-neon-mint/10 text-neon-mint">
                  Saved
                </span>
              ) : null}
            </div>
            <div className="input-group">
              <svg
                className="input-icon h-4 w-4"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                />
              </svg>
              <input
                className="input input-with-icon w-full"
                type="password"
                placeholder="your-webhook-secret"
                value={webhookSecret}
                onChange={(event) => {
                  setWebhookSecret(event.target.value);
                  setSecretTouched(true);
                }}
              />
            </div>
            <p className="mt-2 text-xs text-white/40">
              Secret used to verify webhook payloads
            </p>
            <button
              type="button"
              className="btn-ghost mt-3 text-xs"
              onClick={() => {
                setWebhookSecret("");
                setSecretTouched(true);
              }}
            >
              Clear secret
            </button>
          </div>
        </div>

        <div className="mt-6">
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
              Webhook allowlist
            </label>
            {allowlist.trim() && (
              <span className="text-xs text-white/40">
                {parseAllowlist(allowlist).length} repositories
              </span>
            )}
          </div>
          <textarea
            className="input-textarea min-h-[140px] w-full font-mono text-sm leading-relaxed"
            placeholder={"org/repo\nhttps://github.com/org/repo\nowner/another-repo"}
            value={allowlist}
            onChange={(event) => {
              setAllowlist(event.target.value);
              setAllowlistTouched(true);
            }}
          />
          <p className="mt-2 text-xs text-white/40">
            Enter repository names (owner/repo) or GitHub URLs, one per line
          </p>
        </div>

        <div className="mt-6 flex flex-wrap items-center gap-3">
          <button
            type="button"
            className="btn-primary"
            onClick={() => updateProfile.mutate()}
            disabled={updateProfile.isPending}
          >
            {updateProfile.isPending ? "Saving..." : "Save settings"}
          </button>
          {updateProfile.isError ? (
            <span className="text-sm text-rose-200">
              {updateProfile.error instanceof Error
                ? updateProfile.error.message
                : "Failed to save settings."}
            </span>
          ) : null}
          {updateProfile.isSuccess ? (
            <span className="text-sm text-neon-mint">Saved.</span>
          ) : null}
        </div>
      </div>
    </div>
  );
}
