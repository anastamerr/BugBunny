import { useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { CheckCircle2, Copy, RefreshCw } from "lucide-react";

import { incidentsApi } from "../api/incidents";
import type { DataIncident, IncidentAction } from "../types";

function badgeForIncidentStatus(status: DataIncident["status"]) {
  if (status === "ACTIVE") {
    return "badge border-neon-mint/40 bg-neon-mint/10 text-neon-mint";
  }
  if (status === "RESOLVED") {
    return "badge border-white/10 bg-white/5 text-white/80";
  }
  return "badge";
}

function badgeForActionStatus(status: IncidentAction["status"]) {
  if (status === "done") {
    return "badge border-neon-mint/40 bg-neon-mint/10 text-neon-mint";
  }
  if (status === "doing") {
    return "badge border-white/10 bg-white/5 text-white/80";
  }
  return "badge";
}

function safeDate(value?: string | null) {
  if (!value) return "—";
  const dt = new Date(value);
  return Number.isNaN(dt.getTime()) ? "—" : dt.toLocaleString();
}

export default function IncidentDetail() {
  const { id } = useParams();
  const queryClient = useQueryClient();
  const workflowFormRef = useRef<HTMLFormElement | null>(null);

  const { data: incident, isLoading } = useQuery({
    queryKey: ["incidents", id],
    queryFn: () => incidentsApi.getById(id as string),
    enabled: Boolean(id),
  });

  const { data: actions } = useQuery({
    queryKey: ["incidents", id, "actions"],
    queryFn: () => incidentsApi.getActions(id as string),
    enabled: Boolean(id),
  });

  const { data: relatedBugs } = useQuery({
    queryKey: ["incidents", id, "bugs"],
    queryFn: () => incidentsApi.getRelatedBugs(id as string),
    enabled: Boolean(id),
  });

  const updateIncidentMutation = useMutation({
    mutationFn: async (
      payload: Partial<Pick<DataIncident, "status" | "resolution_notes">>
    ) => incidentsApi.update(id as string, payload),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
  });

  const updateActionMutation = useMutation({
    mutationFn: async (payload: { actionId: string; patch: Partial<IncidentAction> }) =>
      incidentsApi.updateAction(id as string, payload.actionId, payload.patch),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
  });

  const [newActionTitle, setNewActionTitle] = useState("");
  const [newActionDescription, setNewActionDescription] = useState("");
  const [newActionOwner, setNewActionOwner] = useState("");

  const createActionMutation = useMutation({
    mutationFn: async () =>
      incidentsApi.createAction(id as string, {
        title: newActionTitle.trim(),
        description: newActionDescription.trim() || undefined,
        owner_team: newActionOwner.trim() || undefined,
      }),
    onSuccess: async () => {
      setNewActionTitle("");
      setNewActionDescription("");
      setNewActionOwner("");
      await queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
  });

  const postmortemQuery = useQuery({
    queryKey: ["incidents", id, "postmortem"],
    queryFn: () => incidentsApi.getPostmortem(id as string),
    enabled: false,
  });

  const actionProgress = useMemo(() => {
    const list = actions || [];
    const done = list.filter((a) => a.status === "done").length;
    return { done, total: list.length };
  }, [actions]);

  const [copied, setCopied] = useState(false);

  const canCreateAction = Boolean(id) && newActionTitle.trim().length > 0;

  if (!id) {
    return (
      <div className="space-y-6">
        <div className="surface-solid p-6">
          <h1 className="text-2xl font-extrabold tracking-tight text-white">
            Incident
          </h1>
          <p className="mt-1 text-sm text-white/60">Missing incident id.</p>
        </div>
      </div>
    );
  }

  if (isLoading || !incident) {
    return (
      <div className="space-y-6">
        <div className="surface-solid p-6">
          <h1 className="text-2xl font-extrabold tracking-tight text-white">
            Incident
          </h1>
          <p className="mt-1 text-sm text-white/60">Loading...</p>
        </div>
      </div>
    );
  }

  async function onSaveIncident() {
    if (!incident) return;
    if (!workflowFormRef.current) return;
    const data = new FormData(workflowFormRef.current);
    const status = data.get("status");
    const notes = data.get("resolution_notes");

    const statusValue =
      status === "ACTIVE" || status === "INVESTIGATING" || status === "RESOLVED"
        ? status
        : incident.status;
    const notesValue = typeof notes === "string" ? notes.trim() : "";

    await updateIncidentMutation.mutateAsync({
      status: statusValue,
      resolution_notes: notesValue.length ? notesValue : null,
    });
  }

  async function onToggleAction(action: IncidentAction) {
    const next =
      action.status === "todo"
        ? "doing"
        : action.status === "doing"
          ? "done"
          : "todo";
    await updateActionMutation.mutateAsync({
      actionId: action.id,
      patch: { status: next },
    });
  }

  async function onCopyPostmortem() {
    const text = postmortemQuery.data?.markdown;
    if (!text) return;
    await navigator.clipboard.writeText(text);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  }

  return (
    <div className="space-y-6">
      <div className="surface-solid p-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="badge font-mono text-white/80">{incident.incident_id}</span>
              <span className={badgeForIncidentStatus(incident.status)}>
                {incident.status}
              </span>
              <span className="badge">{incident.severity}</span>
              <span className="badge">{incident.incident_type}</span>
            </div>
            <h1 className="mt-3 truncate text-2xl font-extrabold tracking-tight text-white">
              {incident.table_name}
            </h1>
            <p className="mt-1 text-sm text-white/60">
              Detected {safeDate(incident.timestamp)} • Resolved{" "}
              {safeDate(incident.resolved_at)}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Link to="/incidents" className="btn-ghost">
              Back
            </Link>
            <button
              type="button"
              className="btn-primary"
              onClick={() => postmortemQuery.refetch()}
              disabled={postmortemQuery.isFetching}
            >
              <RefreshCw className="mr-2 h-4 w-4" />
              {postmortemQuery.isFetching ? "Generating..." : "Postmortem"}
            </button>
          </div>
        </div>

        <div className="mt-5 grid grid-cols-1 gap-4 lg:grid-cols-3">
          <div className="rounded-card border border-white/10 bg-surface p-4 lg:col-span-2">
            <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
              Blast Radius
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {(incident.downstream_systems || []).length ? (
                incident.downstream_systems?.slice(0, 12).map((s) => (
                  <span key={s} className="badge">
                    {s}
                  </span>
                ))
              ) : (
                <span className="text-sm text-white/60">No downstream systems.</span>
              )}
            </div>
            {(incident.affected_columns || []).length ? (
              <div className="mt-3 text-sm text-white/60">
                Affected columns:{" "}
                <span className="text-white/80">
                  {(incident.affected_columns || []).join(", ")}
                </span>
              </div>
            ) : null}
          </div>

          <div className="rounded-card border border-white/10 bg-surface p-4">
            <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
              Ops Snapshot
            </div>
            <div className="mt-3 grid grid-cols-2 gap-x-3 gap-y-2 text-sm">
              <div className="text-white/60">Playbook</div>
              <div className="font-semibold text-white">
                {actionProgress.done}/{actionProgress.total}
              </div>
              <div className="text-white/60">Correlated bugs</div>
              <div className="font-semibold text-white">{(relatedBugs || []).length}</div>
            </div>
          </div>
        </div>

        <form
          ref={workflowFormRef}
          key={incident.id}
          className="mt-4 rounded-card border border-white/10 bg-surface p-4"
        >
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <div className="lg:col-span-1">
              <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                Update Status
              </div>
              <select className="input mt-3 w-full" name="status" defaultValue={incident.status}>
                <option value="ACTIVE">ACTIVE</option>
                <option value="INVESTIGATING">INVESTIGATING</option>
                <option value="RESOLVED">RESOLVED</option>
              </select>

              <button
                type="button"
                className="btn-primary mt-3 w-full"
                onClick={onSaveIncident}
                disabled={updateIncidentMutation.isPending}
              >
                {updateIncidentMutation.isPending ? "Saving..." : "Save"}
              </button>
            </div>

            <div className="lg:col-span-2">
              <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
                Resolution Notes
              </div>
              <textarea
                className="mt-3 min-h-[96px] w-full resize-y rounded-card border-2 border-white/10 bg-void px-4 py-3 text-sm text-white placeholder-white/30 outline-none transition-colors duration-200 ease-fluid focus:border-neon-mint"
                name="resolution_notes"
                placeholder="What fixed it? Links to PRs/runbooks/follow-ups..."
                defaultValue={incident.resolution_notes || ""}
              />
            </div>
          </div>
        </form>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="surface-solid p-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-sm font-semibold tracking-tight text-white">
                Smart Playbook
              </div>
              <div className="mt-1 text-sm text-white/60">
                {actionProgress.done}/{actionProgress.total} completed
              </div>
            </div>
            <div className="badge border-neon-mint/40 bg-neon-mint/10 text-neon-mint">
              Auto-generated
            </div>
          </div>

          <div className="mt-4 space-y-2">
            {(actions || []).map((action) => (
              <button
                key={action.id}
                type="button"
                onClick={() => onToggleAction(action)}
                className="group w-full rounded-card border border-white/10 bg-surface px-4 py-3 text-left transition-colors duration-200 ease-fluid hover:border-neon-mint/40"
                disabled={updateActionMutation.isPending}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      {action.status === "done" ? (
                        <CheckCircle2 className="h-4 w-4 text-neon-mint" />
                      ) : (
                        <div className="h-4 w-4 rounded-pill border border-white/20 bg-void" />
                      )}
                      <div className="truncate text-sm font-semibold text-white">
                        {action.title}
                      </div>
                    </div>
                    {action.description ? (
                      <div className="mt-2 text-sm text-white/60">
                        {action.description}
                      </div>
                    ) : null}
                    {action.owner_team ? (
                      <div className="mt-2 text-xs text-white/60">
                        Owner:{" "}
                        <span className="font-mono text-white/80">
                          {action.owner_team}
                        </span>
                      </div>
                    ) : null}
                  </div>
                  <span className={badgeForActionStatus(action.status)}>{action.status}</span>
                </div>
              </button>
            ))}
          </div>

          <div className="mt-5 rounded-card border border-white/10 bg-surface p-4">
            <div className="text-xs font-semibold uppercase tracking-[0.2em] text-white/60">
              Add Action
            </div>
            <div className="mt-3 grid grid-cols-1 gap-2">
              <input
                className="input w-full"
                placeholder="Action title"
                value={newActionTitle}
                onChange={(e) => setNewActionTitle(e.target.value)}
              />
              <input
                className="input w-full"
                placeholder="Owner team (optional)"
                value={newActionOwner}
                onChange={(e) => setNewActionOwner(e.target.value)}
              />
              <textarea
                className="min-h-[84px] w-full resize-y rounded-card border-2 border-white/10 bg-void px-4 py-3 text-sm text-white placeholder-white/30 outline-none transition-colors duration-200 ease-fluid focus:border-neon-mint"
                placeholder="Description (optional)"
                value={newActionDescription}
                onChange={(e) => setNewActionDescription(e.target.value)}
              />
              <button
                type="button"
                className="btn-primary w-full"
                onClick={() => createActionMutation.mutate()}
                disabled={!canCreateAction || createActionMutation.isPending}
              >
                {createActionMutation.isPending ? "Adding..." : "Add to Playbook"}
              </button>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="surface-solid p-6">
            <div className="text-sm font-semibold tracking-tight text-white">
              Related Bugs
            </div>
            <div className="mt-1 text-sm text-white/60">
              {(relatedBugs || []).length} correlated
            </div>

            <div className="mt-4 space-y-2">
              {(relatedBugs || []).length === 0 ? (
                <div className="text-sm text-white/60">No correlated bugs yet.</div>
              ) : (
                (relatedBugs || []).slice(0, 10).map((bug) => (
                  <Link
                    key={bug.id}
                    to={`/bugs/${bug.id}`}
                    className="block rounded-card border border-white/10 bg-surface px-4 py-3 transition-colors duration-200 ease-fluid hover:border-neon-mint/40"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="truncate text-sm font-semibold text-white">
                          {bug.title}
                        </div>
                        <div className="mt-1 text-xs text-white/60">
                          {bug.classified_component} • {bug.classified_severity}
                        </div>
                      </div>
                      <span className="badge">{bug.status}</span>
                    </div>
                  </Link>
                ))
              )}
            </div>
          </div>

          {postmortemQuery.data ? (
            <div className="surface-solid overflow-hidden">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 bg-surface px-5 py-4">
                <div>
                  <div className="text-sm font-semibold tracking-tight text-white">
                    Postmortem (Markdown)
                  </div>
                  <div className="mt-1 text-xs text-white/60">
                    Generated {safeDate(postmortemQuery.data.generated_at)}
                  </div>
                </div>
                <button
                  type="button"
                  className="btn-ghost"
                  onClick={onCopyPostmortem}
                  disabled={!postmortemQuery.data?.markdown}
                >
                  <Copy className="mr-2 h-4 w-4" />
                  {copied ? "Copied" : "Copy"}
                </button>
              </div>
              <pre className="max-h-[520px] overflow-auto p-5 text-xs leading-relaxed text-white/80">
                {postmortemQuery.data.markdown}
              </pre>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
