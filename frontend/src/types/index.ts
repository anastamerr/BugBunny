export interface BugReport {
  id: string;
  bug_id: string;
  source: "github" | "jira" | "manual";
  title: string;
  description?: string | null;
  created_at: string;
  reporter?: string | null;
  labels?: unknown;
  stack_trace?: string | null;
  classified_type: "bug" | "feature" | "question";
  classified_component: string;
  classified_severity: "critical" | "high" | "medium" | "low";
  confidence_score?: number | null;
  is_duplicate: boolean;
  duplicate_of_id?: string | null;
  duplicate_score?: number | null;
  assigned_team?: string;
  status: "new" | "triaged" | "assigned" | "resolved";
  resolution_notes?: string | null;
  embedding_id?: string | null;
}

export interface Scan {
  id: string;
  repo_url: string;
  branch: string;
  status: "pending" | "cloning" | "scanning" | "analyzing" | "completed" | "failed";
  trigger: "manual" | "webhook";
  total_findings: number;
  filtered_findings: number;
  error_message?: string | null;
  pr_number?: number | null;
  pr_url?: string | null;
  commit_sha?: string | null;
  commit_url?: string | null;
  created_at: string;
  updated_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  rule_id: string;
  rule_message?: string | null;
  semgrep_severity: "ERROR" | "WARNING" | "INFO";
  ai_severity?: "critical" | "high" | "medium" | "low" | "info" | null;
  is_false_positive: boolean;
  ai_reasoning?: string | null;
  ai_confidence?: number | null;
  exploitability?: string | null;
  file_path: string;
  line_start: number;
  line_end: number;
  code_snippet?: string | null;
  context_snippet?: string | null;
  function_name?: string | null;
  class_name?: string | null;
  is_test_file: boolean;
  is_generated: boolean;
  imports?: string[] | null;
  status: "new" | "confirmed" | "dismissed";
  priority_score?: number | null;
  created_at: string;
  updated_at: string;
}
