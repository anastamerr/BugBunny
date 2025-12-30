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
  repo_id?: string | null;
  repo_url?: string | null;
  branch: string;
  scan_type: "sast" | "dast" | "both";
  dependency_health_enabled?: boolean;
  target_url?: string | null;
  status: "pending" | "cloning" | "scanning" | "analyzing" | "completed" | "failed";
  trigger: "manual" | "webhook";
  total_findings: number;
  filtered_findings: number;
  dast_findings: number;
  error_message?: string | null;
  pr_number?: number | null;
  pr_url?: string | null;
  commit_sha?: string | null;
  commit_url?: string | null;
  detected_languages?: string[] | null;
  rulesets?: string[] | null;
  scanned_files?: number | null;
  semgrep_version?: string | null;
  created_at: string;
  updated_at: string;
}

export interface Repository {
  id: string;
  repo_url: string;
  repo_full_name?: string | null;
  default_branch: string;
  created_at: string;
  updated_at: string;
}

export interface DemoInjectScanResponse {
  scan: Scan;
  findings_created: number;
  real_findings: number;
  false_positives: number;
}

export interface Finding {
  id: string;
  scan_id: string;
  rule_id: string;
  rule_message?: string | null;
  semgrep_severity: "ERROR" | "WARNING" | "INFO";
  finding_type?: "sast" | "dast";
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
  matched_at?: string | null;
  endpoint?: string | null;
  curl_command?: string | null;
  evidence?: string[] | null;
  description?: string | null;
  remediation?: string | null;
  cve_ids?: string[] | null;
  cwe_ids?: string[] | null;
  confirmed_exploitable?: boolean;
  is_reachable?: boolean;
  reachability_score?: number | null;
  reachability_reason?: string | null;
  entry_points?: string[] | null;
  call_path?: string[] | null;
  status: "new" | "confirmed" | "dismissed";
  priority_score?: number | null;
  fix_status?: "generated" | "pr_opened" | "failed" | null;
  fix_summary?: string | null;
  fix_patch?: string | null;
  fix_pr_url?: string | null;
  fix_branch?: string | null;
  fix_error?: string | null;
  fix_confidence?: number | null;
  fix_generated_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface AutoFixResponse {
  status: "generated" | "pr_opened" | "failed";
  patch?: string | null;
  summary?: string | null;
  confidence?: number | null;
  pr_url?: string | null;
  branch?: string | null;
  error?: string | null;
  finding: Finding;
}
