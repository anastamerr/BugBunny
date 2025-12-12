export interface DataIncident {
  id: string;
  incident_id: string;
  timestamp: string;
  table_name: string;
  incident_type:
    | "SCHEMA_DRIFT"
    | "NULL_SPIKE"
    | "VOLUME_ANOMALY"
    | "FRESHNESS"
    | "DISTRIBUTION_DRIFT"
    | "VALIDATION_FAILURE";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  details: Record<string, any>;
  affected_columns: string[];
  anomaly_score: number;
  downstream_systems: string[];
  status: "ACTIVE" | "INVESTIGATING" | "RESOLVED";
  related_bugs_count?: number;
}

export interface BugReport {
  id: string;
  bug_id: string;
  source: "github" | "jira" | "manual";
  title: string;
  description?: string | null;
  created_at: string;
  reporter?: string | null;
  labels?: any;
  stack_trace?: string | null;
  classified_type: "bug" | "feature" | "question";
  classified_component: string;
  classified_severity: "critical" | "high" | "medium" | "low";
  confidence_score?: number | null;
  is_data_related: boolean;
  correlated_incident_id?: string | null;
  correlation_score?: number;
  is_duplicate: boolean;
  duplicate_of_id?: string | null;
  duplicate_score?: number | null;
  assigned_team?: string;
  status: "new" | "triaged" | "assigned" | "resolved";
  resolution_notes?: string | null;
  embedding_id?: string | null;
}

export interface Correlation {
  id: string;
  bug: BugReport;
  incident: DataIncident;
  correlation_score: number;
  explanation: string;
}

export interface BugPrediction {
  id: string;
  incident: DataIncident;
  predicted_bug_count: number;
  predicted_components: string[];
  confidence: number;
  prediction_window_hours: number;
}
