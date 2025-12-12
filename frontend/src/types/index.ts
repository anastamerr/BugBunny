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
  description: string;
  created_at: string;
  classified_type: "bug" | "feature" | "question";
  classified_component: string;
  classified_severity: "critical" | "high" | "medium" | "low";
  is_data_related: boolean;
  correlation_score?: number;
  correlated_incident?: DataIncident;
  is_duplicate: boolean;
  duplicate_of?: BugReport;
  assigned_team?: string;
  status: "new" | "triaged" | "assigned" | "resolved";
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

