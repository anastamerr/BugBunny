# DataBug AI: Data-Aware Intelligent Bug Triage Platform

## Team: CSIS

---

## Executive Summary

DataBug AI is an open-source platform that revolutionizes bug triage by making it **data-pipeline-aware**. By combining **Automated Data Pipeline Validation & Monitoring** with **Bug Triage Automation**, we create an intelligent system that understands the critical connection between data quality issues and downstream bugs.

**The core insight**: Research shows that **72% of data quality issues are discovered only after they've affected business decisions** - meaning bugs are often filed long after the root cause (a data pipeline failure) occurred. DataBug AI bridges this gap by automatically correlating incoming bug reports with upstream data quality incidents, dramatically reducing time-to-root-cause.

This is critical for data-intensive organizations like Unifonic processing **10B+ annual transactions**, where a single data quality issue can cascade into hundreds of bug reports across dashboards, APIs, and applications.

---

## Selected Tracks

| Track | Name | Weight in Solution |
|-------|------|-------------------|
| **Track 4** | Bug Triage Automation | 50% |
| **Track 5** | Automated Data Pipeline Validation & Monitoring | 50% |

---

## Problem Statement

### The Hidden Connection Between Data Issues and Bugs

#### The Data Quality Crisis

| Statistic | Source | Impact |
|-----------|--------|--------|
| **72%** of data issues found after business impact | DataChecks 2024 | Late detection = cascading failures |
| **40%** of data team time spent troubleshooting | Industry Research | Massive productivity drain |
| **67%** of organizations don't trust their data | Precisely 2024 | Decision-making compromised |
| **89%** increase in governance challenges (2023→2024) | Precisely Survey | Growing complexity |

#### How Data Issues Become Bugs

```
Data Pipeline Issue (Root Cause)
        ↓
    [TIME DELAY: Hours to Days]
        ↓
Downstream System Affected
        ↓
    [USER NOTICES PROBLEM]
        ↓
Bug Report Filed (Symptom)
        ↓
    [TRIAGE TEAM INVESTIGATES]
        ↓
Hours/Days Spent Finding Root Cause
```

**Real-World Cascade Example**:
```
1. Schema drift: Column renamed from 'user_id' to 'userId' in source system
        ↓
2. ETL job silently produces NULL values for 3 hours
        ↓
3. Analytics dashboard shows $0 revenue (bug report #1)
        ↓
4. API returns empty user profiles (bug report #2)
        ↓
5. Mobile app crashes on null pointer (bug report #3)
        ↓
6. ML model predicts incorrectly (bug report #4)
        ↓
7. Customer complaints spike (bug report #5-50)
        ↓
8. After 6 hours of investigation, root cause found: schema drift
```

**Without correlation**: 50 separate bug investigations, each taking 1-2 hours
**With DataBug AI**: Single root cause identified in minutes, all bugs linked

#### The Bug Triage Bottleneck

| Challenge | Current State | Business Impact |
|-----------|---------------|-----------------|
| Manual classification | 15-30 min per bug | Slow response times |
| Duplicate detection | 60% accuracy | Fragmented effort |
| Root cause analysis | Hours of investigation | Delayed resolution |
| Data vs. code confusion | No visibility | Wrong team assigned |
| Priority assessment | Subjective | Critical bugs buried |

#### Why Current Tools Fail

**Data Quality Tools** (Great Expectations, Deequ):
- Monitor pipelines in isolation
- Alert on data issues
- No connection to downstream bug reports

**Bug Triage Tools** (Jira, Linear, GitHub Issues):
- Classify and assign bugs
- No awareness of data pipeline health
- Can't identify data-related root causes

**The Gap**: No tool connects data quality incidents to the bugs they cause.

---

## Our Solution: DataBug AI

### Core Value Proposition

A unified platform that:
1. **Monitors data pipelines** continuously for quality issues
2. **Triages incoming bugs** automatically with AI classification
3. **Correlates bugs with data incidents** to identify root causes
4. **Groups related bugs** caused by the same data issue
5. **Routes to the right team** (data team vs. dev team)
6. **Learns patterns** to predict and prevent future issues

### Architecture Overview

```
                          +---------------------------+
                          |      DataBug AI API       |
                          +---------------------------+
                                      |
            +-------------------------+-------------------------+
            |                                                   |
   +--------v---------+                            +-----------v-----------+
   |  Data Pipeline   |                            |    Bug Triage         |
   |  Monitor         |                            |    Engine             |
   +------------------+                            +-----------------------+
   | Great Expectations|                            | DeepTriage Model     |
   | Deequ (Spark)    |                            | CodeBERT Classifier  |
   | DQOps            |                            | RoBERTa for NLP      |
   | Custom Anomaly   |                            | Duplicate Detector   |
   |   Detection      |                            | Severity Predictor   |
   +------------------+                            +-----------------------+
            |                                                   |
            |     +----------------------------------+          |
            +---->|     Correlation Engine          |<---------+
                  +----------------------------------+
                  | - Temporal Analysis              |
                  | - Impact Graph Builder           |
                  | - Root Cause Ranker              |
                  | - Bug Clustering                 |
                  +----------------------------------+
                                |
            +-------------------+-------------------+
            |                   |                   |
   +--------v--------+  +-------v-------+  +-------v--------+
   | Data Incident   |  | Bug Cluster   |  | Smart Router   |
   | Timeline        |  | View          |  | & Assigner     |
   +-----------------+  +---------------+  +----------------+
            |                   |                   |
            +-------------------+-------------------+
                                |
                    +-----------v-----------+
                    |   Unified Dashboard   |
                    |   (Grafana + Custom)  |
                    +-----------------------+
```

### Core Components

#### Module 1: Data Pipeline Monitor

**Purpose**: Continuously validate data quality and detect anomalies across all pipelines

**Open-Source Stack** (from PDF + research):

| Tool | Function | Use Case |
|------|----------|----------|
| **Great Expectations** | Expectation-based validation | Schema, null checks, ranges |
| **Deequ** | Spark-based data quality | Large-scale metrics computation |
| **DQOps** | ML anomaly detection | Drift detection, pattern learning |
| **PyOD** | Outlier detection | Statistical anomaly detection |
| **Pinecone/ChromaDB** | Vector storage | Historical metrics embedding |

**Monitored Dimensions**:

```yaml
Data Quality Checks:
  Freshness:
    - Last update timestamp
    - Expected refresh frequency
    - Late arrival detection

  Volume:
    - Row count trends
    - Sudden spikes/drops
    - Expected ranges

  Schema:
    - Column presence
    - Data type consistency
    - Schema drift detection

  Completeness:
    - NULL percentage per column
    - Required field validation
    - Threshold violations

  Accuracy:
    - Value range checks
    - Referential integrity
    - Business rule validation

  Distribution:
    - Statistical drift
    - Categorical shifts
    - Outlier percentages
```

**Anomaly Detection Pipeline**:

```python
class DataPipelineMonitor:
    def __init__(self):
        self.gx = GreatExpectationsClient()
        self.deequ = DeequClient()
        self.anomaly_detector = PyODEnsemble()
        self.vector_store = ChromaDB()

    def monitor(self, table: str) -> DataIncident:
        # 1. Run Great Expectations suite
        gx_results = self.gx.validate(table)

        # 2. Compute Deequ metrics
        metrics = self.deequ.compute_metrics(table)

        # 3. Compare against historical patterns
        historical = self.vector_store.get_history(table)
        anomaly_score = self.anomaly_detector.score(metrics, historical)

        # 4. Generate incident if threshold exceeded
        if anomaly_score > THRESHOLD or gx_results.has_failures():
            return DataIncident(
                table=table,
                timestamp=now(),
                gx_failures=gx_results.failures,
                anomaly_score=anomaly_score,
                affected_columns=self.identify_affected_columns(),
                downstream_impact=self.trace_lineage(table)
            )
```

**Data Lineage Tracking**:
- Track upstream → downstream dependencies
- Know which dashboards, APIs, models depend on each table
- Predict blast radius of data issues

#### Module 2: Intelligent Bug Triage Engine

**Purpose**: Automatically classify, prioritize, and route incoming bug reports

**Open-Source Stack** (from PDF):

| Tool | Function | Use Case |
|------|----------|----------|
| **DeepTriage** | Bug classification | Labels, owners, duplicates |
| **CodeBERT** | Code-aware embeddings | Technical bug understanding |
| **RoBERTa** | Text classification | Severity, component prediction |
| **Sentence-Transformers** | Semantic similarity | Duplicate detection |
| **LangChain + LLM** | Natural language analysis | Root cause suggestion |

**Classification Pipeline**:

```
Incoming Bug Report
        ↓
┌───────────────────────────────────────┐
│  1. PREPROCESSING                     │
│  - Language detection (AR/EN)         │
│  - Entity extraction                  │
│  - Stack trace parsing                │
└───────────────────────────────────────┘
        ↓
┌───────────────────────────────────────┐
│  2. CLASSIFICATION (DeepTriage)       │
│  - Type: bug/feature/question         │
│  - Component: frontend/backend/data   │
│  - Severity: critical/high/med/low    │
└───────────────────────────────────────┘
        ↓
┌───────────────────────────────────────┐
│  3. DUPLICATE DETECTION               │
│  - Embed with CodeBERT                │
│  - Search similar in vector DB        │
│  - Link if similarity > 0.85          │
└───────────────────────────────────────┘
        ↓
┌───────────────────────────────────────┐
│  4. DATA CORRELATION CHECK            │
│  - Query recent data incidents        │
│  - Match affected tables/columns      │
│  - Calculate correlation score        │
└───────────────────────────────────────┘
        ↓
┌───────────────────────────────────────┐
│  5. SMART ROUTING                     │
│  - Data issue → Data Team             │
│  - Code issue → Dev Team              │
│  - Infrastructure → Platform Team     │
└───────────────────────────────────────┘
```

**Key Innovation - Data-Aware Classification**:

Traditional triage asks: "What component is affected?"
DataBug AI asks: "Is this caused by a data issue?"

```python
class DataAwareBugClassifier:
    def classify(self, bug: BugReport) -> TriageResult:
        # Standard classification
        base_classification = self.deep_triage.classify(bug)

        # NEW: Check for data correlation
        data_correlation = self.check_data_correlation(bug)

        if data_correlation.score > 0.7:
            return TriageResult(
                classification=base_classification,
                root_cause_type="DATA_QUALITY",
                linked_data_incident=data_correlation.incident,
                recommended_team="data_engineering",
                priority_boost=True,  # Data issues affect many users
                related_bugs=self.find_bugs_with_same_root_cause()
            )

        return TriageResult(
            classification=base_classification,
            root_cause_type="CODE",
            recommended_team=base_classification.component_owner
        )
```

#### Module 3: Correlation Engine

**Purpose**: Connect bugs to their data pipeline root causes

**How It Works**:

1. **Temporal Analysis**
   ```
   Data Incident Timeline:
   ─────●─────────────────────────────────►
        │ 10:00 AM
        │ Schema drift detected
        │ Table: user_transactions
        │
   Bug Reports Timeline:
   ─────────●────●────●────●──────────────►
            │    │    │    │
         10:30 10:45 11:00 11:15
         Dashboard API  App   ML
         bug     bug   crash  drift

   Correlation: All bugs within 2 hours of data incident
   affecting downstream systems of user_transactions
   ```

2. **Impact Graph Analysis**
   ```
   user_transactions (SOURCE - incident here)
           │
           ├──► analytics_dashboard (BUG #1: $0 revenue)
           │
           ├──► user_api (BUG #2: empty profiles)
           │
           ├──► mobile_app (BUG #3: null crash)
           │
           └──► recommendation_model (BUG #4: bad predictions)

   Graph traversal identifies all bugs are connected
   ```

3. **Root Cause Ranking**
   ```python
   def rank_root_causes(self, bug: BugReport) -> List[RootCause]:
       candidates = []

       # Check recent data incidents
       data_incidents = self.get_recent_incidents(hours=24)
       for incident in data_incidents:
           if self.is_downstream(bug.affected_component, incident.table):
               score = self.calculate_correlation_score(bug, incident)
               candidates.append(RootCause(
                   type="DATA",
                   incident=incident,
                   score=score
               ))

       # Check recent code deployments
       deployments = self.get_recent_deployments(hours=24)
       for deploy in deployments:
           if deploy.affects(bug.affected_component):
               candidates.append(RootCause(
                   type="CODE",
                   deployment=deploy,
                   score=self.calculate_deploy_correlation(bug, deploy)
               ))

       return sorted(candidates, key=lambda x: x.score, reverse=True)
   ```

4. **Bug Clustering**
   - Group bugs with same root cause
   - Single fix resolves multiple bugs
   - Prevents duplicate investigation effort

---

## Complete Open-Source Stack

### Technology Stack (All from PDF + Research)

| Layer | Component | Source | Purpose |
|-------|-----------|--------|---------|
| **Data Quality** | Great Expectations | PDF Track 5 | Expectation-based validation |
| **Data Quality** | Deequ | PDF Track 5 | Spark-based metrics |
| **Anomaly Detection** | PyOD | PDF Track 5 | Outlier detection |
| **Anomaly Detection** | TensorFlow Probability | PDF Track 5 | Statistical models |
| **Vector Storage** | Pinecone / ChromaDB | PDF Track 5 | Embeddings for similarity |
| **Bug Classification** | DeepTriage | PDF Track 4 | Label/owner prediction |
| **Bug Classification** | CodeBERT | PDF Track 4 | Code-aware embeddings |
| **Bug Classification** | RoBERTa | PDF Track 4 | Text classification |
| **Pipeline** | GitHub Webhook → API | PDF Track 4 | Bug ingestion |
| **LLM Layer** | LangChain + Ollama | Research | Root cause analysis |
| **Orchestration** | Apache Airflow | Research | Pipeline scheduling |
| **Visualization** | Grafana | Research | Unified dashboard |
| **Metadata** | OpenMetadata | Research | Lineage tracking |

### Integration Architecture

```yaml
# docker-compose.yml (simplified)
services:
  databug-api:
    image: databug-ai/api
    ports: ["8000:8000"]

  great-expectations:
    image: greatexpectations/gx

  chromadb:
    image: chromadb/chroma

  grafana:
    image: grafana/grafana
    ports: ["3000:3000"]

  airflow:
    image: apache/airflow

  ollama:
    image: ollama/ollama
    # Local LLM for root cause analysis
```

---

## Expected Inputs & Outputs

### Input 1: Data Pipeline Metrics

```json
{
  "source": "great_expectations",
  "timestamp": "2025-01-15T10:00:00Z",
  "table": "user_transactions",
  "validation_results": {
    "success": false,
    "statistics": {
      "successful_expectations": 45,
      "unsuccessful_expectations": 3
    },
    "failures": [
      {
        "expectation": "expect_column_to_exist",
        "column": "user_id",
        "success": false,
        "details": "Column 'user_id' not found. Similar column 'userId' exists."
      },
      {
        "expectation": "expect_column_values_to_not_be_null",
        "column": "transaction_amount",
        "success": false,
        "details": "23% null values (threshold: 1%)"
      }
    ]
  }
}
```

### Output 1: Data Incident Created

```json
{
  "incident_id": "DI-2025-01-15-001",
  "severity": "CRITICAL",
  "type": "SCHEMA_DRIFT",
  "detected_at": "2025-01-15T10:00:15Z",
  "table": "user_transactions",
  "issues": [
    {
      "type": "column_renamed",
      "from": "user_id",
      "to": "userId",
      "impact": "HIGH"
    },
    {
      "type": "null_spike",
      "column": "transaction_amount",
      "observed": "23%",
      "expected": "<1%"
    }
  ],
  "downstream_impact": {
    "dashboards": ["revenue_daily", "user_analytics"],
    "apis": ["user-service", "transaction-service"],
    "models": ["recommendation_engine"],
    "estimated_bugs": "10-50"
  },
  "recommended_action": "Investigate upstream schema change; backfill affected data"
}
```

### Input 2: Bug Report

```json
{
  "source": "github_issues",
  "issue_id": "4521",
  "title": "Revenue dashboard showing $0 for all regions",
  "body": "Since this morning around 10:30 AM, the revenue dashboard shows $0 across all regions. This is affecting executive reporting. Urgent!",
  "labels": [],
  "reporter": "finance_team",
  "created_at": "2025-01-15T10:45:00Z",
  "attachments": ["screenshot.png"]
}
```

### Output 2: Correlated Triage Result

```json
{
  "issue_id": "4521",
  "triage_result": {
    "classification": {
      "type": "bug",
      "component": "analytics",
      "severity": "critical",
      "priority": "P0"
    },

    "data_correlation": {
      "correlated": true,
      "confidence": 0.94,
      "root_cause": {
        "type": "DATA_QUALITY_INCIDENT",
        "incident_id": "DI-2025-01-15-001",
        "incident_summary": "Schema drift in user_transactions table",
        "time_since_incident": "45 minutes",
        "explanation": "Dashboard reads from user_transactions which experienced schema drift at 10:00 AM. The column rename from 'user_id' to 'userId' caused NULL values in downstream aggregations."
      }
    },

    "related_bugs": [
      {"id": "4522", "title": "User API returning empty profiles", "similarity": 0.91},
      {"id": "4523", "title": "Mobile app crash on user screen", "similarity": 0.87},
      {"id": "4524", "title": "Recommendation engine accuracy dropped", "similarity": 0.82}
    ],

    "routing": {
      "recommended_team": "data_engineering",
      "reason": "Root cause is data pipeline issue, not dashboard code",
      "suggested_assignee": "data_oncall"
    },

    "resolution_hint": {
      "primary": "Fix schema mapping in ETL job for user_transactions",
      "secondary": "Backfill data for 10:00-10:45 AM window",
      "prevents": "Will resolve this bug and 3 related bugs simultaneously"
    }
  },

  "actions_taken": [
    "Classified as P0 critical bug",
    "Linked to data incident DI-2025-01-15-001",
    "Grouped with 3 related bugs",
    "Assigned to data_engineering team",
    "Posted correlation analysis as comment"
  ]
}
```

---

## Expected Impact & Metrics

### Quantitative Goals

| Metric | Without DataBug AI | With DataBug AI | Improvement |
|--------|-------------------|-----------------|-------------|
| Time to identify data-related bugs | Manual investigation | Automatic detection | **90%+ accuracy** |
| Mean Time to Root Cause (MTRC) | 2-4 hours | 5-15 minutes | **90% reduction** |
| Duplicate bug investigation | 40% of bugs duplicated | Clustered automatically | **60% effort saved** |
| Bugs routed to wrong team | 30% initially misrouted | <5% misrouted | **85% improvement** |
| Data issues found via bugs | 72% (reactive) | <20% (proactive) | **70% earlier detection** |
| Bug triage time | 15-30 min manual | <1 min automated | **95% reduction** |

### Business Impact

**For Data Teams**:
- Know immediately when data issues cause downstream bugs
- Fewer "is this a data issue?" interruptions from dev teams
- Clear incident → bug linkage for postmortems
- Proactive issue detection before bug reports

**For Development Teams**:
- Stop investigating bugs caused by data issues
- Clear root cause identification
- Faster handoff to correct team
- Reduced duplicate investigations

**For Engineering Leadership**:
- Single view of data quality → bug relationship
- Metrics on data issue blast radius
- Reduced MTTR across organization
- Evidence for data quality investments

**For Unifonic**:
- Protect 10B+ transactions from data quality cascades
- Reduce support burden from data-related bugs
- Faster incident resolution
- Unified observability across data and applications

---

## Workflow Visualization

### End-to-End Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         DATA PIPELINE LAYER                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  [Source DB] ──► [ETL Job] ──► [Data Warehouse] ──► [Analytics]    │
│       │              │               │                   │          │
│       ▼              ▼               ▼                   ▼          │
│   ┌───────┐     ┌───────┐       ┌───────┐          ┌───────┐       │
│   │ GX    │     │ Deequ │       │ DQOps │          │ PyOD  │       │
│   │ Check │     │ Check │       │ Check │          │ Check │       │
│   └───┬───┘     └───┬───┘       └───┬───┘          └───┬───┘       │
│       └──────────────┴───────────────┴─────────────────┘            │
│                              │                                      │
│                    ┌─────────▼─────────┐                           │
│                    │  DATA INCIDENT    │                           │
│                    │  DI-2025-01-15    │                           │
│                    └─────────┬─────────┘                           │
└──────────────────────────────┼──────────────────────────────────────┘
                               │
                               │ Stored with downstream lineage
                               │
┌──────────────────────────────┼──────────────────────────────────────┐
│                              │     CORRELATION ENGINE               │
│                    ┌─────────▼─────────┐                           │
│                    │  Incident Store   │                           │
│                    │  + Impact Graph   │                           │
│                    └─────────┬─────────┘                           │
│                              │                                      │
│   ┌──────────────────────────┼───────────────────────────┐         │
│   │                          │                           │         │
│   ▼                          ▼                           ▼         │
│ [Bug #1]                 [Bug #2]                    [Bug #3]      │
│ Dashboard                API errors                  App crash     │
│   │                          │                           │         │
│   └──────────────────────────┴───────────────────────────┘         │
│                              │                                      │
│                    ┌─────────▼─────────┐                           │
│                    │   BUG CLUSTER     │                           │
│                    │   Root Cause:     │                           │
│                    │   DI-2025-01-15   │                           │
│                    └─────────┬─────────┘                           │
└──────────────────────────────┼──────────────────────────────────────┘
                               │
                               ▼
                    ┌───────────────────┐
                    │  UNIFIED TICKET   │
                    │  Assigned: Data   │
                    │  Team             │
                    │  Fix Once,        │
                    │  Resolve All      │
                    └───────────────────┘
```

---

## Implementation Roadmap

### Phase 1: Data Pipeline Monitor (Days 1-12)
- Deploy Great Expectations with core expectations
- Integrate Deequ for Spark-based validation
- Implement anomaly detection with PyOD
- Set up data lineage tracking with OpenMetadata
- Create data incident storage and API

### Phase 2: Bug Triage Engine (Days 13-24)
- Implement DeepTriage model for classification
- Add CodeBERT embeddings for semantic similarity
- Build duplicate detection pipeline
- Create GitHub/Jira webhook integrations
- Develop severity and priority prediction

### Phase 3: Correlation Engine (Days 25-36)
- Build temporal correlation analysis
- Implement impact graph traversal
- Create root cause ranking algorithm
- Develop bug clustering logic
- Add LLM-based root cause explanation

### Phase 4: Integration & Demo (Days 37-45)
- Unified Grafana dashboard
- End-to-end demo scenario
- Benchmark metrics collection
- Documentation and presentation
- Video walkthrough creation

---

## Demo Scenario

### Live Demonstration Flow

1. **T+0**: Schema drift injected into `user_transactions` table
2. **T+1min**: Great Expectations detects column rename
3. **T+2min**: Data incident DI-001 created automatically
4. **T+5min**: First bug report filed: "Dashboard shows $0"
5. **T+5.5min**: DataBug AI correlates bug to data incident
6. **T+6min**: Second bug filed: "API returning empty"
7. **T+6.5min**: Automatically clustered with first bug
8. **T+7min**: Third bug filed: "App crash"
9. **T+7.5min**: Added to cluster, single root cause shown
10. **T+8min**: Data team fixes schema mapping
11. **T+10min**: All 3 bugs resolved with single fix

**Key Demo Points**:
- Real-time correlation visualization
- Bug clustering in action
- Root cause explanation generated by LLM
- Time saved: 3 separate investigations → 1 unified resolution

---

## Risk Mitigation

| Risk | Mitigation Strategy |
|------|---------------------|
| False correlation (bug unrelated to data issue) | Confidence thresholds; human review for low-confidence correlations |
| Data lineage incomplete | Graceful degradation; manual lineage input option |
| High volume of bugs overwhelming system | Rate limiting; priority queuing; batch processing |
| LLM explanation inaccuracies | Ground explanations in actual data; show evidence |
| Integration complexity with existing tools | Modular design; standard webhooks; REST APIs |

---

## Why Team CSIS Will Succeed

1. **Unique Problem-Solution Fit**: First tool bridging data quality monitoring and bug triage

2. **Research-Backed**: Built on the finding that 72% of data issues are found too late

3. **100% Open Source**: Uses all tools recommended in hackathon PDF

4. **Measurable Impact**: Clear before/after metrics (MTRC, duplicate rate, routing accuracy)

5. **Judging Criteria Alignment**:
   - **Innovation (30%)**: Novel correlation engine connecting two domains
   - **Technical Execution (30%)**: Robust stack using PDF-recommended tools
   - **Impact (20%)**: 90% reduction in time-to-root-cause
   - **Presentation (20%)**: Compelling cascade demo showing real-world value

---

## Conclusion

DataBug AI transforms bug triage from a reactive, siloed process into a data-aware, intelligent system. By connecting the dots between data pipeline health and downstream bugs, we enable organizations to:

- **Detect** data issues through their bug symptoms
- **Correlate** bugs to their true root causes
- **Cluster** related bugs for efficient resolution
- **Route** issues to the right team immediately
- **Resolve** multiple bugs with single fixes

**Stop treating symptoms. Start finding root causes.**

---

## References

- [State of Data Quality 2024 - DataChecks](https://www.datachecks.io/post/the-state-of-data-quality-2024-analysis-of-1000-data-pipelines)
- [Data Quality Challenges 2025 - Precisely](https://www.precisely.com/blog/data-integrity/2025-planning-insights-data-quality-remains-the-top-data-integrity-challenges/)
- [Common Data Pipeline Failures - Hevo](https://hevodata.com/learn/data-pipeline-failures/)
- [Open Source Data Quality Tools 2025 - Atlan](https://atlan.com/open-source-data-quality-tools/)
- [Great Expectations Documentation](https://docs.greatexpectations.io/)
- [Deequ - AWS Labs](https://github.com/awslabs/deequ)
- [DeepTriage Paper](https://arxiv.org/abs/1911.03657)
- [2026 Open-Source Data Quality Landscape - DataKitchen](https://datakitchen.io/the-2026-open-source-data-quality-and-data-observability-landscape/)

---

*Team CSIS - Unifonic AI Hackathon 2025*
