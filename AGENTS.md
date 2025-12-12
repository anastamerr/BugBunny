# DataBug AI - Implementation Plan

## Current Status (Last updated: 2025-12-12)

### Completed (implemented in repo)
- [x] Monorepo structure: `backend/`, `frontend/`, `docs/`, `demo/`
- [x] Backend API: health, incidents, bugs, correlations, predictions, chat, demo injection
- [x] Realtime updates: Socket.IO server (`/ws`) + frontend query invalidation
- [x] Data monitoring primitives: Great Expectations + anomaly detection wiring
- [x] Correlation + explanations + predictions scaffolding in API/services
- [x] GitHub ingestion: webhook endpoint + upsert/triage + optional backfill script
- [x] Supabase-ready compose: no local Postgres; backend uses `backend/.env` (gitignored)
- [x] Backend tests in place (pytest)

### Pending / Next (ops + verification)
- [ ] Ensure Supabase `DATABASE_URL` uses an IPv4-reachable host (prefer Supabase Session Pooler) + `sslmode=require`
- [ ] Run DB migrations on Supabase: `cd backend && python -m alembic upgrade head`
- [ ] Run initial GitHub backfill: `cd backend && python -m src.integrations.github_backfill`
- [ ] Configure ngrok authtoken + expose port `8000`, then set GitHub webhook URL to `https://<ngrok-host>/api/webhooks/github`
- [ ] Pull Ollama model locally (e.g. Llama 3) if using real chat/explanations

## Project Overview

**DataBug AI** is an intelligent, data-aware bug triage platform that combines **Track 4 (Bug Triage Automation)** and **Track 5 (Automated Data Pipeline Validation & Monitoring)** into a unified system with AI-powered intelligence.

**Core Innovation**: The first platform that not only correlates data pipeline incidents with downstream bug reports, but uses LLM intelligence to explain root causes, predict incoming bugs before they're filed, and learn from resolution patterns.

---

## Why DataBug AI Wins

### The Problem (Backed by Data)
- **72%** of data quality issues are discovered only after business impact
- **40%** of data team time spent troubleshooting
- **67%** of organizations don't trust their data
- Average **2-4 hours** to find root cause of data-related bugs

### Our Solution (4 Layers of Intelligence)

```
Layer 1: DETECTION      - Real-time data pipeline monitoring
Layer 2: CORRELATION    - Link bugs to data incidents automatically
Layer 3: EXPLANATION    - LLM-powered root cause analysis
Layer 4: PREDICTION     - Predict bugs before they're filed
```

### Key Differentiators

| Feature | Traditional Tools | DataBug AI |
|---------|------------------|------------|
| Data monitoring | Yes | Yes |
| Bug triage | Yes | Yes |
| Cross-domain correlation | No | **Yes** |
| LLM root cause explanation | No | **Yes** |
| Predictive bug alerts | No | **Yes** |
| Resolution learning | No | **Yes** |

---

## Judging Criteria Alignment

| Criteria | Weight | Our Strategy | Score Target |
|----------|--------|--------------|--------------|
| **Innovation** | 30% | Novel 4-layer intelligence system, dual-track combination, predictive capabilities | 27/30 |
| **Technical Execution** | 30% | Production-ready stack (React, FastAPI, Pinecone), working LLM integration | 27/30 |
| **Impact** | 20% | Measurable: 90% MTRC reduction, predictive alerts prevent bugs | 18/20 |
| **Presentation** | 20% | Polished React UI, live cascade demo, compelling storytelling | 18/20 |

**Target Total: 90/100**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              FRONTEND                                        │
│                     React + Vite + Tailwind + shadcn/ui                      │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │  Dashboard  │ │  Incidents  │ │  Bug Triage │ │ Predictions │           │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘           │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ REST API + WebSocket
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              BACKEND (FastAPI)                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                           API Gateway                                │   │
│  │         /incidents  /bugs  /correlations  /predictions  /chat        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐            │
│  │   Pipeline   │  Bug Triage  │ Correlation  │  Intelligence │            │
│  │   Monitor    │    Engine    │    Engine    │     Layer     │            │
│  ├──────────────┼──────────────┼──────────────┼──────────────┤            │
│  │ Great        │ Sentence     │ Temporal     │ Ollama/LLM    │            │
│  │ Expectations │ Transformers │ Matcher      │ Integration   │            │
│  │ PyOD Anomaly │ Classifier   │ Impact Graph │ Predictive    │            │
│  │ Schema/Fresh │ Duplicate    │ Root Cause   │ Resolution    │            │
│  │ Validator    │ Detector     │ Ranker       │ Learner       │            │
│  └──────────────┴──────────────┴──────────────┴──────────────┘            │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
             ┌───────────┐  ┌─────────────┐  ┌───────────┐
             │ PostgreSQL│  │  Pinecone   │  │  Ollama   │
             │ Incidents │  │  Vector DB  │  │  (LLM)    │
             │ Bugs      │  │ Embeddings  │  │ Llama 3   │
             │ Patterns  │  │ Similarity  │  │ 8B        │
             └───────────┘  └─────────────┘  └───────────┘
```

<!-- Original diagram below was garbled due to encoding -->
<!--
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              FRONTEND                                        │
│                     React + Vite + Tailwind + shadcn/ui                     │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │  Dashboard  │ │  Incidents  │ │  Bug Triage │ │ Predictions │           │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘           │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ REST API + WebSocket
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              BACKEND (FastAPI)                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                           API Gateway                                │   │
│  │         /incidents  /bugs  /correlations  /predictions  /chat       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐            │
│  │   Pipeline   │  Bug Triage  │ Correlation  │  Intelligence │            │
│  │   Monitor    │    Engine    │    Engine    │     Layer     │            │
│  ├──────────────┼──────────────┼──────────────┼──────────────┤            │
│  │ Great        │ Sentence     │ Temporal     │ Ollama/LLM   │            │
│  │ Expectations │ Transformers │ Matcher      │ Integration  │            │
│  │              │              │              │              │            │
│  │ PyOD         │ Classifier   │ Impact Graph │ Predictive   │            │
│  │ Anomaly      │ Pipeline     │ Traversal    │ Model        │            │
│  │              │              │              │              │            │
│  │ Schema       │ Duplicate    │ Root Cause   │ Resolution   │            │
│  │ Validator    │ Detector     │ Ranker       │ Learner      │            │
│  └──────────────┴──────────────┴──────────────┴──────────────┘            │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
             ┌───────────┐  ┌─────────────┐  ┌───────────┐
             │ PostgreSQL│  │  Pinecone   │  │  Ollama   │
             │           │  │  Vector DB  │  │  (LLM)    │
             │ Incidents │  │             │  │           │
             │ Bugs      │  │ Embeddings  │  │ Llama 3   │
             │ Patterns  │  │ Similarity  │  │ 8B        │
             └───────────┘  └─────────────┘  └───────────┘
```
-->

---

## Technology Stack

### Frontend
| Technology | Purpose |
|------------|---------|
| **React 18** | UI framework |
| **Vite** | Build tool, fast HMR |
| **TypeScript** | Type safety |
| **Tailwind CSS** | Styling |
| **shadcn/ui** | Component library |
| **TanStack Query** | Data fetching, caching |
| **Recharts** | Data visualization |
| **Socket.io Client** | Real-time updates |

### Backend
| Technology | Purpose |
|------------|---------|
| **FastAPI** | API framework |
| **Python 3.11+** | Runtime |
| **SQLAlchemy** | ORM |
| **Pydantic** | Data validation |
| **Celery** | Background tasks |
| **Socket.io** | Real-time events |

### Data & AI
| Technology | Purpose | Source |
|------------|---------|--------|
| **Great Expectations** | Data validation | PDF Track 5 |
| **PyOD** | Anomaly detection | PDF Track 5 |
| **Sentence-Transformers** | Text embeddings | PDF Track 4 |
| **Pinecone** | Vector database | PDF Track 5 |
| **Ollama + Llama 3** | LLM inference | Research |
| **scikit-learn** | ML models | Standard |

### Infrastructure
| Technology | Purpose |
|------------|---------|
| **Docker Compose** | Local development |
| **PostgreSQL** | Primary database |
| **Redis** | Caching, Celery broker |

---

## Testing Strategy

### Testing Philosophy

**Core Principle**: Write tests alongside code, not after. Every feature should be tested before merging.

**Test Pyramid**:
```
        /\
       /  \        E2E Tests (5%)
      /----\       - Demo scenarios, critical user flows
     /      \
    /--------\      Integration Tests (25%)
   /          \     - API endpoints, service interactions
  /------------\
 /              \   Unit Tests (70%)
/________________\  - Individual functions, business logic
```

<!-- Original pyramid below was garbled due to encoding -->
<!--
```
        ╱╲
       ╱  ╲         E2E Tests (5%)
      ╱────╲        - Demo scenarios, critical user flows
     ╱      ╲
    ╱────────╲      Integration Tests (25%)
   ╱          ╲     - API endpoints, service interactions
  ╱────────────╲
 ╱              ╲   Unit Tests (70%)
╱────────────────╲  - Individual functions, business logic
```
-->

### When to Write Tests

| Scenario | Test Type | Timing |
|----------|-----------|--------|
| New service/utility function | Unit test | **Before or during** implementation |
| New API endpoint | Integration test | **Immediately after** endpoint works |
| Bug fix | Regression test | **Before** fixing (TDD style) |
| New feature complete | E2E test | **After** feature integration |
| Refactoring | Ensure existing tests pass | **Before** refactoring |
| External integration (Pinecone, Ollama) | Mock test + manual verification | **During** integration |

### Testing by Phase

#### Phase 1: Foundation (Days 1-10)
```
Tests to write:
├── Unit Tests
│   ├── test_config.py              - Configuration loading
│   ├── test_db_connection.py       - Database connection
│   └── test_pinecone_client.py     - Pinecone service (mocked)
└── Integration Tests
    └── test_health_endpoints.py    - API health checks
```

<!--
```
Tests to write:
├── Unit Tests
│   ├── test_config.py              - Configuration loading
│   ├── test_db_connection.py       - Database connection
│   └── test_pinecone_client.py     - Pinecone service (mocked)
└── Integration Tests
    └── test_health_endpoints.py    - API health checks
```
-->

**Frequency**: Write unit tests for every new utility/service class created.

#### Phase 2: Track 5 - Data Pipeline Monitor (Days 11-20)
```
Tests to write:
├── Unit Tests
│   ├── test_great_expectations_service.py
│   │   ├── test_create_expectation_suite()
│   │   ├── test_validate_table_success()
│   │   └── test_validate_table_failure()
│   ├── test_anomaly_detector.py
│   │   ├── test_compute_metrics()
│   │   ├── test_detect_anomaly_normal()
│   │   ├── test_detect_anomaly_spike()
│   │   └── test_identify_anomalous_metrics()
│   └── test_incident_generator.py
│       ├── test_classify_incident_schema_drift()
│       ├── test_classify_incident_null_spike()
│       ├── test_calculate_severity()
│       └── test_build_details()
└── Integration Tests
    ├── test_incidents_api.py
    │   ├── test_create_incident()
    │   ├── test_get_incidents()
    │   └── test_get_incident_by_id()
    └── test_validation_workflow.py
        └── test_validation_creates_incident()
```

<!--
```
Tests to write:
├── Unit Tests
│   ├── test_great_expectations_service.py
│   │   ├── test_create_expectation_suite()
│   │   ├── test_validate_table_success()
│   │   └── test_validate_table_failure()
│   ├── test_anomaly_detector.py
│   │   ├── test_compute_metrics()
│   │   ├── test_detect_anomaly_normal()
│   │   ├── test_detect_anomaly_spike()
│   │   └── test_identify_anomalous_metrics()
│   └── test_incident_generator.py
│       ├── test_classify_incident_schema_drift()
│       ├── test_classify_incident_null_spike()
│       ├── test_calculate_severity()
│       └── test_build_details()
└── Integration Tests
    ├── test_incidents_api.py
    │   ├── test_create_incident()
    │   ├── test_get_incidents()
    │   └── test_get_incident_by_id()
    └── test_validation_workflow.py
        └── test_validation_creates_incident()
```
-->

**Frequency**:
- Write unit tests **immediately** after completing each service method
- Write integration tests **after** completing each API route file
- Run all tests before moving to Phase 3

#### Phase 3: Track 4 - Bug Triage Engine (Days 21-30)
```
Tests to write:
├── Unit Tests
│   ├── test_classifier.py
│   │   ├── test_classify_bug_type()
│   │   ├── test_classify_component()
│   │   ├── test_classify_severity()
│   │   └── test_confidence_scoring()
│   ├── test_duplicate_detector.py
│   │   ├── test_find_duplicates_exact_match()
│   │   ├── test_find_duplicates_similar()
│   │   ├── test_find_duplicates_no_match()
│   │   └── test_register_bug()
│   └── test_auto_router.py
│       ├── test_route_data_related_bug()
│       ├── test_route_by_component()
│       └── test_calculate_priority()
└── Integration Tests
    ├── test_bugs_api.py
    │   ├── test_create_bug()
    │   ├── test_classify_bug_on_create()
    │   ├── test_detect_duplicates()
    │   └── test_auto_route()
    └── test_pinecone_integration.py
        ├── test_upsert_and_query()
        └── test_similarity_threshold()
```

<!--
```
Tests to write:
├── Unit Tests
│   ├── test_classifier.py
│   │   ├── test_classify_bug_type()
│   │   ├── test_classify_component()
│   │   ├── test_classify_severity()
│   │   └── test_confidence_scoring()
│   ├── test_duplicate_detector.py
│   │   ├── test_find_duplicates_exact_match()
│   │   ├── test_find_duplicates_similar()
│   │   ├── test_find_duplicates_no_match()
│   │   └── test_register_bug()
│   └── test_auto_router.py
│       ├── test_route_data_related_bug()
│       ├── test_route_by_component()
│       └── test_calculate_priority()
└── Integration Tests
    ├── test_bugs_api.py
    │   ├── test_create_bug()
    │   ├── test_classify_bug_on_create()
    │   ├── test_detect_duplicates()
    │   └── test_auto_route()
    └── test_pinecone_integration.py
        ├── test_upsert_and_query()
        └── test_similarity_threshold()
```
-->

**Frequency**:
- Unit test each classifier method **as you implement it**
- Integration tests for Pinecone **after** setting up the connection
- Full bug triage workflow test **at end of phase**

#### Phase 4: Correlation Engine (Days 31-36)
```
Tests to write:
├── Unit Tests
│   ├── test_temporal_matcher.py
│   │   ├── test_temporal_score_immediate()      # bug 0-1hr after incident
│   │   ├── test_temporal_score_delayed()        # bug 2-6hr after incident
│   │   ├── test_temporal_score_too_old()        # bug 24hr+ after incident
│   │   ├── test_component_score_downstream()
│   │   ├── test_keyword_score_multiple_matches()
│   │   └── test_calculate_correlation_score()
│   └── test_bug_clusterer.py
│       ├── test_cluster_by_root_cause()
│       ├── test_get_cluster_summary()
│       └── test_propagate_resolution()
└── Integration Tests
    ├── test_correlations_api.py
    │   ├── test_find_correlations()
    │   ├── test_correlation_creates_link()
    │   └── test_cluster_view()
    └── test_correlation_workflow.py
        └── test_bug_auto_correlates_to_incident()
```

<!--
```
Tests to write:
├── Unit Tests
│   ├── test_temporal_matcher.py
│   │   ├── test_temporal_score_immediate()      # bug 0-1hr after incident
│   │   ├── test_temporal_score_delayed()        # bug 2-6hr after incident
│   │   ├── test_temporal_score_too_old()        # bug 24hr+ after incident
│   │   ├── test_component_score_downstream()
│   │   ├── test_keyword_score_multiple_matches()
│   │   └── test_calculate_correlation_score()
│   └── test_bug_clusterer.py
│       ├── test_cluster_by_root_cause()
│       ├── test_get_cluster_summary()
│       └── test_propagate_resolution()
└── Integration Tests
    ├── test_correlations_api.py
    │   ├── test_find_correlations()
    │   ├── test_correlation_creates_link()
    │   └── test_cluster_view()
    └── test_correlation_workflow.py
        └── test_bug_auto_correlates_to_incident()
```
-->

**Frequency**:
- Test each scoring function **individually** before combining
- Test weighted combination **after** all individual scores work
- Integration test **after** correlation API is complete

#### Phase 5: Intelligence Layer (Days 37-42)
```
Tests to write:
├── Unit Tests
│   ├── test_llm_service.py
│   │   ├── test_generate_success()
│   │   ├── test_generate_timeout()
│   │   └── test_is_available()
│   ├── test_explanation_generator.py
│   │   ├── test_generate_root_cause_explanation()
│   │   └── test_generate_cluster_summary()
│   └── test_prediction_engine.py
│       ├── test_predict_bugs_high_severity()
│       ├── test_predict_bugs_low_severity()
│       ├── test_rule_based_fallback()
│       └── test_generate_recommendation()
└── Integration Tests
    ├── test_chat_api.py
    │   └── test_chat_endpoint()
    ├── test_predictions_api.py
    │   ├── test_get_predictions()
    │   └── test_prediction_accuracy_tracking()
    └── test_ollama_integration.py
        └── test_real_llm_response()  # Manual verification needed
```

<!--
```
Tests to write:
├── Unit Tests
│   ├── test_llm_service.py
│   │   ├── test_generate_success()
│   │   ├── test_generate_timeout()
│   │   └── test_is_available()
│   ├── test_explanation_generator.py
│   │   ├── test_generate_root_cause_explanation()
│   │   └── test_generate_cluster_summary()
│   └── test_prediction_engine.py
│       ├── test_predict_bugs_high_severity()
│       ├── test_predict_bugs_low_severity()
│       ├── test_rule_based_fallback()
│       └── test_generate_recommendation()
└── Integration Tests
    ├── test_chat_api.py
    │   └── test_chat_endpoint()
    ├── test_predictions_api.py
    │   ├── test_get_predictions()
    │   └── test_prediction_accuracy_tracking()
    └── test_ollama_integration.py
        └── test_real_llm_response()  # Manual verification needed
```
-->

**Frequency**:
- Mock LLM tests **immediately** for fast CI
- Real LLM integration tests marked as **manual/slow**
- Prediction tests **after** model training logic works

#### Phase 6: Frontend & Demo (Days 43-45)
```
Tests to write:
├── Frontend Tests (Vitest + React Testing Library)
│   ├── components/
│   │   ├── StatsCard.test.tsx
│   │   ├── IncidentFeed.test.tsx
│   │   └── CorrelationGraph.test.tsx
│   └── pages/
│       ├── Dashboard.test.tsx
│       └── Bugs.test.tsx
└── E2E Tests (Playwright or Cypress)
    ├── test_demo_flow.spec.ts
    │   ├── test_incident_appears_in_dashboard()
    │   ├── test_bug_correlation_flow()
    │   └── test_cluster_view()
    └── test_critical_paths.spec.ts
        ├── test_navigate_all_pages()
        └── test_websocket_updates()
```

<!--
```
Tests to write:
├── Frontend Tests (Vitest + React Testing Library)
│   ├── components/
│   │   ├── StatsCard.test.tsx
│   │   ├── IncidentFeed.test.tsx
│   │   └── CorrelationGraph.test.tsx
│   └── pages/
│       ├── Dashboard.test.tsx
│       └── Bugs.test.tsx
└── E2E Tests (Playwright or Cypress)
    ├── test_demo_flow.spec.ts
    │   ├── test_incident_appears_in_dashboard()
    │   ├── test_bug_correlation_flow()
    │   └── test_cluster_view()
    └── test_critical_paths.spec.ts
        ├── test_navigate_all_pages()
        └── test_websocket_updates()
```
-->

**Frequency**:
- Component tests for **each new component**
- E2E tests for **demo scenarios only** (keep minimal)
- Visual regression tests **optional** for UI polish

### Test Commands

```bash
# Backend tests
cd backend

# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_correlation.py

# Run tests matching pattern
pytest -k "test_temporal"

# Run only unit tests (fast)
pytest tests/unit/

# Run integration tests
pytest tests/integration/

# Skip slow/manual tests
pytest -m "not slow"

# Frontend tests
cd frontend

# Run all tests
npm test

# Run with coverage
npm test -- --coverage

# Run in watch mode during development
npm test -- --watch

# Run E2E tests
npm run test:e2e
```

### Test Configuration

**Backend pytest.ini:**
```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_functions = test_*
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks tests requiring external services
    manual: marks tests requiring manual verification
addopts = -v --tb=short
```

**Backend conftest.py:**
```python
# backend/tests/conftest.py
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import MagicMock

@pytest.fixture
def db_session():
    """Create a test database session."""
    engine = create_engine("sqlite:///:memory:")
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

@pytest.fixture
def mock_pinecone():
    """Mock Pinecone service for unit tests."""
    mock = MagicMock()
    mock.find_similar_bugs.return_value = []
    mock.upsert_bug.return_value = "test-id"
    return mock

@pytest.fixture
def mock_ollama():
    """Mock Ollama service for unit tests."""
    mock = MagicMock()
    mock.generate.return_value = "Test explanation"
    mock.is_available.return_value = True
    return mock

@pytest.fixture
def sample_incident():
    """Sample incident for testing."""
    return {
        "incident_id": "DI-2025-01-15-001",
        "table_name": "user_transactions",
        "incident_type": "SCHEMA_DRIFT",
        "severity": "CRITICAL",
        "affected_columns": ["user_id"],
        "downstream_systems": ["analytics_dashboard", "user_api"]
    }

@pytest.fixture
def sample_bug():
    """Sample bug for testing."""
    return {
        "bug_id": "GH-123",
        "title": "Dashboard shows $0 revenue",
        "description": "Revenue dashboard displaying zero values since this morning",
        "classified_component": "analytics_dashboard",
        "classified_severity": "critical"
    }
```

### Coverage Requirements

| Component | Minimum Coverage | Target Coverage |
|-----------|-----------------|-----------------|
| Services (business logic) | 80% | 90% |
| API Routes | 70% | 85% |
| Utilities | 90% | 95% |
| Frontend Components | 60% | 75% |
| E2E Critical Paths | 100% of demo flow | 100% of demo flow |

### CI/CD Integration

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  backend-tests:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          cd backend
          pip install -r requirements.txt
          pip install -r requirements-dev.txt
      - name: Run tests
        run: |
          cd backend
          pytest --cov=src --cov-report=xml -m "not slow"
      - name: Upload coverage
        uses: codecov/codecov-action@v3

  frontend-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - name: Install dependencies
        run: |
          cd frontend
          npm ci
      - name: Run tests
        run: |
          cd frontend
          npm test -- --coverage --watchAll=false
```

### Testing Best Practices

1. **Test Naming Convention**:
   ```python
   def test_<function_name>_<scenario>_<expected_result>():
       # Example: test_calculate_correlation_score_high_temporal_returns_high_score
   ```

2. **AAA Pattern** (Arrange, Act, Assert):
   ```python
   def test_classify_bug_type_returns_bug():
       # Arrange
       classifier = BugClassifier()
       title = "App crashes on login"
       description = "NullPointerException in LoginActivity"

       # Act
       result = classifier.classify(title, description)

       # Assert
       assert result["type"] == "bug"
       assert result["type_confidence"] > 0.7
   ```

3. **Test One Thing Per Test**:
   ```python
   # Good
   def test_temporal_score_immediate_returns_max():
       ...

   def test_temporal_score_delayed_returns_reduced():
       ...

   # Bad
   def test_temporal_score():  # Tests multiple scenarios
       ...
   ```

4. **Use Fixtures for Setup**:
   ```python
   @pytest.fixture
   def correlation_engine(db_session, mock_pinecone):
       return CorrelationEngine(db_session, mock_pinecone)

   def test_find_correlations(correlation_engine, sample_bug, sample_incident):
       result = correlation_engine.find_correlations(sample_bug)
       assert len(result) > 0
   ```

5. **Mock External Services**:
   ```python
   def test_generate_explanation_success(mock_ollama):
       generator = ExplanationGenerator(mock_ollama)
       mock_ollama.generate.return_value = "Root cause: Schema drift..."

       result = generator.generate_root_cause_explanation(bug, incident, 0.9)

       assert "Root cause" in result
       mock_ollama.generate.assert_called_once()
   ```

### Testing Checklist Per Feature

Before marking any feature complete, ensure:

- [ ] Unit tests written for all public methods
- [ ] Edge cases tested (null inputs, empty lists, boundary values)
- [ ] Error handling tested (exceptions, invalid data)
- [ ] Integration test for API endpoints
- [ ] All tests passing locally
- [ ] Coverage meets minimum threshold
- [ ] Tests run in CI pipeline

---

## Project Structure

```
databug-ai/
├── docker-compose.yml
├── README.md
├── AGENTS.md
├── frontend/                          # React + Vite
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   ├── tsconfig.json
│   ├── index.html
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   ├── api/                       # API client
│   │   │   ├── client.ts
│   │   │   ├── incidents.ts
│   │   │   ├── bugs.ts
│   │   │   └── correlations.ts
│   │   ├── components/
│   │   │   ├── ui/                    # shadcn components
│   │   │   ├── layout/
│   │   │   │   ├── Sidebar.tsx
│   │   │   │   ├── Header.tsx
│   │   │   │   └── Layout.tsx
│   │   │   ├── dashboard/
│   │   │   │   ├── StatsCard.tsx
│   │   │   │   ├── IncidentFeed.tsx
│   │   │   │   ├── BugQueue.tsx
│   │   │   │   └── CorrelationGraph.tsx
│   │   │   ├── incidents/
│   │   │   │   ├── IncidentList.tsx
│   │   │   │   ├── IncidentDetail.tsx
│   │   │   │   └── IncidentTimeline.tsx
│   │   │   ├── bugs/
│   │   │   │   ├── BugList.tsx
│   │   │   │   ├── BugDetail.tsx
│   │   │   │   ├── BugClassification.tsx
│   │   │   │   └── DuplicatePanel.tsx
│   │   │   ├── correlations/
│   │   │   │   ├── CorrelationView.tsx
│   │   │   │   ├── RootCauseCard.tsx
│   │   │   │   ├── BugCluster.tsx
│   │   │   │   └── ImpactGraph.tsx
│   │   │   ├── predictions/
│   │   │   │   ├── PredictionList.tsx
│   │   │   │   ├── PredictionCard.tsx
│   │   │   │   └── AlertConfig.tsx
│   │   │   └── chat/
│   │   │       ├── ChatInterface.tsx
│   │   │       └── ChatMessage.tsx
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Incidents.tsx
│   │   │   ├── Bugs.tsx
│   │   │   ├── Correlations.tsx
│   │   │   ├── Predictions.tsx
│   │   │   └── Settings.tsx
│   │   ├── hooks/
│   │   │   ├── useIncidents.ts
│   │   │   ├── useBugs.ts
│   │   │   ├── useCorrelations.ts
│   │   │   └── useWebSocket.ts
│   │   ├── store/                     # Zustand state
│   │   │   └── index.ts
│   │   ├── types/
│   │   │   └── index.ts
│   │   └── lib/
│   │       └── utils.ts
│   └── public/
├── backend/                           # FastAPI
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   ├── src/
│   │   ├── __init__.py
│   │   ├── main.py                    # FastAPI app
│   │   ├── config.py                  # Settings
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── deps.py                # Dependencies
│   │   │   └── routes/
│   │   │       ├── __init__.py
│   │   │       ├── incidents.py
│   │   │       ├── bugs.py
│   │   │       ├── correlations.py
│   │   │       ├── predictions.py
│   │   │       ├── chat.py
│   │   │       ├── webhooks.py
│   │   ├── models/                    # SQLAlchemy models
│   │   │   ├── __init__.py
│   │   │   ├── incident.py
│   │   │   ├── bug.py
│   │   │   ├── correlation.py
│   │   │   ├── pattern.py
│   │   ├── schemas/                   # Pydantic schemas
│   │   │   ├── __init__.py
│   │   │   ├── incident.py
│   │   │   ├── bug.py
│   │   │   ├── correlation.py
│   │   │   ├── prediction.py
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── pipeline_monitor/      # Track 5
│   │   │   │   ├── __init__.py
│   │   │   │   ├── great_expectations_service.py
│   │   │   │   ├── anomaly_detector.py
│   │   │   │   ├── schema_validator.py
│   │   │   │   ├── freshness_checker.py
│   │   │   │   ├── incident_generator.py
│   │   │   ├── bug_triage/            # Track 4
│   │   │   │   ├── __init__.py
│   │   │   │   ├── classifier.py
│   │   │   │   ├── duplicate_detector.py
│   │   │   │   ├── severity_predictor.py
│   │   │   │   ├── embeddings.py
│   │   │   │   ├── auto_router.py
│   │   │   ├── correlation/           # Core Innovation
│   │   │   │   ├── __init__.py
│   │   │   │   ├── temporal_matcher.py
│   │   │   │   ├── impact_graph.py
│   │   │   │   ├── root_cause_ranker.py
│   │   │   │   ├── bug_clusterer.py
│   │   │   └── intelligence/          # AI Layer
│   │   │       ├── __init__.py
│   │   │       ├── llm_service.py
│   │   │       ├── explanation_generator.py
│   │   │       ├── prediction_engine.py
│   │   │       ├── resolution_learner.py
│   │   ├── db/
│   │   │   ├── __init__.py
│   │   │   ├── session.py
│   │   │   └── migrations/
│   │   ├── integrations/
│   │   │   ├── __init__.py
│   │   │   ├── pinecone_client.py
│   │   │   ├── ollama_client.py
│   │   │   ├── github_webhook.py
│   │   ├── workers/                   # Celery tasks
│   │   │   ├── __init__.py
│   │   │   ├── validation_task.py
│   │   │   ├── correlation_task.py
│   │   │   ├── prediction_task.py
│   │   ├── utils/
│   │   │   ├── __init__.py
│   │   │   ├── helpers.py
│   │   └── tests/
├── demo/                              # Demo utilities
│   ├── simulate_incident.py
│   ├── generate_bugs.py
│   ├── demo_sequence.py
│   └── sample_data/
│       ├── incidents.json
│       └── bugs.json
└── docs/
    ├── api.md
    ├── setup.md
    └── demo_guide.md
```

<!--
```
databug-ai/
├── docker-compose.yml
├── README.md
├── AGENTS.md
│
├── frontend/                          # React + Vite
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   ├── tsconfig.json
│   ├── index.html
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   ├── api/                       # API client
│   │   │   ├── client.ts
│   │   │   ├── incidents.ts
│   │   │   ├── bugs.ts
│   │   │   └── correlations.ts
│   │   ├── components/
│   │   │   ├── ui/                    # shadcn components
│   │   │   ├── layout/
│   │   │   │   ├── Sidebar.tsx
│   │   │   │   ├── Header.tsx
│   │   │   │   └── Layout.tsx
│   │   │   ├── dashboard/
│   │   │   │   ├── StatsCard.tsx
│   │   │   │   ├── IncidentFeed.tsx
│   │   │   │   ├── BugQueue.tsx
│   │   │   │   └── CorrelationGraph.tsx
│   │   │   ├── incidents/
│   │   │   │   ├── IncidentList.tsx
│   │   │   │   ├── IncidentDetail.tsx
│   │   │   │   └── IncidentTimeline.tsx
│   │   │   ├── bugs/
│   │   │   │   ├── BugList.tsx
│   │   │   │   ├── BugDetail.tsx
│   │   │   │   ├── BugClassification.tsx
│   │   │   │   └── DuplicatePanel.tsx
│   │   │   ├── correlations/
│   │   │   │   ├── CorrelationView.tsx
│   │   │   │   ├── RootCauseCard.tsx
│   │   │   │   ├── BugCluster.tsx
│   │   │   │   └── ImpactGraph.tsx
│   │   │   ├── predictions/
│   │   │   │   ├── PredictionList.tsx
│   │   │   │   ├── PredictionCard.tsx
│   │   │   │   └── AlertConfig.tsx
│   │   │   └── chat/
│   │   │       ├── ChatInterface.tsx
│   │   │       └── ChatMessage.tsx
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Incidents.tsx
│   │   │   ├── Bugs.tsx
│   │   │   ├── Correlations.tsx
│   │   │   ├── Predictions.tsx
│   │   │   └── Settings.tsx
│   │   ├── hooks/
│   │   │   ├── useIncidents.ts
│   │   │   ├── useBugs.ts
│   │   │   ├── useCorrelations.ts
│   │   │   └── useWebSocket.ts
│   │   ├── store/                     # Zustand state
│   │   │   └── index.ts
│   │   ├── types/
│   │   │   └── index.ts
│   │   └── lib/
│   │       └── utils.ts
│   └── public/
│
├── backend/                           # FastAPI
│   ├── pyproject.toml
│   ├── src/
│   │   ├── __init__.py
│   │   ├── main.py                    # FastAPI app
│   │   ├── config.py                  # Settings
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── deps.py                # Dependencies
│   │   │   └── routes/
│   │   │       ├── __init__.py
│   │   │       ├── incidents.py
│   │   │       ├── bugs.py
│   │   │       ├── correlations.py
│   │   │       ├── predictions.py
│   │   │       ├── chat.py
│   │   │       └── webhooks.py
│   │   ├── models/                    # SQLAlchemy models
│   │   │   ├── __init__.py
│   │   │   ├── incident.py
│   │   │   ├── bug.py
│   │   │   ├── correlation.py
│   │   │   └── pattern.py
│   │   ├── schemas/                   # Pydantic schemas
│   │   │   ├── __init__.py
│   │   │   ├── incident.py
│   │   │   ├── bug.py
│   │   │   ├── correlation.py
│   │   │   └── prediction.py
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── pipeline_monitor/      # Track 5
│   │   │   │   ├── __init__.py
│   │   │   │   ├── great_expectations_service.py
│   │   │   │   ├── anomaly_detector.py
│   │   │   │   ├── schema_validator.py
│   │   │   │   ├── freshness_checker.py
│   │   │   │   └── incident_generator.py
│   │   │   ├── bug_triage/            # Track 4
│   │   │   │   ├── __init__.py
│   │   │   │   ├── classifier.py
│   │   │   │   ├── duplicate_detector.py
│   │   │   │   ├── severity_predictor.py
│   │   │   │   ├── embeddings.py
│   │   │   │   └── auto_router.py
│   │   │   ├── correlation/           # Core Innovation
│   │   │   │   ├── __init__.py
│   │   │   │   ├── temporal_matcher.py
│   │   │   │   ├── impact_graph.py
│   │   │   │   ├── root_cause_ranker.py
│   │   │   │   └── bug_clusterer.py
│   │   │   └── intelligence/          # AI Layer
│   │   │       ├── __init__.py
│   │   │       ├── llm_service.py
│   │   │       ├── explanation_generator.py
│   │   │       ├── prediction_engine.py
│   │   │       └── resolution_learner.py
│   │   ├── db/
│   │   │   ├── __init__.py
│   │   │   ├── session.py
│   │   │   └── migrations/
│   │   ├── integrations/
│   │   │   ├── __init__.py
│   │   │   ├── pinecone_client.py
│   │   │   ├── ollama_client.py
│   │   │   └── github_webhook.py
│   │   ├── workers/                   # Celery tasks
│   │   │   ├── __init__.py
│   │   │   ├── validation_task.py
│   │   │   ├── correlation_task.py
│   │   │   └── prediction_task.py
│   │   └── utils/
│   │       ├── __init__.py
│   │       └── helpers.py
│   └── tests/
│
├── demo/                              # Demo utilities
│   ├── simulate_incident.py
│   ├── generate_bugs.py
│   ├── demo_sequence.py
│   └── sample_data/
│       ├── incidents.json
│       └── bugs.json
│
└── docs/
    ├── api.md
    ├── setup.md
    └── demo_guide.md
```
-->

---

## Implementation Phases

### Phase 1: Foundation (Days 1-10)

#### 1.1 Project Setup (Days 1-3)

**Backend Setup:**
```bash
# Initialize backend
cd backend
python -m venv .venv
# activate venv (Windows: .venv\Scripts\activate, mac/linux: source .venv/bin/activate)
pip install fastapi uvicorn sqlalchemy asyncpg pydantic python-dotenv celery redis sentence-transformers pinecone great-expectations pyod scikit-learn httpx python-socketio
pip freeze > requirements.txt
```

**Frontend Setup:**
```bash
# Initialize frontend
npm create vite@latest frontend -- --template react-ts
cd frontend
npm install
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p
npx shadcn-ui@latest init
npm install @tanstack/react-query axios recharts socket.io-client zustand
npm install lucide-react date-fns
```

**Docker Compose:**
```yaml
# docker-compose.yml
version: "3.8"

services:
  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    environment:
      - VITE_API_URL=http://localhost:8000
    depends_on:
      - backend

  backend:
    build: ./backend
    ports:
      - "8000:8000"
    env_file:
      - ./backend/.env
    environment:
      - REDIS_URL=redis://redis:6379/0
      - OLLAMA_HOST=http://ollama:11434
    depends_on:
      - redis
      - ollama

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  ollama:
    image: ollama/ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama

  celery_worker:
    build: ./backend
    command: celery -A src.workers worker --loglevel=info
    env_file:
      - ./backend/.env
    environment:
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - redis
      - backend

volumes:
  ollama_data:
```

**Tasks:**
```
- [x] Initialize monorepo structure
- [x] Set up backend with FastAPI
- [x] Set up frontend with React + Vite
- [x] Configure Docker Compose
- [x] Define models + Alembic migrations
- [ ] Apply migrations to Supabase
- [x] Configure Pinecone indexes (auto-create)
- [x] Implement GitHub webhook ingestion
- [ ] Configure ngrok + GitHub webhook URL
- [ ] Pull Llama 3 model in Ollama
- [x] Create basic API health endpoints
- [x] Set up frontend routing
```

#### 1.2 Database Models (Days 4-5)

```python
# backend/src/models/incident.py
from sqlalchemy import Column, String, DateTime, JSON, Enum, Float
from sqlalchemy.dialects.postgresql import UUID
import uuid
from .base import Base

class DataIncident(Base):
    __tablename__ = "data_incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(String, unique=True, index=True)  # DI-2025-01-15-001
    timestamp = Column(DateTime, nullable=False)
    table_name = Column(String, nullable=False, index=True)
    incident_type = Column(Enum(
        'SCHEMA_DRIFT', 'NULL_SPIKE', 'VOLUME_ANOMALY',
        'FRESHNESS', 'DISTRIBUTION_DRIFT', 'VALIDATION_FAILURE',
        name='incident_type'
    ))
    severity = Column(Enum('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', name='severity'))
    details = Column(JSON)  # Flexible storage for incident specifics
    affected_columns = Column(JSON)  # List of column names
    anomaly_score = Column(Float)
    downstream_systems = Column(JSON)  # List of affected systems
    status = Column(Enum('ACTIVE', 'INVESTIGATING', 'RESOLVED', name='status'))
    resolved_at = Column(DateTime, nullable=True)
    resolution_notes = Column(String, nullable=True)
    created_at = Column(DateTime, server_default='now()')


# backend/src/models/bug.py
class BugReport(Base):
    __tablename__ = "bug_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    bug_id = Column(String, unique=True, index=True)  # External ID (GitHub, Jira)
    source = Column(Enum('github', 'jira', 'manual', name='bug_source'))
    title = Column(String, nullable=False)
    description = Column(String)
    created_at = Column(DateTime, nullable=False)
    reporter = Column(String)
    labels = Column(JSON)  # Original labels
    stack_trace = Column(String, nullable=True)

    # Classification results
    classified_type = Column(Enum('bug', 'feature', 'question', name='bug_type'))
    classified_component = Column(String)
    classified_severity = Column(Enum('critical', 'high', 'medium', 'low', name='bug_severity'))
    confidence_score = Column(Float)

    # Correlation results
    is_data_related = Column(Boolean, default=False)
    correlated_incident_id = Column(UUID(as_uuid=True), ForeignKey('data_incidents.id'), nullable=True)
    correlation_score = Column(Float, nullable=True)

    # Duplicate detection
    is_duplicate = Column(Boolean, default=False)
    duplicate_of_id = Column(UUID(as_uuid=True), ForeignKey('bug_reports.id'), nullable=True)
    duplicate_score = Column(Float, nullable=True)

    # Routing
    assigned_team = Column(String, nullable=True)
    status = Column(Enum('new', 'triaged', 'assigned', 'resolved', name='bug_status'))

    # Embedding reference
    embedding_id = Column(String, nullable=True)  # Pinecone vector ID


# backend/src/models/correlation.py
class BugIncidentCorrelation(Base):
    __tablename__ = "correlations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    bug_id = Column(UUID(as_uuid=True), ForeignKey('bug_reports.id'))
    incident_id = Column(UUID(as_uuid=True), ForeignKey('data_incidents.id'))

    correlation_score = Column(Float)
    temporal_score = Column(Float)
    component_score = Column(Float)
    keyword_score = Column(Float)

    explanation = Column(String)  # LLM-generated explanation
    created_at = Column(DateTime, server_default='now()')


# backend/src/models/pattern.py
class ResolutionPattern(Base):
    __tablename__ = "resolution_patterns"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_type = Column(String)
    affected_table = Column(String)
    symptom_keywords = Column(JSON)  # Keywords from related bugs
    resolution_action = Column(String)
    resolution_time_avg = Column(Float)  # Average time to resolve in hours
    occurrence_count = Column(Integer, default=1)
    last_seen = Column(DateTime)
    embedding_id = Column(String)  # For similarity matching


class BugPrediction(Base):
    __tablename__ = "bug_predictions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey('data_incidents.id'))
    predicted_bug_count = Column(Integer)
    predicted_components = Column(JSON)
    confidence = Column(Float)
    prediction_window_hours = Column(Integer)
    created_at = Column(DateTime, server_default='now()')

    # Validation
    actual_bug_count = Column(Integer, nullable=True)
    was_accurate = Column(Boolean, nullable=True)
```

**Tasks:**
```
- [x] Create SQLAlchemy models for all entities
- [x] Set up Alembic migrations
- [x] Create Pydantic schemas for API
- [x] Initialize database with sample data
```

#### 1.3 Pinecone Setup (Days 6-7)

```python
# backend/src/integrations/pinecone_client.py
from pinecone import Pinecone, ServerlessSpec
from sentence_transformers import SentenceTransformer
import os

class PineconeService:
    def __init__(self):
        self.pc = Pinecone(api_key=os.getenv("PINECONE_API_KEY"))
        self.encoder = SentenceTransformer('all-MiniLM-L6-v2')

        # Create indexes if they don't exist
        self._ensure_indexes()

    def _ensure_indexes(self):
        indexes = self.pc.list_indexes()

        # Bug embeddings index
        if "databug-bugs" not in [idx.name for idx in indexes]:
            self.pc.create_index(
                name="databug-bugs",
                dimension=384,  # all-MiniLM-L6-v2 dimension
                metric="cosine",
                spec=ServerlessSpec(cloud="aws", region="us-east-1")
            )

        # Resolution patterns index
        if "databug-patterns" not in [idx.name for idx in indexes]:
            self.pc.create_index(
                name="databug-patterns",
                dimension=384,
                metric="cosine",
                spec=ServerlessSpec(cloud="aws", region="us-east-1")
            )

        self.bugs_index = self.pc.Index("databug-bugs")
        self.patterns_index = self.pc.Index("databug-patterns")

    def embed_text(self, text: str) -> list:
        """Generate embedding for text."""
        return self.encoder.encode(text).tolist()

    def upsert_bug(self, bug_id: str, title: str, description: str, metadata: dict):
        """Store bug embedding in Pinecone."""
        text = f"{title} {description}"
        embedding = self.embed_text(text)

        self.bugs_index.upsert(vectors=[{
            "id": bug_id,
            "values": embedding,
            "metadata": metadata
        }])

        return bug_id

    def find_similar_bugs(self, title: str, description: str, top_k: int = 10) -> list:
        """Find similar bugs for duplicate detection."""
        text = f"{title} {description}"
        embedding = self.embed_text(text)

        results = self.bugs_index.query(
            vector=embedding,
            top_k=top_k,
            include_metadata=True
        )

        return results.matches

    def upsert_pattern(self, pattern_id: str, description: str, metadata: dict):
        """Store resolution pattern embedding."""
        embedding = self.embed_text(description)

        self.patterns_index.upsert(vectors=[{
            "id": pattern_id,
            "values": embedding,
            "metadata": metadata
        }])

    def find_similar_patterns(self, incident_description: str, top_k: int = 5) -> list:
        """Find similar resolution patterns for an incident."""
        embedding = self.embed_text(incident_description)

        results = self.patterns_index.query(
            vector=embedding,
            top_k=top_k,
            include_metadata=True
        )

        return results.matches
```

**Tasks:**
```
- [ ] Set up Pinecone account and get API key
- [x] Create PineconeService class
- [x] Create databug-bugs index (for duplicate detection)
- [x] Create databug-patterns index (for resolution learning)
- [ ] Test embedding and retrieval
- [x] Write unit tests for Pinecone operations
```

#### 1.4 Basic Frontend Structure (Days 8-10)

```typescript
// frontend/src/types/index.ts
export interface DataIncident {
  id: string;
  incident_id: string;
  timestamp: string;
  table_name: string;
  incident_type: 'SCHEMA_DRIFT' | 'NULL_SPIKE' | 'VOLUME_ANOMALY' | 'FRESHNESS' | 'DISTRIBUTION_DRIFT';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  details: Record<string, any>;
  affected_columns: string[];
  anomaly_score: number;
  downstream_systems: string[];
  status: 'ACTIVE' | 'INVESTIGATING' | 'RESOLVED';
  related_bugs_count?: number;
}

export interface BugReport {
  id: string;
  bug_id: string;
  source: 'github' | 'jira' | 'manual';
  title: string;
  description: string;
  created_at: string;
  classified_type: 'bug' | 'feature' | 'question';
  classified_component: string;
  classified_severity: 'critical' | 'high' | 'medium' | 'low';
  is_data_related: boolean;
  correlation_score?: number;
  correlated_incident?: DataIncident;
  is_duplicate: boolean;
  duplicate_of?: BugReport;
  assigned_team?: string;
  status: 'new' | 'triaged' | 'assigned' | 'resolved';
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

// frontend/src/api/client.ts
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

// frontend/src/api/incidents.ts
import { api } from './client';
import { DataIncident } from '../types';

export const incidentsApi = {
  getAll: async (params?: { status?: string; severity?: string }) => {
    const { data } = await api.get<DataIncident[]>('/api/incidents', { params });
    return data;
  },

  getById: async (id: string) => {
    const { data } = await api.get<DataIncident>(`/api/incidents/${id}`);
    return data;
  },

  getRelatedBugs: async (id: string) => {
    const { data } = await api.get<BugReport[]>(`/api/incidents/${id}/bugs`);
    return data;
  },
};

// frontend/src/api/bugs.ts
import { api } from './client';
import { BugReport } from '../types';

export const bugsApi = {
  getAll: async (params?: { status?: string; is_data_related?: boolean }) => {
    const { data } = await api.get<BugReport[]>('/api/bugs', { params });
    return data;
  },

  getById: async (id: string) => {
    const { data } = await api.get<BugReport>(`/api/bugs/${id}`);
    return data;
  },

  getDuplicates: async (id: string) => {
    const { data } = await api.get<BugReport[]>(`/api/bugs/${id}/duplicates`);
    return data;
  },
};
```

```tsx
// frontend/src/App.tsx
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Layout from './components/layout/Layout';
import Dashboard from './pages/Dashboard';
import Incidents from './pages/Incidents';
import Bugs from './pages/Bugs';
import Correlations from './pages/Correlations';
import Predictions from './pages/Predictions';

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="incidents" element={<Incidents />} />
            <Route path="bugs" element={<Bugs />} />
            <Route path="correlations" element={<Correlations />} />
            <Route path="predictions" element={<Predictions />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
```

**Tasks:**
```
- [x] Set up React Router with all pages
- [x] Create Layout component with sidebar navigation
- [x] Set up TanStack Query for data fetching
- [x] Create API client modules
- [x] Build TypeScript type definitions
- [x] Set up WebSocket connection for real-time updates
- [x] Create basic Dashboard page with placeholder components
```

---

### Phase 2: Track 5 - Data Pipeline Monitor (Days 11-20)

#### 2.1 Great Expectations Integration (Days 11-14)

```python
# backend/src/services/pipeline_monitor/great_expectations_service.py
import great_expectations as gx
from great_expectations.core import ExpectationSuite
from datetime import datetime
from typing import List, Dict, Any
import json

class GreatExpectationsService:
    def __init__(self, connection_string: str):
        self.context = gx.get_context()
        self.connection_string = connection_string
        self._setup_datasource()

    def _setup_datasource(self):
        """Configure database datasource."""
        self.datasource = self.context.sources.add_or_update_postgres(
            name="databug_source",
            connection_string=self.connection_string
        )

    def create_expectation_suite(self, table_name: str) -> ExpectationSuite:
        """Create default expectation suite for a table."""
        suite_name = f"{table_name}_suite"

        suite = self.context.add_or_update_expectation_suite(suite_name)

        # Add common expectations
        expectations = [
            # Row count check
            {
                "expectation_type": "expect_table_row_count_to_be_between",
                "kwargs": {"min_value": 1}
            },
        ]

        for exp in expectations:
            suite.add_expectation(
                expectation_configuration=gx.core.ExpectationConfiguration(**exp)
            )

        return suite

    def add_column_expectations(self, suite_name: str, column: str, config: dict):
        """Add column-specific expectations."""
        suite = self.context.get_expectation_suite(suite_name)

        if config.get("not_null", False):
            suite.add_expectation(
                gx.core.ExpectationConfiguration(
                    expectation_type="expect_column_values_to_not_be_null",
                    kwargs={"column": column}
                )
            )

        if "value_set" in config:
            suite.add_expectation(
                gx.core.ExpectationConfiguration(
                    expectation_type="expect_column_values_to_be_in_set",
                    kwargs={"column": column, "value_set": config["value_set"]}
                )
            )

        if "min_value" in config or "max_value" in config:
            suite.add_expectation(
                gx.core.ExpectationConfiguration(
                    expectation_type="expect_column_values_to_be_between",
                    kwargs={
                        "column": column,
                        "min_value": config.get("min_value"),
                        "max_value": config.get("max_value")
                    }
                )
            )

        self.context.save_expectation_suite(suite)

    def validate_table(self, table_name: str) -> Dict[str, Any]:
        """Run validation on a table and return results."""
        suite_name = f"{table_name}_suite"

        # Get data asset
        asset = self.datasource.add_table_asset(
            name=table_name,
            table_name=table_name
        )

        batch_request = asset.build_batch_request()

        # Run validation
        checkpoint = self.context.add_or_update_checkpoint(
            name=f"{table_name}_checkpoint",
            validations=[{
                "batch_request": batch_request,
                "expectation_suite_name": suite_name
            }]
        )

        results = checkpoint.run()

        return self._parse_results(results, table_name)

    def _parse_results(self, results, table_name: str) -> Dict[str, Any]:
        """Parse validation results into incident-ready format."""
        validation_result = list(results.run_results.values())[0]

        success = validation_result["success"]
        statistics = validation_result["statistics"]

        failures = []
        for result in validation_result["results"]:
            if not result["success"]:
                failures.append({
                    "expectation_type": result["expectation_config"]["expectation_type"],
                    "column": result["expectation_config"]["kwargs"].get("column"),
                    "details": result["result"]
                })

        return {
            "table": table_name,
            "timestamp": datetime.utcnow().isoformat(),
            "success": success,
            "statistics": {
                "successful": statistics["successful_expectations"],
                "unsuccessful": statistics["unsuccessful_expectations"],
                "total": statistics["evaluated_expectations"]
            },
            "failures": failures
        }
```

**Demo Table Expectations:**
```python
# Configuration for demo tables
DEMO_TABLE_CONFIGS = {
    "user_transactions": {
        "columns": {
            "user_id": {"not_null": True},
            "transaction_amount": {"not_null": True, "min_value": 0},
            "transaction_date": {"not_null": True},
            "status": {"not_null": True, "value_set": ["completed", "pending", "failed"]}
        },
        "row_count": {"min": 100, "max": 1000000}
    },
    "user_profiles": {
        "columns": {
            "user_id": {"not_null": True},
            "email": {"not_null": True, "regex": r"^[\w\.-]+@[\w\.-]+\.\w+$"},
            "created_at": {"not_null": True}
        }
    },
    "product_catalog": {
        "columns": {
            "product_id": {"not_null": True},
            "name": {"not_null": True},
            "price": {"not_null": True, "min_value": 0}
        }
    }
}
```

**Tasks:**
```
- [x] Set up Great Expectations context
- [x] Create expectation suites for demo tables
- [x] Implement validation runner
- [x] Create validation result parser
- [ ] Build scheduled validation job (Celery)
- [ ] Test with sample data
```

#### 2.2 Anomaly Detection (Days 15-17)

```python
# backend/src/services/pipeline_monitor/anomaly_detector.py
from pyod.models.iforest import IForest
from pyod.models.knn import KNN
from pyod.models.ensemble import Ensemble
import numpy as np
from typing import Dict, List, Tuple
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

class AnomalyDetector:
    def __init__(self, db: Session):
        self.db = db
        self.models = {}

    def compute_metrics(self, table_name: str) -> Dict[str, float]:
        """Compute current metrics for a table."""
        query = f"""
            SELECT
                COUNT(*) as row_count,
                COUNT(*) FILTER (WHERE user_id IS NULL) * 100.0 / NULLIF(COUNT(*), 0) as null_rate_user_id,
                COUNT(*) FILTER (WHERE transaction_amount IS NULL) * 100.0 / NULLIF(COUNT(*), 0) as null_rate_amount,
                AVG(transaction_amount) as avg_amount,
                STDDEV(transaction_amount) as std_amount,
                MAX(transaction_date) as latest_record
            FROM {table_name}
        """
        result = self.db.execute(query).fetchone()

        return {
            "row_count": result.row_count,
            "null_rate_user_id": result.null_rate_user_id or 0,
            "null_rate_amount": result.null_rate_amount or 0,
            "avg_amount": float(result.avg_amount or 0),
            "std_amount": float(result.std_amount or 0),
            "freshness_hours": self._compute_freshness(result.latest_record)
        }

    def _compute_freshness(self, latest_record: datetime) -> float:
        """Compute hours since last record."""
        if latest_record is None:
            return 999.0  # Very stale
        delta = datetime.utcnow() - latest_record
        return delta.total_seconds() / 3600

    def get_historical_metrics(self, table_name: str, days: int = 30) -> List[Dict]:
        """Get historical metrics from stored snapshots."""
        # Query from metrics_history table
        query = """
            SELECT metrics, recorded_at
            FROM metrics_history
            WHERE table_name = :table_name
            AND recorded_at > :start_date
            ORDER BY recorded_at
        """
        results = self.db.execute(
            query,
            {"table_name": table_name, "start_date": datetime.utcnow() - timedelta(days=days)}
        ).fetchall()

        return [{"metrics": r.metrics, "timestamp": r.recorded_at} for r in results]

    def train_model(self, table_name: str):
        """Train anomaly detection model on historical data."""
        historical = self.get_historical_metrics(table_name)

        if len(historical) < 10:
            return None  # Not enough data

        # Extract feature vectors
        features = []
        for record in historical:
            m = record["metrics"]
            features.append([
                m["row_count"],
                m["null_rate_user_id"],
                m["null_rate_amount"],
                m["avg_amount"],
                m["freshness_hours"]
            ])

        X = np.array(features)

        # Ensemble of anomaly detectors
        detectors = [
            IForest(contamination=0.1, random_state=42),
            KNN(contamination=0.1)
        ]

        model = Ensemble(base_estimators=detectors, n_jobs=-1)
        model.fit(X)

        self.models[table_name] = model
        return model

    def detect_anomaly(self, table_name: str, metrics: Dict) -> Tuple[bool, float, Dict]:
        """Detect if current metrics are anomalous."""
        if table_name not in self.models:
            self.train_model(table_name)

        model = self.models.get(table_name)
        if model is None:
            return False, 0.0, {}  # No model available

        # Create feature vector
        X = np.array([[
            metrics["row_count"],
            metrics["null_rate_user_id"],
            metrics["null_rate_amount"],
            metrics["avg_amount"],
            metrics["freshness_hours"]
        ]])

        # Get anomaly score
        score = model.decision_function(X)[0]
        is_anomaly = model.predict(X)[0] == 1

        # Identify which metrics are anomalous
        anomalous_metrics = self._identify_anomalous_metrics(table_name, metrics)

        return is_anomaly, float(score), anomalous_metrics

    def _identify_anomalous_metrics(self, table_name: str, metrics: Dict) -> Dict:
        """Identify which specific metrics are anomalous."""
        historical = self.get_historical_metrics(table_name)
        if len(historical) < 5:
            return {}

        anomalies = {}

        # Compute z-scores for each metric
        for key in ["row_count", "null_rate_user_id", "null_rate_amount", "freshness_hours"]:
            values = [h["metrics"][key] for h in historical]
            mean = np.mean(values)
            std = np.std(values) or 1
            z_score = (metrics[key] - mean) / std

            if abs(z_score) > 3:
                anomalies[key] = {
                    "current": metrics[key],
                    "mean": mean,
                    "std": std,
                    "z_score": z_score,
                    "direction": "high" if z_score > 0 else "low"
                }

        return anomalies
```

**Tasks:**
```
- [x] Implement metrics computation for tables
- [x] Create historical metrics storage
- [x] Build PyOD ensemble model
- [x] Implement anomaly scoring
- [x] Create metric-level anomaly identification
- [x] Test with simulated anomalies
```

#### 2.3 Incident Generation (Days 18-20)

```python
# backend/src/services/pipeline_monitor/incident_generator.py
from typing import Dict, Optional
from datetime import datetime
import uuid

class IncidentGenerator:
    def __init__(self, db, lineage_graph):
        self.db = db
        self.lineage = lineage_graph

    def generate_incident(
        self,
        table_name: str,
        validation_result: Dict,
        anomaly_result: Optional[Dict] = None
    ) -> DataIncident:
        """Generate incident from validation/anomaly results."""

        # Determine incident type
        incident_type = self._classify_incident(validation_result, anomaly_result)

        # Calculate severity
        severity = self._calculate_severity(incident_type, validation_result, anomaly_result)

        # Get affected columns
        affected_columns = self._extract_affected_columns(validation_result)

        # Get downstream impact
        downstream = self.lineage.get_downstream_systems(table_name)

        # Build details
        details = self._build_details(validation_result, anomaly_result)

        # Create incident
        incident = DataIncident(
            incident_id=f"DI-{datetime.utcnow().strftime('%Y-%m-%d')}-{uuid.uuid4().hex[:6]}",
            timestamp=datetime.utcnow(),
            table_name=table_name,
            incident_type=incident_type,
            severity=severity,
            details=details,
            affected_columns=affected_columns,
            anomaly_score=anomaly_result.get("score", 0) if anomaly_result else 0,
            downstream_systems=downstream,
            status="ACTIVE"
        )

        self.db.add(incident)
        self.db.commit()

        return incident

    def _classify_incident(self, validation: Dict, anomaly: Optional[Dict]) -> str:
        """Classify incident type based on failures."""
        failures = validation.get("failures", [])

        for failure in failures:
            exp_type = failure["expectation_type"]

            if "column_to_exist" in exp_type:
                return "SCHEMA_DRIFT"
            if "not_be_null" in exp_type:
                return "NULL_SPIKE"
            if "row_count" in exp_type:
                return "VOLUME_ANOMALY"

        if anomaly and anomaly.get("is_anomaly"):
            anomalous = anomaly.get("anomalous_metrics", {})
            if "freshness_hours" in anomalous:
                return "FRESHNESS"
            if "row_count" in anomalous:
                return "VOLUME_ANOMALY"
            return "DISTRIBUTION_DRIFT"

        return "VALIDATION_FAILURE"

    def _calculate_severity(self, incident_type: str, validation: Dict, anomaly: Optional[Dict]) -> str:
        """Calculate incident severity."""
        # Base severity by type
        type_severity = {
            "SCHEMA_DRIFT": "CRITICAL",
            "NULL_SPIKE": "HIGH",
            "VOLUME_ANOMALY": "HIGH",
            "FRESHNESS": "MEDIUM",
            "DISTRIBUTION_DRIFT": "MEDIUM",
            "VALIDATION_FAILURE": "LOW"
        }

        base = type_severity.get(incident_type, "LOW")

        # Boost for high anomaly scores
        if anomaly and anomaly.get("score", 0) > 0.8:
            if base == "MEDIUM":
                return "HIGH"
            if base == "HIGH":
                return "CRITICAL"

        return base

    def _extract_affected_columns(self, validation: Dict) -> List[str]:
        """Extract list of affected columns from failures."""
        columns = set()
        for failure in validation.get("failures", []):
            col = failure.get("column")
            if col:
                columns.add(col)
        return list(columns)

    def _build_details(self, validation: Dict, anomaly: Optional[Dict]) -> Dict:
        """Build detailed incident information."""
        return {
            "validation": {
                "total_expectations": validation["statistics"]["total"],
                "failed_expectations": validation["statistics"]["unsuccessful"],
                "failures": validation.get("failures", [])
            },
            "anomaly": anomaly or {},
            "generated_at": datetime.utcnow().isoformat()
        }
```

**Data Lineage Graph:**
```python
# backend/src/services/pipeline_monitor/lineage_graph.py
class DataLineageGraph:
    """Simple lineage graph for demo purposes."""

    LINEAGE = {
        "user_transactions": {
            "downstream": ["analytics_dashboard", "user_api", "mobile_app", "recommendation_model"],
            "owners": ["data_engineering"],
            "criticality": "HIGH",
            "refresh_frequency_hours": 1
        },
        "user_profiles": {
            "downstream": ["user_api", "mobile_app", "personalization_service"],
            "owners": ["data_engineering"],
            "criticality": "HIGH",
            "refresh_frequency_hours": 24
        },
        "product_catalog": {
            "downstream": ["search_service", "recommendation_model", "inventory_api"],
            "owners": ["data_engineering"],
            "criticality": "MEDIUM",
            "refresh_frequency_hours": 6
        }
    }

    COMPONENT_TO_TABLES = {
        "analytics_dashboard": ["user_transactions", "aggregated_metrics"],
        "user_api": ["user_transactions", "user_profiles"],
        "mobile_app": ["user_transactions", "user_profiles"],
        "recommendation_model": ["user_transactions", "product_catalog"],
        "search_service": ["product_catalog"],
        "personalization_service": ["user_profiles"]
    }

    def get_downstream_systems(self, table_name: str) -> List[str]:
        """Get systems affected by this table."""
        return self.LINEAGE.get(table_name, {}).get("downstream", [])

    def get_tables_for_component(self, component: str) -> List[str]:
        """Get tables that a component depends on."""
        return self.COMPONENT_TO_TABLES.get(component, [])

    def is_downstream(self, component: str, table: str) -> bool:
        """Check if component is downstream of table."""
        downstream = self.get_downstream_systems(table)
        return component in downstream
```

**Tasks:**
```
- [x] Implement incident classification logic
- [x] Create severity calculation algorithm
- [x] Build data lineage graph
- [x] Create incident storage and API
- [x] Set up real-time incident notifications (WebSocket)
- [ ] Build incident detail page in frontend
```

---

### Phase 3: Track 4 - Bug Triage Engine (Days 21-30)

#### 3.1 Bug Classification (Days 21-24)

```python
# backend/src/services/bug_triage/classifier.py
from sentence_transformers import SentenceTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import pickle
import numpy as np
from typing import Dict, Tuple

class BugClassifier:
    def __init__(self):
        self.encoder = SentenceTransformer('all-MiniLM-L6-v2')

        # Classifiers for each category
        self.type_classifier = None
        self.component_classifier = None
        self.severity_classifier = None

        # Label encoders
        self.type_encoder = LabelEncoder()
        self.component_encoder = LabelEncoder()
        self.severity_encoder = LabelEncoder()

        self._load_or_train_models()

    def _load_or_train_models(self):
        """Load pre-trained models or train on sample data."""
        try:
            with open("models/bug_classifier.pkl", "rb") as f:
                models = pickle.load(f)
                self.type_classifier = models["type"]
                self.component_classifier = models["component"]
                self.severity_classifier = models["severity"]
                self.type_encoder = models["type_encoder"]
                self.component_encoder = models["component_encoder"]
                self.severity_encoder = models["severity_encoder"]
        except FileNotFoundError:
            self._train_on_sample_data()

    def _train_on_sample_data(self):
        """Train on sample bug data for demo."""
        # Sample training data
        samples = [
            # (title, description, type, component, severity)
            ("Dashboard shows $0 revenue", "Revenue dashboard displaying zero values", "bug", "analytics", "critical"),
            ("API returns empty response", "User API returning null for profile", "bug", "backend", "high"),
            ("App crashes on login", "Mobile app crash when user tries to login", "bug", "mobile", "critical"),
            ("Add dark mode", "Please add dark mode support", "feature", "frontend", "low"),
            ("Slow page load", "Dashboard takes 10 seconds to load", "bug", "frontend", "medium"),
            ("Database connection timeout", "Getting connection timeouts to primary DB", "bug", "backend", "critical"),
            ("Recommendation engine wrong results", "ML model predicting incorrect items", "bug", "ml", "high"),
            ("How to reset password", "Can't find password reset option", "question", "frontend", "low"),
            # Add more samples for better training...
        ]

        # Generate embeddings
        texts = [f"{s[0]} {s[1]}" for s in samples]
        embeddings = self.encoder.encode(texts)

        # Fit encoders
        types = [s[2] for s in samples]
        components = [s[3] for s in samples]
        severities = [s[4] for s in samples]

        self.type_encoder.fit(types)
        self.component_encoder.fit(components)
        self.severity_encoder.fit(severities)

        # Train classifiers
        self.type_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.type_classifier.fit(embeddings, self.type_encoder.transform(types))

        self.component_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.component_classifier.fit(embeddings, self.component_encoder.transform(components))

        self.severity_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.severity_classifier.fit(embeddings, self.severity_encoder.transform(severities))

        # Save models
        self._save_models()

    def _save_models(self):
        """Save trained models."""
        import os
        os.makedirs("models", exist_ok=True)

        with open("models/bug_classifier.pkl", "wb") as f:
            pickle.dump({
                "type": self.type_classifier,
                "component": self.component_classifier,
                "severity": self.severity_classifier,
                "type_encoder": self.type_encoder,
                "component_encoder": self.component_encoder,
                "severity_encoder": self.severity_encoder
            }, f)

    def classify(self, title: str, description: str) -> Dict:
        """Classify a bug report."""
        text = f"{title} {description}"
        embedding = self.encoder.encode([text])

        # Get predictions with probabilities
        type_probs = self.type_classifier.predict_proba(embedding)[0]
        type_pred = self.type_encoder.inverse_transform([np.argmax(type_probs)])[0]

        component_probs = self.component_classifier.predict_proba(embedding)[0]
        component_pred = self.component_encoder.inverse_transform([np.argmax(component_probs)])[0]

        severity_probs = self.severity_classifier.predict_proba(embedding)[0]
        severity_pred = self.severity_encoder.inverse_transform([np.argmax(severity_probs)])[0]

        # Calculate overall confidence
        confidence = (max(type_probs) + max(component_probs) + max(severity_probs)) / 3

        return {
            "type": type_pred,
            "type_confidence": float(max(type_probs)),
            "component": component_pred,
            "component_confidence": float(max(component_probs)),
            "severity": severity_pred,
            "severity_confidence": float(max(severity_probs)),
            "overall_confidence": float(confidence)
        }
```

**Tasks:**
```
- [x] Implement bug classification pipeline
- [x] Create training data from sample bugs
- [x] Train type/component/severity classifiers
- [x] Add confidence scoring
- [ ] Create API endpoint for classification
- [ ] Test with various bug types
```

#### 3.2 Duplicate Detection (Days 25-27)

```python
# backend/src/services/bug_triage/duplicate_detector.py
from typing import List, Tuple, Optional
from ..integrations.pinecone_client import PineconeService

class DuplicateDetector:
    def __init__(self, pinecone: PineconeService):
        self.pinecone = pinecone
        self.similarity_threshold = 0.85

    def find_duplicates(
        self,
        bug_id: str,
        title: str,
        description: str,
        exclude_ids: List[str] = None
    ) -> List[Dict]:
        """Find potential duplicate bugs."""
        # Search for similar bugs
        matches = self.pinecone.find_similar_bugs(title, description, top_k=10)

        duplicates = []
        for match in matches:
            # Skip self and excluded bugs
            if match.id == bug_id:
                continue
            if exclude_ids and match.id in exclude_ids:
                continue

            # Only return high similarity matches
            if match.score >= self.similarity_threshold:
                duplicates.append({
                    "bug_id": match.id,
                    "similarity_score": match.score,
                    "title": match.metadata.get("title"),
                    "status": match.metadata.get("status"),
                    "created_at": match.metadata.get("created_at")
                })

        return duplicates

    def register_bug(self, bug: BugReport):
        """Register a new bug in the vector store."""
        self.pinecone.upsert_bug(
            bug_id=str(bug.id),
            title=bug.title,
            description=bug.description,
            metadata={
                "title": bug.title,
                "status": bug.status,
                "created_at": bug.created_at.isoformat(),
                "component": bug.classified_component,
                "severity": bug.classified_severity
            }
        )

    def get_duplicate_clusters(self) -> List[List[str]]:
        """Get clusters of duplicate bugs."""
        # Implementation for grouping duplicates
        pass
```

**Tasks:**
```
- [x] Implement duplicate detection with Pinecone
- [x] Set similarity threshold (0.85)
- [x] Create duplicate linking logic
- [ ] Build duplicate cluster view in frontend
- [ ] Test with similar bug reports
```

#### 3.3 Auto-Routing (Days 28-30)

```python
# backend/src/services/bug_triage/auto_router.py
from typing import Dict, Optional

class AutoRouter:
    """Routes bugs to appropriate teams based on classification and correlation."""

    COMPONENT_TEAM_MAP = {
        "frontend": "frontend_team",
        "backend": "backend_team",
        "mobile": "mobile_team",
        "analytics": "analytics_team",
        "ml": "ml_team",
        "infrastructure": "platform_team",
        "data": "data_engineering"
    }

    def route_bug(
        self,
        classification: Dict,
        is_data_related: bool,
        correlation_score: Optional[float] = None
    ) -> Dict:
        """Determine routing for a bug."""

        # If highly correlated with data incident, route to data team
        if is_data_related and correlation_score and correlation_score > 0.7:
            return {
                "team": "data_engineering",
                "reason": "Bug is highly correlated with a data pipeline incident",
                "confidence": correlation_score,
                "priority_boost": True
            }

        # Route based on component
        component = classification.get("component", "backend")
        team = self.COMPONENT_TEAM_MAP.get(component, "backend_team")

        return {
            "team": team,
            "reason": f"Classified as {component} issue",
            "confidence": classification.get("component_confidence", 0.5),
            "priority_boost": False
        }

    def calculate_priority(
        self,
        severity: str,
        is_data_related: bool,
        correlation_score: Optional[float] = None
    ) -> str:
        """Calculate bug priority."""
        base_priority = {
            "critical": "P0",
            "high": "P1",
            "medium": "P2",
            "low": "P3"
        }

        priority = base_priority.get(severity, "P2")

        # Boost priority for data-related bugs (they affect multiple users)
        if is_data_related and correlation_score and correlation_score > 0.7:
            if priority == "P1":
                priority = "P0"
            elif priority == "P2":
                priority = "P1"

        return priority
```

**Tasks:**
```
- [x] Implement routing logic
- [x] Create team assignment rules
- [x] Add priority calculation
- [ ] Build routing explanation generator
- [ ] Create bug assignment API
- [ ] Test routing accuracy
```

---

### Phase 4: Correlation Engine (Days 31-36)

#### 4.1 Temporal & Component Correlation (Days 31-33)

```python
# backend/src/services/correlation/temporal_matcher.py
from datetime import datetime, timedelta
from typing import List, Tuple
from sqlalchemy.orm import Session

class TemporalMatcher:
    def __init__(self, db: Session):
        self.db = db

    def find_correlated_incidents(
        self,
        bug: BugReport,
        window_hours: int = 24
    ) -> List[Tuple[DataIncident, float]]:
        """Find incidents that may have caused this bug."""

        # Get incidents in time window before bug
        incidents = self.db.query(DataIncident).filter(
            DataIncident.timestamp >= bug.created_at - timedelta(hours=window_hours),
            DataIncident.timestamp <= bug.created_at,
            DataIncident.status.in_(["ACTIVE", "INVESTIGATING"])
        ).all()

        correlations = []
        for incident in incidents:
            score = self.calculate_correlation_score(bug, incident)
            if score > 0.3:  # Minimum threshold
                correlations.append((incident, score))

        # Sort by score descending
        return sorted(correlations, key=lambda x: x[1], reverse=True)

    def calculate_correlation_score(self, bug: BugReport, incident: DataIncident) -> float:
        """Calculate correlation score between bug and incident."""
        scores = {
            "temporal": self._temporal_score(bug, incident),
            "component": self._component_score(bug, incident),
            "keyword": self._keyword_score(bug, incident),
            "severity": self._severity_alignment_score(bug, incident)
        }

        # Weighted combination
        weights = {
            "temporal": 0.35,
            "component": 0.35,
            "keyword": 0.20,
            "severity": 0.10
        }

        total = sum(scores[k] * weights[k] for k in scores)
        return min(total, 1.0)

    def _temporal_score(self, bug: BugReport, incident: DataIncident) -> float:
        """Score based on time between incident and bug."""
        time_diff = (bug.created_at - incident.timestamp).total_seconds() / 3600

        if time_diff < 0:  # Bug before incident
            return 0.0
        elif time_diff <= 1:
            return 1.0
        elif time_diff <= 2:
            return 0.9 - (time_diff - 1) * 0.2
        elif time_diff <= 6:
            return 0.7 - (time_diff - 2) * 0.1
        elif time_diff <= 24:
            return 0.3 - (time_diff - 6) * 0.015
        else:
            return 0.0

    def _component_score(self, bug: BugReport, incident: DataIncident) -> float:
        """Score based on component-table relationship."""
        from .lineage_graph import DataLineageGraph
        lineage = DataLineageGraph()

        bug_component = bug.classified_component
        if not bug_component:
            return 0.3  # Unknown component, slight possibility

        # Check if bug's component is downstream of incident's table
        if lineage.is_downstream(bug_component, incident.table_name):
            return 1.0

        # Check for partial matches
        tables = lineage.get_tables_for_component(bug_component)
        if incident.table_name in tables:
            return 0.8

        return 0.0

    def _keyword_score(self, bug: BugReport, incident: DataIncident) -> float:
        """Score based on keyword overlap."""
        # Keywords from incident
        incident_keywords = set()
        incident_keywords.add(incident.table_name.lower())
        for col in incident.affected_columns:
            incident_keywords.add(col.lower())
        incident_keywords.add(incident.incident_type.lower().replace("_", " "))

        # Keywords from bug
        bug_text = f"{bug.title} {bug.description}".lower()

        # Count matches
        matches = sum(1 for kw in incident_keywords if kw in bug_text)

        if matches >= 3:
            return 1.0
        elif matches >= 2:
            return 0.7
        elif matches >= 1:
            return 0.4
        return 0.0

    def _severity_alignment_score(self, bug: BugReport, incident: DataIncident) -> float:
        """Score based on severity alignment."""
        severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        incident_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        bug_sev = severity_map.get(bug.classified_severity, 2)
        inc_sev = incident_map.get(incident.severity, 2)

        # High severity incident + high severity bug = likely related
        if inc_sev >= 3 and bug_sev >= 3:
            return 1.0
        elif abs(inc_sev - bug_sev) <= 1:
            return 0.7
        return 0.3
```

**Tasks:**
```
- [x] Implement temporal scoring algorithm
- [x] Create component-based scoring
- [x] Add keyword overlap detection
- [x] Build weighted score combination
- [x] Test correlation accuracy
```

#### 4.2 Bug Clustering (Days 34-36)

```python
# backend/src/services/correlation/bug_clusterer.py
from typing import List, Dict
from collections import defaultdict

class BugClusterer:
    def __init__(self, db):
        self.db = db

    def cluster_by_root_cause(self, bugs: List[BugReport]) -> Dict[str, List[BugReport]]:
        """Group bugs by their correlated incident."""
        clusters = defaultdict(list)

        for bug in bugs:
            if bug.correlated_incident_id:
                cluster_key = str(bug.correlated_incident_id)
            else:
                cluster_key = "uncorrelated"

            clusters[cluster_key].append(bug)

        return dict(clusters)

    def get_cluster_summary(self, incident_id: str) -> Dict:
        """Get summary of a bug cluster."""
        bugs = self.db.query(BugReport).filter(
            BugReport.correlated_incident_id == incident_id
        ).all()

        incident = self.db.query(DataIncident).get(incident_id)

        return {
            "incident": incident,
            "bug_count": len(bugs),
            "bugs": bugs,
            "components_affected": list(set(b.classified_component for b in bugs)),
            "total_reporters": len(set(b.reporter for b in bugs)),
            "resolution_impact": f"Fixing this incident will resolve {len(bugs)} bug reports"
        }

    def propagate_resolution(self, incident_id: str, resolution_notes: str):
        """When incident is resolved, update all related bugs."""
        bugs = self.db.query(BugReport).filter(
            BugReport.correlated_incident_id == incident_id
        ).all()

        for bug in bugs:
            bug.status = "resolved"
            bug.resolution_notes = f"Resolved via data incident fix: {resolution_notes}"

        self.db.commit()

        return len(bugs)
```

**Tasks:**
```
- [x] Implement clustering by root cause
- [x] Create cluster summary generator
- [x] Build resolution propagation
- [ ] Create cluster view in frontend
- [x] Test with multiple correlated bugs
```

---

### Phase 5: Intelligence Layer (Days 37-42)

#### 5.1 LLM Root Cause Explanation (Days 37-39)

```python
# backend/src/services/intelligence/llm_service.py
import httpx
from typing import Optional

class OllamaService:
    def __init__(self, host: str = "http://localhost:11434"):
        self.host = host
        self.model = "llama3:8b"

    async def generate(self, prompt: str, system: str = None) -> str:
        """Generate text using Ollama."""
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self.host}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "system": system,
                    "stream": False
                }
            )
            result = response.json()
            return result.get("response", "")

    async def is_available(self) -> bool:
        """Check if Ollama is available."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.host}/api/tags")
                return response.status_code == 200
        except:
            return False


# backend/src/services/intelligence/explanation_generator.py
class ExplanationGenerator:
    def __init__(self, llm: OllamaService):
        self.llm = llm

    async def generate_root_cause_explanation(
        self,
        bug: BugReport,
        incident: DataIncident,
        correlation_score: float
    ) -> str:
        """Generate human-readable explanation of root cause."""

        system_prompt = """You are a data engineering expert helping to explain
        the root cause of software bugs. Be concise, technical, and actionable.
        Format your response in 3 parts:
        1. Root Cause: What happened
        2. Impact: How it caused the bug
        3. Suggested Fix: What to do"""

        prompt = f"""
        A bug report has been correlated with a data pipeline incident.

        BUG REPORT:
        - Title: {bug.title}
        - Description: {bug.description}
        - Component: {bug.classified_component}
        - Severity: {bug.classified_severity}
        - Reported: {bug.created_at}

        DATA INCIDENT:
        - Type: {incident.incident_type}
        - Table: {incident.table_name}
        - Affected Columns: {', '.join(incident.affected_columns)}
        - Severity: {incident.severity}
        - Time: {incident.timestamp}
        - Details: {incident.details}

        Correlation Score: {correlation_score:.0%}

        Explain the connection between this data incident and the bug report.
        """

        explanation = await self.llm.generate(prompt, system_prompt)
        return explanation

    async def generate_cluster_summary(
        self,
        incident: DataIncident,
        bugs: List[BugReport]
    ) -> str:
        """Generate summary for a cluster of related bugs."""

        system_prompt = """You are summarizing a group of related bug reports
        that were all caused by the same data incident. Be concise."""

        bug_summaries = "\n".join([
            f"- {b.title} ({b.classified_component}, {b.classified_severity})"
            for b in bugs[:10]  # Limit to 10 for prompt size
        ])

        prompt = f"""
        A data incident caused {len(bugs)} related bug reports:

        INCIDENT:
        - Type: {incident.incident_type}
        - Table: {incident.table_name}
        - Severity: {incident.severity}

        RELATED BUGS:
        {bug_summaries}

        Provide a brief summary of:
        1. The common root cause
        2. The blast radius (what was affected)
        3. Priority recommendation
        """

        return await self.llm.generate(prompt, system_prompt)
```

**Tasks:**
```
- [ ] Set up Ollama with Llama 3 model
- [x] Create explanation generation prompts
- [x] Implement async LLM calls
- [ ] Add explanation caching
- [x] Create chat interface for Q&A
- [ ] Test explanation quality
```

#### 5.2 Predictive Bug Alerts (Days 40-42)

```python
# backend/src/services/intelligence/prediction_engine.py
from sklearn.ensemble import GradientBoostingRegressor
import numpy as np
from typing import Dict, List

class PredictionEngine:
    def __init__(self, db, pinecone):
        self.db = db
        self.pinecone = pinecone
        self.model = None
        self._train_model()

    def _train_model(self):
        """Train prediction model on historical data."""
        # Get historical incident -> bug patterns
        patterns = self.db.query("""
            SELECT
                i.incident_type,
                i.severity,
                i.anomaly_score,
                COUNT(b.id) as bug_count,
                AVG(EXTRACT(EPOCH FROM (b.created_at - i.timestamp))/3600) as avg_time_to_bug
            FROM data_incidents i
            LEFT JOIN bug_reports b ON b.correlated_incident_id = i.id
            WHERE i.timestamp > NOW() - INTERVAL '90 days'
            GROUP BY i.id, i.incident_type, i.severity, i.anomaly_score
        """).fetchall()

        if len(patterns) < 10:
            return  # Not enough data

        # Prepare features
        type_map = {"SCHEMA_DRIFT": 4, "NULL_SPIKE": 3, "VOLUME_ANOMALY": 3,
                    "FRESHNESS": 2, "DISTRIBUTION_DRIFT": 2, "VALIDATION_FAILURE": 1}
        sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        X = []
        y = []
        for p in patterns:
            X.append([
                type_map.get(p.incident_type, 1),
                sev_map.get(p.severity, 1),
                p.anomaly_score or 0.5
            ])
            y.append(p.bug_count)

        self.model = GradientBoostingRegressor(n_estimators=50, random_state=42)
        self.model.fit(np.array(X), np.array(y))

    def predict_bugs(self, incident: DataIncident) -> Dict:
        """Predict how many bugs an incident will generate."""
        if self.model is None:
            return self._rule_based_prediction(incident)

        # Prepare features
        type_map = {"SCHEMA_DRIFT": 4, "NULL_SPIKE": 3, "VOLUME_ANOMALY": 3,
                    "FRESHNESS": 2, "DISTRIBUTION_DRIFT": 2, "VALIDATION_FAILURE": 1}
        sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        X = np.array([[
            type_map.get(incident.incident_type, 1),
            sev_map.get(incident.severity, 1),
            incident.anomaly_score or 0.5
        ]])

        predicted_count = max(0, int(self.model.predict(X)[0]))

        # Find similar past incidents for component prediction
        similar = self._find_similar_incidents(incident)
        predicted_components = self._predict_affected_components(incident, similar)

        return {
            "predicted_bug_count": predicted_count,
            "predicted_components": predicted_components,
            "confidence": self._calculate_confidence(incident),
            "prediction_window_hours": 6,
            "recommendation": self._generate_recommendation(predicted_count, incident)
        }

    def _rule_based_prediction(self, incident: DataIncident) -> Dict:
        """Fallback rule-based prediction."""
        base_counts = {
            "SCHEMA_DRIFT": 5,
            "NULL_SPIKE": 3,
            "VOLUME_ANOMALY": 2,
            "FRESHNESS": 1,
            "DISTRIBUTION_DRIFT": 2,
            "VALIDATION_FAILURE": 1
        }

        count = base_counts.get(incident.incident_type, 1)

        # Adjust by severity
        if incident.severity == "CRITICAL":
            count *= 2
        elif incident.severity == "HIGH":
            count *= 1.5

        return {
            "predicted_bug_count": int(count),
            "predicted_components": incident.downstream_systems[:3],
            "confidence": 0.6,
            "prediction_window_hours": 6,
            "recommendation": f"Expect ~{int(count)} bug reports in the next 6 hours"
        }

    def _generate_recommendation(self, predicted_count: int, incident: DataIncident) -> str:
        """Generate actionable recommendation."""
        if predicted_count >= 5:
            return f"HIGH ALERT: Expect {predicted_count}+ bug reports. Consider proactive communication to affected teams: {', '.join(incident.downstream_systems)}"
        elif predicted_count >= 2:
            return f"MODERATE: Expect {predicted_count} bug reports. Monitor {', '.join(incident.downstream_systems)} closely."
        else:
            return f"LOW: Expect minimal bug reports. Standard monitoring sufficient."
```

**Tasks:**
```
- [x] Implement prediction model training
- [x] Create rule-based fallback predictions
- [x] Build component prediction from lineage
- [x] Add confidence scoring
- [x] Create prediction alerts in frontend
- [x] Test prediction accuracy
```

---

### Phase 6: Frontend Polish & Demo (Days 43-45)

#### 6.1 Dashboard Components

```tsx
// frontend/src/pages/Dashboard.tsx
import { useQuery } from '@tanstack/react-query';
import { incidentsApi } from '../api/incidents';
import { bugsApi } from '../api/bugs';
import { StatsCard } from '../components/dashboard/StatsCard';
import { IncidentFeed } from '../components/dashboard/IncidentFeed';
import { BugQueue } from '../components/dashboard/BugQueue';
import { CorrelationGraph } from '../components/dashboard/CorrelationGraph';
import { PredictionAlert } from '../components/predictions/PredictionAlert';

export default function Dashboard() {
  const { data: incidents } = useQuery(['incidents'], () => incidentsApi.getAll());
  const { data: bugs } = useQuery(['bugs'], () => bugsApi.getAll());

  const activeIncidents = incidents?.filter(i => i.status === 'ACTIVE').length || 0;
  const unresolvedBugs = bugs?.filter(b => b.status !== 'resolved').length || 0;
  const dataRelatedBugs = bugs?.filter(b => b.is_data_related).length || 0;
  const correlationRate = bugs?.length ? (dataRelatedBugs / bugs.length * 100) : 0;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">DataBug AI Dashboard</h1>

      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-4">
        <StatsCard
          title="Active Incidents"
          value={activeIncidents}
          trend="up"
          icon="AlertTriangle"
          color="red"
        />
        <StatsCard
          title="Bug Queue"
          value={unresolvedBugs}
          trend="neutral"
          icon="Bug"
          color="yellow"
        />
        <StatsCard
          title="Data-Related Bugs"
          value={`${correlationRate.toFixed(0)}%`}
          subtitle={`${dataRelatedBugs} of ${bugs?.length || 0}`}
          icon="Database"
          color="blue"
        />
        <StatsCard
          title="Avg Time to Root Cause"
          value="12 min"
          previousValue="4.2 hrs"
          trend="down"
          icon="Clock"
          color="green"
        />
      </div>

      {/* Prediction Alerts */}
      <PredictionAlert />

      {/* Main Content */}
      <div className="grid grid-cols-2 gap-6">
        <div className="space-y-6">
          <IncidentFeed incidents={incidents?.slice(0, 5) || []} />
          <BugQueue bugs={bugs?.filter(b => b.status === 'new').slice(0, 5) || []} />
        </div>
        <div>
          <CorrelationGraph />
        </div>
      </div>
    </div>
  );
}
```

**Tasks:**
```
- [x] Build responsive dashboard layout
- [x] Create real-time stats cards
- [x] Implement incident feed with live updates
- [x] Create bug queue with classification badges
- [x] Build correlation graph visualization
- [x] Add prediction alerts panel
- [ ] Implement dark mode
```

#### 6.2 Demo Scenario Script

```python
# demo/demo_sequence.py
import asyncio
import httpx
from datetime import datetime

API_URL = "http://localhost:8000"

async def run_demo():
    """Run the complete demo sequence."""
    async with httpx.AsyncClient() as client:
        print("=== DataBug AI Live Demo ===\n")

        # Step 1: Show clean state
        print("[T+0:00] Starting with clean dashboard...")
        await asyncio.sleep(5)

        # Step 2: Inject schema drift
        print("[T+0:30] Injecting schema drift in user_transactions...")
        await client.post(f"{API_URL}/demo/inject-incident", json={
            "type": "SCHEMA_DRIFT",
            "table": "user_transactions",
            "details": {
                "column_renamed": {"from": "user_id", "to": "userId"}
            }
        })
        await asyncio.sleep(30)

        # Step 3: Great Expectations detects
        print("[T+1:00] Great Expectations validation running...")
        await asyncio.sleep(30)

        # Step 4: Incident created
        print("[T+1:30] Data Incident DI-001 created automatically")
        await asyncio.sleep(30)

        # Step 5: First bug
        print("[T+2:00] First bug report: 'Dashboard shows $0 revenue'")
        await client.post(f"{API_URL}/demo/inject-bug", json={
            "title": "Dashboard shows $0 revenue for all regions",
            "description": "Since this morning, the revenue dashboard shows $0 across all regions. Urgent!",
            "component": "analytics_dashboard"
        })
        await asyncio.sleep(30)

        # Step 6: Correlation detected
        print("[T+2:30] Bug correlated to incident (94% confidence)")
        await asyncio.sleep(30)

        # Step 7: Second bug
        print("[T+3:00] Second bug: 'API returning empty profiles'")
        await client.post(f"{API_URL}/demo/inject-bug", json={
            "title": "User API returning empty profile data",
            "description": "GET /api/users/{id} returning null for all users",
            "component": "user_api"
        })
        await asyncio.sleep(30)

        # Step 8: Clustered
        print("[T+3:30] Bug automatically clustered with first bug")
        await asyncio.sleep(30)

        # Step 9: Third bug
        print("[T+4:00] Third bug: 'Mobile app crash on user screen'")
        await client.post(f"{API_URL}/demo/inject-bug", json={
            "title": "App crashes when viewing user profile",
            "description": "NullPointerException in UserProfileFragment",
            "component": "mobile_app"
        })
        await asyncio.sleep(30)

        # Step 10: Show cluster
        print("[T+4:30] All 3 bugs linked to single root cause")
        print("\n=== Root Cause Explanation ===")
        print("The schema drift in user_transactions (user_id -> userId)")
        print("caused NULL values in downstream systems:")
        print("  - analytics_dashboard: $0 revenue display")
        print("  - user_api: empty profile responses")
        print("  - mobile_app: null pointer crash")
        print("\nSuggested Fix: Revert schema change or update ETL mapping")
        print("\n=== Demo Complete ===")

if __name__ == "__main__":
    asyncio.run(run_demo())
```

**Tasks:**
```
- [x] Create demo injection endpoints
- [x] Build automated demo sequence
- [ ] Test demo timing
- [ ] Create backup recorded video
- [ ] Prepare Q&A answers
- [ ] Rehearse presentation 3+ times
```

---

## Final Deliverables Checklist

### Code
- [ ] Backend API (FastAPI) - all endpoints working
- [ ] Frontend (React) - polished UI
- [x] Great Expectations integration
- [x] PyOD anomaly detection
- [x] Pinecone vector search
- [x] Ollama LLM integration
- [x] Docker Compose setup

### Documentation
- [ ] README.md with setup instructions
- [ ] API documentation
- [ ] Architecture diagrams
- [ ] Demo guide

### Demo
- [ ] Live demo script tested
- [ ] Backup video recorded
- [ ] Sample data prepared
- [ ] Presentation slides

### Metrics
- [ ] MTRC reduction documented
- [ ] Correlation accuracy measured
- [ ] Duplicate detection rate calculated
- [ ] Prediction accuracy tracked

---

## Quick Start

```bash
# Clone repository
git clone https://github.com/team-csis/databug-ai.git
cd databug-ai

# Set environment variables
cp .env.example .env
# Edit .env with your Pinecone API key

# Start all services
docker-compose up -d

# Wait for services to be ready
docker-compose logs -f backend

# Access the application
# Frontend: http://localhost:3000
# API: http://localhost:8000
# API Docs: http://localhost:8000/docs

# Run demo
python demo/demo_sequence.py
```

---

*Team CSIS - Unifonic AI Hackathon 2025*
*DataBug AI: Stop treating symptoms. Start finding root causes.*
