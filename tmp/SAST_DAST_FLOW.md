# SAST → DAST Flow Update Report (2026-01-31)

## Implemented Changes (file + line)
- `backend/src/services/scanner/targeted_dast_runner.py:584-604` — Removed false-positive filtering so DAST attacks all SAST findings.
- `backend/src/services/scanner/targeted_dast_runner.py:753-865` — DAST attack config now prefers SAST metadata (endpoint/method/parameter) and preserves it on findings.
- `backend/src/services/scanner/targeted_dast_runner.py:1143-1184` — DAST results map back to all findings (no is_false_positive skip).
- `backend/src/services/scanner/scan_pipeline.py:250-260` — Added SAST metadata extraction after AI triage.
- `backend/src/services/scanner/scan_pipeline.py:393-416` — Targeted DAST now reports/attacks full triaged set.
- `backend/src/services/scanner/scan_pipeline.py:520-556` — Persist SAST endpoint/method/parameter/vuln_type to DB.
- `backend/src/services/scanner/sast_metadata.py:1-214` — New extractor for endpoint/method/parameter/vuln_type from routes/context.
- `backend/src/services/scanner/zap_parser.py:9-99` — Rule-id → vuln_type mapping plus fallback keyword matching.
- `backend/src/services/scanner/correlation.py:15-33` — Correlates DAST findings without skipping AI false positives.
- `backend/src/services/scanner/ai_triage.py:102-178` — Prompt clarified that AI is metadata-only; DAST is final judge.
- `backend/src/models/finding.py:62-65` + `backend/src/schemas/finding.py:77-80` — New SAST metadata fields.
- `backend/alembic/versions/0019_sast_metadata_fields.py:1-27` — Migration for new SAST metadata columns.
- `backend/tests/unit/test_targeted_dast_runner.py:45-128` — Updated tests to reflect DAST attacks false positives.

## Test Results
- `pytest` not available in the environment (`command not found`).
- Semgrep CLI present (`semgrep --version` => 1.52.0).
- Docker present (`docker --version` => 28.4.0).
- Live target check:
  - `https://juice-shop.herokuapp.com/rest/products/search?q=test` returned `503` during check.
- Targeted DAST attempt (manual script using `TargetedDASTRunner`):
  - Target: `http://testphp.vulnweb.com/listproducts.php?cat=scanguard`
  - Result: `verification_status=error_tooling` (ZAP error `url_not_found`)
  - Evidence: `dast_target=http://testphp.vulnweb.com/listproducts.php?cat=scanguard method=GET param=cat location=query`

## Example Finding (SAST + DAST Evidence)
- SAST (manual test input):
  - rule_id: `custom.sql-injection`
  - endpoint: `/listproducts.php`
  - method: `GET`
  - parameter: `cat`
  - vuln_type: `sqli`
- DAST:
  - verification_status: `error_tooling`
  - evidence: `dast_target=http://testphp.vulnweb.com/listproducts.php?cat=scanguard method=GET param=cat location=query`

## Remaining Issues / TODO
- Need a confirmed exploitable example (DAST `confirmed_exploitable=true`).
  - Juice Shop API endpoints returned `503` from this environment; recommend local deployment or alternate known-vulnerable target.
  - Consider enhancing ZAP pre-access or scan-tree population if `url_not_found` persists.
- Install `pytest` in the environment to run unit/integration tests.
- Optional: add a small scripted end-to-end demo that runs Semgrep + targeted DAST on a local vulnerable app for reproducible confirmation.
