#!/usr/bin/env bash
set -euo pipefail

BACKEND_URL=${BACKEND_URL:-"http://localhost:8000"}
TARGET_NAME=${TARGET_NAME:-"scanguard-webgoat"}
TARGET_URL=${TARGET_URL:-"http://localhost:8080/WebGoat"}

cleanup() {
  if docker ps -a --format '{{.Names}}' | grep -q "^${TARGET_NAME}$"; then
    docker stop "${TARGET_NAME}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "Starting WebGoat target..."
docker run -d --rm --name "${TARGET_NAME}" -p 8080:8080 -p 9090:9090 webgoat/webgoat >/dev/null

echo "Waiting for target to be ready..."
for i in {1..30}; do
  if curl -fsS "${TARGET_URL}" >/dev/null 2>&1; then
    break
  fi
  sleep 2
  if [[ $i -eq 30 ]]; then
    echo "Target did not become ready in time."
    exit 1
  fi
  echo "..."
done

echo "Triggering SAST + DAST scan..."
SCAN_RESPONSE=$(curl -fsS -X POST "${BACKEND_URL}/api/v2/scans/both" \
  -H "Content-Type: application/json" \
  -d "{\"repo_url\": \"https://github.com/OWASP/WebGoat\", \"branch\": \"main\", \"target_url\": \"${TARGET_URL}\", \"auth\": {\"headers\": {}, \"cookies\": \"\"}, \"semgrep_config\": \"auto\", \"timeouts\": {\"sast_seconds\": 900, \"dast_seconds\": 1800}}")

SCAN_ID=$(printf '%s' "$SCAN_RESPONSE" | python - <<'PY'
import json
import sys
print(json.load(sys.stdin)["scan_id"])
PY
)

echo "Scan ID: ${SCAN_ID}"

echo "Polling scan status..."
for i in {1..60}; do
  STATUS=$(curl -fsS "${BACKEND_URL}/api/v2/scans/${SCAN_ID}" | python - <<PY
import json,sys
print(json.load(sys.stdin).get("status"))
PY
)
  echo "Status: ${STATUS}"
  if [[ "${STATUS}" == "completed" || "${STATUS}" == "failed" ]]; then
    break
  fi
  sleep 10
  if [[ $i -eq 60 ]]; then
    echo "Timed out waiting for scan to complete."
    exit 1
  fi
done

echo "Fetching results summary..."
curl -fsS "${BACKEND_URL}/api/v2/scans/${SCAN_ID}/results" | python - <<'PY'
import json
import sys
results = json.load(sys.stdin)
print("SAST findings:", len(results.get("sast_findings", [])))
print("DAST alerts:", len(results.get("dast_alerts", [])))
confirmed = [c for c in results.get("correlations", []) if c.get("status") == "CONFIRMED_EXPLOITABLE"]
print("Confirmed exploitable:", len(confirmed))
PY
