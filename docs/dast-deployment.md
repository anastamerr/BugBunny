# DAST Deployment Verification

## Overview

To ensure DAST tests the exact code SAST analyzed, deployments must expose their commit SHA through a standardized version endpoint. This prevents false positives/negatives caused by testing different code versions.

## Why This Matters

**The Problem**: Without verification, DAST may test:
- An older deployment (missing the vulnerable code)
- A newer deployment (vulnerability already fixed)
- A different branch entirely
- Same code with different configuration

**The Solution**: Deployments expose `/.well-known/scanguard-version` endpoint returning the deployed commit SHA.

## Deployment Methods

### Option 1: Automated Deployment (Recommended)

Configure `DAST_DEPLOY_SCRIPT` to build and deploy the scanned commit automatically.

**Example Deploy Script** (`deploy.sh`):

```bash
#!/bin/bash
set -e

REPO_PATH=$1
COMMIT_SHA=$2
BRANCH=$3

echo "Deploying commit $COMMIT_SHA from branch $BRANCH"

cd "$REPO_PATH"

# Build Docker image with commit SHA
docker build -t myapp:$COMMIT_SHA \
  --build-arg COMMIT_SHA=$COMMIT_SHA \
  --build-arg BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ") \
  .

# Stop existing container if running
docker rm -f dast-myapp 2>/dev/null || true

# Start new container
CONTAINER_ID=$(docker run -d \
  --name dast-myapp \
  -p 8080:8080 \
  -e COMMIT_SHA=$COMMIT_SHA \
  myapp:$COMMIT_SHA)

# Wait for healthcheck
sleep 5
if ! curl -f http://localhost:8080/health > /dev/null 2>&1; then
  echo "ERROR: Deployment failed healthcheck" >&2
  exit 1
fi

# Output target URL (must be last line on stdout)
echo "http://localhost:8080"
```

**Configuration**:
```bash
# backend/.env
DAST_DEPLOY_SCRIPT=/path/to/deploy.sh
```

**API Usage**:
```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/org/repo",
    "branch": "main",
    "scan_type": "both"
  }'
```

Result: ✅ `dast_verification_status = "verified"`

---

### Option 2: Manual Deployment with Verification

Deploy manually but add a version endpoint to your application.

#### Flask Example

```python
import os
from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/.well-known/scanguard-version")
def version():
    return jsonify({
        "commit_sha": os.getenv("COMMIT_SHA", "unknown"),
        "deployed_at": os.getenv("DEPLOY_TIMESTAMP"),
        "version": os.getenv("APP_VERSION"),
        "branch": os.getenv("GIT_BRANCH")
    })

@app.route("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    app.run()
```

#### Express.js Example

```javascript
const express = require('express');
const app = express();

app.get('/.well-known/scanguard-version', (req, res) => {
  res.json({
    commit_sha: process.env.COMMIT_SHA || 'unknown',
    deployed_at: process.env.DEPLOY_TIMESTAMP,
    version: process.env.APP_VERSION,
    branch: process.env.GIT_BRANCH
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000);
```

#### Django Example

```python
# urls.py
from django.http import JsonResponse
from django.urls import path
import os

def scanguard_version(request):
    return JsonResponse({
        'commit_sha': os.getenv('COMMIT_SHA', 'unknown'),
        'deployed_at': os.getenv('DEPLOY_TIMESTAMP'),
        'version': os.getenv('APP_VERSION'),
        'branch': os.getenv('GIT_BRANCH')
    })

urlpatterns = [
    path('.well-known/scanguard-version', scanguard_version),
    # ... other URLs
]
```

#### FastAPI Example

```python
from fastapi import FastAPI
import os

app = FastAPI()

@app.get("/.well-known/scanguard-version")
def version():
    return {
        "commit_sha": os.getenv("COMMIT_SHA", "unknown"),
        "deployed_at": os.getenv("DEPLOY_TIMESTAMP"),
        "version": os.getenv("APP_VERSION"),
        "branch": os.getenv("GIT_BRANCH")
    }
```

#### Spring Boot Example

```java
@RestController
public class VersionController {

    @GetMapping("/.well-known/scanguard-version")
    public Map<String, String> version() {
        Map<String, String> version = new HashMap<>();
        version.put("commit_sha", System.getenv("COMMIT_SHA"));
        version.put("deployed_at", System.getenv("DEPLOY_TIMESTAMP"));
        version.put("version", System.getenv("APP_VERSION"));
        version.put("branch", System.getenv("GIT_BRANCH"));
        return version;
    }
}
```

---

## Deployment with Commit SHA

### Docker Example

```bash
# Get current commit SHA
COMMIT_SHA=$(git rev-parse HEAD)
DEPLOY_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build and run with environment variables
docker build -t myapp:$COMMIT_SHA .
docker run -d \
  -e COMMIT_SHA=$COMMIT_SHA \
  -e DEPLOY_TIMESTAMP=$DEPLOY_TIMESTAMP \
  -e APP_VERSION=1.0.0 \
  -p 8080:8080 \
  myapp:$COMMIT_SHA
```

### Kubernetes Example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:
      - name: myapp
        image: myapp:${COMMIT_SHA}
        env:
        - name: COMMIT_SHA
          value: "${COMMIT_SHA}"
        - name: DEPLOY_TIMESTAMP
          value: "${DEPLOY_TIMESTAMP}"
        - name: APP_VERSION
          value: "1.0.0"
```

Deploy:
```bash
COMMIT_SHA=$(git rev-parse HEAD)
DEPLOY_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
envsubst < deployment.yaml | kubectl apply -f -
```

### CI/CD Pipeline Example (GitHub Actions)

```yaml
name: Deploy with Commit SHA

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build and Deploy
        env:
          COMMIT_SHA: ${{ github.sha }}
          DEPLOY_TIMESTAMP: ${{ github.event.head_commit.timestamp }}
        run: |
          docker build -t myapp:$COMMIT_SHA \
            --build-arg COMMIT_SHA=$COMMIT_SHA \
            .
          docker run -d \
            -e COMMIT_SHA=$COMMIT_SHA \
            -e DEPLOY_TIMESTAMP=$DEPLOY_TIMESTAMP \
            -p 8080:8080 \
            myapp:$COMMIT_SHA
```

---

## Verification Status Meanings

| Status | Meaning | Action |
|--------|---------|--------|
| **verified** | Deployment matches scanned commit | ✅ Safe to proceed |
| **unverified_url** | Manual URL without version endpoint | ⚠️ Cannot verify - proceed with caution |
| **commit_mismatch** | Deployment has different commit | ❌ High risk - results may be invalid |
| **verification_error** | Endpoint error or timeout | ⚠️ Cannot verify - check deployment |
| **not_applicable** | SAST-only scan, no DAST | N/A |

---

## API Usage Examples

### Scan with Automated Deployment (scan_type="both")

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "repo_url": "https://github.com/org/repo",
    "branch": "main",
    "scan_type": "both",
    "dast_consent": true
  }'
```

**Result**: System deploys commit ABC123, runs DAST against it.
- `commit_sha`: ABC123
- `target_url`: http://localhost:8080 (from deploy script)
- `dast_verification_status`: "verified"

### Scan with Manual Deployment

```bash
# 1. Deploy your app with commit SHA
COMMIT_SHA=$(git rev-parse HEAD)
docker run -d -e COMMIT_SHA=$COMMIT_SHA -p 8080:8080 myapp

# 2. Verify version endpoint works
curl http://localhost:8080/.well-known/scanguard-version
# {"commit_sha": "abc123...", "deployed_at": "..."}

# 3. Create scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/org/repo",
    "branch": "main",
    "commit_sha": "abc123...",
    "scan_type": "sast",
    "target_url": "http://localhost:8080",
    "dast_consent": true
  }'
```

**Result**: System verifies deployment matches commit SHA.
- `dast_verification_status`: "verified" (if match) or "commit_mismatch" (if different)

### Scan without Verification (Legacy)

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/org/repo",
    "branch": "main",
    "scan_type": "sast",
    "target_url": "http://staging.example.com",
    "dast_consent": true
  }'
```

**Result**: No verification possible.
- `dast_verification_status`: "unverified_url"
- ⚠️ Warning in logs: "Manual target_url: ensure it matches commit X"

---

## Testing Your Implementation

### 1. Test Version Endpoint

```bash
curl http://localhost:8080/.well-known/scanguard-version

# Expected response:
{
  "commit_sha": "abc123def456...",
  "deployed_at": "2024-01-26T12:00:00Z",
  "version": "1.0.0"
}
```

### 2. Test Verification with Matching Commit

```bash
# Deploy commit abc123
COMMIT_SHA=abc123def456
docker run -d -e COMMIT_SHA=$COMMIT_SHA -p 8080:8080 myapp

# Scan same commit
curl -X POST http://localhost:8000/api/scans \
  -d '{
    "commit_sha": "abc123def456",
    "target_url": "http://localhost:8080",
    ...
  }'

# Check verification status
curl http://localhost:8000/api/scans/{scan_id}
# "dast_verification_status": "verified"
```

### 3. Test Mismatch Detection

```bash
# Deploy commit abc123
docker run -d -e COMMIT_SHA=abc123 -p 8080:8080 myapp

# Scan different commit
curl -X POST http://localhost:8000/api/scans \
  -d '{
    "commit_sha": "def456",
    "target_url": "http://localhost:8080",
    ...
  }'

# Check logs
# ERROR: Commit mismatch: expected def456, got abc123
# "dast_verification_status": "commit_mismatch"
```

---

## Troubleshooting

### Version Endpoint Returns 404

**Problem**: `/.well-known/scanguard-version` not found

**Solutions**:
1. Verify route is registered in your app
2. Check for reverse proxy/load balancer stripping the path
3. Ensure route doesn't require authentication
4. Test directly: `curl http://localhost:8080/.well-known/scanguard-version`

### Commit SHA is "unknown"

**Problem**: Environment variable not set

**Solutions**:
1. Pass `-e COMMIT_SHA=$(git rev-parse HEAD)` when running container
2. Set in Dockerfile: `ARG COMMIT_SHA` → `ENV COMMIT_SHA=$COMMIT_SHA`
3. In CI/CD, use `${{ github.sha }}` (GitHub) or `$CI_COMMIT_SHA` (GitLab)

### Verification Always Fails

**Problem**: Network timeout or connection refused

**Solutions**:
1. Check `target_url` is accessible from scan server
2. Verify no firewall blocking requests
3. Test: `curl http://target_url/.well-known/scanguard-version`
4. Check container networking (Docker bridge, Kubernetes service)

### Short SHA vs Full SHA

**Problem**: Mismatch between 7-char and 40-char SHAs

**Solution**: System accepts both. `abc123` matches `abc123def456...`

---

## Best Practices

1. **Always Deploy with Commit SHA**: Make it part of your deployment process
2. **Use Build Args**: Pass commit SHA during Docker build for immutability
3. **Add to Healthcheck**: Include version in existing health endpoint
4. **Monitor Verification Rate**: Track % of scans that are verified
5. **Fail Fast**: Consider rejecting scans with commit_mismatch in production

---

## Configuration Reference

### Environment Variables

```bash
# backend/.env

# Required for scan_type="both" (automated deployment)
DAST_DEPLOY_SCRIPT=/path/to/deploy.sh

# Optional: restrict allowed target URLs by hostname
DAST_ALLOWED_HOSTS=localhost,staging.example.com,*.internal

# Future: strict mode (fail scans on mismatch)
# DAST_REQUIRE_VERIFICATION=true
```

### Deploy Script Requirements

Your `DAST_DEPLOY_SCRIPT` must:
1. Accept 3 arguments: `<repo_path> <commit_sha> <branch>`
2. Build/deploy the application from that exact commit
3. Output target URL as the **last line** on stdout
4. Exit with code 0 on success, non-zero on failure
5. Return within reasonable time (< 5 minutes)

Example output:
```
Building commit abc123...
Starting container...
http://localhost:8080
```

---

## Security Considerations

1. **Public Endpoints**: Version endpoint should be public (no auth required)
2. **Information Disclosure**: Only expose commit SHA, not sensitive build info
3. **SSRF Protection**: System blocks private IPs in target_url by default
4. **Rate Limiting**: DAST respects standard rate limits (30 req/s)
5. **Consent Required**: `dast_consent: true` must be explicit

---

## Metrics & Observability

Scan logs include:
```json
{
  "scan_id": "...",
  "scan_type": "both",
  "commit_sha": "abc123...",
  "dast_verification_status": "verified",
  "manual_target_url": false,
  "total_findings": 15,
  "dast_confirmed_count": 3
}
```

Monitor these metrics:
- % scans with `verified` status (goal: > 90%)
- % scans with `commit_mismatch` (goal: < 1%)
- % scans with `unverified_url` (track for compliance)

---

## Migration Guide

### Migrating Existing Deployments

**Phase 1: Add Version Endpoint** (non-breaking)
- Add `/.well-known/scanguard-version` to your app
- Deploy without commit SHA initially (returns "unknown")
- Scans get `verification_error` status but continue

**Phase 2: Pass Commit SHA** (recommended)
- Update deployment to pass `COMMIT_SHA` env var
- Scans now get `verified` status
- No code changes required

**Phase 3: Enable Automated Deployment** (optional)
- Configure `DAST_DEPLOY_SCRIPT`
- Switch to `scan_type="both"`
- Fully automated verification

---

## Support

For issues or questions:
- GitHub: https://github.com/your-org/scanguard
- Docs: https://docs.scanguard.ai/dast-verification
- Email: security@example.com
