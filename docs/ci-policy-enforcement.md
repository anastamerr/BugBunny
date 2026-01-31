# CI/CD Policy Enforcement

This guide shows how to integrate ScanGuard AI scans into your CI/CD pipeline with policy enforcement that fails builds when vulnerabilities exceed severity thresholds.

## Overview

The policy enforcement feature allows you to:
- Evaluate scan results against severity thresholds (info, low, medium, high, critical)
- Fail CI builds when violations are found
- Exclude false positives from policy checks
- Get machine-readable JSON output for custom tooling

## API Endpoint

```http
GET /api/scans/{scan_id}/policy?fail_on=high&include_false_positives=false
```

**Parameters:**
- `fail_on`: Minimum severity to fail on (`info|low|medium|high|critical`). Default: `high`
- `include_false_positives`: Whether to include findings marked as false positives. Default: `false`

**Response:**
```json
{
  "passed": false,
  "exit_code": 1,
  "fail_on": "high",
  "violations_count": 3,
  "violations": [
    {
      "finding_id": "uuid",
      "severity": "critical",
      "rule_id": "sql-injection",
      "rule_message": "SQL Injection vulnerability",
      "file_path": "app.py",
      "line_start": 42
    }
  ]
}
```

## CLI Command

```bash
# Install backend dependencies
cd backend
pip install -r requirements.txt

# Evaluate policy
python -m src.cli.scan_policy \
  --scan-id <scan-uuid> \
  --fail-on high \
  [--include-fps] \
  [--json]

# Exit codes:
# 0 = Policy passed (no violations)
# 1 = Policy failed (violations found)
# 2 = Error (invalid arguments, scan not found)
```

**Examples:**

```bash
# Compact summary output
python -m src.cli.scan_policy --scan-id abc123 --fail-on high
# Output: Policy: FAIL (fail_on=high, violations=2)

# Full JSON output
python -m src.cli.scan_policy --scan-id abc123 --fail-on critical --json
# Output: {"passed": true, "exit_code": 0, ...}

# Include false positives in evaluation
python -m src.cli.scan_policy --scan-id abc123 --fail-on medium --include-fps
```

## GitHub Actions Integration

### Example 1: Fail on High/Critical Vulnerabilities

```yaml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install dependencies
        run: |
          cd backend
          pip install -r requirements.txt

      - name: Trigger Security Scan
        id: scan
        env:
          API_URL: ${{ secrets.SCANGUARD_API_URL }}
          API_TOKEN: ${{ secrets.SCANGUARD_API_TOKEN }}
        run: |
          # Trigger scan
          SCAN_RESPONSE=$(curl -X POST "$API_URL/api/scans" \
            -H "Authorization: Bearer $API_TOKEN" \
            -H "Content-Type: application/json" \
            -d '{
              "repo_url": "${{ github.repository }}",
              "branch": "${{ github.ref_name }}",
              "commit_sha": "${{ github.sha }}",
              "scan_type": "sast"
            }')

          SCAN_ID=$(echo "$SCAN_RESPONSE" | jq -r '.id')
          echo "scan_id=$SCAN_ID" >> $GITHUB_OUTPUT

          # Wait for scan to complete (poll every 10s, max 10min)
          for i in {1..60}; do
            STATUS=$(curl -s "$API_URL/api/scans/$SCAN_ID" \
              -H "Authorization: Bearer $API_TOKEN" | jq -r '.status')

            echo "Scan status: $STATUS"

            if [ "$STATUS" = "completed" ]; then
              echo "Scan completed!"
              break
            elif [ "$STATUS" = "failed" ]; then
              echo "Scan failed!"
              exit 1
            fi

            sleep 10
          done

      - name: Evaluate Security Policy
        env:
          API_URL: ${{ secrets.SCANGUARD_API_URL }}
          API_TOKEN: ${{ secrets.SCANGUARD_API_TOKEN }}
        run: |
          cd backend
          python -m src.cli.scan_policy \
            --scan-id ${{ steps.scan.outputs.scan_id }} \
            --fail-on high

      - name: Upload Scan Results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-scan-results
          path: |
            backend/scan-results.json
```

### Example 2: Different Thresholds for Main vs PR

```yaml
name: Security Scan with Branch-Specific Policy

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install dependencies
        run: |
          cd backend
          pip install -r requirements.txt

      - name: Trigger and Wait for Scan
        id: scan
        run: |
          # ... (same as Example 1)
          echo "scan_id=abc123" >> $GITHUB_OUTPUT

      - name: Evaluate Policy (Main Branch - Strict)
        if: github.ref == 'refs/heads/main'
        run: |
          cd backend
          python -m src.cli.scan_policy \
            --scan-id ${{ steps.scan.outputs.scan_id }} \
            --fail-on high

      - name: Evaluate Policy (PR - Relaxed)
        if: github.event_name == 'pull_request'
        run: |
          cd backend
          python -m src.cli.scan_policy \
            --scan-id ${{ steps.scan.outputs.scan_id }} \
            --fail-on critical

      - name: Comment PR with Results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const policyResult = require('./backend/policy-result.json');
            const comment = policyResult.passed
              ? '✅ Security scan passed!'
              : `⚠️ Security scan found ${policyResult.violations_count} violations`;
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

### Example 3: Custom Violation Reporting

```yaml
name: Security Scan with Custom Reporting

on:
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install dependencies
        run: |
          cd backend
          pip install -r requirements.txt

      - name: Trigger and Wait for Scan
        id: scan
        run: |
          # ... (scan logic)
          echo "scan_id=abc123" >> $GITHUB_OUTPUT

      - name: Check Policy and Generate Report
        id: policy
        run: |
          cd backend
          python -m src.cli.scan_policy \
            --scan-id ${{ steps.scan.outputs.scan_id }} \
            --fail-on high \
            --json > policy-result.json

          # Extract results
          EXIT_CODE=$?
          VIOLATIONS=$(jq -r '.violations_count' policy-result.json)

          echo "exit_code=$EXIT_CODE" >> $GITHUB_OUTPUT
          echo "violations=$VIOLATIONS" >> $GITHUB_OUTPUT

          # Exit with policy exit code
          exit $EXIT_CODE

      - name: Create GitHub Issue for Violations
        if: failure() && steps.policy.outputs.violations > 0
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const policy = JSON.parse(fs.readFileSync('./backend/policy-result.json'));

            let body = `## 🚨 Security Policy Violation\n\n`;
            body += `Found ${policy.violations_count} ${policy.fail_on}+ severity vulnerabilities:\n\n`;

            for (const v of policy.violations.slice(0, 10)) {
              body += `- **[${v.severity.toUpperCase()}]** ${v.rule_message}\n`;
              body += `  \`${v.file_path}:${v.line_start}\`\n\n`;
            }

            if (policy.violations_count > 10) {
              body += `\n... and ${policy.violations_count - 10} more violations.\n`;
            }

            body += `\n[View full scan results](${process.env.SCANGUARD_API_URL}/scans/${{ steps.scan.outputs.scan_id }})`;

            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: `Security: ${policy.violations_count} ${policy.fail_on}+ vulnerabilities found`,
              body: body,
              labels: ['security', 'automated']
            });
```

## GitLab CI Integration

```yaml
# .gitlab-ci.yml

security-scan:
  stage: test
  image: python:3.10

  script:
    - cd backend
    - pip install -r requirements.txt

    # Trigger scan
    - |
      SCAN_RESPONSE=$(curl -X POST "$SCANGUARD_API_URL/api/scans" \
        -H "Authorization: Bearer $SCANGUARD_API_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
          \"repo_url\": \"$CI_PROJECT_URL\",
          \"branch\": \"$CI_COMMIT_REF_NAME\",
          \"commit_sha\": \"$CI_COMMIT_SHA\",
          \"scan_type\": \"sast\"
        }")
      SCAN_ID=$(echo "$SCAN_RESPONSE" | jq -r '.id')

    # Wait for completion
    - |
      for i in {1..60}; do
        STATUS=$(curl -s "$SCANGUARD_API_URL/api/scans/$SCAN_ID" \
          -H "Authorization: Bearer $SCANGUARD_API_TOKEN" | jq -r '.status')
        [ "$STATUS" = "completed" ] && break
        [ "$STATUS" = "failed" ] && exit 1
        sleep 10
      done

    # Evaluate policy
    - python -m src.cli.scan_policy --scan-id $SCAN_ID --fail-on high

  only:
    - main
    - merge_requests
```

## Jenkins Integration

```groovy
// Jenkinsfile

pipeline {
    agent any

    environment {
        SCANGUARD_API_URL = credentials('scanguard-api-url')
        SCANGUARD_API_TOKEN = credentials('scanguard-api-token')
    }

    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Trigger scan
                    def scanResponse = sh(
                        script: """
                            curl -X POST "${SCANGUARD_API_URL}/api/scans" \
                              -H "Authorization: Bearer ${SCANGUARD_API_TOKEN}" \
                              -H "Content-Type: application/json" \
                              -d '{
                                "repo_url": "${env.GIT_URL}",
                                "branch": "${env.BRANCH_NAME}",
                                "commit_sha": "${env.GIT_COMMIT}",
                                "scan_type": "sast"
                              }'
                        """,
                        returnStdout: true
                    ).trim()

                    def scanId = readJSON(text: scanResponse).id

                    // Wait for completion
                    timeout(time: 10, unit: 'MINUTES') {
                        waitUntil {
                            def status = sh(
                                script: "curl -s '${SCANGUARD_API_URL}/api/scans/${scanId}' -H 'Authorization: Bearer ${SCANGUARD_API_TOKEN}' | jq -r '.status'",
                                returnStdout: true
                            ).trim()
                            return status == 'completed'
                        }
                    }

                    // Evaluate policy
                    dir('backend') {
                        sh "pip install -r requirements.txt"
                        sh "python -m src.cli.scan_policy --scan-id ${scanId} --fail-on high"
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'backend/policy-result.json', allowEmptyArchive: true
        }
    }
}
```

## Best Practices

### 1. Choose Appropriate Thresholds

- **Production/Main branch**: `fail_on=high` or `fail_on=critical`
- **Development branches**: `fail_on=critical` (less strict)
- **PRs**: `fail_on=critical` with warnings for high

### 2. Handle False Positives

```bash
# Exclude false positives from policy check (default behavior)
python -m src.cli.scan_policy --scan-id $SCAN_ID --fail-on high

# Include false positives for auditing
python -m src.cli.scan_policy --scan-id $SCAN_ID --fail-on high --include-fps
```

Mark false positives in the UI or via API:
```bash
curl -X PATCH "$API_URL/api/findings/$FINDING_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"status": "dismissed"}'
```

### 3. Gradual Rollout

Start with relaxed thresholds and tighten over time:

**Week 1-2:** `fail_on=critical` (baseline)
**Week 3-4:** Fix critical issues, then `fail_on=high`
**Week 5+:** Maintain `fail_on=high`, fix incrementally

### 4. Combine with Other Checks

```yaml
- name: Security Checks
  run: |
    # Policy check
    python -m src.cli.scan_policy --scan-id $SCAN_ID --fail-on high

    # Additional validation
    if [ $(jq '.violations_count' policy-result.json) -gt 10 ]; then
      echo "Too many violations! Needs security review."
      exit 1
    fi
```

### 5. Notify on Violations

- Create GitHub/GitLab issues for violations
- Send Slack/Teams notifications
- Update security dashboards
- Block deployments

## Troubleshooting

**Policy check fails with "Scan not found":**
- Ensure scan ID is correct
- Verify scan has completed (not still running)
- Check API token has access to the scan

**Policy always passes despite findings:**
- Verify findings have `ai_severity` field populated
- Check if findings are marked as false positives
- Ensure `fail_on` threshold is appropriate

**CLI exits with code 2:**
- Invalid arguments (check `--fail-on` value)
- Database connection issues
- Scan doesn't exist

## Reference

### Severity Hierarchy

From lowest to highest:
1. `info`
2. `low`
3. `medium`
4. `high`
5. `critical`

Setting `fail_on=medium` will fail on medium, high, and critical findings.

### Exit Codes

- `0`: Policy passed (no violations above threshold)
- `1`: Policy failed (violations found)
- `2`: Error (invalid arguments, scan not found, etc.)

### API Authentication

All policy endpoints require authentication. Use one of:

- **Production**: Supabase JWT token
- **Dev/CI**: `DEV_AUTH_BYPASS=true` with `DEV_AUTH_USER_ID`
- **Service accounts**: Generate long-lived tokens (future feature)
