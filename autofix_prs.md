# AutoFix PRs (FixFlow) Plan

## Goal
Deliver one-click, safe auto-remediation for high-confidence SAST findings by generating a minimal patch, previewing it, and optionally opening a GitHub PR.

## MVP scope
- Supported findings: SAST, non-test, non-generated, reachable, AI confidence >= 0.7.
- Languages: Python only (initial). Expand later.
- Categories: SQL injection, command injection, path traversal, SSRF, XSS (JS/TS).
- Outputs: patch diff, summary, confidence, PR link (optional), PR comment with diff.

## Non-goals (for hackathon MVP)
- Multi-file refactors or large rewrites.
- Dependency-adding fixes that require new third-party libraries.
- Auto-merging or running full test suites.

## Plan
- [x] Data model: add fix metadata to Finding (status, summary, patch, PR URL, confidence, errors).
- [x] Backend service: LLM patch generation, strict patch validation, safe git apply, commit/push, GitHub PR creation.
- [x] API: POST /findings/{id}/autofix with preview + create_pr options; update Finding with fix metadata.
- [x] Frontend: add Generate Fix + Open PR actions, show patch preview and PR link in FindingCard.
- [x] Docs/demo: update README/manual for setup and required GitHub token permissions.

## Acceptance criteria
- Generates a patch for eligible findings and stores it on the Finding record.
- Rejects unsupported findings with a clear reason.
- Creates a PR on GitHub when requested and records the PR URL.
- UI shows fix status, patch preview, and PR link.

## Risks and mitigations
- LLM patch invalid: strict diff validation + git apply check; fallback with error.
- Unsafe edits: allowlist categories + confidence threshold + single-file limit.
- Missing GitHub token: require token to open PR; preview still works.
