# ScanGuard AI: Context-Aware Static Analysis Platform

## Team: CSIS

---

## Executive Summary

ScanGuard AI reduces static analysis noise by running Semgrep first and then using LLMs to understand code context, filter false positives, and adjust severity based on exploitability. Teams focus on the real issues instead of alert fatigue.

---

## Selected Track

| Track | Name | Weight in Solution |
|-------|------|-------------------|
| **Track 1** | AI-Enhanced DevSecOps Pipeline | 70% |
| **Track 4** | Bug Triage Automation | 30% |

---

## Problem Statement

### The Static Analysis Noise Problem

| Challenge | Current State | Business Impact |
|-----------|---------------|-----------------|
| False positives | 70-90% of findings | Alert fatigue |
| Severity mismatch | Everything is "critical" | Wrong prioritization |
| No code context | Pattern matches only | Wasted investigation |
| Duplication | Same root cause repeated | Inefficient remediation |

---

## Our Solution: ScanGuard AI

### Core Value Proposition

A context-aware static analysis pipeline that:
1. Runs Semgrep with best-practice rulesets
2. Extracts code context for every finding
3. Uses an LLM to triage false positives and adjust severity
4. Deduplicates similar findings via embeddings
5. Ranks issues by exploitability with clear reasoning

### Architecture Overview

```
[GitHub/Webhook] -> [Repo Fetcher] -> [Semgrep Scan] -> [Context Extractor]
                                                   |
                                                   v
                                           [LLM Triage]
                                                   |
                                                   v
                                          [Dedupe + Rank]
                                                   |
                                               [Frontend]
```

---

## Expected Impact & Metrics

| Metric | Without ScanGuard AI | With ScanGuard AI | Improvement |
|--------|----------------------|------------------|-------------|
| False positive rate | 70-90% | < 30% | 70%+ reduction |
| Mean time to triage | Hours | Minutes | 80%+ faster |
| Severity accuracy | Pattern only | Context-aware | Higher precision |

---

## Demo Scenario

1. Trigger a scan on a public repo
2. Semgrep reports raw findings
3. LLM triage filters false positives and adjusts severity
4. Dashboard shows noise reduction and top real issues

---

## Risk Mitigation

| Risk | Mitigation Strategy |
|------|---------------------|
| LLM inaccuracies | Provide full code context and enforce JSON parsing |
| False negatives | Preserve Semgrep raw output for review |
| Rate limits | Batch and throttle LLM calls |

---

## Conclusion

ScanGuard AI makes static analysis actionable by eliminating noise and surfacing the most exploitable findings first.

---

*Team CSIS - Unifonic AI Hackathon 2025*
