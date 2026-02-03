import { describe, expect, it } from "vitest";

import { groupFindingsForDisplay } from "./dastGrouping";
import type { Finding } from "../types";

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    id: "finding-1",
    scan_id: "scan-1",
    rule_id: "10038",
    rule_message: "Content Security Policy Header Not Set",
    semgrep_severity: "INFO",
    finding_type: "dast",
    ai_severity: "info",
    is_false_positive: false,
    file_path: "https://example.com",
    line_start: 0,
    line_end: 0,
    is_test_file: false,
    is_generated: false,
    status: "new",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

describe("groupFindingsForDisplay", () => {
  it("dedupes DAST alerts by plugin id and aggregates URLs", () => {
    const first = makeFinding({
      id: "f1",
      matched_at: "https://app.example.com/a",
      evidence: [
        "zap_alert=id:10038 name:CSP risk:low confidence:medium url:https://app.example.com/a param:n/a description:test",
      ],
    });
    const second = makeFinding({
      id: "f2",
      matched_at: "https://app.example.com/b",
      evidence: [
        "zap_alert=id:10038 name:CSP risk:low confidence:medium url:https://app.example.com/b param:n/a description:test",
      ],
    });

    const { items, rawDastCount, groupedDastCount } = groupFindingsForDisplay([
      first,
      second,
    ]);

    expect(rawDastCount).toBe(2);
    expect(groupedDastCount).toBe(1);
    expect(items).toHaveLength(1);
    expect(items[0].affected_urls).toEqual([
      "https://app.example.com/a",
      "https://app.example.com/b",
    ]);
    expect(items[0].raw_count).toBe(2);
  });
});
