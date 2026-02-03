import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import { scansApi } from "../api/scans";
import ScanDetail from "./ScanDetail";
import type { Finding, Scan } from "../types";

function makeScan(): Scan {
  return {
    id: "scan-1",
    repo_id: null,
    repo_url: "https://github.com/example/repo",
    branch: "main",
    scan_type: "dast",
    dependency_health_enabled: false,
    target_url: "https://juice-shop.herokuapp.com",
    status: "completed",
    is_paused: false,
    trigger: "manual",
    total_findings: 0,
    filtered_findings: 0,
    dast_findings: 0,
    dast_confirmed_count: 0,
    dast_verification_status: "not_applicable",
    error_message: null,
    pr_number: null,
    pr_url: null,
    commit_sha: null,
    commit_url: null,
    detected_languages: null,
    rulesets: null,
    scanned_files: null,
    semgrep_version: null,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    report_url: null,
    report_generated_at: null,
  };
}

function makeFinding(): Finding {
  return {
    id: "finding-1",
    scan_id: "scan-1",
    rule_id: "10038",
    rule_message: "CSP Header Not Set",
    semgrep_severity: "INFO",
    finding_type: "dast",
    ai_severity: "info",
    is_false_positive: false,
    file_path: "https://juice-shop.herokuapp.com",
    line_start: 0,
    line_end: 0,
    is_test_file: false,
    is_generated: false,
    status: "new",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  };
}

describe("ScanDetail", () => {
  it("renders the include false positives toggle label", async () => {
    vi.spyOn(scansApi, "getById").mockResolvedValue(makeScan());
    vi.spyOn(scansApi, "getFindings").mockResolvedValue([makeFinding()]);

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/scans/scan-1"]}>
          <Routes>
            <Route path="/scans/:id" element={<ScanDetail />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    const toggle = await screen.findByLabelText(/include false positives/i);
    expect(toggle).toBeInTheDocument();
    expect(screen.getByText(/include false positives/i)).toBeInTheDocument();
  });
});
