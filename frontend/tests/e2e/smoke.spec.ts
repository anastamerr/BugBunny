import { test, expect } from "@playwright/test";

test.describe("BugBunny smoke", () => {
  test("login bypass, start scan, open scan detail, open chat", async ({ page }) => {
    const scanId = "00000000-0000-0000-0000-000000000001";
    const scan = {
      id: scanId,
      repo_id: null,
      repo_url: "https://github.com/example/repo",
      branch: "main",
      scan_type: "sast",
      dependency_health_enabled: true,
      target_url: null,
      status: "completed",
      is_paused: false,
      trigger: "manual",
      total_findings: 4,
      filtered_findings: 2,
      dast_findings: 0,
      dast_confirmed_count: 0,
      dast_verification_status: "not_applicable",
      error_message: null,
      pr_number: null,
      pr_url: null,
      commit_sha: "abc123456789",
      commit_url: null,
      detected_languages: ["python"],
      rulesets: ["p/python"],
      scanned_files: 12,
      semgrep_version: "1.82.0",
      phase: "completed",
      phase_message: "done",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      report_url: null,
      report_generated_at: null,
    };

    const scans: typeof scan[] = [];

    await page.route("http://localhost:8000/**", async (route) => {
      const url = new URL(route.request().url());
      const method = route.request().method();
      const path = url.pathname;

      if (method === "GET" && path === "/api/scans") {
        return route.fulfill({ json: scans });
      }
      if (method === "POST" && path === "/api/scans") {
        scans.splice(0, scans.length, scan);
        return route.fulfill({ json: scan });
      }
      if (method === "GET" && path === `/api/scans/${scanId}`) {
        return route.fulfill({ json: scan });
      }
      if (method === "GET" && path === `/api/scans/${scanId}/findings`) {
        return route.fulfill({ json: [] });
      }
      if (method === "GET" && path === "/api/repos") {
        return route.fulfill({ json: [] });
      }
      if (method === "GET" && path === "/api/findings") {
        return route.fulfill({ json: [] });
      }
      if (method === "GET" && path === "/api/bugs") {
        return route.fulfill({ json: [] });
      }

      return route.fulfill({ status: 200, body: "" });
    });

    await page.goto("/scans");
    await expect(page.getByRole("heading", { name: "Security Scans" })).toBeVisible();

    await page.getByPlaceholder("https://github.com/org/repo").fill("https://github.com/example/repo");
    await page.getByRole("button", { name: /Start SAST Scan/i }).click();

    await expect(page.getByText("example/repo")).toBeVisible();
    await page.getByRole("link", { name: /View Details/i }).click();

    await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();
    await page.getByRole("link", { name: "Ask AI" }).click();

    await expect(page.getByRole("heading", { name: "Chat" })).toBeVisible();
  });
});
