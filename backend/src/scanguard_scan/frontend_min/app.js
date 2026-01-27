const apiBase = window.location.protocol === "file:"
  ? "http://localhost:8000/api/v2/scans"
  : `${window.location.origin}/api/v2/scans`;

const repoUrlEl = document.getElementById("repoUrl");
const targetUrlEl = document.getElementById("targetUrl");
const authHeadersEl = document.getElementById("authHeaders");
const authCookiesEl = document.getElementById("authCookies");
const formErrorEl = document.getElementById("formError");

const scanStatusEl = document.getElementById("scanStatus");
const scanIdEl = document.getElementById("scanId");
const sastCountEl = document.getElementById("sastCount");
const dastCountEl = document.getElementById("dastCount");
const confirmedCountEl = document.getElementById("confirmedCount");
const correlationTableEl = document.getElementById("correlationTable");
const confirmedAlertsEl = document.getElementById("confirmedAlerts");

let pollingTimer = null;

function setStatus(status, scanId) {
  scanStatusEl.textContent = status || "idle";
  scanIdEl.textContent = scanId || "-";
}

function setCounts(sastCount, dastCount, confirmedCount) {
  sastCountEl.textContent = String(sastCount ?? 0);
  dastCountEl.textContent = String(dastCount ?? 0);
  confirmedCountEl.textContent = String(confirmedCount ?? 0);
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function parseHeaders() {
  const raw = authHeadersEl.value.trim();
  if (!raw) {
    return {};
  }
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed !== "object" || Array.isArray(parsed) || parsed === null) {
      throw new Error("Headers must be a JSON object");
    }
    return parsed;
  } catch (err) {
    throw new Error(`Invalid JSON in headers: ${err.message}`);
  }
}

function buildAuth() {
  const headers = parseHeaders();
  const cookies = authCookiesEl.value.trim();
  if (Object.keys(headers).length === 0 && !cookies) {
    return null;
  }
  return { headers, cookies };
}

async function postScan(type) {
  formErrorEl.textContent = "";
  if (pollingTimer) {
    clearTimeout(pollingTimer);
    pollingTimer = null;
  }

  const repoUrl = repoUrlEl.value.trim();
  const targetUrl = targetUrlEl.value.trim();

  try {
    let payload = {};
    if (type === "sast") {
      if (!repoUrl) {
        throw new Error("Repo URL is required for SAST.");
      }
      payload = { repo_url: repoUrl };
    }
    if (type === "dast") {
      if (!targetUrl) {
        throw new Error("Target URL is required for DAST.");
      }
      const auth = buildAuth();
      payload = { target_url: targetUrl };
      if (auth) {
        payload.auth = auth;
      }
    }
    if (type === "both") {
      if (!repoUrl || !targetUrl) {
        throw new Error("Repo URL and Target URL are required for BOTH.");
      }
      const auth = buildAuth();
      payload = { repo_url: repoUrl, target_url: targetUrl };
      if (auth) {
        payload.auth = auth;
      }
    }

    const response = await fetch(`${apiBase}/${type}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`API error: ${response.status} ${text}`);
    }

    const data = await response.json();
    setStatus(data.status, data.scan_id);
    setCounts(0, 0, 0);
    correlationTableEl.innerHTML = "";
    confirmedAlertsEl.innerHTML = "";

    pollScan(data.scan_id);
  } catch (err) {
    formErrorEl.textContent = err.message;
  }
}

async function pollScan(scanId) {
  try {
    const response = await fetch(`${apiBase}/${scanId}`);
    if (!response.ok) {
      throw new Error("Failed to fetch scan status");
    }
    const data = await response.json();
    setStatus(data.status, scanId);

    if (data.status === "completed" || data.status === "failed") {
      await fetchResults(scanId);
      return;
    }
  } catch (err) {
    formErrorEl.textContent = err.message;
  }
  pollingTimer = setTimeout(() => pollScan(scanId), 3000);
}

async function fetchResults(scanId) {
  try {
    const response = await fetch(`${apiBase}/${scanId}/results`);
    if (!response.ok) {
      throw new Error("Failed to fetch scan results");
    }
    const data = await response.json();
    const sastFindings = data.sast_findings || [];
    const dastAlerts = data.dast_alerts || [];
    const correlations = data.correlations || [];

    const sastMap = Object.fromEntries(
      sastFindings.map((finding) => [finding.id, finding])
    );
    const dastMap = Object.fromEntries(
      dastAlerts.map((alert) => [alert.id, alert])
    );

    const confirmed = correlations.filter(
      (item) => item.status === "CONFIRMED_EXPLOITABLE"
    );

    setCounts(sastFindings.length, dastAlerts.length, confirmed.length);
    renderCorrelation(correlations, sastMap);
    renderConfirmed(confirmed, dastMap);
  } catch (err) {
    formErrorEl.textContent = err.message;
  }
}

function renderCorrelation(correlations, sastMap) {
  if (!correlations.length) {
    correlationTableEl.innerHTML = "<p>No correlation results yet.</p>";
    return;
  }

  const rows = correlations.map((item) => {
    const finding = sastMap[item.sast_finding_id] || {};
    const status = escapeHtml(item.status);
    const reason = escapeHtml(item.reason || "");
    const ruleId = escapeHtml(finding.rule_id || "");
    const filePath = escapeHtml(finding.file_path || "");
    const statusPill = status === "CONFIRMED_EXPLOITABLE"
      ? '<span class="pill">Confirmed</span>'
      : '<span class="pill warn">Unverified</span>';
    return `
      <tr>
        <td>${ruleId}</td>
        <td>${filePath}</td>
        <td>${statusPill}<div>${status}</div></td>
        <td>${reason}</td>
      </tr>
    `;
  });

  correlationTableEl.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Rule</th>
          <th>File</th>
          <th>Status</th>
          <th>Reason</th>
        </tr>
      </thead>
      <tbody>
        ${rows.join("")}
      </tbody>
    </table>
  `;
}

function renderConfirmed(confirmed, dastMap) {
  if (!confirmed.length) {
    confirmedAlertsEl.innerHTML = "<p>No confirmed alerts.</p>";
    return;
  }

  const items = confirmed.map((item) => {
    const alert = dastMap[item.matched_dast_alert_id] || {};
    return `
      <div class="stat">
        <h4>${escapeHtml(alert.name || "Confirmed Alert")}</h4>
        <p>${escapeHtml(alert.url || "")}</p>
        <p>${escapeHtml(alert.evidence || "")}</p>
      </div>
    `;
  });

  confirmedAlertsEl.innerHTML = items.join("");
}

document.getElementById("runSast").addEventListener("click", () => postScan("sast"));
document.getElementById("runDast").addEventListener("click", () => postScan("dast"));
document.getElementById("runBoth").addEventListener("click", () => postScan("both"));
