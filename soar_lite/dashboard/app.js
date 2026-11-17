// SOAR Lite Live Web Dashboard Client

let ws = null;
let pollTimer = null;

function init() {
  connectWebSocket();
  fetchFullState();
}

function connectWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws/live`;
  
  try {
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      document.getElementById("connectionStatus").innerHTML = `
        <span class="pulse-dot" style="background:#22c55e; box-shadow: 0 0 8px #22c55e;"></span>
        <span style="color:#22c55e;">Live WebSocket Connected</span>
      `;
      if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        handleStreamMessage(msg);
      } catch (err) {
        console.error("WS Parse error", err);
      }
    };

    ws.onclose = () => {
      handleDisconnect();
    };

    ws.onerror = () => {
      handleDisconnect();
    };
  } catch (e) {
    handleDisconnect();
  }
}

function handleDisconnect() {
  document.getElementById("connectionStatus").innerHTML = `
    <span class="pulse-dot" style="background:#facc15; box-shadow: 0 0 8px #facc15;"></span>
    <span style="color:#facc15;">Auto-Refresh (Polling)</span>
  `;
  if (!pollTimer) {
    pollTimer = setInterval(fetchFullState, 3000);
  }
}

function handleStreamMessage(msg) {
  if (msg.type === "new_event") {
    prependEventRow(msg.data);
  } else if (msg.type === "new_threat") {
    fetchFullState();
  } else if (msg.type === "device_update") {
    updateDeviceMetrics(msg.data);
  }
}

async function fetchFullState() {
  try {
    const [statusRes, threatsRes, eventsRes, vulnsRes, playbooksRes, devicesRes] = await Promise.all([
      fetch("/api/status").then(r => r.json()).catch(() => null),
      fetch("/api/threats").then(r => r.json()).catch(() => []),
      fetch("/api/events?limit=40").then(r => r.json()).catch(() => []),
      fetch("/api/vulnerabilities").then(r => r.json()).catch(() => []),
      fetch("/api/playbooks").then(r => r.json()).catch(() => []),
      fetch("/api/devices").then(r => r.json()).catch(() => []),
    ]);

    if (statusRes) updateDashboardMetrics(statusRes);
    renderThreats(threatsRes || []);
    renderEvents(eventsRes || []);
    renderVulns(vulnsRes || []);
    renderPlaybooks(playbooksRes || []);
    renderDevices(devicesRes || []);
  } catch (err) {
    console.debug("Full state fetch notice", err);
  }
}

function updateDashboardMetrics(status) {
  const riskScoreEl = document.getElementById("mRiskScore");
  const riskLevelEl = document.getElementById("mRiskLevel");
  const score = status.risk_score || 0;
  riskScoreEl.innerText = `${score} / 100`;

  if (score >= 70) {
    riskScoreEl.style.color = "#f87171";
    riskLevelEl.innerText = "Risk Level: CRITICAL";
  } else if (score >= 50) {
    riskScoreEl.style.color = "#fb923c";
    riskLevelEl.innerText = "Risk Level: HIGH";
  } else if (score >= 25) {
    riskScoreEl.style.color = "#facc15";
    riskLevelEl.innerText = "Risk Level: MEDIUM";
  } else {
    riskScoreEl.style.color = "#22c55e";
    riskLevelEl.innerText = "Risk Level: Low (Healthy)";
  }

  document.getElementById("mActiveThreats").innerText = status.active_threats || 0;
  document.getElementById("mVulnsCount").innerText = status.vulnerabilities_count || 0;
  document.getElementById("mEventsCount").innerText = status.events_count || 0;
  document.getElementById("mDevicesCount").innerText = status.devices_count || 1;
  if (status.hostname) {
    document.getElementById("mLocalHostname").innerText = `Host: ${status.hostname}`;
  }
}

function renderThreats(threats) {
  const tbody = document.getElementById("threatsBody");
  if (!threats || threats.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color: var(--text-muted); padding: 2rem;">✅ No active threats detected. System is clean.</td></tr>`;
    return;
  }

  tbody.innerHTML = threats.map(t => {
    const sevClass = `sev-${t.severity.toLowerCase()}`;
    const playbook = t.evidence?.recommended_playbook || "host_isolation";
    return `
      <tr>
        <td><span class="sev-badge ${sevClass}">${t.severity}</span></td>
        <td><b>${escapeHtml(t.title)}</b></td>
        <td>${escapeHtml(t.category)}</td>
        <td><span class="code-pill">${escapeHtml(t.target)}</span></td>
        <td><b>${t.numeric_score || 'N/A'}</b></td>
        <td><small style="color:var(--text-muted);">${escapeHtml(t.mitre_technique || 'N/A')}</small></td>
        <td>
          <button class="btn btn-sm btn-danger" onclick="triggerPlaybook('${playbook}', '${t.target}', false, '${t.threat_id}')">
            ⚡ Contain (${playbook})
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

function renderEvents(events) {
  const tbody = document.getElementById("eventsBody");
  if (!events || events.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 2rem;">No telemetry events recorded yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = events.map(e => createEventRowHtml(e)).join("");
}

function prependEventRow(e) {
  const tbody = document.getElementById("eventsBody");
  const rowHtml = createEventRowHtml(e);
  tbody.insertAdjacentHTML("afterbegin", rowHtml);
}

function createEventRowHtml(e) {
  const sevClass = `sev-${e.severity.toLowerCase()}`;
  const timeStr = new Date(e.timestamp).toLocaleTimeString();
  const summary = e.raw_payload?.message || JSON.stringify(e.raw_payload).slice(0, 80);
  return `
    <tr>
      <td><small style="color: var(--text-muted);">${timeStr}</small></td>
      <td><span class="code-pill">${escapeHtml(e.source)}</span></td>
      <td><b>${escapeHtml(e.event_type)}</b></td>
      <td><span class="sev-badge ${sevClass}">${e.severity}</span></td>
      <td style="color: var(--text-muted);"><small>${escapeHtml(summary)}</small></td>
    </tr>
  `;
}

function renderVulns(vulns) {
  const tbody = document.getElementById("vulnsBody");
  if (!vulns || vulns.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color: var(--text-muted); padding: 2rem;">No vulnerabilities recorded. Click "Run Full Scan" to audit endpoint.</td></tr>`;
    return;
  }

  tbody.innerHTML = vulns.map(v => {
    const sevClass = `sev-${v.severity.toLowerCase()}`;
    return `
      <tr>
        <td><span class="sev-badge ${sevClass}">${v.severity}</span></td>
        <td><span class="code-pill" style="color: var(--accent-cyan);">${escapeHtml(v.cve_id || 'N/A')}</span></td>
        <td><b>${escapeHtml(v.title)}</b></td>
        <td>${escapeHtml(v.software_name || 'System')}</td>
        <td><span class="code-pill">${escapeHtml(v.installed_version || 'N/A')}</span></td>
        <td><b>${v.cvss_score || '0.0'}</b></td>
      </tr>
    `;
  }).join("");
}

function renderPlaybooks(runs) {
  const tbody = document.getElementById("playbooksBody");
  if (!runs || runs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color: var(--text-muted); padding: 2rem;">No containment playbooks executed yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = runs.map(r => {
    const isPending = r.status === "pending_approval";
    const isExecuted = r.status === "executed";
    return `
      <tr>
        <td><small class="code-pill">${escapeHtml(r.run_id)}</small></td>
        <td><b>${escapeHtml(r.playbook_name)}</b></td>
        <td><span class="code-pill">${escapeHtml(r.target)}</span></td>
        <td>${r.dry_run ? '<span style="color:#facc15;">Simulation</span>' : '<span style="color:#22c55e;">Live Real</span>'}</td>
        <td><span class="code-pill">${escapeHtml(r.status)}</span></td>
        <td>${escapeHtml(r.executed_by)}</td>
        <td>
          ${isPending ? `<button class="btn btn-sm btn-primary" onclick="approvePlaybook('${r.run_id}')">✅ Approve</button>` : ''}
          ${isExecuted && r.rollback_data?.action ? `<button class="btn btn-sm" onclick="rollbackPlaybook('${r.run_id}')">⏪ Rollback</button>` : ''}
        </td>
      </tr>
    `;
  }).join("");
}

function renderDevices(devices) {
  const tbody = document.getElementById("devicesBody");
  if (!devices || devices.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color: var(--text-muted); padding: 2rem;">No devices registered.</td></tr>`;
    return;
  }

  tbody.innerHTML = devices.map(d => {
    const timeStr = new Date(d.last_seen).toLocaleTimeString();
    return `
      <tr>
        <td><b>${escapeHtml(d.hostname)}</b></td>
        <td><span class="code-pill">${escapeHtml(d.ip_address)}</span></td>
        <td>${escapeHtml(d.os_version || d.os_type)}</td>
        <td><b>${d.risk_score} / 100</b></td>
        <td><span class="code-pill" style="color: ${d.status === 'online' ? '#22c55e' : '#f87171'};">${escapeHtml(d.status.toUpperCase())}</span></td>
        <td><small style="color:var(--text-muted);">${timeStr}</small></td>
      </tr>
    `;
  }).join("");
}

async function triggerPlaybook(playbook, target, dryRun, threatId) {
  if (!confirm(`Are you sure you want to execute containment playbook '${playbook}' for target '${target}'?`)) {
    return;
  }
  try {
    const res = await fetch("/api/playbooks/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        playbook: playbook,
        target: target,
        dry_run: dryRun,
        threat_id: threatId,
        require_approval: false
      })
    });
    const data = await res.json();
    alert(`Playbook run status: ${data.status}`);
    fetchFullState();
  } catch (err) {
    alert("Playbook request failed: " + err);
  }
}

async function approvePlaybook(runId) {
  try {
    const res = await fetch(`/api/playbooks/${runId}/approve`, { method: "POST" });
    const data = await res.json();
    alert(`Approved and executed: ${data.status}`);
    fetchFullState();
  } catch (err) {
    alert("Approval failed: " + err);
  }
}

async function rollbackPlaybook(runId) {
  if (!confirm("Are you sure you want to rollback this containment action?")) return;
  try {
    const res = await fetch(`/api/playbooks/${runId}/rollback`, { method: "POST" });
    const data = await res.json();
    alert(`Rollback status: ${data.status || 'Success'}`);
    fetchFullState();
  } catch (err) {
    alert("Rollback failed: " + err);
  }
}

async function triggerVulnScan() {
  const btn = event?.target;
  if (btn) btn.innerText = "⏳ Scanning...";
  try {
    const res = await fetch("/api/scan/vulnerabilities", { method: "POST" });
    const data = await res.json();
    alert(`Scan completed! Discovered ${data.count} vulnerability issues.`);
    fetchFullState();
  } catch (err) {
    alert("Scan failed: " + err);
  } finally {
    if (btn) btn.innerText = "🔍 Scan Vulnerabilities";
  }
}

function switchTab(tabId) {
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
  document.getElementById(`tab-${tabId}`).classList.add("active");
  event.target.classList.add("active");
}

function clearEventFeed() {
  document.getElementById("eventsBody").innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 2rem;">Feed cleared.</td></tr>`;
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

window.onload = init;
