// Vigil.AI traffic page logic: live tshark monitoring plus manual ML checks.
// The null checks let this script be reused on pages that only include part of
// the traffic-analysis UI.

const $ = (id) => document.getElementById(id);

// ---------- Live Monitoring Elements ----------
const ifaceSelect = $("iface-select");
const filterSelect = $("filter-select");
const refreshRateSelect = $("refresh-rate");
const btnStart = $("btn-start");
const btnStop = $("btn-stop");
const btnClear = $("btn-clear");
const liveStatus = $("live-status");

const tbody = $("live-tbody");
const metricCount = $("metric-count");
const metricHigh = $("metric-high");
const metricPort = $("metric-port");

let es = null;
let buffer = [];
let renderTimer = null;

// Simple, explainable risk scoring for the prototype. It is intentionally a
// heuristic layer, not a replacement for the trained ML model.
function isPrivateIP(ip) {
  if (!ip) return false;
  return (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)
  );
}

function scoreRisk(evt) {
  let score = 0;
  const reasons = [];

  const dport = Number(evt.dport || 0);
  const len = Number(evt.len || 0);
  const proto = (evt.proto || "").toUpperCase();

  if (evt.dst && !isPrivateIP(evt.dst)) {
    score += 10;
    reasons.push("External destination");
  }

  // Common ports lower the score slightly because normal browsing/DNS traffic
  // should not look scary just because it leaves the local network.
  const common = new Set([53, 80, 443, 123, 22, 3389]);
  if (dport && common.has(dport)) {
    score -= 5;
    reasons.push("Common service port");
  }

  const suspiciousPorts = new Set([4444, 5555, 6666, 1337, 31337, 2323, 23, 445, 139]);
  if (dport && suspiciousPorts.has(dport)) {
    score += 35;
    reasons.push("Suspicious/abused port");
  }

  if (len > 1400) {
    score += 5;
    reasons.push("Large packet size");
  }

  if (proto === "UDP" && dport && !common.has(dport) && dport !== 0) {
    score += 10;
    reasons.push("UDP to uncommon port");
  }

  if (dport > 0 && dport < 1024 && !common.has(dport)) {
    score += 10;
    reasons.push("Uncommon privileged port");
  }

  score = Math.max(0, Math.min(100, score));

  let level = "low";
  if (score >= 55) level = "high";
  else if (score >= 30) level = "med";

  const reasonText = reasons.length ? reasons.join(", ") : "Normal pattern (heuristic)";
  return { score, level, reasonText };
}

// Attack alert popup system.

// Track recent high-risk events so one suspicious packet does not trigger a
// dramatic alert by itself.
let highRiskWindow = [];
const HIGH_RISK_THRESHOLD = 5;      // number of high-risk events
const HIGH_RISK_WINDOW_MS = 10000;  // within this many milliseconds
let alertCooldown = false;          // prevent spamming alerts
const ALERT_COOLDOWN_MS = 30000;    // 30 seconds between alerts

// Classify the alert based on recent patterns. This keeps the advice practical
// even before the user asks the chatbot for help.
function classifyAttackType(recentHighRisk) {
  const reasons = recentHighRisk.map(r => r.risk.reasonText).join(" ").toLowerCase();
  const ports = recentHighRisk.map(r => Number(r.dport || 0));
  const protos = recentHighRisk.map(r => (r.proto || "").toUpperCase());

  const udpCount = protos.filter(p => p === "UDP").length;
  const suspCount = recentHighRisk.filter(r =>
    [4444,5555,6666,1337,31337,2323,23,445,139].includes(Number(r.dport))
  ).length;

  if (udpCount > recentHighRisk.length * 0.6) {
    return {
      type: "Possible DDoS / UDP Flood",
      severity: "HIGH",
      color: "#ef4444",
      icon: "🚨",
      steps: [
        "Block incoming UDP traffic from suspicious external IPs at your firewall",
        "Enable rate limiting on your router or network device",
        "Contact your ISP if the flood continues — they can block upstream",
        "Document source IPs and timestamps for incident reporting"
      ]
    };
  }

  if (suspCount > 0) {
    return {
      type: "Possible Malware / Botnet Activity",
      severity: "CRITICAL",
      color: "#dc2626",
      icon: "☠️",
      steps: [
        "Immediately isolate the affected device from the network",
        "Run a full antivirus/malware scan on all connected devices",
        "Block outbound traffic to the suspicious ports (4444, 1337, etc.)",
        "Change all passwords — credentials may be compromised"
      ]
    };
  }

  if (reasons.includes("privileged port") || reasons.includes("uncommon")) {
    return {
      type: "Possible Port Scan / Reconnaissance",
      severity: "MEDIUM",
      color: "#f59e0b",
      icon: "🔍",
      steps: [
        "Enable port scan detection on your firewall or IDS",
        "Block the scanning IP address temporarily",
        "Audit which services are exposed and close unnecessary ports",
        "Monitor for follow-up intrusion attempts in the next 24 hours"
      ]
    };
  }

  return {
    type: "Suspicious Traffic Detected",
    severity: "MEDIUM",
    color: "#f59e0b",
    icon: "⚠️",
    steps: [
      "Review the flagged connections in the traffic table below",
      "Block any unrecognized external IP addresses",
      "Check if any devices recently installed new software",
      "Consider running a network scan to identify rogue devices"
    ]
  };
}

// Build and show the alert popup with the IPs, ports, and next steps.
function showAttackAlert(attack, recentHighRisk) {
  // Keep only one alert visible so repeated detections do not stack modals.
  const existing = document.getElementById("vigil-alert");
  if (existing) existing.remove();

  const topIPs = [...new Set(recentHighRisk.map(r => r.src).filter(Boolean))].slice(0, 3);
  const topPorts = [...new Set(recentHighRisk.map(r => r.dport).filter(Boolean))].slice(0, 3);

  const alert = document.createElement("div");
  alert.id = "vigil-alert";
  alert.innerHTML = `
    <div class="vigil-alert-overlay" id="vigil-alert-overlay"></div>
    <div class="vigil-alert-box">
      <div class="vigil-alert-header" style="border-left: 4px solid ${attack.color}">
        <div class="vigil-alert-title">
          <span class="vigil-alert-icon">${attack.icon}</span>
          <div>
            <div class="vigil-alert-type">${attack.type}</div>
            <div class="vigil-alert-severity" style="color:${attack.color}">
              Severity: ${attack.severity} &bull; ${recentHighRisk.length} high-risk events in 10s
            </div>
          </div>
        </div>
        <button class="vigil-alert-close" id="vigil-alert-close">✕</button>
      </div>

      <div class="vigil-alert-body">
        <div class="vigil-alert-section">
          <div class="vigil-alert-section-title">📡 Source IPs Involved</div>
          <div class="vigil-alert-chips">
            ${topIPs.length ? topIPs.map(ip => `<span class="vigil-chip">${ip}</span>`).join("") : '<span class="vigil-chip">Unknown</span>'}
          </div>
        </div>

        <div class="vigil-alert-section">
          <div class="vigil-alert-section-title">🔌 Target Ports</div>
          <div class="vigil-alert-chips">
            ${topPorts.length ? topPorts.map(p => `<span class="vigil-chip">${p}</span>`).join("") : '<span class="vigil-chip">Various</span>'}
          </div>
        </div>

        <div class="vigil-alert-section">
          <div class="vigil-alert-section-title">🛡️ Recommended Actions</div>
          <ol class="vigil-alert-steps">
            ${attack.steps.map(s => `<li>${s}</li>`).join("")}
          </ol>
        </div>
      </div>

      <div class="vigil-alert-footer">
        <button class="vigil-alert-btn vigil-btn-chatbot" id="vigil-ask-chatbot">
  💬 Ask Vigil for Help
        </button>
        <button class="vigil-alert-btn vigil-btn-dismiss" id="vigil-alert-dismiss">
          Dismiss
        </button>
      </div>
    </div>
  `;

  document.body.appendChild(alert);

  // Dismiss handlers share the same fade-out behavior.
  const dismiss = () => {
    alert.classList.add("vigil-alert-hiding");
    setTimeout(() => alert.remove(), 300);
  };

  document.getElementById("vigil-alert-close").addEventListener("click", dismiss);
  document.getElementById("vigil-alert-dismiss").addEventListener("click", dismiss);
  document.getElementById("vigil-alert-overlay").addEventListener("click", dismiss);

  // Send the user to the chatbot with context already filled in.
  document.getElementById("vigil-ask-chatbot").addEventListener("click", () => {
    const query = encodeURIComponent(
      `I'm seeing a "${attack.type}" on my network. Source IPs: ${topIPs.join(", ")}. Target ports: ${topPorts.join(", ")}. What should I do?`
    );
    window.location.href = `/chatbot-index.html?alert=${query}`;
  });

  // Wait one frame so the CSS transition starts from the hidden state.
  requestAnimationFrame(() => alert.classList.add("vigil-alert-visible"));
}

// Check whether the recent high-risk traffic crosses the alert threshold.
function checkForAttack(newRow) {
  if (alertCooldown) return;
  if (newRow.risk.level !== "high") return;

  const now = Date.now();
  highRiskWindow.push({ ...newRow, timestamp: now });

  // Drop older events so the threshold reflects a burst, not the whole session.
  highRiskWindow = highRiskWindow.filter(r => now - r.timestamp < HIGH_RISK_WINDOW_MS);

  if (highRiskWindow.length >= HIGH_RISK_THRESHOLD) {
    alertCooldown = true;
    setTimeout(() => { alertCooldown = false; }, ALERT_COOLDOWN_MS);

    const attack = classifyAttackType(highRiskWindow);
    showAttackAlert(attack, [...highRiskWindow]);
    highRiskWindow = [];
  }
}

// ---------- Live UI rendering ----------
function formatTime(ts) {
  const t = Number(ts);
  if (!t) return "—";
  const d = new Date(t * 1000);
  return d.toLocaleTimeString();
}

function updateMetrics(rows) {
  if (metricCount) metricCount.textContent = String(rows.length);

  const high = rows.filter((r) => r.risk.level === "high").length;
  if (metricHigh) metricHigh.textContent = String(high);

  const portCounts = new Map();
  // The top destination port is a quick clue for scans or repeated service use.
  for (const r of rows) {
    const p = r.dport || "";
    if (!p) continue;
    portCounts.set(p, (portCounts.get(p) || 0) + 1);
  }
  let topPort = "—";
  let topCount = 0;
  for (const [p, c] of portCounts.entries()) {
    if (c > topCount) { topCount = c; topPort = p; }
  }
  if (metricPort) metricPort.textContent = topPort;
}

function renderTable(rows) {
  if (!tbody) return;

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty">Waiting for live data…</td></tr>`;
    updateMetrics([]);
    return;
  }

  // Rendering only recent rows keeps the table responsive during long captures.
  const recent = rows.slice(-200).reverse();

  tbody.innerHTML = recent
    .map((r) => {
      const ports = `${r.sport || "—"} → ${r.dport || "—"}`;
      const riskClass = `risk ${r.risk.level}`;
      return `
      <tr>
        <td>${formatTime(r.ts)}</td>
        <td>${r.src || "—"}</td>
        <td>${r.dst || "—"}</td>
        <td>${(r.proto || "—").toUpperCase()}</td>
        <td>${ports}</td>
        <td>${r.len || "—"}</td>
        <td class="${riskClass}">${r.risk.score}</td>
        <td title="${r.risk.reasonText}">${r.risk.reasonText}</td>
      </tr>`;
    })
    .join("");

  updateMetrics(rows);
}

function setLiveStatus(text, isActive = false) {
  if (!liveStatus) return;
  liveStatus.textContent = text;
  liveStatus.style.borderColor = isActive
    ? "rgba(56,189,248,.35)"
    : "rgba(148,163,184,0.18)";
}

// ---------- Live controls ----------
async function loadInterfaces() {
  if (!ifaceSelect) return;

  try {
    const res = await fetch("/api/interfaces");
    const data = await res.json();

    ifaceSelect.innerHTML = "";
    if (!data.ok || !Array.isArray(data.interfaces) || !data.interfaces.length) {
      ifaceSelect.innerHTML = `<option value="">No interfaces found</option>`;
      return;
    }

    for (const it of data.interfaces) {
      const opt = document.createElement("option");
      opt.value = String(it.index);
      opt.textContent = `${it.index}. ${it.name}`;
      ifaceSelect.appendChild(opt);
    }

    // Wi-Fi is the most likely demo adapter, but the user can still choose any
    // tshark interface from the dropdown.
    const wifi = data.interfaces.find((i) => /wi-?fi/i.test(i.name));
    if (wifi) ifaceSelect.value = String(wifi.index);
  } catch (e) {
    ifaceSelect.innerHTML = `<option value="">Failed to load</option>`;
  }
}

function startRenderLoop() {
  if (!refreshRateSelect) return;
  const rate = Number(refreshRateSelect.value || 500);
  if (renderTimer) clearInterval(renderTimer);
  renderTimer = setInterval(() => renderTable(buffer), rate);
}

function stopRenderLoop() {
  if (renderTimer) clearInterval(renderTimer);
  renderTimer = null;
}

function connectSSE() {
  if (es) es.close();

  es = new EventSource("/api/live");

  es.onmessage = (msg) => {
    try {
      const evt = JSON.parse(msg.data);

      const row = {
        ts: evt.ts,
        src: evt.src,
        dst: evt.dst,
        proto: evt.proto,
        sport: evt.sport,
        dport: evt.dport,
        len: evt.len
      };

      row.risk = scoreRisk(row);
      buffer.push(row);

      checkForAttack(row);

      // Bound the client-side buffer for the same reason the server has a ring
      // buffer: live traffic can run for a long time.
      if (buffer.length > 2000) buffer = buffer.slice(-1500);
    } catch {}
  };

  es.addEventListener("status", (msg) => {
    try {
      const data = JSON.parse(msg.data);
      setLiveStatus(data.message || "Live", true);
    } catch {}
  });

  es.addEventListener("error", () => {
    setLiveStatus("Error (check server/tshark)", false);
  });
}

async function startLive() {
  if (!ifaceSelect || !filterSelect || !btnStart || !btnStop) return;

  const iface = ifaceSelect.value;
  const mode = filterSelect.value;

  if (!iface) { alert("Pick an interface first."); return; }

  btnStart.disabled = true;

  try {
    // The server owns tshark permissions and parsing; the browser only asks for
    // the selected interface and filter mode.
    const res = await fetch(
      `/api/start?iface=${encodeURIComponent(iface)}&mode=${encodeURIComponent(mode)}`,
      { method: "POST" }
    );
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || "Failed to start");

    setLiveStatus("Live", true);
    btnStop.disabled = false;

    connectSSE();
    startRenderLoop();
  } catch (e) {
    setLiveStatus("Idle", false);
    btnStart.disabled = false;
    btnStop.disabled = true;
    alert(`Could not start live capture: ${e.message}`);
  }
}

async function stopLive() {
  if (!btnStop || !btnStart) return;

  btnStop.disabled = true;
  try { await fetch("/api/stop", { method: "POST" }); } catch {}

  if (es) { es.close(); es = null; }

  stopRenderLoop();
  setLiveStatus("Idle", false);
  btnStart.disabled = false;
}

function clearLive() {
  buffer = [];
  renderTable(buffer);
}

// ---------- Manual ML form ----------
const featureGrid = $("feature-grid");
const form = $("analysis-form");
const btnSampleBenign = $("btn-sample-benign");
const btnSampleAttack = $("btn-sample-attack");
const btnClearFeatures = $("btn-clear-features");

function buildFeatureInputs() {
  if (!featureGrid) return;
  featureGrid.innerHTML = "";
  // The capstone form exposes each trained feature as a numeric field. Labels
  // stay generic here because the feature order is documented in the model code.
  for (let i = 1; i <= 32; i++) {
    const div = document.createElement("div");
    div.className = "field";
    div.innerHTML = `
      <label for="feature${i}">Feature ${i}</label>
      <input id="feature${i}" type="number" step="any" placeholder="0" />
    `;
    featureGrid.appendChild(div);
  }
}

function setFeatures(arr) {
  for (let i = 1; i <= 32; i++) {
    const el = $(`feature${i}`);
    if (el) el.value = arr[i - 1];
  }
}

function clearFeatures() {
  for (let i = 1; i <= 32; i++) {
    const el = $(`feature${i}`);
    if (el) el.value = "";
  }
}

function getFeatures() {
  const out = [];
  for (let i = 1; i <= 32; i++) {
    const el = $(`feature${i}`);
    // Empty fields become zero so partial demos still produce a prediction.
    out.push(Number(el?.value || 0));
  }
  return out;
}

function showResults(pred) {
  const results = $("results");
  if (!results) return;
  results.style.display = "block";
  const classification = $("classification-text");
  const severity = $("severity-text");
  const explanation = $("explanation-text");
  if (classification) classification.textContent = pred?.label ?? String(pred?.prediction ?? "—");
  if (severity) severity.textContent = pred?.severity ?? "—";
  if (explanation) explanation.textContent = pred?.explanation ?? "—";
}

if (form) {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const features = getFeatures();
    try {
      const res = await fetch("/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ features })
      });
      const data = await res.json();
      // Some early versions returned only a number, so this keeps the UI
      // compatible with both response shapes.
      const pred = typeof data === "object" && data !== null ? data : { prediction: data };
      showResults(pred);
    } catch {
      alert("Model request failed. Check server /predict endpoint.");
    }
  });
}

if (btnSampleBenign) {
  btnSampleBenign.addEventListener("click", () => {
    setFeatures(Array.from({ length: 32 }, (_, i) => (i % 5 === 0 ? 0.2 : 0)));
  });
}

if (btnSampleAttack) {
  btnSampleAttack.addEventListener("click", () => {
    setFeatures(Array.from({ length: 32 }, (_, i) => (i < 8 ? 120 : i < 16 ? 35 : i < 24 ? 8 : 3)));
  });
}

if (btnClearFeatures) btnClearFeatures.addEventListener("click", clearFeatures);

if (btnStart) btnStart.addEventListener("click", startLive);
if (btnStop) btnStop.addEventListener("click", stopLive);
if (btnClear) btnClear.addEventListener("click", clearLive);

if (refreshRateSelect) {
  refreshRateSelect.addEventListener("change", () => {
    if (renderTimer) startRenderLoop();
  });
}

window.addEventListener("beforeunload", () => {
  if (es) es.close();
});

buildFeatureInputs();
loadInterfaces();
renderTable([]);
setLiveStatus("Idle", false);
