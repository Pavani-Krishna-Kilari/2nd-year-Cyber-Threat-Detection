/**
 * AI-SIEM Main Frontend Application Controller
 * Pure Vanilla JavaScript ES6+ Modules
 */

import * as api from "./api.js";
import * as charts from "./charts.js";

let activeStreamSessionId = null;
let activeStreamRecords = [];
let isStreamPaused = false;
let allDetectionLogs = [];

const PAGE_SIZE = 50;
const tableState = {
  knownThreats: { data: [], page: 1 },
  unknownAnomalies: { data: [], page: 1 },
  campaigns: { data: [], page: 1 },
};

document.addEventListener("DOMContentLoaded", async () => {
  initDashboardBackground();
  initThemeToggle();
  initTabNavigation();
  initAnalyzerEvents();
  initEnsembleControls();
  initAnomalyControls();
  initHistoryControls();
  initAssistantControls();
  initFloatingChatbot();
  initOperatorAuthStatus();

  await loadInitialTelemetry();
});

// -----------------------------------------------------------------------------
// Theme Management (Dark Cyber SOC vs Light)
// -----------------------------------------------------------------------------
function initThemeToggle() {
  const toggleBtn = document.getElementById("themeToggleBtn");
  const currentTheme = localStorage.getItem("soc_theme") || "dark";
  document.documentElement.setAttribute("data-theme", currentTheme);
  updateThemeBtnLabel(toggleBtn, currentTheme);

  toggleBtn.addEventListener("click", () => {
    const active = document.documentElement.getAttribute("data-theme");
    const next = active === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("soc_theme", next);
    updateThemeBtnLabel(toggleBtn, next);
  });
}

function updateThemeBtnLabel(btn, theme) {
  if (btn) {
    btn.innerHTML = theme === "dark" ? "☀️ Light Mode" : "🌙 Cyber Dark";
  }
}

function initOperatorAuthStatus() {
  const nameEl = document.getElementById("operatorDisplayName");
  const authActionBtn = document.getElementById("btnAuthAction");
  if (!nameEl || !authActionBtn) return;

  const storedUserRaw = localStorage.getItem("siem_operator") || sessionStorage.getItem("siem_operator");
  const token = localStorage.getItem("siem_auth_token") || sessionStorage.getItem("siem_auth_token");

  if (storedUserRaw && token) {
    try {
      const user = JSON.parse(storedUserRaw);
      nameEl.innerText = `${user.name || 'SOC Analyst'} (${user.callsign || 'Overwatch'})`;
      authActionBtn.innerText = "Sign Out";
      authActionBtn.addEventListener("click", (e) => {
        e.preventDefault();
        const activeToken = localStorage.getItem("siem_auth_token") || sessionStorage.getItem("siem_auth_token");
        fetch("/api/auth/logout" + (activeToken ? "?token=" + encodeURIComponent(activeToken) : ""), {
          method: "POST",
          credentials: "same-origin"
        }).catch(() => {});
        localStorage.removeItem("siem_auth_token");
        localStorage.removeItem("siem_operator");
        sessionStorage.removeItem("siem_auth_token");
        sessionStorage.removeItem("siem_operator");
        if (window.top && window.top !== window) {
          window.top.location.href = "/login";
        } else {
          window.location.href = "/login";
        }
      });

      // Verify token validity asynchronously with backend
      fetch(`/api/auth/me?token=${encodeURIComponent(token)}`, { credentials: "same-origin" })
        .then(res => {
          if (!res.ok) {
            localStorage.removeItem("siem_auth_token");
            localStorage.removeItem("siem_operator");
            sessionStorage.removeItem("siem_auth_token");
            sessionStorage.removeItem("siem_operator");
            if (window.top && window.top !== window) {
              window.top.location.replace("/login");
            } else {
              window.location.replace("/login");
            }
          }
        })
        .catch(() => {});
      return;
    } catch (_) {}
  }

  // Not logged in default state
  nameEl.innerText = "Guest Analyst";
  authActionBtn.innerText = "Sign In";
  authActionBtn.href = "/login";
}

// -----------------------------------------------------------------------------
// Tab Navigation Router (9 Planned SOC Sections)
// -----------------------------------------------------------------------------
function initTabNavigation() {
  const navItems = document.querySelectorAll(".nav-item");
  const views = document.querySelectorAll(".tab-view");
  const pageTitle = document.getElementById("pageTitle");

  navItems.forEach(item => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      const targetView = item.getAttribute("data-view");

      navItems.forEach(n => n.classList.remove("active"));
      views.forEach(v => v.classList.remove("active"));

      item.classList.add("active");
      const activeEl = document.getElementById(targetView);
      if (activeEl) activeEl.classList.add("active");

      if (pageTitle) {
        pageTitle.innerText = item.querySelector("span:last-child")?.innerText || "SIEM Dashboard";
      }

      if (targetView === "view-history") {
        if (!activeStreamRecords || activeStreamRecords.length === 0) {
          loadThreatStream();
        }
      }
    });
  });
}

// -----------------------------------------------------------------------------
// Dashboard Summary UI Updater (Home / SOC Overview)
// -----------------------------------------------------------------------------
export function formatVerdictLabel(verdict) {
  if (!verdict) return "Normal";
  const v = String(verdict).toUpperCase();
  if (v === "KNOWN_THREAT" || v === "THREAT" || v === "ANN_ALERT") return "ANN Alert";
  if (v === "UNKNOWN_ANOMALOUS" || v === "ANOMALOUS") return "Unknown Anomalous";
  if (v === "NORMAL") return "Normal";
  return verdict;
}

export function getVerdictBadgeClass(verdict) {
  const v = String(verdict || "").toUpperCase();
  if (v === "KNOWN_THREAT" || v === "THREAT" || v === "ANN_ALERT") return "badge-threat";
  if (v === "UNKNOWN_ANOMALOUS" || v === "ANOMALOUS") return "badge-warning";
  return "badge-normal";
}

export function updateDashboardSummaryUI(summary) {
  const elTotal = document.getElementById("kpiTotalAnalysed");
  const elTotalSub = document.getElementById("kpiTotalAnalysedSub");
  const elNormal = document.getElementById("kpiNormalEvents");
  const elNormalSub = document.getElementById("kpiNormalEventsSub");
  const elThreat = document.getElementById("kpiThreatsDetected");
  const elThreatSub = document.getElementById("kpiThreatsDetectedSub");
  const elInvalid = document.getElementById("kpiInvalidRecords");
  const elInvalidSub = document.getElementById("kpiInvalidRecordsSub");
  const noticeBox = document.getElementById("socBatchNotice");
  const noticeText = document.getElementById("socBatchNoticeText");
  const noticeBadge = document.getElementById("socBatchNoticeBadge");
  const badgeDet = document.getElementById("badgeDetectionSummary");
  const badgeCat = document.getElementById("badgeAttackCategories");

  const emptyMsg = "No uploaded dataset has been analysed yet. Upload a CSV in Threat Analyzer to view batch classification statistics.";

  if (!summary || !summary.has_data) {
    if (elTotal) elTotal.innerText = "0";
    if (elTotalSub) elTotalSub.innerText = "Source: Awaiting Upload";
    if (elNormal) elNormal.innerText = "0";
    if (elNormalSub) elNormalSub.innerText = "0.0% of analysed";
    if (elThreat) elThreat.innerText = "0";
    if (elThreatSub) elThreatSub.innerText = "0.0% of analysed";
    if (elInvalid) elInvalid.innerText = "0";
    if (elInvalidSub) elInvalidSub.innerText = "0 malformed rows";

    if (noticeBox) {
      noticeBox.className = "batch-status-panel";
      noticeBox.style.borderLeft = "3px solid var(--accent-cyan)";
    }
    if (noticeText) noticeText.innerText = emptyMsg;
    if (noticeBadge) {
      noticeBadge.className = "badge badge-info";
      noticeBadge.innerText = "Awaiting CSV Upload";
    }
    if (badgeDet) badgeDet.innerText = "Awaiting Batch Upload";
    if (badgeCat) badgeCat.innerText = "Awaiting Batch Upload";

    charts.renderEmptyChartState("chartDetectionSummary", emptyMsg);
    charts.renderEmptyChartState("chartAttackCategories", emptyMsg);
    return;
  }

  const flowStats = summary.flow_statistics;
  const eventStats = summary.event_set_statistics;
  const campStats = summary.campaign_statistics;

  const total = flowStats?.total_raw_flows ?? summary.total_records ?? 0;
  const normal = eventStats?.normal_event_sets ?? summary.normal_events ?? 0;
  const threat = campStats?.total_campaigns ?? summary.threats_detected ?? 0;
  const known = campStats?.known_threat_campaigns ?? summary.known_threats ?? threat;
  const unknown = campStats?.unknown_anomalous_campaigns ?? summary.unknown_anomalous ?? 0;
  const invalid = flowStats?.invalid_flows ?? summary.invalid_records ?? 0;
  const validTotal = normal + threat;
  const filename = summary.filename || "Uploaded CSV";

  if (elTotal) elTotal.innerText = total.toLocaleString();
  if (elTotalSub) {
    if (summary.detected_type === "profile") {
      elTotalSub.innerText = `${total.toLocaleString()} profiles uploaded`;
    } else {
      elTotalSub.innerText = flowStats && eventStats 
        ? `${flowStats.total_raw_flows.toLocaleString()} flows • ${eventStats.total_event_sets.toLocaleString()} windows`
        : "Source: Uploaded CSV Batch";
    }
  }

  const normalPct = validTotal > 0 ? ((normal / validTotal) * 100).toFixed(1) : "0.0";
  const threatPct = validTotal > 0 ? ((threat / validTotal) * 100).toFixed(1) : "0.0";

  if (elNormal) elNormal.innerText = normal.toLocaleString();
  if (elNormalSub) {
    elNormalSub.innerText = summary.detected_type === "profile" 
      ? `${normalPct}% normal events` 
      : `${normalPct}% normal windows`;
  }

  if (elThreat) elThreat.innerText = threat.toLocaleString();
  if (elThreatSub) {
    elThreatSub.innerText = unknown > 0 ? `${known} known, ${unknown} anomalous campaign(s)` : `${threat} alert campaign(s)`;
  }

  if (elInvalid) elInvalid.innerText = invalid.toLocaleString();
  if (elInvalidSub) elInvalidSub.innerText = invalid === 0 ? "All records valid" : `${invalid} invalid row(s)`;

  if (noticeBox) {
    noticeBox.className = "batch-status-panel complete";
    noticeBox.style.borderLeft = "3px solid var(--accent-green)";
  }
  if (noticeText) {
    const extraInfo = eventStats ? `${total.toLocaleString()} flows • ${eventStats.total_event_sets.toLocaleString()} windows analysed` : `${total.toLocaleString()} records analysed`;
    noticeText.innerHTML = `✅ Active Batch Dataset: <strong>${escapeHtml(filename)}</strong> (${extraInfo} • Source: Uploaded CSV Batch)`;
  }
  if (noticeBadge) {
    noticeBadge.className = "badge badge-normal";
    noticeBadge.innerText = "Source: Uploaded CSV Batch";
  }
  if (badgeDet) badgeDet.innerText = `Source: Uploaded CSV Batch (${filename})`;
  if (badgeCat) badgeCat.innerText = `Source: Uploaded CSV Batch (${filename})`;

  // Render Charts from actual latest batch analysis
  charts.renderDetectionSummaryDoughnut("chartDetectionSummary", normal, known, unknown);
  charts.renderThreatCategoryChart("chartAttackCategories", summary.attack_categories || {});
}

// -----------------------------------------------------------------------------
// Data Ingestion & Initial Telemetry
// -----------------------------------------------------------------------------
async function loadInitialTelemetry() {
  try {
    const [status, summary, profiles, benchmarks, anomaly, history] = await Promise.all([
      api.fetchSystemStatus(),
      api.fetchDashboardSummary(),
      api.fetchProfilesOverview(),
      api.fetchModelBenchmarks(),
      api.fetchAnomalyOverview(),
      api.fetchDetectionHistory({ limit: 50 })
    ]);

    // Update Status Pill
    const statusPill = document.getElementById("systemStatusPill");
    if (statusPill) {
      statusPill.innerHTML = `<span class="pulsing-dot"></span> Status: ${status.status}`;
    }

    // Sync Active Experiment label
    const activeExpLabel = document.getElementById("activeExperimentLabel");
    if (activeExpLabel && status.experiment_id) {
      activeExpLabel.innerText = `Experiment ${status.experiment_id}`;
    }

    // Sync Ensemble Sliders from active config
    if (status.ensemble_config) {
      const ensThresh = Number(status.ensemble_config.threshold || 0.6561).toFixed(4);
      const sliderThresh = document.getElementById("sliderThreshold");
      const valThresh = document.getElementById("valThreshold");
      if (sliderThresh) sliderThresh.value = ensThresh;
      if (valThresh) valThresh.innerText = ensThresh;

      const weights = status.ensemble_config.weights;
      if (Array.isArray(weights) && weights.length >= 3) {
        const [w1, w2, w3] = weights.map(w => Number(w).toFixed(2));
        const s1 = document.getElementById("sliderWeightFcnn");
        const s2 = document.getElementById("sliderWeightCnn");
        const s3 = document.getElementById("sliderWeightLstm");
        const v1 = document.getElementById("valWeightFcnn");
        const v2 = document.getElementById("valWeightCnn");
        const v3 = document.getElementById("valWeightLstm");
        if (s1) s1.value = w1;
        if (s2) s2.value = w2;
        if (s3) s3.value = w3;
        if (v1) v1.innerText = w1;
        if (v2) v2.innerText = w2;
        if (v3) v3.innerText = w3;
      }
    }

    // Home / SOC Overview: Update Detection Cards (starts at 0 if no analysis)
    updateDashboardSummaryUI(summary);

    // Populate Historical/Model Hub & Event Profiles Tables
    populateBasepointsTable(profiles.basepoints || []);
    populateThresholdsTable(profiles.thresholds || []);
    populateBenchmarkTable("benchmarkTableUnseen", benchmarks.evaluation_a_unseen?.model_metrics || {});
    populateBenchmarkTable("benchmarkTableControl", benchmarks.evaluation_b_control?.model_metrics || {});

    // Populate Anomaly Telemetry in Anomaly View (Experiment B verified)
    if (anomaly) {
      const kpiIsoTrain = document.getElementById("kpiIsoTrain");
      const kpiIsoRecall = document.getElementById("kpiIsoRecall");
      const kpiIsoRoc = document.getElementById("kpiIsoRoc");
      const kpiIsoFpr = document.getElementById("kpiIsoFpr");
      const isoThreshDisplay = document.getElementById("isoThreshDisplay");

      if (kpiIsoTrain) kpiIsoTrain.innerText = (anomaly.training_samples || 1997246).toLocaleString();
      if (kpiIsoRecall) {
        const rec = anomaly.metrics_on_test?.recall !== undefined ? (anomaly.metrics_on_test.recall * 100).toFixed(2) : "6.19";
        kpiIsoRecall.innerText = `${rec}%`;
      }
      if (kpiIsoRoc) {
        const roc = anomaly.metrics_on_test?.roc_auc !== undefined ? (anomaly.metrics_on_test.roc_auc * 100).toFixed(2) : "57.92";
        kpiIsoRoc.innerText = `${roc}%`;
      }
      if (kpiIsoFpr) {
        const fpr = anomaly.metrics_on_test?.false_positive_rate !== undefined ? (anomaly.metrics_on_test.false_positive_rate * 100).toFixed(2) : "1.05";
        kpiIsoFpr.innerText = `${fpr}%`;
      }
      if (isoThreshDisplay) {
        isoThreshDisplay.innerText = Number(anomaly.optimal_threshold !== undefined ? anomaly.optimal_threshold : -0.012676).toFixed(6);
      }
    }

    // Populate Model Benchmarks Bar Chart in Model Hub view
    charts.renderModelBenchmarksChart("chartModelBenchmarks", benchmarks.evaluation_a_unseen?.model_metrics || {});

    // Populate Detection History from SQLite
    if (Array.isArray(history)) {
      allDetectionLogs = history;
      renderFilteredHistory();
    }

    // Initialize Live Stream Chart and load genuine latest upload stream
    charts.initLiveStreamLine("chartLiveStream");
    await loadThreatStream();

  } catch (err) {
    console.error("Error loading telemetry:", err);
  }
}

function populateBasepointsTable(basepoints) {
  const tbody = document.querySelector("#basepointsTable tbody");
  if (!tbody || !basepoints) return;
  tbody.innerHTML = basepoints.map(bp => `
    <tr>
      <td><strong>${bp.basepoint}</strong></td>
      <td>${Number(bp.HIGH_FLOW_RATE || 0).toFixed(4)}</td>
      <td>${Number(bp.HIGH_PACKET_RATE || 0).toFixed(4)}</td>
      <td>${Number(bp.HIGH_BYTE_RATE || 0).toFixed(4)}</td>
      <td>${Number(bp.SYN_ACTIVITY || 0).toFixed(4)}</td>
      <td>${Number(bp.SHORT_REPEATED_CONNECTIONS || 0).toFixed(4)}</td>
      <td>${bp.max_cosine_to_previous !== null && bp.max_cosine_to_previous !== undefined ? Number(bp.max_cosine_to_previous).toFixed(4) : "—"}</td>
    </tr>
  `).join("");
}

function populateThresholdsTable(thresholds) {
  const tbody = document.querySelector("#thresholdsTable tbody");
  if (!tbody || !thresholds) return;
  const entries = Array.isArray(thresholds) ? thresholds : Object.entries(thresholds).map(([name, t]) => ({ name, ...t }));
  tbody.innerHTML = entries.map(t => `
    <tr>
      <td><code>${t.name || t.event_name}</code></td>
      <td><span class="badge badge-info">${t.level || 'Window'}</span></td>
      <td>${t.feature || t.source_feature}</td>
      <td>${t.comparison}</td>
      <td><strong>${Number(t.threshold).toLocaleString()}</strong></td>
    </tr>
  `).join("");
}

export function populateBenchmarkTable(tableId, modelsReport) {
  const tbody = document.querySelector(`#${tableId} tbody`);
  if (!tbody || !modelsReport) return;
  tbody.innerHTML = Object.entries(modelsReport).map(([name, m]) => {
    const threshStr = m.threshold !== undefined && m.threshold !== null ? Number(m.threshold).toFixed(4) : "—";
    const accStr = m.accuracy !== undefined ? `${(m.accuracy * 100).toFixed(2)}%` : "—";
    const balAccStr = m.balanced_accuracy !== undefined ? `<strong>${(m.balanced_accuracy * 100).toFixed(2)}%</strong>` : "—";
    const recStr = m.recall !== undefined ? `<strong>${(m.recall * 100).toFixed(2)}%</strong>` : "—";
    const precStr = m.precision !== undefined ? `${(m.precision * 100).toFixed(2)}%` : "—";
    const f1Str = m.f1_score !== undefined ? `${(m.f1_score * 100).toFixed(2)}%` : "—";
    const prAucStr = m.pr_auc !== undefined ? Number(m.pr_auc).toFixed(4) : "—";
    const rocAucStr = m.roc_auc !== undefined ? `<strong>${(m.roc_auc * 100).toFixed(2)}%</strong>` : "—";
    const fprStr = m.false_positive_rate !== undefined ? `<span class="badge badge-normal">${(m.false_positive_rate * 100).toFixed(2)}%</span>` : "—";
    const cmStr = m.confusion_matrix ? `TP:${m.confusion_matrix.tp} / FP:${m.confusion_matrix.fp}` : "—";

    return `
      <tr>
        <td><strong>${name}</strong></td>
        <td><code>${threshStr}</code></td>
        <td>${accStr}</td>
        <td>${balAccStr}</td>
        <td>${recStr}</td>
        <td>${precStr}</td>
        <td>${f1Str}</td>
        <td>${prAucStr}</td>
        <td>${rocAucStr}</td>
        <td>${fprStr}</td>
        <td><code>${cmStr}</code></td>
      </tr>
    `;
  }).join("");
}

// -----------------------------------------------------------------------------
// Interactive Threat Analyzer & File Upload Interface (CSV, TXT, PDF)
// -----------------------------------------------------------------------------
function initAnalyzerEvents() {
  const form = document.getElementById("flowAnalyzerForm");
  const fileInput = document.getElementById("fileInput");
  const dropzone = document.getElementById("uploadDropzone");

  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const payload = {
        source_ip: document.getElementById("flowSrcIp").value,
        destination_ip: document.getElementById("flowDstIp").value,
        source_port: parseInt(document.getElementById("flowSrcPort").value) || 0,
        destination_port: parseInt(document.getElementById("flowDstPort").value) || 0,
        protocol: 6,
        flow_packets_s: parseFloat(document.getElementById("flowPackets").value) || 0,
        flow_bytes_s: parseFloat(document.getElementById("flowBytes").value) || 0,
        syn_flag_count: parseInt(document.getElementById("flowSyn").value) || 0,
        flow_duration: parseFloat(document.getElementById("flowDuration").value) || 0,
        flow_count: parseInt(document.getElementById("flowCount").value) || 1
      };

      try {
        const res = await api.predictFlow(payload);
        displayVerdict(res);

        // STRICT SEPARATION RULE: Manual single-flow classification updates ONLY
        // the Manual Single-Flow Verdict panel in Threat Analyzer.
        // It NEVER updates or contributes to SOC Overview statistics, charts, or records.
        const newHistory = await api.fetchDetectionHistory({ limit: 50 });
        if (Array.isArray(newHistory)) {
          allDetectionLogs = newHistory;
          renderFilteredHistory();
        }
      } catch (err) {
        alert("Inference error: " + err.message);
      }
    });
  }

  // Pre-fill Sample Buttons (pure input population, strictly decoupled from submission)
  document.getElementById("btnSampleBenign")?.addEventListener("click", () => {
    document.getElementById("flowSrcIp").value = "192.168.10.15";
    document.getElementById("flowDstIp").value = "192.168.10.3";
    document.getElementById("flowDstPort").value = 443;
    document.getElementById("flowPackets").value = 120.0;
    document.getElementById("flowBytes").value = 45000.0;
    document.getElementById("flowSyn").value = 0;
    document.getElementById("flowDuration").value = 850000.0;
    document.getElementById("flowCount").value = 3;
  });

  document.getElementById("btnSampleFtpPatator")?.addEventListener("click", () => {
    document.getElementById("flowSrcIp").value = "172.16.0.1";
    document.getElementById("flowDstIp").value = "192.168.10.50";
    document.getElementById("flowDstPort").value = 21;
    document.getElementById("flowPackets").value = 500000.0;
    document.getElementById("flowBytes").value = 2000000.0;
    document.getElementById("flowSyn").value = 1;
    document.getElementById("flowDuration").value = 1000.0;
    document.getElementById("flowCount").value = 15;
  });

  document.getElementById("btnSampleSshPatator")?.addEventListener("click", () => {
    document.getElementById("flowSrcIp").value = "172.16.0.1";
    document.getElementById("flowDstIp").value = "192.168.10.50";
    document.getElementById("flowDstPort").value = 22;
    document.getElementById("flowPackets").value = 650000.0;
    document.getElementById("flowBytes").value = 2800000.0;
    document.getElementById("flowSyn").value = 2;
    document.getElementById("flowDuration").value = 1000.0;
    document.getElementById("flowCount").value = 25;
  });

  // Dropzone Events
  if (dropzone && fileInput) {
    dropzone.addEventListener("click", () => fileInput.click());
    dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("dragover"); });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
      if (e.dataTransfer.files.length) handleFileUpload(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener("change", () => {
      if (fileInput.files.length) handleFileUpload(fileInput.files[0]);
    });
  }
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

async function clearBatchResults() {
  const statusEl = document.getElementById("uploadStatus");
  if (statusEl) statusEl.innerHTML = "";
  const metricsPanel = document.getElementById("batchMetricsPanel");
  if (metricsPanel) metricsPanel.style.display = "none";
  const campTable = document.getElementById("campaignResultsTable");
  if (campTable) {
    const tbody = campTable.querySelector("tbody");
    if (tbody) tbody.innerHTML = "";
  }
  const table = document.getElementById("batchResultsTable");
  if (table) {
    const tbody = table.querySelector("tbody");
    if (tbody) tbody.innerHTML = "";
    table.style.display = "none";
  }
  const fileInput = document.getElementById("fileInput");
  if (fileInput) fileInput.value = "";

  // Reset backend batch analysis summary and restore SOC Overview empty state
  try {
    await api.clearBatchSummary();
  } catch (err) {
    console.warn("Could not clear backend batch summary:", err);
  }
  updateDashboardSummaryUI({ has_data: false });
  clearThreatStreamUI();
}

async function handleFileUpload(file) {
  const statusEl = document.getElementById("uploadStatus");
  const metricsPanel = document.getElementById("batchMetricsPanel");
  if (statusEl) {
    statusEl.innerHTML = `
      <div class="batch-status-panel processing">
        <div style="display: flex; align-items: center; gap: 10px;">
          <span style="display: inline-block; width: 14px; height: 14px; border: 2px solid var(--accent-cyan); border-right-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite;"></span>
          <span style="color: var(--accent-cyan); font-weight: 600;">Ingesting, aggregating, and classifying <code>${escapeHtml(file.name)}</code> (${(file.size / 1024).toFixed(1)} KB)...</span>
        </div>
      </div>
    `;
  }

  try {
    const res = await api.uploadThreatFile(file);
    if (res.error || res.detail) {
      let errMsg = "";
      let detailExtra = "";
      if (typeof res.detail === "object" && res.detail !== null) {
        errMsg = res.detail.message || res.detail.error || JSON.stringify(res.detail);
        if (res.detail.details && res.detail.details.extracted_records !== undefined) {
          detailExtra = `
            <div style="margin-top: 6px; font-size: 11px; color: var(--text-muted);">
              Extracted: <strong>${escapeHtml(res.detail.details.extracted_records)}</strong> flow record(s) • Detected columns: <code>${escapeHtml((res.detail.details.columns_found || []).join(", "))}</code>
            </div>
          `;
        }
      } else {
        errMsg = res.detail || res.error;
      }
      if (statusEl) {
        statusEl.innerHTML = `
          <div class="batch-status-panel" style="border-left: 3px solid var(--accent-red);">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
              <div>
                <span style="color: var(--accent-red); font-weight: 600;">⚠️ Ingestion Error: ${escapeHtml(errMsg)}</span>
                ${detailExtra}
              </div>
              <button class="btn btn-secondary" id="btnClearBatchResults" type="button" style="padding: 4px 10px; font-size: 12px; margin-left: 10px;">Clear</button>
            </div>
          </div>
        `;
        document.getElementById("btnClearBatchResults")?.addEventListener("click", clearBatchResults);
      }
      return;
    }

    const flowStats = res.flow_statistics || {};
    const eventStats = res.event_set_statistics || {};
    const campStats = res.campaign_statistics || {};

    const totalRawFlows = flowStats.total_raw_flows ?? res.total_records ?? 0;
    const totalSets = eventStats.total_event_sets ?? res.total_records ?? 0;
    const normalSets = eventStats.normal_event_sets ?? res.normal_events ?? 0;
    const totalCampaigns = campStats.total_campaigns ?? res.threats_detected ?? 0;
    const threatCampaigns = campStats.known_threat_campaigns ?? res.known_threats ?? 0;
    const anomCampaigns = campStats.unknown_anomalous_campaigns ?? res.unknown_anomalous ?? 0;
    const invalidFlows = flowStats.invalid_flows ?? res.invalid_records ?? 0;
    const procDuration = res.processing_time_ms ? `${res.processing_time_ms} ms` : "N/A";
    const captureType = res.detected_type === "flow" ? "Raw Network Flows" : "Event Profiles";

    if (statusEl) {
      statusEl.innerHTML = `
        <div class="batch-status-panel complete">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 8px;">
            <div>
              <span style="color: var(--accent-green); font-weight: 700;">✅ Batch Analysis Complete</span>
              <span style="color: var(--text-secondary); margin-left: 8px;"><code>${escapeHtml(res.filename || file.name)}</code> (${escapeHtml(captureType)} • ${procDuration})</span>
            </div>
            <button class="btn btn-secondary" id="btnClearBatchResults" type="button" style="padding: 4px 10px; font-size: 12px;">Clear Results</button>
          </div>
          <div style="display: flex; flex-wrap: wrap; gap: 8px;">
            <div class="kpi-mini-pill">Total Analysed: <strong>${totalSets.toLocaleString()}</strong></div>
            <div class="kpi-mini-pill">Uploaded Flows: <strong>${totalRawFlows.toLocaleString()}</strong></div>
            <div class="kpi-mini-pill">Generated Event Sets: <strong>${totalSets.toLocaleString()}</strong></div>
            <div class="kpi-mini-pill threat">Alert Campaigns: <strong>${totalCampaigns.toLocaleString()}</strong></div>
            <div class="kpi-mini-pill normal">Normal Sets: <strong>${normalSets.toLocaleString()}</strong></div>
            <div class="kpi-mini-pill threat">Known Threats: <strong>${threatCampaigns.toLocaleString()}</strong></div>
            <div class="kpi-mini-pill warning">Unknown Anomalous: <strong>${anomCampaigns.toLocaleString()}</strong></div>
            ${invalidFlows > 0 ? `<div class="kpi-mini-pill info">Invalid: <strong>${invalidFlows.toLocaleString()}</strong></div>` : ''}
          </div>
        </div>
      `;
      document.getElementById("btnClearBatchResults")?.addEventListener("click", clearBatchResults);
    }

    // Populate and show Batch Metrics Panel
    if (metricsPanel) {
      metricsPanel.style.display = "block";
      const elFlows = document.getElementById("metricUploadedFlows");
      const elSets = document.getElementById("metricGeneratedEventSets");
      const elCamps = document.getElementById("metricUniqueCampaigns");
      const elNorm = document.getElementById("metricNormalSets");
      const elThreatC = document.getElementById("metricKnownThreatCampaigns");
      const elAnomC = document.getElementById("metricUnknownAnomalousCampaigns");
      const elDur = document.getElementById("metricProcessingDuration");

      if (elFlows) elFlows.innerText = totalRawFlows.toLocaleString();
      if (elSets) elSets.innerText = totalSets.toLocaleString();
      if (elCamps) elCamps.innerText = totalCampaigns.toLocaleString();
      if (elNorm) elNorm.innerText = normalSets.toLocaleString();
      if (elThreatC) elThreatC.innerText = threatCampaigns.toLocaleString();
      if (elAnomC) elAnomC.innerText = anomCampaigns.toLocaleString();
      if (elDur) elDur.innerText = procDuration;
    }

    // Render Section A: Known Threats / ANN Alerts
    renderKnownThreatsTable(res.known_threats_list || []);

    // Render Section B: Unknown Anomalous Activity
    renderUnknownAnomaliesTable(res.unknown_anomalies_list || []);

    // Render Section C: Coalesced Security Campaigns Table
    renderCampaignResultsTable(res.campaigns || []);

    // Render Window Batch Table (Collapsible Audit Trail)
    renderBatchResultsTable(res.sample_results || [], totalSets);

    // Update Dashboard Summary Cards & Charts for SOC Overview
    updateDashboardSummaryUI(res);

    // Refresh Sessions Archive from SQLite
    loadSessionsArchive();

    // Load genuine Sliding Window Threat Stream for this newly uploaded session
    loadThreatStream(res.session_id);
  } catch (err) {
    if (statusEl) {
      statusEl.innerHTML = `
        <div class="batch-status-panel" style="border-left: 3px solid var(--accent-red);">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <span style="color: var(--accent-red);">Upload failed: ${escapeHtml(err.message)}</span>
            <button class="btn btn-secondary" id="btnClearBatchResults" type="button" style="padding: 4px 10px; font-size: 12px;">Clear</button>
          </div>
        </div>
      `;
      document.getElementById("btnClearBatchResults")?.addEventListener("click", clearBatchResults);
    }
  }
}

function renderKnownThreatsTable(threats, tableId = "knownThreatsTable", badgeId = "badgeKnownThreatsCount") {
  const table = document.getElementById(tableId);
  const tbody = table?.querySelector("tbody");
  const countBadge = document.getElementById(badgeId);
  const n = (threats || []).length;
  if (countBadge) {
    countBadge.innerText = `${n} Known Threat${n === 1 ? '' : 's'}`;
  }
  if (!tbody) return;

  if (!threats || threats.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 16px;">No known threats identified by the ANN ensemble. All evaluated event profiles were within benign limits or handled as anomalous.</td></tr>`;
    return;
  }

  tbody.innerHTML = threats.map((t, idx) => {
    const esId = escapeHtml(t.event_set_id || t.id || `ES${String(idx + 1).padStart(7, '0')}`);
    const campId = escapeHtml(t.campaign_id || "-");
    const srcHost = escapeHtml(t.source_ip || "N/A");
    const dstHost = escapeHtml(t.destination_ip ? `${t.destination_ip}${t.destination_port ? ':' + t.destination_port : ''}` : "N/A");
    const timeRange = escapeHtml(String(t.timestamp || t.window_start || "N/A").replace("T", " "));
    const confVal = (Number(t.confidence ?? t.threat_confidence ?? 0) * 100).toFixed(2);
    const sev = t.severity || "HIGH";
    const flowCount = t.n_flows ?? (t.flow_metadata && t.flow_metadata.n_flows ? t.flow_metadata.n_flows : 1);

    return `
      <tr>
        <td><strong style="color: var(--accent-red); font-family: var(--font-mono);">${esId}</strong></td>
        <td><code style="color: var(--accent-cyan);">${campId}</code></td>
        <td><code>${srcHost}</code></td>
        <td><code>${dstHost}</code></td>
        <td style="font-size: 11.5px; color: var(--text-secondary); font-family: var(--font-mono);">${timeRange}</td>
        <td><strong>${confVal}%</strong></td>
        <td><span class="badge badge-threat">${escapeHtml(sev)}</span></td>
        <td><span class="badge badge-normal">${Number(flowCount).toLocaleString()} flows</span></td>
      </tr>
    `;
  }).join("");
}

function renderUnknownAnomaliesTable(anomalies, tableId = "unknownAnomaliesTable", badgeId = "badgeUnknownAnomaliesCount") {
  const table = document.getElementById(tableId);
  const tbody = table?.querySelector("tbody");
  const countBadge = document.getElementById(badgeId);
  const n = (anomalies || []).length;
  if (countBadge) {
    countBadge.innerText = `${n} Anomal${n === 1 ? 'y' : 'ies'}`;
  }
  if (!tbody) return;

  if (!anomalies || anomalies.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 16px;">No anomalous activity flagged by Isolation Forest. Traffic adheres to expected distribution baselines.</td></tr>`;
    return;
  }

  tbody.innerHTML = anomalies.map((a, idx) => {
    const esId = escapeHtml(a.event_set_id || a.id || `ES${String(idx + 1).padStart(7, '0')}`);
    const campId = escapeHtml(a.campaign_id || "-");
    const srcHost = escapeHtml(a.source_ip || "N/A");
    const dstHost = escapeHtml(a.destination_ip ? `${a.destination_ip}${a.destination_port ? ':' + a.destination_port : ''}` : "N/A");
    const timeRange = escapeHtml(String(a.timestamp || a.window_start || "N/A").replace("T", " "));
    const anomScore = a.anomaly_score !== undefined ? Number(a.anomaly_score).toFixed(4) : "N/A";
    const sev = a.severity || "MEDIUM";
    const flowCount = a.n_flows ?? (a.flow_metadata && a.flow_metadata.n_flows ? a.flow_metadata.n_flows : 1);

    return `
      <tr>
        <td><strong style="color: var(--accent-amber); font-family: var(--font-mono);">${esId}</strong></td>
        <td><code style="color: var(--accent-cyan);">${campId}</code></td>
        <td><code>${srcHost}</code></td>
        <td><code>${dstHost}</code></td>
        <td style="font-size: 11.5px; color: var(--text-secondary); font-family: var(--font-mono);">${timeRange}</td>
        <td><strong style="color: var(--accent-amber);">${anomScore}</strong></td>
        <td><span class="badge badge-warning">${escapeHtml(sev)}</span></td>
        <td><span class="badge badge-normal">${Number(flowCount).toLocaleString()} flows</span></td>
      </tr>
    `;
  }).join("");
}

function renderCampaignResultsTable(campaigns, tableId = "campaignResultsTable", badgeId = "badgeCampaignCount") {
  const table = document.getElementById(tableId);
  const tbody = table?.querySelector("tbody");
  const countBadge = document.getElementById(badgeId);
  if (countBadge) {
    countBadge.innerText = `${(campaigns || []).length} Campaign${(campaigns || []).length === 1 ? '' : 's'}`;
  }
  if (!tbody) return;

  if (!campaigns || campaigns.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 16px;">No alert campaigns identified. All observed sliding windows are within normal traffic baseline.</td></tr>`;
    return;
  }

  tbody.innerHTML = campaigns.map(c => {
    const cid = escapeHtml(c.campaign_id);
    const srcIp = escapeHtml(c.source_ip || "N/A");
    const dstIp = escapeHtml(c.destination_ip || "N/A");
    const startT = escapeHtml(String(c.start_time || "").replace("T", " "));
    const endT = escapeHtml(String(c.end_time || "").replace("T", " "));
    const verdict = c.verdict || "UNKNOWN";
    const badgeClass = getVerdictBadgeClass(verdict);
    const verdictLabel = formatVerdictLabel(verdict);
    const confVal = (Number(c.max_confidence || 0) * 100).toFixed(2);
    const winCount = c.window_count ?? (c.constituent_windows ? c.constituent_windows.length : 1);
    const flowCount = c.attributed_flow_count ?? (c.attributed_flow_indices ? c.attributed_flow_indices.length : 0);

    return `
      <tr>
        <td><strong style="color: var(--accent-cyan); font-family: var(--font-mono);">${cid}</strong></td>
        <td><code>${srcIp}</code></td>
        <td><code>${dstIp}</code></td>
        <td style="font-size: 11.5px; color: var(--text-secondary); font-family: var(--font-mono);">${startT}</td>
        <td style="font-size: 11.5px; color: var(--text-secondary); font-family: var(--font-mono);">${endT}</td>
        <td><span class="badge ${badgeClass}">${verdictLabel}</span></td>
        <td><strong>${confVal}%</strong></td>
        <td><span class="badge badge-info">${winCount} win</span></td>
        <td><span class="badge badge-normal">${flowCount.toLocaleString()} flows</span></td>
      </tr>
    `;
  }).join("");
}

function renderBatchResultsTable(results, totalCount) {
  const table = document.getElementById("batchResultsTable");
  const tbody = table?.querySelector("tbody");
  const countBadge = document.getElementById("badgeWindowCount");
  if (countBadge) {
    const n = totalCount ?? (results || []).length;
    countBadge.innerText = `${n.toLocaleString()} Windows${results && results.length < n ? ` (showing first ${results.length})` : ''}`;
  }
  if (!tbody) return;
  table.style.display = "table";

  if (!results || results.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 16px;">No records available to display.</td></tr>`;
    return;
  }

  tbody.innerHTML = results.map((r, idx) => {
    const recNum = r.index ?? r.id ?? (idx + 1);
    const srcHost = r.source_ip || "N/A";
    const dstHost = (r.destination_ip) ? `${r.destination_ip}${r.destination_port ? ':' + r.destination_port : ''}` : "N/A";
    const verdict = r.verdict || "UNKNOWN";
    const badgeClass = getVerdictBadgeClass(verdict);
    const verdictLabel = formatVerdictLabel(verdict);
    const confVal = (Number(r.confidence ?? r.threat_confidence ?? 0) * 100).toFixed(2);
    const severity = r.severity || "LOW";

    let sevBadgeClass = "badge-info";
    if (severity === "CRITICAL" || severity === "HIGH") sevBadgeClass = "badge-threat";
    else if (severity === "MEDIUM") sevBadgeClass = "badge-warning";
    else if (severity === "LOW" || severity === "INFO") sevBadgeClass = "badge-normal";

    return `
      <tr>
        <td>${recNum}</td>
        <td><code>${escapeHtml(srcHost)}</code></td>
        <td><code>${escapeHtml(dstHost)}</code></td>
        <td><span class="badge ${badgeClass}">${escapeHtml(verdictLabel)}</span></td>
        <td><strong>${confVal}%</strong></td>
        <td><span class="badge ${sevBadgeClass}">${escapeHtml(severity)}</span></td>
      </tr>
    `;
  }).join("");
}

// -----------------------------------------------------------------------------
// STRICT REQUIREMENT: Display ONE Final Verdict (NORMAL, KNOWN_THREAT, or UNKNOWN_ANOMALOUS)
// -----------------------------------------------------------------------------
function displayVerdict(res) {
  const box = document.getElementById("verdictBox");
  if (!box) return;

  const v = res.verdict || res.prediction_status || "NORMAL";
  const isKnownThreat = (v === "KNOWN_THREAT" || v === "THREAT" || v === "ANN_ALERT");
  const isAnomalous = (v === "UNKNOWN_ANOMALOUS" || v === "ANOMALOUS");

  if (isKnownThreat) {
    box.className = "verdict-box threat";
  } else if (isAnomalous) {
    box.className = "verdict-box anomalous";
  } else {
    box.className = "verdict-box normal";
  }

  document.getElementById("verdictTitle").innerText = formatVerdictLabel(v);
  document.getElementById("verdictConfidence").innerText = `${(Number(res.confidence ?? res.threat_confidence ?? 0) * 100).toFixed(2)}%`;
  
  const sevBadge = document.getElementById("verdictSeverityBadge");
  if (sevBadge) {
    sevBadge.innerText = res.severity || "LOW";
    sevBadge.className = `badge ${isKnownThreat ? 'badge-threat' : (isAnomalous ? 'badge-warning' : 'badge-normal')}`;
  }

  document.getElementById("verdictDominantBp").innerText = `${res.dominant_basepoint} (${Number(res.dominant_basepoint_similarity || 0).toFixed(4)})`;

  const clsEl = document.getElementById("verdictPredictedClass");
  if (clsEl && res.predicted_class) {
    clsEl.innerText = res.predicted_class;
  }
  const reasonEl = document.getElementById("verdictReason");
  if (reasonEl && res.detection_reason) {
    reasonEl.innerText = res.detection_reason;
  }

  // Submodel probabilities for transparency
  document.getElementById("meterFcnn").style.width = `${((res.model_breakdown?.fcnn || 0) * 100).toFixed(1)}%`;
  document.getElementById("meterCnn").style.width = `${((res.model_breakdown?.cnn || 0) * 100).toFixed(1)}%`;
  document.getElementById("meterLstm").style.width = `${((res.model_breakdown?.lstm || 0) * 100).toFixed(1)}%`;

  document.getElementById("valFcnn").innerText = `${((res.model_breakdown?.fcnn || 0) * 100).toFixed(1)}%`;
  document.getElementById("valCnn").innerText = `${((res.model_breakdown?.cnn || 0) * 100).toFixed(1)}%`;
  document.getElementById("valLstm").innerText = `${((res.model_breakdown?.lstm || 0) * 100).toFixed(1)}%`;

  box.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// -----------------------------------------------------------------------------
// SECTION 5: Anomaly Detection Controls (Isolation Forest)
// -----------------------------------------------------------------------------
function initAnomalyControls() {
  const form = document.getElementById("anomalyForm");
  const verdictCard = document.getElementById("isoVerdictCard");
  const verdictTitle = document.getElementById("isoVerdictTitle");
  const scoreVal = document.getElementById("isoScoreValue");

  // Presets
  document.getElementById("btnIsoNormal")?.addEventListener("click", () => {
    for (let i = 1; i <= 8; i++) {
      const el = document.getElementById(`isoBp${i}`);
      if (el) el.value = "0.0";
    }
    form?.requestSubmit();
  });

  document.getElementById("btnIsoAttack")?.addEventListener("click", () => {
    const vals = [0.85, 0.20, 0.10, 0.05, 0.70, 0.80, 0.75, 0.05];
    for (let i = 1; i <= 8; i++) {
      const el = document.getElementById(`isoBp${i}`);
      if (el) el.value = vals[i - 1].toFixed(2);
    }
    form?.requestSubmit();
  });

  document.getElementById("btnIsoOutlier")?.addEventListener("click", () => {
    const vals = [0.95, 0.85, 0.90, 0.80, 0.95, 0.90, 0.95, 0.85];
    for (let i = 1; i <= 8; i++) {
      const el = document.getElementById(`isoBp${i}`);
      if (el) el.value = vals[i - 1].toFixed(2);
    }
    form?.requestSubmit();
  });

  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {};
    for (let i = 1; i <= 8; i++) {
      payload[`bp_${String(i).padStart(2, "0")}`] = parseFloat(document.getElementById(`isoBp${i}`).value) || 0.0;
    }

    try {
      const res = await api.predictAnomaly(payload);
      if (verdictCard && verdictTitle && scoreVal) {
        const isAnomaly = res.is_anomaly;
        verdictCard.className = `verdict-box ${isAnomaly ? "threat" : "normal"}`;
        verdictTitle.innerText = res.verdict;
        verdictTitle.style.color = isAnomaly ? "var(--accent-red)" : "var(--accent-green)";
        scoreVal.innerHTML = `${res.anomaly_score.toFixed(4)} <span style="font-size: 12px; color: var(--text-muted)">/ ${res.threshold.toFixed(4)}</span>`;
      }
    } catch (err) {
      alert("Anomaly evaluation error: " + err.message);
    }
  });
}

// -----------------------------------------------------------------------------
// SECTION 6: Persistent Classification Reports Archive & Session Management
// -----------------------------------------------------------------------------
let currentSessionArchive = [];
let filteredSessionArchive = [];
let sessionArchivePage = 0;
const SESSIONS_PER_PAGE = 10;
let pendingDeleteSession = null;
let activeSessionReport = null;

async function loadSessionsArchive() {
  const tbody = document.querySelector("#sessionHistoryTable tbody");
  const infoEl = document.getElementById("sessionPaginationInfo");
  if (!tbody) return;

  tbody.innerHTML = `
    <tr>
      <td colspan="11" style="text-align: center; color: var(--accent-cyan); padding: 24px;">
        <span style="display: inline-block; width: 14px; height: 14px; border: 2px solid var(--accent-cyan); border-right-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 8px;"></span>
        Loading persistent classification reports from SQLite...
      </td>
    </tr>
  `;

  try {
    const sessions = await api.fetchSessions({ limit: 200, offset: 0 });
    currentSessionArchive = Array.isArray(sessions) ? sessions : [];

    // Apply any active search filter
    const searchInput = document.getElementById("sessionSearchInput");
    const query = searchInput ? searchInput.value.trim().toLowerCase() : "";
    if (query) {
      filteredSessionArchive = currentSessionArchive.filter(s =>
        (s.filename || s.source_name || "").toLowerCase().includes(query) ||
        (s.session_id || "").toLowerCase().includes(query)
      );
    } else {
      filteredSessionArchive = [...currentSessionArchive];
    }

    sessionArchivePage = 0;
    renderSessionsArchiveTable();
  } catch (err) {
    console.error("Failed to load sessions archive:", err);
    tbody.innerHTML = `
      <tr>
        <td colspan="11" style="text-align: center; color: var(--accent-red); padding: 20px;">
          ⚠️ Error loading classification archive: ${escapeHtml(err.message)}
        </td>
      </tr>
    `;
    if (infoEl) infoEl.innerText = "Error loading reports";
  }
}

function renderSessionsArchiveTable() {
  const tbody = document.querySelector("#sessionHistoryTable tbody");
  const infoEl = document.getElementById("sessionPaginationInfo");
  const btnPrev = document.getElementById("btnPrevSessions");
  const btnNext = document.getElementById("btnNextSessions");
  if (!tbody) return;

  const total = filteredSessionArchive.length;
  if (total === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="11" style="text-align: center; color: var(--text-muted); padding: 28px; font-style: italic;">
          No classification reports found. Upload a network capture to generate persistent reports.
        </td>
      </tr>
    `;
    if (infoEl) infoEl.innerText = "0 reports archived";
    if (btnPrev) btnPrev.disabled = true;
    if (btnNext) btnNext.disabled = true;
    return;
  }

  const maxPage = Math.max(0, Math.ceil(total / SESSIONS_PER_PAGE) - 1);
  if (sessionArchivePage > maxPage) sessionArchivePage = maxPage;
  if (sessionArchivePage < 0) sessionArchivePage = 0;

  const startIdx = sessionArchivePage * SESSIONS_PER_PAGE;
  const pageItems = filteredSessionArchive.slice(startIdx, startIdx + SESSIONS_PER_PAGE);

  if (infoEl) {
    infoEl.innerText = `Showing ${startIdx + 1}–${Math.min(startIdx + SESSIONS_PER_PAGE, total)} of ${total} reports (Page ${sessionArchivePage + 1} of ${maxPage + 1})`;
  }
  if (btnPrev) btnPrev.disabled = sessionArchivePage === 0;
  if (btnNext) btnNext.disabled = sessionArchivePage >= maxPage;

  tbody.innerHTML = pageItems.map(s => {
    const sid = escapeHtml(s.session_id);
    const fname = escapeHtml(s.filename || s.source_name || "Capture");
    const dateStr = escapeHtml(String(s.timestamp || "").replace("T", " "));
    const flows = Number(s.uploaded_flows ?? s.total_records ?? 0).toLocaleString();
    const sets = Number(s.event_sets ?? s.total_records ?? 0).toLocaleString();
    const normal = Number(s.normal_events ?? 0).toLocaleString();
    const threats = Number(s.known_threats ?? 0).toLocaleString();
    const anom = Number(s.unknown_anomalous ?? 0).toLocaleString();
    const camps = Number(s.campaigns_count ?? 0).toLocaleString();
    const status = escapeHtml(s.status || "Completed");

    const threatBadgeClass = Number(s.known_threats || 0) > 0 ? "badge-threat" : "badge-normal";
    const anomBadgeClass = Number(s.unknown_anomalous || 0) > 0 ? "badge-warning" : "badge-normal";

    return `
      <tr>
        <td><code style="font-size: 11px; color: var(--accent-cyan); font-family: var(--font-mono);">${sid}</code></td>
        <td><strong>${fname}</strong></td>
        <td style="font-size: 11.5px; color: var(--text-secondary); font-family: var(--font-mono);">${dateStr}</td>
        <td>${flows}</td>
        <td>${sets}</td>
        <td><span class="badge badge-normal">${normal}</span></td>
        <td><span class="badge ${threatBadgeClass}">${threats}</span></td>
        <td><span class="badge ${anomBadgeClass}">${anom}</span></td>
        <td><span class="badge badge-info">${camps}</span></td>
        <td><span class="badge badge-normal">${status}</span></td>
        <td style="white-space: nowrap;">
          <button class="btn btn-secondary btn-view-report" data-session-id="${sid}" style="padding: 4px 10px; font-size: 11.5px;">View Report</button>
          <button class="btn btn-threat btn-delete-session" data-session-id="${sid}" data-filename="${fname}" style="padding: 4px 8px; font-size: 11.5px; margin-left: 4px;">Delete</button>
        </td>
      </tr>
    `;
  }).join("");

  // Attach event listeners to row buttons
  tbody.querySelectorAll(".btn-view-report").forEach(btn => {
    btn.addEventListener("click", () => {
      const sid = btn.getAttribute("data-session-id");
      if (sid) viewSessionReport(sid);
    });
  });

  tbody.querySelectorAll(".btn-delete-session").forEach(btn => {
    btn.addEventListener("click", () => {
      const sid = btn.getAttribute("data-session-id");
      const fname = btn.getAttribute("data-filename");
      if (sid) promptDeleteSession(sid, fname);
    });
  });
}

async function viewSessionReport(sessionId) {
  const historyCard = document.getElementById("sessionHistoryCard");
  const reportPanel = document.getElementById("sessionReportPanel");

  try {
    const report = await api.fetchSessionReport(sessionId);
    if (!report || report.detail) {
      alert("Failed to load report: " + (report?.detail || "Session not found"));
      return;
    }
    activeSessionReport = report;

    // Toggle panels
    if (historyCard) historyCard.style.display = "none";
    if (reportPanel) reportPanel.style.display = "block";

    // Populate Header
    const fnEl = document.getElementById("reportHeaderFilename");
    const metaEl = document.getElementById("reportHeaderMeta");
    const fname = report.filename || report.source_name || "Network Capture";
    const itype = report.input_type === "flow" ? "Raw Network Flows" : "Event Profiles";
    if (fnEl) fnEl.innerText = `${fname} (${itype})`;
    if (metaEl) metaEl.innerText = `Session ID: ${report.session_id} • Analyzed on ${String(report.timestamp || "").replace("T", " ")}`;

    // Populate Metrics
    const flowStats = report.flow_statistics || {};
    const eventStats = report.event_set_statistics || {};
    const campStats = report.campaign_statistics || {};

    const elFlows = document.getElementById("repMetricFlows");
    const elSets = document.getElementById("repMetricSets");
    const elNorm = document.getElementById("repMetricNormal");
    const elThreat = document.getElementById("repMetricThreats");
    const elAnom = document.getElementById("repMetricAnomalies");
    const elCamps = document.getElementById("repMetricCampaigns");

    if (elFlows) elFlows.innerText = Number(flowStats.total_raw_flows ?? report.total_records ?? 0).toLocaleString();
    if (elSets) elSets.innerText = Number(eventStats.total_event_sets ?? report.total_records ?? 0).toLocaleString();
    if (elNorm) elNorm.innerText = Number(eventStats.normal_event_sets ?? report.normal_events ?? 0).toLocaleString();
    if (elThreat) elThreat.innerText = Number(campStats.known_threat_campaigns ?? report.known_threats ?? 0).toLocaleString();
    if (elAnom) elAnom.innerText = Number(campStats.unknown_anomalous_campaigns ?? report.unknown_anomalous ?? 0).toLocaleString();
    const campTotal = campStats.total_campaigns ?? (report.campaigns ? report.campaigns.length : (report.threats_detected ?? 0));
    if (elCamps) elCamps.innerText = Number(campTotal).toLocaleString();

    // Populate Model Summary
    const ms = report.model_summary || {};
    const elFcnn = document.getElementById("repModelFcnn");
    const elCnn = document.getElementById("repModelCnn");
    const elLstm = document.getElementById("repModelLstm");
    const elEns = document.getElementById("repModelEns");
    if (elFcnn) elFcnn.innerText = `${((ms.fcnn_avg || 0) * 100).toFixed(1)}%`;
    if (elCnn) elCnn.innerText = `${((ms.cnn_avg || 0) * 100).toFixed(1)}%`;
    if (elLstm) elLstm.innerText = `${((ms.lstm_avg || 0) * 100).toFixed(1)}%`;
    if (elEns) elEns.innerText = `${((ms.ensemble_avg || 0) * 100).toFixed(1)}%`;

    // Render Section A: Known Threats
    renderKnownThreatsTable(report.known_threats_list || [], "reportKnownThreatsTable", "repBadgeKnownThreats");

    // Render Section B: Unknown Anomalies
    renderUnknownAnomaliesTable(report.unknown_anomalies_list || [], "reportUnknownAnomaliesTable", "repBadgeUnknownAnomalies");

    // Render Section C: Logical Security Campaigns
    renderCampaignResultsTable(report.campaigns || [], "reportCampaignsTable", "repBadgeCampaigns");

    // Collapsible all detections audit log
    const allDets = report.sample_results || [];
    const repBadgeAll = document.getElementById("repBadgeAllDetections");
    if (repBadgeAll) repBadgeAll.innerText = `${allDets.length} Records`;
    const tbodyAll = document.querySelector("#reportAllDetectionsTable tbody");
    if (tbodyAll) {
      if (allDets.length === 0) {
        tbodyAll.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 14px;">No individual detection records to display.</td></tr>`;
      } else {
        tbodyAll.innerHTML = allDets.map(r => `
          <tr>
            <td><code>${escapeHtml(String(r.timestamp || 'N/A').replace('T', ' '))}</code></td>
            <td><code>${escapeHtml(r.source_ip || 'N/A')}</code></td>
            <td><code>${escapeHtml(r.destination_ip || 'N/A')}${r.destination_port ? ':' + r.destination_port : ''}</code></td>
            <td><span class="badge ${getVerdictBadgeClass(r.verdict)}">${escapeHtml(formatVerdictLabel(r.verdict))}</span></td>
            <td><strong>${(Number(r.confidence ?? r.threat_confidence ?? 0) * 100).toFixed(1)}%</strong></td>
            <td><span class="badge badge-info">${escapeHtml(r.severity || 'LOW')}</span></td>
          </tr>
        `).join("");
      }
    }
  } catch (err) {
    console.error("Error viewing session report:", err);
    alert("Could not load report: " + err.message);
  }
}

function backToHistory() {
  const historyCard = document.getElementById("sessionHistoryCard");
  const reportPanel = document.getElementById("sessionReportPanel");
  if (reportPanel) reportPanel.style.display = "none";
  if (historyCard) historyCard.style.display = "block";
  activeSessionReport = null;
  loadSessionsArchive();
}

function promptDeleteSession(sessionId, filename) {
  pendingDeleteSession = { sessionId, filename };
  const modal = document.getElementById("deleteSessionModal");
  const fnEl = document.getElementById("delModalFilename");
  const sidEl = document.getElementById("delModalSessionId");
  if (fnEl) fnEl.innerText = filename || "Session Report";
  if (sidEl) sidEl.innerText = sessionId;
  if (modal) modal.style.display = "flex";
}

function closeDeleteModal() {
  const modal = document.getElementById("deleteSessionModal");
  if (modal) modal.style.display = "none";
  pendingDeleteSession = null;
}

async function confirmDeleteSession() {
  if (!pendingDeleteSession) return;
  const { sessionId } = pendingDeleteSession;
  const btnConfirm = document.getElementById("btnConfirmDelete");
  if (btnConfirm) btnConfirm.disabled = true;

  try {
    const res = await api.deleteSession(sessionId);
    closeDeleteModal();

    // If currently viewing the deleted report, navigate back to history
    if (activeSessionReport && activeSessionReport.session_id === sessionId) {
      backToHistory();
    } else {
      loadSessionsArchive();
    }
  } catch (err) {
    alert("Failed to delete classification report: " + err.message);
    closeDeleteModal();
  } finally {
    if (btnConfirm) btnConfirm.disabled = false;
  }
}

function initHistoryControls() {
  // Initial load of sessions archive from SQLite
  loadSessionsArchive();

  // Refresh archive button
  document.getElementById("btnRefreshSessions")?.addEventListener("click", () => {
    loadSessionsArchive();
  });

  // Client-side search and filtering
  document.getElementById("sessionSearchInput")?.addEventListener("input", (e) => {
    const query = e.target.value.trim().toLowerCase();
    if (!query) {
      filteredSessionArchive = [...currentSessionArchive];
    } else {
      filteredSessionArchive = currentSessionArchive.filter(s =>
        (s.filename || s.source_name || "").toLowerCase().includes(query) ||
        (s.session_id || "").toLowerCase().includes(query)
      );
    }
    sessionArchivePage = 0;
    renderSessionsArchiveTable();
  });

  // Export entire archive metadata to JSON
  document.getElementById("btnExportSessionsJson")?.addEventListener("click", () => {
    if (!currentSessionArchive.length) {
      alert("No classification reports to export.");
      return;
    }
    const jsonContent = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentSessionArchive, null, 2));
    const link = document.createElement("a");
    link.setAttribute("href", jsonContent);
    link.setAttribute("download", `siem_sessions_archive_${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  });

  // Archive pagination controls
  document.getElementById("btnPrevSessions")?.addEventListener("click", () => {
    if (sessionArchivePage > 0) {
      sessionArchivePage--;
      renderSessionsArchiveTable();
    }
  });

  document.getElementById("btnNextSessions")?.addEventListener("click", () => {
    const maxPage = Math.max(0, Math.ceil(filteredSessionArchive.length / SESSIONS_PER_PAGE) - 1);
    if (sessionArchivePage < maxPage) {
      sessionArchivePage++;
      renderSessionsArchiveTable();
    }
  });

  // Report Detail Panel controls
  document.getElementById("btnBackToHistory")?.addEventListener("click", backToHistory);

  document.getElementById("btnExportSingleReportJson")?.addEventListener("click", () => {
    if (!activeSessionReport) return;
    const jsonContent = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(activeSessionReport, null, 2));
    const link = document.createElement("a");
    link.setAttribute("href", jsonContent);
    link.setAttribute("download", `siem_report_${activeSessionReport.session_id}_${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  });

  document.getElementById("btnDeleteCurrentReport")?.addEventListener("click", () => {
    if (activeSessionReport) {
      promptDeleteSession(activeSessionReport.session_id, activeSessionReport.filename);
    }
  });

  // Delete Confirmation Modal controls
  document.getElementById("btnCloseDeleteModal")?.addEventListener("click", closeDeleteModal);
  document.getElementById("btnCancelDelete")?.addEventListener("click", closeDeleteModal);
  document.getElementById("btnConfirmDelete")?.addEventListener("click", confirmDeleteSession);

  // Close modal when clicking on backdrop
  document.getElementById("deleteSessionModal")?.addEventListener("click", (e) => {
    if (e.target && e.target.id === "deleteSessionModal") {
      closeDeleteModal();
    }
  });
}

// -----------------------------------------------------------------------------
// Real-Time Sliding Window Threat Stream Controller (Latest Uploaded CSV Only)
// -----------------------------------------------------------------------------
export async function loadThreatStream(sessionId = null) {
  try {
    const res = await api.fetchStreamEvent(sessionId);
    const badge = document.getElementById("streamSessionBadge");
    const toggleBtn = document.getElementById("btnToggleStream");

    if (res && res.has_data && Array.isArray(res.records) && res.records.length > 0) {
      activeStreamSessionId = res.session_id;
      activeStreamRecords = res.records;

      if (badge) {
        const fname = res.source_name || "Uploaded Capture";
        badge.innerText = `Session: ${res.session_id} • ${fname} (${res.total_windows} Windows)`;
        badge.className = "badge badge-info";
      }

      // Populate chart with the entire uploaded sliding-window stream
      charts.populateLiveStreamChart(activeStreamRecords);

      // Render all evaluated windows in the threat stream table
      renderThreatStreamTable(activeStreamRecords);

      if (toggleBtn) {
        toggleBtn.innerText = "⏸️ Pause Stream";
        isStreamPaused = false;
      }
    } else {
      clearThreatStreamUI();
    }
  } catch (err) {
    console.warn("Could not load threat stream:", err);
    clearThreatStreamUI();
  }
}

export function clearThreatStreamUI() {
  activeStreamSessionId = null;
  activeStreamRecords = [];

  const badge = document.getElementById("streamSessionBadge");
  if (badge) {
    badge.innerText = "No Active Upload";
    badge.className = "badge badge-info";
  }

  charts.clearLiveStreamChart();

  const tbody = document.querySelector("#liveStreamTable tbody");
  if (tbody) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align: center; color: var(--text-muted); font-style: italic; padding: 24px;">
          No uploaded sliding-window stream available. Upload a network flow or event profile CSV to view stream telemetry.
        </td>
      </tr>
    `;
  }
}

export function renderThreatStreamTable(records) {
  const tbody = document.querySelector("#liveStreamTable tbody");
  if (!tbody) return;

  if (!records || records.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align: center; color: var(--text-muted); font-style: italic; padding: 24px;">
          No sliding window records found for this upload session.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = records.map(r => {
    const wTime = r.window_time || r.window_start || r.timestamp || "N/A";
    const wId = r.window_id || r.id || "-";
    const esId = r.event_set_id || "-";
    const campBadge = (r.campaign_id && r.campaign_id !== "-")
      ? `<span class="badge badge-warning">${escapeHtml(r.campaign_id)}</span>`
      : `<span style="color: var(--text-muted);">-</span>`;
    const flows = r.n_flows !== undefined ? r.n_flows : 1;
    const confVal = Number(r.threat_confidence ?? r.confidence ?? 0);
    const confPct = (confVal * 100).toFixed(1);
    const sev = r.severity || "LOW";
    const sevClass = (sev === "CRITICAL" || sev === "HIGH") ? "badge-threat" : (sev === "MEDIUM" ? "badge-warning" : "badge-normal");

    return `
      <tr>
        <td><code>${escapeHtml(wTime)}</code></td>
        <td><code>${escapeHtml(wId)}</code></td>
        <td><code>${escapeHtml(esId)}</code></td>
        <td>${campBadge}</td>
        <td><code>${Number(flows).toLocaleString()}</code></td>
        <td><span class="badge ${getVerdictBadgeClass(r.verdict)}">${formatVerdictLabel(r.verdict)}</span></td>
        <td><strong>${confPct}%</strong></td>
        <td><span class="badge ${sevClass}">${escapeHtml(sev)}</span></td>
      </tr>
    `;
  }).join("");
}

export function renderFilteredHistory() {
  // Maintained for backward compatibility; stream table is populated exclusively via renderThreatStreamTable
  if (activeStreamRecords && activeStreamRecords.length > 0) {
    renderThreatStreamTable(activeStreamRecords);
  }
}

function toggleThreatStreamPlayback() {
  const toggleBtn = document.getElementById("btnToggleStream");
  if (isStreamPaused) {
    isStreamPaused = false;
    if (toggleBtn) toggleBtn.innerText = "⏸️ Pause Stream";
    if (activeStreamRecords && activeStreamRecords.length > 0) {
      charts.populateLiveStreamChart(activeStreamRecords);
    }
  } else {
    isStreamPaused = true;
    if (toggleBtn) toggleBtn.innerText = "▶️ Resume Stream";
  }
}

document.getElementById("btnToggleStream")?.addEventListener("click", toggleThreatStreamPlayback);

// -----------------------------------------------------------------------------
// SECTION 7: AI Cybersecurity Assistant Controls (Dedicated Section)
// -----------------------------------------------------------------------------
function initAssistantControls() {
  const chatForm = document.getElementById("chatInputForm");
  const chatInput = document.getElementById("chatInputText");
  const chatMessages = document.getElementById("chatMessages");
  const btnClearChat = document.getElementById("btnClearChat");
  const chips = document.querySelectorAll("#chatChipsArea .chip-btn");

  const sendQuery = async (queryText) => {
    if (!queryText || !queryText.trim()) return;

    appendChatMessage("user", queryText, "chatMessages");
    appendChatMessage("user", queryText, "floatingChatMessages");
    if (chatInput) chatInput.value = "";

    const loadingId = "loader_" + Date.now();
    const loadingMsg = document.createElement("div");
    loadingMsg.className = "chat-msg assistant";
    loadingMsg.id = loadingId;
    loadingMsg.innerHTML = `
      <div class="chat-avatar">🤖</div>
      <div class="chat-bubble">
        <em>Consulting SIEM telemetry and detection records...</em>
      </div>
    `;
    chatMessages?.appendChild(loadingMsg);
    if (chatMessages) chatMessages.scrollTop = chatMessages.scrollHeight;

    try {
      const res = await api.chatAssistant(queryText);
      const loader = document.getElementById(loadingId);
      if (loader) loader.remove();

      appendChatMessage("assistant", res.reply, "chatMessages", res.suggestions || [], (q) => sendQuery(q));
      appendChatMessage("assistant", res.reply, "floatingChatMessages", res.suggestions || [], (q) => sendQuery(q));
    } catch (err) {
      const loader = document.getElementById(loadingId);
      if (loader) loader.remove();
      appendChatMessage("assistant", `**Error consulting AI Analyst:** ${err.message}`, "chatMessages");
    }
  };

  chatForm?.addEventListener("submit", (e) => {
    e.preventDefault();
    if (chatInput) sendQuery(chatInput.value);
  });

  chips.forEach(chip => {
    chip.addEventListener("click", () => {
      const q = chip.getAttribute("data-query");
      if (q) sendQuery(q);
    });
  });

  btnClearChat?.addEventListener("click", () => {
    if (chatMessages) {
      chatMessages.innerHTML = `
        <div class="chat-msg assistant">
          <div class="chat-avatar">🤖</div>
          <div class="chat-bubble">
            <h3>Conversation Reset</h3>
            <p>AI SIEM Analyst is ready for your next threat inquiry.</p>
          </div>
        </div>
      `;
    }
  });
}

// -----------------------------------------------------------------------------
// FLOATING AI CYBERSECURITY ASSISTANT (Accessible Across All 9 Sections)
// -----------------------------------------------------------------------------
function initFloatingChatbot() {
  const floatBtn = document.getElementById("floatingChatBtn");
  const floatPanel = document.getElementById("floatingChatPanel");
  const closeBtn = document.getElementById("btnCloseFloatingChat");
  const floatForm = document.getElementById("floatingChatForm");
  const floatInput = document.getElementById("floatingChatInput");
  const floatChips = document.querySelectorAll("#floatingChatChips .chip-btn");

  floatBtn?.addEventListener("click", () => {
    const isHidden = floatPanel.style.display === "none" || !floatPanel.style.display;
    floatPanel.style.display = isHidden ? "flex" : "none";
    if (isHidden && floatInput) {
      setTimeout(() => floatInput.focus(), 100);
    }
  });

  closeBtn?.addEventListener("click", () => {
    floatPanel.style.display = "none";
  });

  const sendFloatingQuery = async (queryText) => {
    if (!queryText || !queryText.trim()) return;

    appendChatMessage("user", queryText, "floatingChatMessages");
    appendChatMessage("user", queryText, "chatMessages");
    if (floatInput) floatInput.value = "";

    const loadingId = "float_loader_" + Date.now();
    const loadingMsg = document.createElement("div");
    loadingMsg.className = "chat-msg assistant";
    loadingMsg.id = loadingId;
    loadingMsg.innerHTML = `
      <div class="chat-avatar">🤖</div>
      <div class="chat-bubble">
        <em>Querying live detection engine...</em>
      </div>
    `;
    const floatContainer = document.getElementById("floatingChatMessages");
    if (floatContainer) {
      floatContainer.appendChild(loadingMsg);
      floatContainer.scrollTop = floatContainer.scrollHeight;
    }

    try {
      const res = await api.chatAssistant(queryText);
      const loader = document.getElementById(loadingId);
      if (loader) loader.remove();

      appendChatMessage("assistant", res.reply, "floatingChatMessages", res.suggestions || [], (q) => sendFloatingQuery(q));
      appendChatMessage("assistant", res.reply, "chatMessages", res.suggestions || [], (q) => sendFloatingQuery(q));
    } catch (err) {
      const loader = document.getElementById(loadingId);
      if (loader) loader.remove();
      appendChatMessage("assistant", `**Error:** ${err.message}`, "floatingChatMessages");
    }
  };

  floatForm?.addEventListener("submit", (e) => {
    e.preventDefault();
    if (floatInput) sendFloatingQuery(floatInput.value);
  });

  floatChips.forEach(chip => {
    chip.addEventListener("click", () => {
      const q = chip.getAttribute("data-query");
      if (q) sendFloatingQuery(q);
    });
  });
}

function appendChatMessage(role, text, targetId, suggestions = [], onSuggestionClick = null) {
  const container = document.getElementById(targetId);
  if (!container) return;

  if (typeof text !== "string") text = String(text || "");

  const msgDiv = document.createElement("div");
  msgDiv.className = `chat-msg ${role}`;

  let formatted = text
    .replace(/^### (.*$)/gim, "<h3>$1</h3>")
    .replace(/^## (.*$)/gim, "<h3>$1</h3>")
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*(.*?)\*/g, "<em>$1</em>")
    .replace(/```([\s\S]*?)```/g, "<pre><code>$1</code></pre>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\n\n/g, "<p></p>")
    .replace(/\n/g, "<br>");

  let html = `
    <div class="chat-avatar">${role === "user" ? "👤" : "🤖"}</div>
    <div class="chat-bubble">
      ${formatted}
  `;

  if (suggestions && suggestions.length > 0) {
    html += `<div class="chat-reply-suggestions" style="margin-top: 10px; display: flex; flex-wrap: wrap; gap: 6px;">`;
    suggestions.forEach(s => {
      const escaped = s.replace(/"/g, '&quot;');
      html += `<button type="button" class="chip-btn suggestion-pill" data-query="${escaped}" style="font-size: 11px; padding: 4px 10px;">${s}</button>`;
    });
    html += `</div>`;
  }

  html += `</div>`;
  msgDiv.innerHTML = html;

  if (suggestions && suggestions.length > 0 && onSuggestionClick) {
    msgDiv.querySelectorAll(".suggestion-pill").forEach(btn => {
      btn.addEventListener("click", () => {
        const q = btn.getAttribute("data-query");
        if (q) onSuggestionClick(q);
      });
    });
  }

  container.appendChild(msgDiv);
  container.scrollTop = container.scrollHeight;
}

// -----------------------------------------------------------------------------
// Soft-Voting Ensemble Tuning Controls
// -----------------------------------------------------------------------------
function initEnsembleControls() {
  const w1Slider = document.getElementById("sliderWeightFcnn");
  const w2Slider = document.getElementById("sliderWeightCnn");
  const w3Slider = document.getElementById("sliderWeightLstm");
  const threshSlider = document.getElementById("sliderThreshold");
  const applyBtn = document.getElementById("btnApplyEnsemble");

  const syncVals = () => {
    if (w1Slider) document.getElementById("valWeightFcnn").innerText = w1Slider.value;
    if (w2Slider) document.getElementById("valWeightCnn").innerText = w2Slider.value;
    if (w3Slider) document.getElementById("valWeightLstm").innerText = w3Slider.value;
    if (threshSlider) document.getElementById("valThreshold").innerText = threshSlider.value;
  };

  [w1Slider, w2Slider, w3Slider, threshSlider].forEach(s => s?.addEventListener("input", syncVals));

  applyBtn?.addEventListener("click", async () => {
    const weights = [
      parseFloat(w1Slider.value),
      parseFloat(w2Slider.value),
      parseFloat(w3Slider.value)
    ];
    const threshold = parseFloat(threshSlider.value);
    await api.updateEnsembleConfig(weights, threshold);
    alert(`Ensemble parameters updated: Weights=[${weights.join(", ")}], Threshold=${threshold}`);
  });
}

// -----------------------------------------------------------------------------
// Dynamic Background Particle Network (Matches Login Page Cybersecurity Theme)
// -----------------------------------------------------------------------------
function initDashboardBackground() {
  const canvas = document.getElementById("dashboardNetworkCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  // Respect prefers-reduced-motion accessibility setting
  const mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
  if (mediaQuery.matches) {
    canvas.style.display = "none";
    return;
  }

  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  window.addEventListener("resize", () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  });

  const mouse = { x: null, y: null, radius: 120 };
  window.addEventListener("mousemove", (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  });
  window.addEventListener("mouseleave", () => {
    mouse.x = null;
    mouse.y = null;
  });

  // Dynamic particle count based on screen area (up to 75 particles matching login theme)
  const particleCount = Math.min(Math.floor((width * height) / 16000), 75);
  const particles = [];
  const colors = ["#00E5FF", "#8B35FF", "#287BFF", "#00b4d8", "#38bdf8"];

  for (let i = 0; i < particleCount; i++) {
    particles.push({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.55,
      vy: (Math.random() - 0.5) * 0.55,
      radius: Math.random() * 2.2 + 1.4,
      color: colors[Math.floor(Math.random() * colors.length)],
      alpha: Math.random() * 0.45 + 0.45
    });
  }

  // Telemetry pulses along edges
  const packets = [];
  function spawnPacket(p1, p2) {
    packets.push({
      p1,
      p2,
      progress: 0,
      speed: Math.random() * 0.016 + 0.010,
      color: Math.random() > 0.35 ? "#00E5FF" : "#ffffff"
    });
  }

  let frameCount = 0;
  function render() {
    // If light mode is active, clear and skip rendering to save CPU
    const isLight = document.documentElement.getAttribute("data-theme") === "light";
    if (isLight) {
      ctx.clearRect(0, 0, width, height);
      requestAnimationFrame(render);
      return;
    }

    ctx.clearRect(0, 0, width, height);
    frameCount++;

    // Update & draw particles
    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0) p.x = width;
      else if (p.x > width) p.x = 0;
      if (p.y < 0) p.y = height;
      else if (p.y > height) p.y = 0;

      // Mouse attraction
      if (mouse.x !== null && mouse.y !== null) {
        const dx = mouse.x - p.x;
        const dy = mouse.y - p.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < mouse.radius) {
          const force = (mouse.radius - dist) / mouse.radius;
          p.x -= (dx / dist) * force * 1.2;
          p.y -= (dy / dist) * force * 1.2;
        }
      }

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.globalAlpha = p.alpha;
      ctx.shadowBlur = 10;
      ctx.shadowColor = p.color;
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    // Connect nearby particles with subtle glowing lines
    const maxDistance = 140;
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const p1 = particles[i];
        const p2 = particles[j];
        const dx = p1.x - p2.x;
        const dy = p1.y - p2.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < maxDistance) {
          const alpha = (1 - dist / maxDistance) * 0.32;
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.strokeStyle = p1.color;
          ctx.globalAlpha = alpha;
          ctx.lineWidth = 1.0;
          ctx.stroke();

          // Spawn traveling telemetry data pulses along connecting lines
          if (frameCount % 60 === 0 && Math.random() < 0.08 && packets.length < 15) {
            spawnPacket(p1, p2);
          }
        }
      }
    }

    // Connect mouse to nearby particles
    if (mouse.x !== null && mouse.y !== null) {
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        const dx = mouse.x - p.x;
        const dy = mouse.y - p.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 110) {
          const alpha = (1 - dist / 110) * 0.35;
          ctx.beginPath();
          ctx.moveTo(mouse.x, mouse.y);
          ctx.lineTo(p.x, p.y);
          ctx.strokeStyle = "#00E5FF";
          ctx.globalAlpha = alpha;
          ctx.lineWidth = 1.1;
          ctx.stroke();
        }
      }
    }

    // Render traveling telemetry packets
    for (let i = packets.length - 1; i >= 0; i--) {
      const pkt = packets[i];
      pkt.progress += pkt.speed;
      if (pkt.progress >= 1) {
        packets.splice(i, 1);
        continue;
      }
      const curX = pkt.p1.x + (pkt.p2.x - pkt.p1.x) * pkt.progress;
      const curY = pkt.p1.y + (pkt.p2.y - pkt.p1.y) * pkt.progress;

      ctx.beginPath();
      ctx.arc(curX, curY, 2.8, 0, Math.PI * 2);
      ctx.fillStyle = pkt.color;
      ctx.globalAlpha = 0.95;
      ctx.shadowBlur = 12;
      ctx.shadowColor = pkt.color;
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    ctx.globalAlpha = 1.0;
    requestAnimationFrame(render);
  }

  requestAnimationFrame(render);
}
