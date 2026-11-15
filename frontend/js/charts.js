/**
 * Chart.js Visualizations for AI SIEM Cyber Dashboard
 */

let detectionDoughnutChart = null;
let threatCategoryChart = null;
let basepointRadarChart = null;
let tfidfBarChart = null;
let modelComparisonChart = null;
let liveStreamLineChart = null;

export function clearChart(canvasId) {
  const ctx = document.getElementById(canvasId);
  if (!ctx || typeof Chart === "undefined") return;
  const existing = Chart.getChart(ctx);
  if (existing) existing.destroy();
}

export function renderEmptyChartState(canvasId, message = "No uploaded dataset has been analysed yet. Upload a CSV in Threat Analyzer to view batch classification statistics.") {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  clearChart(canvasId);

  const parent = ctx.parentElement;
  if (!parent) return;

  let placeholder = parent.querySelector(".chart-placeholder-text");
  if (!placeholder) {
    placeholder = document.createElement("div");
    placeholder.className = "chart-placeholder-text";
    placeholder.style.position = "absolute";
    placeholder.style.inset = "0";
    placeholder.style.display = "flex";
    placeholder.style.alignItems = "center";
    placeholder.style.justifyContent = "center";
    placeholder.style.color = "var(--text-muted)";
    placeholder.style.fontSize = "13px";
    placeholder.style.fontStyle = "italic";
    placeholder.style.textAlign = "center";
    placeholder.style.padding = "16px";
    placeholder.style.pointerEvents = "none";
    parent.appendChild(placeholder);
  }
  placeholder.innerText = message;
  placeholder.style.display = "flex";
}

export function hideEmptyChartState(canvasId) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  const parent = ctx.parentElement;
  if (!parent) return;
  const placeholder = parent.querySelector(".chart-placeholder-text");
  if (placeholder) placeholder.style.display = "none";
}

export function renderDetectionSummaryDoughnut(canvasId, normalCount, threatCount, unknownCount = 0) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  hideEmptyChartState(canvasId);
  if (typeof Chart === "undefined") return;
  if (detectionDoughnutChart) detectionDoughnutChart.destroy();

  const isTriState = unknownCount > 0 || (threatCount > 0 && arguments.length >= 4);
  const total = isTriState ? (normalCount + threatCount + unknownCount) : (normalCount + threatCount);

  if (total === 0) {
    renderEmptyChartState(canvasId);
    return;
  }

  const labels = isTriState 
    ? ["Normal Events", "Known Threats", "Unknown / Anomalous"]
    : ["Normal Events", "Threats Detected"];
  const data = isTriState
    ? [normalCount, threatCount, unknownCount]
    : [normalCount, threatCount];
  const bgColors = isTriState
    ? ["#00e676", "#ff1744", "#ffab00"]
    : ["#00e676", "#ff1744"];

  detectionDoughnutChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: labels,
      datasets: [{
        data: data,
        backgroundColor: bgColors,
        borderColor: "#0e1626",
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: { color: "#8da2c0", font: { family: "SF Mono, monospace" } }
        }
      },
      cutout: "70%"
    }
  });
}

export function renderThreatCategoryChart(canvasId, categoriesDict = {}) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  hideEmptyChartState(canvasId);
  if (typeof Chart === "undefined") return;
  if (threatCategoryChart) threatCategoryChart.destroy();

  const keys = Object.keys(categoriesDict);
  const values = Object.values(categoriesDict);

  if (keys.length === 0 || values.reduce((a, b) => a + b, 0) === 0) {
    renderEmptyChartState(canvasId, "No threats detected in the current analysis.");
    return;
  }

  const palette = ["#00e676", "#ff1744", "#ffab00", "#00f2fe", "#7928ca", "#ff007f"];

  threatCategoryChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: keys,
      datasets: [{
        label: "Detected Events",
        data: values,
        backgroundColor: keys.map((k, i) => k.includes("Benign") ? "#00e676aa" : (palette[i % palette.length] + "aa")),
        borderColor: keys.map((k, i) => k.includes("Benign") ? "#00e676" : palette[i % palette.length]),
        borderWidth: 1,
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: "#8da2c0", font: { size: 11 } }, grid: { display: false } },
        y: { ticks: { color: "#8da2c0", stepSize: 1 }, grid: { color: "#1e3154" } }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

export function renderBasepointsRadar(canvasId, basepointsList) {
  const ctx = document.getElementById(canvasId);
  if (!ctx || !basepointsList || basepointsList.length === 0 || typeof Chart === "undefined") return;
  if (basepointRadarChart) basepointRadarChart.destroy();

  const labels = ["HIGH_FLOW_RATE", "HIGH_PACKET_RATE", "HIGH_BYTE_RATE", "SYN_ACTIVITY", "SHORT_REPEATED_CONNECTIONS"];
  const colors = [
    "#00f2fe", "#0072ff", "#00e676", "#ff1744",
    "#ffab00", "#7928ca", "#ff007f", "#38ef7d"
  ];

  const datasets = basepointsList.map((bp, i) => ({
    label: bp.basepoint || `bp_${String(i + 1).padStart(2, "0")}`,
    data: [
      bp.HIGH_FLOW_RATE || 0,
      bp.HIGH_PACKET_RATE || 0,
      bp.HIGH_BYTE_RATE || 0,
      bp.SYN_ACTIVITY || 0,
      bp.SHORT_REPEATED_CONNECTIONS || 0
    ],
    borderColor: colors[i % colors.length],
    backgroundColor: colors[i % colors.length] + "22",
    borderWidth: 2,
    pointRadius: 3
  }));

  basepointRadarChart = new Chart(ctx, {
    type: "radar",
    data: { labels, datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          grid: { color: "#1e3154" },
          angleLines: { color: "#1e3154" },
          pointLabels: { color: "#8da2c0", font: { size: 10, family: "SF Mono, monospace" } },
          ticks: { backdropColor: "transparent", color: "#536988" },
          suggestedMin: 0,
          suggestedMax: 1
        }
      },
      plugins: {
        legend: { position: "right", labels: { color: "#8da2c0", boxWidth: 12, font: { size: 11 } } }
      }
    }
  });
}

export function renderModelBenchmarksChart(canvasId, modelsReport) {
  const ctx = document.getElementById(canvasId);
  if (!ctx || !modelsReport || typeof Chart === "undefined") return;
  if (modelComparisonChart) modelComparisonChart.destroy();

  const candidateNames = ["FCNN", "CNN", "LSTM", "Ensemble", "IsolationForest"];
  const modelNames = candidateNames.filter(m => m in modelsReport);
  if (modelNames.length === 0) {
    Object.keys(modelsReport).forEach(m => modelNames.push(m));
  }

  const balAccs = [];
  const recalls = [];
  const precisions = [];
  const f1s = [];
  const rocAucs = [];

  modelNames.forEach(m => {
    const stats = modelsReport[m] || {};
    balAccs.push(Number(stats.balanced_accuracy || 0));
    recalls.push(Number(stats.recall || 0));
    precisions.push(Number(stats.precision || 0));
    f1s.push(Number(stats.f1_score || 0));
    rocAucs.push(Number(stats.roc_auc || 0));
  });

  modelComparisonChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: modelNames,
      datasets: [
        { label: "Balanced Acc", data: balAccs, backgroundColor: "#7928caaa", borderRadius: 4 },
        { label: "Recall", data: recalls, backgroundColor: "#ff1744aa", borderRadius: 4 },
        { label: "Precision", data: precisions, backgroundColor: "#00f2feaa", borderRadius: 4 },
        { label: "F1-Score", data: f1s, backgroundColor: "#ffab00aa", borderRadius: 4 },
        { label: "ROC-AUC", data: rocAucs, backgroundColor: "#00e676aa", borderRadius: 4 }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: "#8da2c0", font: { weight: "600" } }, grid: { display: false } },
        y: { min: 0, max: 1.0, ticks: { color: "#8da2c0" }, grid: { color: "#1e3154" } }
      },
      plugins: {
        legend: { position: "top", labels: { color: "#8da2c0", boxWidth: 12 } }
      }
    }
  });
}

export function initLiveStreamLine(canvasId) {
  const ctx = document.getElementById(canvasId);
  if (!ctx || typeof Chart === "undefined") return;
  if (liveStreamLineChart) liveStreamLineChart.destroy();

  liveStreamLineChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: [],
      datasets: [{
        label: "Threat Probability",
        data: [],
        borderColor: "#00f2fe",
        backgroundColor: "rgba(0, 242, 254, 0.1)",
        fill: true,
        tension: 0.3,
        pointRadius: 4,
        pointBackgroundColor: []
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: "#8da2c0", maxTicksLimit: 12 }, grid: { color: "#1e3154" } },
        y: { min: 0, max: 1.0, ticks: { color: "#8da2c0" }, grid: { color: "#1e3154" } }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

export function clearLiveStreamChart() {
  if (!liveStreamLineChart) return;
  liveStreamLineChart.data.labels = [];
  liveStreamLineChart.data.datasets[0].data = [];
  liveStreamLineChart.data.datasets[0].pointBackgroundColor = [];
  liveStreamLineChart.update("none");
}

export function populateLiveStreamChart(records) {
  if (!liveStreamLineChart) return;
  if (!records || records.length === 0) {
    clearLiveStreamChart();
    return;
  }
  const labels = [];
  const data = [];
  const pointColors = [];

  // Display up to 50 windows chronologically
  const windowSlice = records.slice(-50);
  for (const r of windowSlice) {
    const rawTime = r.window_time || r.window_start || r.timestamp || "";
    const shortLabel = rawTime.includes(" ") ? rawTime.split(" ")[1] : (rawTime.length > 8 ? rawTime.slice(-8) : rawTime);
    labels.push(shortLabel || (r.window_id ? `W-${r.window_id}` : "Window"));
    data.push(Number(r.threat_confidence ?? r.confidence ?? 0));

    let pointColor = "#00e676";
    const v = String(r.verdict || "").toUpperCase();
    if (v === "KNOWN_THREAT" || v === "THREAT") {
      pointColor = "#ff1744";
    } else if (v === "UNKNOWN_ANOMALOUS" || v === "ANOMALOUS") {
      pointColor = "#ffab00";
    }
    pointColors.push(pointColor);
  }

  liveStreamLineChart.data.labels = labels;
  liveStreamLineChart.data.datasets[0].data = data;
  liveStreamLineChart.data.datasets[0].pointBackgroundColor = pointColors;
  liveStreamLineChart.update("none");
}

export function pushLiveStreamPoint(timestamp, probability, isThreatOrVerdict) {
  if (!liveStreamLineChart) return;
  const labels = liveStreamLineChart.data.labels;
  const data = liveStreamLineChart.data.datasets[0].data;
  const pointColors = liveStreamLineChart.data.datasets[0].pointBackgroundColor;

  labels.push(timestamp);
  data.push(probability);

  let pointColor = "#00e676";
  if (typeof isThreatOrVerdict === "string") {
    if (isThreatOrVerdict === "KNOWN_THREAT" || isThreatOrVerdict === "THREAT") {
      pointColor = "#ff1744";
    } else if (isThreatOrVerdict === "UNKNOWN_ANOMALOUS") {
      pointColor = "#ffab00";
    }
  } else if (isThreatOrVerdict) {
    pointColor = "#ff1744";
  }
  pointColors.push(pointColor);

  if (labels.length > 20) {
    labels.shift();
    data.shift();
    pointColors.shift();
  }
  liveStreamLineChart.update("none");
}
