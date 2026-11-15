/**
 * AI-SIEM REST API Client
 */

const API_BASE = "";

export async function fetchDashboardSummary() {
  const res = await fetch(`${API_BASE}/api/dashboard/summary`);
  return res.json();
}

export async function fetchSystemStatus() {
  const res = await fetch(`${API_BASE}/api/status`);
  return res.json();
}

export async function fetchDatasetOverview() {
  const res = await fetch(`${API_BASE}/api/dataset/overview`);
  return res.json();
}

export async function fetchProfilesOverview() {
  const res = await fetch(`${API_BASE}/api/profiles/overview`);
  return res.json();
}

export async function fetchModelBenchmarks() {
  const res = await fetch(`${API_BASE}/api/models/benchmarks`);
  return res.json();
}

export async function predictProfile(profile) {
  const res = await fetch(`${API_BASE}/api/models/predict/profile`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(profile)
  });
  return res.json();
}

export async function predictFlow(flow) {
  const res = await fetch(`${API_BASE}/api/models/predict/flow`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(flow)
  });
  return res.json();
}

export async function uploadThreatFile(file) {
  const formData = new FormData();
  formData.append("file", file);
  const res = await fetch(`${API_BASE}/api/detect/upload`, {
    method: "POST",
    body: formData
  });
  return res.json();
}

export async function fetchStreamEvent(sessionId = null) {
  const url = sessionId ? `${API_BASE}/api/detect/stream?session_id=${encodeURIComponent(sessionId)}` : `${API_BASE}/api/detect/stream`;
  const res = await fetch(url);
  return res.json();
}

export async function fetchLatestStream(sessionId = null) {
  return fetchStreamEvent(sessionId);
}

export async function fetchDetectionHistory(params = {}) {
  const query = new URLSearchParams(params).toString();
  const url = `${API_BASE}/api/history${query ? '?' + query : ''}`;
  const res = await fetch(url);
  return res.json();
}

export async function fetchCampaigns(params = {}) {
  const query = new URLSearchParams(params).toString();
  const url = `${API_BASE}/api/campaigns${query ? '?' + query : ''}`;
  const res = await fetch(url);
  return res.json();
}

export async function clearDetectionHistory() {
  const res = await fetch(`${API_BASE}/api/history`, { method: "DELETE" });
  return res.json();
}

export async function clearBatchSummary() {
  const res = await fetch(`${API_BASE}/api/batch/clear`, { method: "POST" });
  return res.json();
}

export async function updateEnsembleConfig(weights, threshold) {
  const res = await fetch(`${API_BASE}/api/ensemble/configure`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ weights, threshold })
  });
  return res.json();
}

export async function fetchAnomalyOverview() {
  const res = await fetch(`${API_BASE}/api/anomaly/overview`);
  return res.json();
}

export async function predictAnomaly(profile) {
  const res = await fetch(`${API_BASE}/api/models/predict/anomaly`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(profile)
  });
  return res.json();
}

export async function chatAssistant(query, context = null) {
  const res = await fetch(`${API_BASE}/api/assistant/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query, context })
  });
  return res.json();
}

export async function fetchSessions(params = {}) {
  const query = new URLSearchParams(params).toString();
  const url = `${API_BASE}/api/sessions${query ? '?' + query : ''}`;
  const res = await fetch(url);
  return res.json();
}

export async function fetchSessionsCount() {
  const res = await fetch(`${API_BASE}/api/sessions/count`);
  return res.json();
}

export async function fetchSessionReport(sessionId) {
  const res = await fetch(`${API_BASE}/api/sessions/${encodeURIComponent(sessionId)}`);
  return res.json();
}

export async function deleteSession(sessionId) {
  const res = await fetch(`${API_BASE}/api/sessions/${encodeURIComponent(sessionId)}`, {
    method: "DELETE"
  });
  return res.json();
}

export async function fetchSessionThreats(sessionId, params = {}) {
  const query = new URLSearchParams(params).toString();
  const url = `${API_BASE}/api/sessions/${encodeURIComponent(sessionId)}/threats${query ? '?' + query : ''}`;
  const res = await fetch(url);
  return res.json();
}

export async function fetchSessionAnomalies(sessionId, params = {}) {
  const query = new URLSearchParams(params).toString();
  const url = `${API_BASE}/api/sessions/${encodeURIComponent(sessionId)}/anomalies${query ? '?' + query : ''}`;
  const res = await fetch(url);
  return res.json();
}

export async function fetchSessionCampaigns(sessionId, params = {}) {
  const query = new URLSearchParams(params).toString();
  const url = `${API_BASE}/api/sessions/${encodeURIComponent(sessionId)}/campaigns${query ? '?' + query : ''}`;
  const res = await fetch(url);
  return res.json();
}
