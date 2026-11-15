"""
SQLite Persistence Layer for AI-SIEM Threat Detection History and Analysis Sessions.

Provides lightweight, robust, zero-dependency persistence for actual inference records,
historical queries, filtering, and context retrieval for the AI Assistant.
"""

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional

from src.config import PROJECT_ROOT

DB_PATH = PROJECT_ROOT / "data" / "detection_history.db"


def get_connection() -> sqlite3.Connection:
    """Returns a thread-safe connection to the SQLite database."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes database tables if they do not already exist, with safe schema migrations."""
    conn = get_connection()
    try:
        with conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS analysis_sessions (
                session_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source_name TEXT NOT NULL,
                input_type TEXT NOT NULL,
                total_records INTEGER NOT NULL,
                normal_events INTEGER NOT NULL,
                threats_detected INTEGER NOT NULL,
                known_threats INTEGER NOT NULL DEFAULT 0,
                unknown_anomalous INTEGER NOT NULL DEFAULT 0,
                invalid_records INTEGER NOT NULL,
                threat_ratio REAL NOT NULL,
                attack_categories TEXT NOT NULL,
                severity_distribution TEXT NOT NULL,
                model_summary TEXT NOT NULL
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                id TEXT PRIMARY KEY,
                session_id TEXT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                input_type TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                destination_port INTEGER,
                protocol TEXT,
                verdict TEXT NOT NULL,
                prediction_status TEXT NOT NULL DEFAULT 'NORMAL',
                predicted_class TEXT NOT NULL DEFAULT 'Benign Network Traffic',
                confidence REAL NOT NULL DEFAULT 0.0,
                threat_confidence REAL NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                dominant_basepoint TEXT,
                dominant_similarity REAL,
                profile_vector TEXT,
                model_breakdown TEXT,
                anomaly_verdict TEXT,
                anomaly_status TEXT NOT NULL DEFAULT 'NORMAL',
                anomaly_score REAL,
                detection_reason TEXT NOT NULL DEFAULT '',
                requires_investigation INTEGER NOT NULL DEFAULT 0,
                flow_metadata TEXT,
                FOREIGN KEY(session_id) REFERENCES analysis_sessions(session_id)
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS campaigns (
                campaign_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                start_time TEXT,
                end_time TEXT,
                verdict TEXT NOT NULL,
                max_confidence REAL NOT NULL,
                window_count INTEGER NOT NULL,
                attributed_flow_count INTEGER NOT NULL,
                constituent_windows TEXT,
                PRIMARY KEY (session_id, campaign_id),
                FOREIGN KEY(session_id) REFERENCES analysis_sessions(session_id)
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                token TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                name TEXT NOT NULL,
                callsign TEXT NOT NULL,
                role TEXT NOT NULL,
                clearance TEXT NOT NULL,
                department TEXT NOT NULL,
                avatar TEXT NOT NULL,
                remember_me INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                auth_method TEXT NOT NULL
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS access_clearance_tickets (
                ticket_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                clearance_level TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS password_recovery_requests (
                token TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL DEFAULT '',
                used INTEGER NOT NULL DEFAULT 0
            );
            """)

            conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_verdict ON detections(verdict);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_session ON detections(session_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_campaigns_session ON campaigns(session_id);")

            # Safe schema migrations for existing databases
            existing_sess_cols = [c[1] for c in conn.execute("PRAGMA table_info(analysis_sessions);").fetchall()]
            if "known_threats" not in existing_sess_cols:
                conn.execute("ALTER TABLE analysis_sessions ADD COLUMN known_threats INTEGER NOT NULL DEFAULT 0;")
            if "unknown_anomalous" not in existing_sess_cols:
                conn.execute("ALTER TABLE analysis_sessions ADD COLUMN unknown_anomalous INTEGER NOT NULL DEFAULT 0;")
            if "report_data" not in existing_sess_cols:
                conn.execute("ALTER TABLE analysis_sessions ADD COLUMN report_data TEXT;")

            existing_det_cols = [c[1] for c in conn.execute("PRAGMA table_info(detections);").fetchall()]
            cols_to_add = [
                ("prediction_status", "TEXT NOT NULL DEFAULT 'NORMAL'"),
                ("predicted_class", "TEXT NOT NULL DEFAULT 'Benign Network Traffic'"),
                ("confidence", "REAL NOT NULL DEFAULT 0.0"),
                ("anomaly_status", "TEXT NOT NULL DEFAULT 'NORMAL'"),
                ("detection_reason", "TEXT NOT NULL DEFAULT ''"),
                ("requires_investigation", "INTEGER NOT NULL DEFAULT 0"),
                ("campaign_id", "TEXT NOT NULL DEFAULT '-'")
            ]
            for col_name, col_type in cols_to_add:
                if col_name not in existing_det_cols:
                    conn.execute(f"ALTER TABLE detections ADD COLUMN {col_name} {col_type};")

            existing_rec_cols = [c[1] for c in conn.execute("PRAGMA table_info(password_recovery_requests);").fetchall()]
            if "expires_at" not in existing_rec_cols:
                conn.execute("ALTER TABLE password_recovery_requests ADD COLUMN expires_at TEXT NOT NULL DEFAULT '';")
            if "used" not in existing_rec_cols:
                conn.execute("ALTER TABLE password_recovery_requests ADD COLUMN used INTEGER NOT NULL DEFAULT 0;")

            conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_status ON detections(prediction_status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_detections_campaign ON detections(campaign_id);")
    finally:
        conn.close()


def insert_session(session_data: Dict[str, Any]) -> str:
    """Persists an analysis session summary into the database."""
    init_db()
    session_id = session_data.get("session_id") or f"SESS-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    conn = get_connection()
    try:
        with conn:
            conn.execute("""
            INSERT OR REPLACE INTO analysis_sessions (
                session_id, timestamp, source_name, input_type,
                total_records, normal_events, threats_detected, known_threats, unknown_anomalous, invalid_records,
                threat_ratio, attack_categories, severity_distribution, model_summary, report_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                session_data.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S"),
                session_data.get("source_name", "Unknown Source"),
                session_data.get("input_type", "unknown"),
                int(session_data.get("total_records", 0)),
                int(session_data.get("normal_events", 0)),
                int(session_data.get("threats_detected", session_data.get("known_threats", 0))),
                int(session_data.get("known_threats", session_data.get("threats_detected", 0))),
                int(session_data.get("unknown_anomalous", 0)),
                int(session_data.get("invalid_records", 0)),
                float(session_data.get("threat_ratio", 0.0)),
                json.dumps(session_data.get("attack_categories", {})),
                json.dumps(session_data.get("severity_distribution", {})),
                json.dumps(session_data.get("model_summary", {})),
                json.dumps(session_data)
            ))
        return session_id
    finally:
        conn.close()


def insert_detections(records: List[Dict[str, Any]], session_id: Optional[str] = None):
    """Batch-persists individual detection inference records."""
    if not records:
        return
    init_db()
    conn = get_connection()
    try:
        with conn:
            for r in records:
                det_id = r.get("id") or f"DET-{time.strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
                verdict = r.get("verdict", "NORMAL")
                status = r.get("prediction_status", verdict)
                conn.execute("""
                INSERT OR REPLACE INTO detections (
                    id, session_id, timestamp, source, input_type,
                    source_ip, destination_ip, destination_port, protocol,
                    verdict, prediction_status, predicted_class, confidence,
                    threat_confidence, threat_type, severity,
                    dominant_basepoint, dominant_similarity, profile_vector,
                    model_breakdown, anomaly_verdict, anomaly_status, anomaly_score,
                    detection_reason, requires_investigation, flow_metadata, campaign_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    det_id,
                    session_id or r.get("session_id"),
                    r.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S"),
                    r.get("source", "Threat Analyzer"),
                    r.get("input_type", "flow"),
                    str(r.get("source_ip", "N/A")),
                    str(r.get("destination_ip", "N/A")),
                    int(r.get("destination_port", 0)),
                    str(r.get("protocol", "TCP")),
                    verdict,
                    status,
                    str(r.get("predicted_class", r.get("threat_type", "Benign Communication"))),
                    float(r.get("confidence", r.get("threat_confidence", 0.0))),
                    float(r.get("threat_confidence", 0.0)),
                    str(r.get("threat_type", r.get("predicted_class", "Benign Communication"))),
                    str(r.get("severity", "LOW")),
                    str(r.get("dominant_basepoint", "bp_01")),
                    float(r.get("dominant_similarity", 0.0)),
                    json.dumps(r.get("profile_vector", [])),
                    json.dumps(r.get("model_breakdown", {})),
                    str(r.get("anomaly_verdict", "NORMAL")),
                    str(r.get("anomaly_status", "NORMAL")),
                    float(r.get("anomaly_score", 0.0)),
                    str(r.get("detection_reason", "")),
                    1 if r.get("requires_investigation") else 0,
                    json.dumps(r.get("flow_metadata", {})),
                    str(r.get("campaign_id", "-"))
                ))
    finally:
        conn.close()


def get_latest_session() -> Optional[Dict[str, Any]]:
    """Retrieves the most recent analysis session from SQLite."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("""
        SELECT * FROM analysis_sessions ORDER BY timestamp DESC LIMIT 1
        """)
        row = cur.fetchone()
        if not row:
            return None
        keys = row.keys()
        return {
            "session_id": row["session_id"],
            "timestamp": row["timestamp"],
            "source_name": row["source_name"],
            "input_type": row["input_type"],
            "total_records": row["total_records"],
            "normal_events": row["normal_events"],
            "threats_detected": row["threats_detected"],
            "known_threats": row["known_threats"] if "known_threats" in keys else row["threats_detected"],
            "unknown_anomalous": row["unknown_anomalous"] if "unknown_anomalous" in keys else 0,
            "invalid_records": row["invalid_records"],
            "threat_ratio": row["threat_ratio"],
            "attack_categories": json.loads(row["attack_categories"]),
            "severity_distribution": json.loads(row["severity_distribution"]),
            "model_summary": json.loads(row["model_summary"])
        }
    finally:
        conn.close()


def get_detections(
    limit: int = 50,
    offset: int = 0,
    verdict: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    session_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Fetches paginated and filtered actual detection records."""
    init_db()
    conn = get_connection()
    try:
        query = "SELECT * FROM detections WHERE 1=1"
        params: List[Any] = []

        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)

        if verdict and verdict.upper() != "ALL":
            v_up = verdict.upper()
            if v_up == "THREAT":
                query += " AND (verdict = 'THREAT' OR verdict = 'KNOWN_THREAT' OR prediction_status = 'KNOWN_THREAT' OR verdict = 'UNKNOWN_ANOMALOUS' OR prediction_status = 'UNKNOWN_ANOMALOUS' OR requires_investigation = 1)"
            elif v_up in ["KNOWN_THREAT", "UNKNOWN_ANOMALOUS", "NORMAL"]:
                query += " AND (verdict = ? OR prediction_status = ?)"
                params.extend([v_up, v_up])
            else:
                query += " AND (verdict = ? OR prediction_status = ?)"
                params.extend([v_up, v_up])

        if severity and severity.upper() != "ALL":
            query += " AND severity = ?"
            params.append(severity.upper())

        if search and search.strip():
            term = f"%{search.strip().lower()}%"
            query += " AND (LOWER(source_ip) LIKE ? OR LOWER(destination_ip) LIKE ? OR LOWER(threat_type) LIKE ? OR LOWER(predicted_class) LIKE ?)"
            params.extend([term, term, term, term])

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur = conn.execute(query, params)
        rows = cur.fetchall()

        results = []
        for r in rows:
            keys = r.keys()
            camp_id = r["campaign_id"] if "campaign_id" in keys and r["campaign_id"] else "-"
            results.append({
                "id": r["id"],
                "session_id": r["session_id"],
                "campaign_id": camp_id,
                "timestamp": r["timestamp"],
                "source": r["source"],
                "input_type": r["input_type"],
                "source_ip": r["source_ip"],
                "destination_ip": r["destination_ip"],
                "destination_port": r["destination_port"],
                "protocol": r["protocol"],
                "verdict": r["verdict"],
                "prediction_status": r["prediction_status"] if "prediction_status" in keys else r["verdict"],
                "predicted_class": r["predicted_class"] if "predicted_class" in keys else r["threat_type"],
                "confidence": r["confidence"] if "confidence" in keys else r["threat_confidence"],
                "threat_confidence": r["threat_confidence"],
                "threat_type": r["threat_type"],
                "severity": r["severity"],
                "dominant_basepoint": r["dominant_basepoint"],
                "dominant_similarity": r["dominant_similarity"],
                "profile_vector": json.loads(r["profile_vector"]) if r["profile_vector"] else [],
                "model_breakdown": json.loads(r["model_breakdown"]) if r["model_breakdown"] else {},
                "anomaly_verdict": r["anomaly_verdict"],
                "anomaly_status": r["anomaly_status"] if "anomaly_status" in keys else r.get("anomaly_verdict", "NORMAL"),
                "anomaly_score": r["anomaly_score"],
                "detection_reason": r["detection_reason"] if "detection_reason" in keys else "",
                "requires_investigation": bool(r["requires_investigation"]) if "requires_investigation" in keys else (r["verdict"] in ["THREAT", "KNOWN_THREAT", "UNKNOWN_ANOMALOUS"])
            })
        return results
    finally:
        conn.close()


def get_detections_count(
    verdict: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    session_id: Optional[str] = None
) -> int:
    """Returns the total number of detections matching filters."""
    init_db()
    conn = get_connection()
    try:
        query = "SELECT COUNT(*) FROM detections WHERE 1=1"
        params: List[Any] = []

        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)

        if verdict and verdict.upper() != "ALL":
            v_up = verdict.upper()
            if v_up == "THREAT":
                query += " AND (verdict = 'THREAT' OR verdict = 'KNOWN_THREAT' OR prediction_status = 'KNOWN_THREAT' OR verdict = 'UNKNOWN_ANOMALOUS' OR prediction_status = 'UNKNOWN_ANOMALOUS' OR requires_investigation = 1)"
            elif v_up in ["KNOWN_THREAT", "UNKNOWN_ANOMALOUS", "NORMAL"]:
                query += " AND (verdict = ? OR prediction_status = ?)"
                params.extend([v_up, v_up])
            else:
                query += " AND (verdict = ? OR prediction_status = ?)"
                params.extend([v_up, v_up])

        if severity and severity.upper() != "ALL":
            query += " AND severity = ?"
            params.append(severity.upper())

        if search and search.strip():
            term = f"%{search.strip().lower()}%"
            query += " AND (LOWER(source_ip) LIKE ? OR LOWER(destination_ip) LIKE ? OR LOWER(threat_type) LIKE ? OR LOWER(predicted_class) LIKE ?)"
            params.extend([term, term, term, term])

        cur = conn.execute(query, params)
        return int(cur.fetchone()[0])
    finally:
        conn.close()


def get_recent_threats(limit: int = 5, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves the most recent actual threat detections."""
    return get_detections(limit=limit, verdict="THREAT", session_id=session_id)


def get_recent_unknown_anomalous(limit: int = 5, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves the most recent unknown / anomalous detections."""
    return get_detections(limit=limit, verdict="UNKNOWN_ANOMALOUS", session_id=session_id)


def get_session_stream(session_id: str) -> List[Dict[str, Any]]:
    """
    Retrieves all sliding-window detection records for a specific upload session ordered
    chronologically (by rowid ASC) for sliding-window stream display and telemetry analysis.
    """
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("""
            SELECT id, session_id, timestamp, source, input_type,
                   source_ip, destination_ip, destination_port, protocol,
                   verdict, prediction_status, predicted_class,
                   confidence, threat_confidence, threat_type, severity,
                   dominant_basepoint, dominant_similarity,
                   anomaly_verdict, anomaly_status, anomaly_score,
                   detection_reason, requires_investigation,
                   flow_metadata, campaign_id
            FROM detections
            WHERE session_id = ?
            ORDER BY rowid ASC
        """, (session_id,))
        rows = cur.fetchall()
        stream = []
        for r in rows:
            meta = {}
            if r["flow_metadata"]:
                try:
                    meta = json.loads(r["flow_metadata"])
                except Exception:
                    meta = {}

            window_id = meta.get("window_id") or r["id"]
            event_set_id = meta.get("event_set_id") or "-"
            n_flows = meta.get("n_flows", 1)
            window_start = meta.get("window_start") or r["timestamp"]
            window_end = meta.get("window_end") or r["timestamp"]

            camp_id = r["campaign_id"] if (r["campaign_id"] and r["campaign_id"] != "-") else "-"

            verdict = r["verdict"]
            status = r["prediction_status"] or verdict
            conf = float(r["threat_confidence"] if r["threat_confidence"] is not None else r["confidence"])

            stream.append({
                "id": r["id"],
                "session_id": r["session_id"],
                "timestamp": window_start,
                "window_time": window_start,
                "window_start": window_start,
                "window_end": window_end,
                "window_id": str(window_id),
                "event_set_id": str(event_set_id),
                "n_flows": int(n_flows),
                "source_ip": r["source_ip"] or "N/A",
                "destination_ip": r["destination_ip"] or "N/A",
                "destination_port": int(r["destination_port"] or 0),
                "protocol": r["protocol"] or "TCP",
                "verdict": verdict,
                "prediction_status": status,
                "predicted_class": r["predicted_class"],
                "threat_type": r["threat_type"],
                "confidence": conf,
                "threat_confidence": conf,
                "severity": r["severity"],
                "campaign_id": camp_id,
                "dominant_basepoint": r["dominant_basepoint"] or "bp_01",
                "dominant_similarity": float(r["dominant_similarity"] or 0.0),
                "anomaly_verdict": r["anomaly_verdict"] or "NORMAL",
                "anomaly_status": r["anomaly_status"] or "NORMAL",
                "anomaly_score": float(r["anomaly_score"] or 0.0),
                "detection_reason": r["detection_reason"] or "",
                "requires_investigation": bool(r["requires_investigation"])
            })
        return stream
    finally:
        conn.close()


def insert_campaigns(campaigns: List[Dict[str, Any]], session_id: str):
    """Batch-persists logical security campaigns into SQLite."""
    if not campaigns:
        return
    init_db()
    conn = get_connection()
    try:
        with conn:
            for c in campaigns:
                conn.execute("""
                INSERT OR REPLACE INTO campaigns (
                    campaign_id, session_id, source_ip, destination_ip,
                    start_time, end_time, verdict, max_confidence,
                    window_count, attributed_flow_count, constituent_windows
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    c["campaign_id"],
                    session_id,
                    str(c.get("source_ip", "")),
                    str(c.get("destination_ip", "")),
                    str(c.get("start_time", "")),
                    str(c.get("end_time", "")),
                    c.get("verdict", "UNKNOWN_ANOMALOUS"),
                    float(c.get("max_confidence", 0.0)),
                    int(c.get("window_count", 1)),
                    int(c.get("attributed_flow_count", 0)),
                    json.dumps(c.get("constituent_windows", []))
                ))
    finally:
        conn.close()


def get_campaigns(limit: int = 50, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves security campaigns, optionally filtered by session_id."""
    init_db()
    conn = get_connection()
    try:
        query = "SELECT * FROM campaigns WHERE 1=1"
        params: List[Any] = []
        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        query += " ORDER BY start_time DESC LIMIT ?"
        params.append(limit)
        cur = conn.execute(query, params)
        rows = cur.fetchall()
        out = []
        for r in rows:
            out.append({
                "campaign_id": r["campaign_id"],
                "session_id": r["session_id"],
                "source_ip": r["source_ip"],
                "destination_ip": r["destination_ip"],
                "start_time": r["start_time"],
                "end_time": r["end_time"],
                "verdict": r["verdict"],
                "max_confidence": r["max_confidence"],
                "window_count": r["window_count"],
                "attributed_flow_count": r["attributed_flow_count"],
                "constituent_windows": json.loads(r["constituent_windows"]) if r["constituent_windows"] else []
            })
        return out
    finally:
        conn.close()


def get_sessions(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """Retrieves paginated analysis sessions sorted chronologically descending."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("""
            SELECT session_id, timestamp, source_name, input_type,
                   total_records, normal_events, threats_detected,
                   known_threats, unknown_anomalous, invalid_records,
                   threat_ratio, attack_categories, severity_distribution, model_summary
            FROM analysis_sessions
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        rows = cur.fetchall()
        out = []
        for r in rows:
            keys = r.keys()
            sid = r["session_id"]

            camp_cur = conn.execute("SELECT COUNT(*) FROM campaigns WHERE session_id = ?", (sid,))
            camp_count = int(camp_cur.fetchone()[0])

            det_cur = conn.execute("SELECT COUNT(*) FROM detections WHERE session_id = ?", (sid,))
            det_count = int(det_cur.fetchone()[0])

            out.append({
                "session_id": sid,
                "timestamp": r["timestamp"],
                "filename": r["source_name"],
                "source_name": r["source_name"],
                "input_type": r["input_type"],
                "total_records": r["total_records"],
                "uploaded_flows": r["total_records"],
                "event_sets": det_count if det_count > 0 else r["total_records"],
                "normal_events": r["normal_events"],
                "known_threats": r["known_threats"] if "known_threats" in keys else r["threats_detected"],
                "unknown_anomalous": r["unknown_anomalous"] if "unknown_anomalous" in keys else 0,
                "threats_detected": r["threats_detected"],
                "campaigns_count": camp_count,
                "status": "Completed"
            })
        return out
    finally:
        conn.close()


def get_sessions_count() -> int:
    """Returns the total number of recorded analysis sessions."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("SELECT COUNT(*) FROM analysis_sessions")
        return int(cur.fetchone()[0])
    finally:
        conn.close()


def get_session_by_id(session_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single analysis session summary by its ID."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("""
            SELECT * FROM analysis_sessions WHERE session_id = ?
        """, (session_id,))
        row = cur.fetchone()
        if not row:
            return None
        keys = row.keys()
        return {
            "session_id": row["session_id"],
            "timestamp": row["timestamp"],
            "source_name": row["source_name"],
            "filename": row["source_name"],
            "input_type": row["input_type"],
            "total_records": row["total_records"],
            "normal_events": row["normal_events"],
            "threats_detected": row["threats_detected"],
            "known_threats": row["known_threats"] if "known_threats" in keys else row["threats_detected"],
            "unknown_anomalous": row["unknown_anomalous"] if "unknown_anomalous" in keys else 0,
            "invalid_records": row["invalid_records"],
            "threat_ratio": row["threat_ratio"],
            "attack_categories": json.loads(row["attack_categories"]) if row["attack_categories"] else {},
            "severity_distribution": json.loads(row["severity_distribution"]) if row["severity_distribution"] else {},
            "model_summary": json.loads(row["model_summary"]) if row["model_summary"] else {},
            "status": "Completed"
        }
    finally:
        conn.close()


def get_session_report(session_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves the complete, immutable persistent classification report for a session.
    If report_data is cached, loads and enriches it; otherwise synthesizes the report
    from session columns, actual detections, and campaigns.
    """
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM analysis_sessions WHERE session_id = ?", (session_id,))
        row = cur.fetchone()
        if not row:
            return None
        keys = row.keys()

        report: Dict[str, Any] = {}
        if "report_data" in keys and row["report_data"]:
            try:
                report = json.loads(row["report_data"])
            except Exception:
                report = {}

        report["session_id"] = row["session_id"]
        report["filename"] = report.get("filename") or row["source_name"]
        report["source_name"] = report.get("source_name") or row["source_name"]
        report["input_type"] = report.get("input_type") or row["input_type"]
        report["timestamp"] = report.get("timestamp") or row["timestamp"]
        report["status"] = "Completed"
        report["has_data"] = True

        report["total_records"] = report.get("total_records") or row["total_records"]
        report["normal_events"] = report.get("normal_events") or row["normal_events"]
        report["threats_detected"] = report.get("threats_detected") or row["threats_detected"]
        report["known_threats"] = report.get("known_threats", row["known_threats"] if "known_threats" in keys else row["threats_detected"])
        report["unknown_anomalous"] = report.get("unknown_anomalous", row["unknown_anomalous"] if "unknown_anomalous" in keys else 0)
        report["invalid_records"] = report.get("invalid_records") or row["invalid_records"]
        report["threat_ratio"] = report.get("threat_ratio", row["threat_ratio"])

        if "attack_categories" not in report or not report["attack_categories"]:
            report["attack_categories"] = json.loads(row["attack_categories"]) if row["attack_categories"] else {}
        if "severity_distribution" not in report or not report["severity_distribution"]:
            report["severity_distribution"] = json.loads(row["severity_distribution"]) if row["severity_distribution"] else {}
        if "model_summary" not in report or not report["model_summary"]:
            report["model_summary"] = json.loads(row["model_summary"]) if row["model_summary"] else {}

        # Enrich campaigns, known_threats_list, and unknown_anomalies_list
        if not report.get("campaigns"):
            report["campaigns"] = get_campaigns(session_id=session_id, limit=500)
        if not report.get("known_threats_list"):
            report["known_threats_list"] = get_detections(session_id=session_id, verdict="KNOWN_THREAT", limit=1000)
        if not report.get("unknown_anomalies_list"):
            report["unknown_anomalies_list"] = get_detections(session_id=session_id, verdict="UNKNOWN_ANOMALOUS", limit=1000)

        # Ensure structured statistics
        if not report.get("flow_statistics"):
            report["flow_statistics"] = {
                "total_raw_flows": report["total_records"],
                "unique_flows_analysed": report["total_records"],
                "benign_flows": report["normal_events"],
                "known_threat_flows": report["known_threats"],
                "unknown_anomalous_flows": report["unknown_anomalous"],
                "invalid_flows": report["invalid_records"]
            }
        if not report.get("event_set_statistics"):
            det_count = len(report.get("known_threats_list", [])) + len(report.get("unknown_anomalies_list", [])) + report["normal_events"]
            report["event_set_statistics"] = {
                "total_event_sets": det_count if det_count > 0 else report["total_records"],
                "normal_event_sets": report["normal_events"],
                "ann_alert_sets": report["known_threats"],
                "unknown_anomalous_sets": report["unknown_anomalous"]
            }
        if not report.get("campaign_statistics"):
            camps = report.get("campaigns", [])
            report["campaign_statistics"] = {
                "total_campaigns": len(camps),
                "known_threat_campaigns": sum(1 for c in camps if c.get("verdict") == "KNOWN_THREAT"),
                "unknown_anomalous_campaigns": sum(1 for c in camps if c.get("verdict") == "UNKNOWN_ANOMALOUS")
            }

        return report
    finally:
        conn.close()


def delete_session(session_id: str) -> bool:
    """
    Transactionally deletes a single session and its associated detections and campaigns.
    Does NOT affect any other sessions or call clear_all_history().
    Returns True if the session existed and was deleted, False if not found.
    """
    init_db()
    conn = get_connection()
    try:
        with conn:
            cur = conn.execute("SELECT session_id FROM analysis_sessions WHERE session_id = ?", (session_id,))
            if not cur.fetchone():
                return False

            conn.execute("DELETE FROM detections WHERE session_id = ?", (session_id,))
            conn.execute("DELETE FROM campaigns WHERE session_id = ?", (session_id,))
            conn.execute("DELETE FROM analysis_sessions WHERE session_id = ?", (session_id,))
            return True
    finally:
        conn.close()


def clear_all_history():
    """Wipes all sessions, campaigns, and detection records for a clean test state."""
    init_db()
    conn = get_connection()
    try:
        with conn:
            conn.execute("DELETE FROM detections;")
            conn.execute("DELETE FROM campaigns;")
            conn.execute("DELETE FROM analysis_sessions;")
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# User Sessions & Access Control Persistence
# -----------------------------------------------------------------------------

def save_user_session(session_dict: Dict[str, Any]):
    """Persists an active authenticated user session into SQLite."""
    init_db()
    conn = get_connection()
    try:
        with conn:
            conn.execute("""
            INSERT OR REPLACE INTO user_sessions (
                token, email, name, callsign, role, clearance,
                department, avatar, remember_me, created_at, expires_at, auth_method
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_dict["token"],
                session_dict["email"],
                session_dict.get("name", "SOC Operator"),
                session_dict.get("callsign", "Sentinel"),
                session_dict.get("role", "Security Analyst"),
                session_dict.get("clearance", "Level 3"),
                session_dict.get("department", "SOC"),
                session_dict.get("avatar", "SO"),
                1 if session_dict.get("remember_me") else 0,
                session_dict["created_at"],
                session_dict["expires_at"],
                session_dict.get("auth_method", "SOC_CREDENTIALS")
            ))
    finally:
        conn.close()


def get_user_session(token: str) -> Optional[Dict[str, Any]]:
    """Retrieves an active user session by token from SQLite."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM user_sessions WHERE token = ?", (token,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            "token": row["token"],
            "email": row["email"],
            "name": row["name"],
            "callsign": row["callsign"],
            "role": row["role"],
            "clearance": row["clearance"],
            "department": row["department"],
            "avatar": row["avatar"],
            "remember_me": bool(row["remember_me"]),
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "auth_method": row["auth_method"]
        }
    finally:
        conn.close()


def delete_user_session(token: str) -> bool:
    """Deletes and revokes a user session token from SQLite."""
    init_db()
    conn = get_connection()
    try:
        with conn:
            cur = conn.execute("DELETE FROM user_sessions WHERE token = ?", (token,))
            return cur.rowcount > 0
    finally:
        conn.close()


def save_clearance_ticket(ticket_dict: Dict[str, Any]):
    """Persists an access clearance ticket into SQLite."""
    init_db()
    conn = get_connection()
    try:
        with conn:
            conn.execute("""
            INSERT OR REPLACE INTO access_clearance_tickets (
                ticket_id, name, email, clearance_level, reason, status, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                ticket_dict["ticket_id"],
                ticket_dict["name"],
                ticket_dict["email"],
                ticket_dict["clearance_level"],
                ticket_dict["reason"],
                ticket_dict["status"],
                ticket_dict["timestamp"]
            ))
    finally:
        conn.close()


def save_recovery_token(token: str, email: str, created_at: str, expires_at: str = ""):
    """Persists a password recovery token into SQLite with expiry tracking."""
    init_db()
    conn = get_connection()
    try:
        with conn:
            conn.execute("""
            INSERT OR REPLACE INTO password_recovery_requests (
                token, email, created_at, expires_at, used
            ) VALUES (?, ?, ?, ?, 0)
            """, (token, email, created_at, expires_at))
    finally:
        conn.close()


def get_recovery_token(token: str) -> Optional[Dict[str, Any]]:
    """Retrieves a recovery token record from SQLite."""
    init_db()
    conn = get_connection()
    try:
        cur = conn.execute("SELECT * FROM password_recovery_requests WHERE token = ?", (token,))
        row = cur.fetchone()
        if not row:
            return None
        return {
            "token": row["token"],
            "email": row["email"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"] if "expires_at" in row.keys() else "",
            "used": bool(row["used"]) if "used" in row.keys() else False
        }
    finally:
        conn.close()


def mark_recovery_token_used(token: str) -> bool:
    """Marks a recovery token as consumed in SQLite (single-use enforcement)."""
    init_db()
    conn = get_connection()
    try:
        with conn:
            cur = conn.execute("UPDATE password_recovery_requests SET used = 1 WHERE token = ?", (token,))
            return cur.rowcount > 0
    finally:
        conn.close()
