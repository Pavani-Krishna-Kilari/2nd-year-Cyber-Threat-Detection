"""
FastAPI Server for AI-Based SIEM Cyber Threat Detection System.
Provides REST endpoints and serves the Vanilla JS/HTML/CSS frontend.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, File, UploadFile, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from src.config import PROJECT_ROOT
from backend.schemas import (
    ProfileInput,
    FlowInput,
    EnsembleConfigInput,
    SinglePredictionResponse,
    BatchPredictionResponse,
    AnomalyInput,
    AnomalyPredictionResponse,
    AssistantQueryInput,
    AssistantQueryResponse
)
from backend.aggregator import (
    AggregatorError,
    InsufficientTemporalSpanError,
    MissingFeatureColumnsError,
    InvalidTimestampError,
    InvalidBenchmarkAnnotationError
)
from backend.service import siem_service
from backend.auth import (
    LoginRequest,
    GoogleSSORequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    ContactAdminRequest,
    AuthResponse,
    authenticate_operator,
    authenticate_google_sso,
    get_current_user,
    revoke_session,
    request_password_recovery,
    reset_password_with_token,
    submit_access_clearance_request,
    extract_token_from_request,
    get_google_oauth_auth_url,
    IS_PRODUCTION
)

app = FastAPI(
    title="AI SIEM Threat Detection API",
    description="Full-stack AI-based SIEM system for cyber threat detection using Artificial Neural Networks based on Event Profiles",
    version="1.0.0"
)

# Enable CORS for external frontends or dev servers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = PROJECT_ROOT / "frontend"


# -----------------------------------------------------------------------------
# REST API Endpoints
# -----------------------------------------------------------------------------

@app.get("/api/status", summary="System Health & Subsystem Status")
def get_status() -> Dict[str, Any]:
    return siem_service.get_system_status()


@app.get("/api/dashboard/summary", summary="Current Analysis Session Telemetry Summary")
def get_dashboard_summary() -> Dict[str, Any]:
    """
    Returns actual detection counts from the latest user input analysis.
    Starts at 0 for all counters before user uploads or analyzes traffic.
    """
    return siem_service.get_dashboard_summary()


@app.get("/api/dataset/overview", summary="Dataset Inspection & Preprocessing Statistics (Historical)")
def get_dataset_overview() -> Dict[str, Any]:
    return siem_service.get_dataset_stats()


@app.get("/api/profiles/overview", summary="Event Profile & Basepoint Telemetry (Historical)")
def get_profiles_overview() -> Dict[str, Any]:
    return siem_service.get_profile_stats()


@app.get("/api/models/benchmarks", summary="Phase 4 Model Comparison & Evaluation Report")
def get_model_benchmarks() -> Dict[str, Any]:
    return siem_service.get_model_benchmarks()


@app.post("/api/models/predict/profile", response_model=SinglePredictionResponse, summary="Analyze Single Event Profile")
def predict_profile(payload: ProfileInput) -> SinglePredictionResponse:
    vec = [
        payload.bp_01, payload.bp_02, payload.bp_03, payload.bp_04,
        payload.bp_05, payload.bp_06, payload.bp_07, payload.bp_08
    ]
    res = siem_service.predict_single_profile(vec)
    return SinglePredictionResponse(**res)


@app.post("/api/models/predict/flow", response_model=SinglePredictionResponse, summary="Analyze Single Network Flow")
def predict_flow(payload: FlowInput) -> SinglePredictionResponse:
    res = siem_service.predict_single_flow(payload.model_dump())
    return SinglePredictionResponse(**res)


@app.post("/api/detect/upload", summary="Upload CSV, TXT, or PDF for Threat Triage")
@app.post("/api/analyze", summary="Alias: Upload Network Traffic for Threat Triage")
async def upload_file(file: UploadFile = File(...)) -> Dict[str, Any]:
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    
    try:
        result = siem_service.process_file_upload(contents, file.filename or "uploaded_file.csv")
        return result
    except (InsufficientTemporalSpanError, MissingFeatureColumnsError, InvalidTimestampError, InvalidBenchmarkAnnotationError, AggregatorError) as ae:
        raise HTTPException(
            status_code=422,
            detail={
                "error": ae.__class__.__name__,
                "message": str(ae),
                "details": getattr(ae, "details", {})
            }
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {str(e)}")


@app.get("/api/campaigns", summary="Retrieve Logical Security Campaigns from SQLite")
def get_campaigns_endpoint(
    limit: int = Query(50, ge=1, le=500),
    session_id: Optional[str] = Query(None)
) -> List[Dict[str, Any]]:
    return siem_service.get_campaigns(limit=limit, session_id=session_id)


@app.get("/api/detect/stream", summary="Real-Time Sliding Window Threat Stream from Latest Uploaded CSV")
@app.get("/api/detect/stream/latest", summary="Alias: Real-Time Sliding Window Threat Stream")
def get_stream_event(session_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    return siem_service.get_latest_stream(session_id=session_id)


@app.get("/api/detect/history", summary="Actual Detection History Records from SQLite")
@app.get("/api/history", summary="Alias: Detection History Records")
def get_history(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    verdict: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    session_id: Optional[str] = Query(None)
) -> List[Dict[str, Any]]:
    return siem_service.get_history(limit=limit, offset=offset, verdict=verdict, severity=severity, search=search, session_id=session_id)


# -----------------------------------------------------------------------------
# Persistent Classification Reports & Session Management Endpoints
# -----------------------------------------------------------------------------

@app.get("/api/sessions", summary="List Persistent Upload Sessions & Classification Reports")
def get_sessions_endpoint(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0)
) -> List[Dict[str, Any]]:
    return siem_service.get_sessions(limit=limit, offset=offset)


@app.get("/api/sessions/count", summary="Total Count of Recorded Upload Sessions")
def get_sessions_count_endpoint() -> Dict[str, int]:
    return {"count": siem_service.get_sessions_count()}


@app.get("/api/sessions/{session_id}", summary="Retrieve Complete Persistent Classification Report")
def get_session_report_endpoint(session_id: str) -> Dict[str, Any]:
    report = siem_service.get_session_report(session_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
    return report


@app.delete("/api/sessions/{session_id}", summary="Transactionally Delete Single Session Report and Records")
def delete_session_endpoint(session_id: str) -> Dict[str, Any]:
    deleted = siem_service.delete_session(session_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
    return {
        "status": "SUCCESS",
        "message": f"Classification report and history for session '{session_id}' permanently deleted.",
        "session_id": session_id
    }


@app.get("/api/sessions/{session_id}/threats", summary="Retrieve Known Threats for Session")
def get_session_threats_endpoint(
    session_id: str,
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0)
) -> List[Dict[str, Any]]:
    return siem_service.get_history(limit=limit, offset=offset, verdict="KNOWN_THREAT", session_id=session_id)


@app.get("/api/sessions/{session_id}/anomalies", summary="Retrieve Unknown Anomalies for Session")
def get_session_anomalies_endpoint(
    session_id: str,
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0)
) -> List[Dict[str, Any]]:
    return siem_service.get_history(limit=limit, offset=offset, verdict="UNKNOWN_ANOMALOUS", session_id=session_id)


@app.get("/api/sessions/{session_id}/campaigns", summary="Retrieve Logical Security Campaigns for Session")
def get_session_campaigns_endpoint(
    session_id: str,
    limit: int = Query(500, ge=1, le=2000)
) -> List[Dict[str, Any]]:
    return siem_service.get_campaigns(limit=limit, session_id=session_id)


@app.delete("/api/history", summary="Clear Detection History and Reset Current Session")
def clear_history() -> Dict[str, Any]:
    from backend.database import clear_all_history
    clear_all_history()
    siem_service.current_analysis_summary = None
    return {"status": "SUCCESS", "message": "Detection history cleared and session reset."}


@app.post("/api/batch/clear", summary="Clear Current Batch Summary and Restore Dashboard Empty State")
def clear_batch_summary() -> Dict[str, Any]:
    """Clears the active batch analysis summary without modifying detection history."""
    siem_service.clear_batch_summary()
    return {"status": "SUCCESS", "message": "Batch summary cleared. Dashboard restored to empty state."}


@app.post("/api/ensemble/configure", summary="Tune Soft-Voting Ensemble Weights & Threshold")
def configure_ensemble(payload: EnsembleConfigInput) -> Dict[str, Any]:
    return siem_service.update_ensemble_config(payload.weights, payload.threshold)


@app.get("/api/anomaly/overview", summary="Isolation Forest Anomaly Telemetry & Metrics")
def get_anomaly_overview() -> Dict[str, Any]:
    return siem_service.get_anomaly_overview()


@app.post("/api/models/predict/anomaly", response_model=AnomalyPredictionResponse, summary="Analyze Profile for Out-of-Distribution Anomalies")
def predict_anomaly(payload: AnomalyInput) -> AnomalyPredictionResponse:
    vec = [
        payload.bp_01, payload.bp_02, payload.bp_03, payload.bp_04,
        payload.bp_05, payload.bp_06, payload.bp_07, payload.bp_08
    ]
    res = siem_service.predict_anomaly(vec)
    return AnomalyPredictionResponse(**res)


@app.post("/api/assistant/chat", response_model=AssistantQueryResponse, summary="Interact with SOC AI Analyst Assistant")
def chat_assistant(payload: AssistantQueryInput) -> AssistantQueryResponse:
    res = siem_service.query_assistant(payload.query, payload.context)
    return AssistantQueryResponse(**res)


# -----------------------------------------------------------------------------
# SOC Authentication & Access Clearance Endpoints
# -----------------------------------------------------------------------------

@app.post("/api/auth/login", response_model=AuthResponse, summary="SOC Operator Authentication")
def login_endpoint(payload: LoginRequest, request: Request, response: Response):
    client_ip = request.client.host if request.client else "127.0.0.1"
    try:
        res = authenticate_operator(
            payload.email,
            payload.password,
            payload.remember_me,
            client_ip=client_ip
        )
        # Set secure HttpOnly, SameSite session cookie
        response.set_cookie(
            key="siem_session",
            value=res["session_token"],
            httponly=True,
            samesite="lax",
            secure=IS_PRODUCTION,
            max_age=res["validity_seconds"],
            path="/"
        )
        return AuthResponse(**res)
    except ValueError as ve:
        raise HTTPException(status_code=401, detail=str(ve))


@app.get("/api/auth/oauth/google/url", summary="Get Google Workspace OAuth 2.0 Auth URL & Status")
def google_oauth_url_endpoint():
    return get_google_oauth_auth_url()


@app.post("/api/auth/google", response_model=AuthResponse, summary="Google Workspace SSO Authentication")
def google_sso_endpoint(payload: GoogleSSORequest, response: Response):
    res = authenticate_google_sso(
        payload.requested_email or "analyst.google@soc-siem.cloud",
        code=payload.code,
        state=payload.state
    )
    # Set secure HttpOnly cookie
    response.set_cookie(
        key="siem_session",
        value=res["session_token"],
        httponly=True,
        samesite="lax",
        secure=IS_PRODUCTION,
        max_age=res["validity_seconds"],
        path="/"
    )
    return AuthResponse(**res)


@app.get("/api/auth/me", summary="Get Authenticated Operator Details")
def get_me_endpoint(request: Request, token: Optional[str] = Query(None)):
    active_token = extract_token_from_request(request, token)
    user = get_current_user(active_token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid token.")
    return {"status": "SUCCESS", "user": user}


@app.get("/api/dashboard/secure-session", summary="Verify Active Authenticated SOC Operator Session")
def verify_secure_session(request: Request, token: Optional[str] = Query(None)):
    """
    Protected dashboard route: validates the session token via HttpOnly cookie, header, or query.
    Returns operator telemetry clearance if valid; raises 401 Unauthorized if invalid or missing.
    """
    active_token = extract_token_from_request(request, token)
    if not active_token:
        raise HTTPException(
            status_code=401,
            detail="Access Denied: Authentication token required to access protected SOC telemetry."
        )
    user = get_current_user(active_token)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Access Denied: Invalid or expired SOC security clearance token."
        )
    return {
        "status": "AUTHENTICATED",
        "clearance": user.get("clearance", "Level 3"),
        "user": user
    }


@app.post("/api/auth/logout", summary="Logout Operator Session")
def logout_endpoint(request: Request, response: Response, token: Optional[str] = Query(None)):
    active_token = extract_token_from_request(request, token)
    revoke_session(active_token)
    response.delete_cookie(key="siem_session", path="/")
    return {"status": "SUCCESS", "message": "Session invalidated."}


@app.post("/api/auth/forgot-password", summary="Password Recovery Protocol")
def forgot_password_endpoint(payload: ForgotPasswordRequest):
    try:
        res = request_password_recovery(payload.email)
        return res
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@app.post("/api/auth/reset-password", summary="Consume One-Time Token to Reset Password")
def reset_password_endpoint(payload: ResetPasswordRequest):
    try:
        res = reset_password_with_token(payload.token, payload.new_password)
        return res
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@app.post("/api/auth/contact-admin", summary="Request SOC Access Clearance")
def contact_admin_endpoint(payload: ContactAdminRequest):
    try:
        res = submit_access_clearance_request(payload.name, payload.email, payload.clearance_level, payload.reason)
        return res
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


# -----------------------------------------------------------------------------
# Static Frontend Serving & Application Routing
# -----------------------------------------------------------------------------
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def serve_frontend_index():
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return {"message": "AI SIEM Backend is running. Frontend index.html not found."}

    @app.get("/login", include_in_schema=False)
    def serve_frontend_login():
        login_file = FRONTEND_DIR / "login.html"
        if login_file.exists():
            return FileResponse(login_file)
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return {"message": "AI SIEM Backend is running. Frontend login.html not found."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
