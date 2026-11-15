"""
Convenience launcher for the AI SIEM Full-Stack Web Application.

Run from PowerShell:
    python run_server.py

Then open your browser at:
    http://127.0.0.1:8000
"""

import sys
import uvicorn

if __name__ == "__main__":
    print("=" * 70)
    print(" AI SIEM System for Cyber Threat Detection (ANN Event Profiles)")
    print("=" * 70)
    print(" * Backend:  FastAPI on http://127.0.0.1:8000/api")
    print(" * Frontend: Modern Cyber SOC Dashboard on http://127.0.0.1:8000")
    print(" * API Docs: Interactive Swagger UI on http://127.0.0.1:8000/docs")
    print("=" * 70)
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=False)
