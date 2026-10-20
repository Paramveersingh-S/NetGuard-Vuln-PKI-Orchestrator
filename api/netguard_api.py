"""FastAPI microservice exposing PCAP alerts, Nmap SME vulnerability tickets, and X.509 PKI audit results."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI


ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title="NetGuard Security Engineering API", version="2.0.0")


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": "NetGuard-Vuln-PKI-Orchestrator"}


@app.get("/api/v1/audit-summary")
def audit_summary() -> dict:
    p = ROOT / "reports" / "netguard_full_audit.json"
    if not p.exists():
        return {"status": "no_audit_run_yet"}
    return json.loads(p.read_text(encoding="utf-8"))
