#!/usr/bin/env python3
"""
SIH26160 IPsec VPN Intelligence Platform - FastAPI Backend
Provides REST endpoints for deterministic IKE auditing, AI encrypted traffic classification,
tournament leaderboard metrics, and live PCAP analysis.
"""

import os
import sys
import json
import glob
import shutil
import tempfile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from analyzer.security_evaluator import NISTSecurityEvaluator

app = FastAPI(
    title="NTRO IPsec Intelligence & Security Assessment Platform",
    description="SIH26160 Automated Cryptographic Audit & AI Encrypted Traffic Classifier",
    version="2.0.0"
)

STATIC_DIR = os.path.join(BASE_DIR, "static")
DATASET_DIR = os.path.join(PROJECT_ROOT, "dataset", "raw_pcapng")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")

evaluator = NISTSecurityEvaluator()

# Mount static files
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Dashboard index.html not found</h1>"


@app.get("/api/health")
async def health_check():
    leaderboard_file = os.path.join(MODELS_DIR, "tournament_leaderboard.json")
    champ = "HistGradientBoosting (80.50%)"
    if os.path.exists(leaderboard_file):
        try:
            with open(leaderboard_file, "r") as f:
                d = json.load(f)
                champ = f"{d.get('champion')} ({d.get('test_accuracy')*100:.1f}%)"
        except Exception:
            pass

    return {
        "status": "ONLINE",
        "system": "NTRO IPsec VPN Protocol Analyzer (SIH26160)",
        "offline_mode": True,
        "air_gapped": True,
        "active_traffic_model": champ,
        "active_mode_model": "Extra Trees (95.44%)",
        "dataset_samples_available": len(glob.glob(os.path.join(DATASET_DIR, "*.pcapng")))
    }


@app.get("/api/samples")
async def list_sample_pcaps():
    """
    Returns a curated list of sample captures covering all key scenarios.
    """
    curated = [
        {
            "id": "golden_audit",
            "title": "Golden IKEv2 VoIP (NIST SP 800-77 Full Audit)",
            "description": "AES-256-GCM, PRF_HMAC_SHA2_256, DH Group 19 (ECP-256), 557 packets, RFC 4303 verified.",
            "expected_verdict": "PASS [LOW RISK] (Score: 100/100)",
            "expected_app": "VOIP (100.0%)",
            "tag": "GOLDEN",
            "pcap": "sih26_asim_golden.pcap"
        },
        {
            "id": "secure_voip",
            "title": "Secure IKEv2 VoIP (Transport Mode)",
            "description": "AES-CBC-128, HMAC-SHA256, Diffie-Hellman Group 14. Clean NIST SP 800-77 Compliant.",
            "expected_verdict": "PASS [LOW RISK] (Score: 90/100)",
            "expected_app": "VOIP (99.8%)",
            "tag": "SECURE",
            "pcap": "exp_002_voip_transport_aes_gcm_16_128_1789042405.pcapng"
        },
        {
            "id": "vulnerable_3des",
            "title": "Vulnerable Legacy IKEv1 3DES (Sweet32 Vulnerable)",
            "description": "3DES-CBC, SHA-1, DH Group 2. Deprecated IKEv1. Active exploit risk.",
            "expected_verdict": "FAIL [CRITICAL RISK] (Score: 0/100)",
            "expected_app": "VOIP (99.8%)",
            "tag": "CRITICAL_FAIL",
            "pcap": "exp_005_voip_tunnel_3des_cbc_1789042535.pcapng"
        },
        {
            "id": "midstream_wiretap",
            "title": "Mid-Stream ESP Wiretap (Missing Handshake)",
            "description": "Wiretap attached after key exchange. ESP-only encapsulation with no IKE packets.",
            "expected_verdict": "UNVERIFIED_HANDSHAKE (Score: 50/100)",
            "expected_app": "VOIP (99.9%)",
            "tag": "WIRETAP",
            "pcap": "exp_001_voip_tunnel_aes_gcm_16_256_1789042363.pcapng"
        },
        {
            "id": "concurrent_mixed",
            "title": "Concurrent Multiplexed Flow (Chat + ICMP)",
            "description": "Interleaved concurrent multi-application streams within a single encrypted tunnel.",
            "expected_verdict": "PASS (Score: 100/100)",
            "expected_app": "MIXED (Multi-App De-muxing)",
            "tag": "CONCURRENT",
            "pcap": "exp_106_mixed_tunnel_aes_gcm_16_256_1789046857.pcapng"
        },
        {
            "id": "video_stream",
            "title": "High-Throughput Video Streaming",
            "description": "Variable frame bursts with MTU-saturating encrypted ESP payloads.",
            "expected_verdict": "PASS (Score: 100/100)",
            "expected_app": "VIDEO (99.9%)",
            "tag": "HIGH_BW",
            "pcap": "exp_016_video_tunnel_aes_gcm_16_256_1789043005.pcapng"
        },
        {
            "id": "web_browsing",
            "title": "Interactive Web Browsing",
            "description": "Bursty HTTP/1.1 transactions with variable asset sizes and idle dwell periods.",
            "expected_verdict": "PASS (Score: 100/100)",
            "expected_app": "WEB (100.0%)",
            "tag": "BURSTY",
            "pcap": "exp_031_web_tunnel_aes_gcm_16_256_1789043654.pcapng"
        }
    ]
    return curated


class SampleRequest(BaseModel):
    pcap_filename: str


@app.post("/api/analyze/sample")
async def analyze_sample(req: SampleRequest):
    pcap_path = os.path.join(DATASET_DIR, req.pcap_filename)
    if not os.path.exists(pcap_path):
        # Check if relative path provided
        if os.path.exists(req.pcap_filename):
            pcap_path = req.pcap_filename
        else:
            raise HTTPException(status_code=404, detail=f"Sample file {req.pcap_filename} not found")

    try:
        report = evaluator.evaluate_pcap(pcap_path, models_dir=MODELS_DIR)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/api/analyze/upload")
async def analyze_upload(file: UploadFile = File(...)):
    """
    Accepts arbitrary .pcap or .pcapng file uploads from the analyst.
    """
    if not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are supported")

    temp_fd, temp_path = tempfile.mkstemp(suffix=os.path.splitext(file.filename)[1])
    try:
        with os.fdopen(temp_fd, "wb") as f:
            shutil.copyfileobj(file.file, f)

        report = evaluator.evaluate_pcap(temp_path, models_dir=MODELS_DIR)
        report["pcap_file"] = file.filename
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


@app.get("/api/tournament")
async def get_tournament_leaderboard():
    board_file = os.path.join(MODELS_DIR, "tournament_leaderboard.json")
    if not os.path.exists(board_file):
        raise HTTPException(status_code=404, detail="Leaderboard not found")
    with open(board_file, "r") as f:
        return json.load(f)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

