#!/usr/bin/env python3
"""
NTRO IPsec Intelligence Platform - Main Service Launcher
Launches the FastAPI backend and Web Dashboard on http://127.0.0.1:8000
"""

import os
import sys
import uvicorn

# Ensure repository root is in sys.path
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from dashboard.app import app

if __name__ == "__main__":
    print("\n" + "="*70)
    print("      NATIONAL TECHNICAL RESEARCH ORGANISATION (NTRO) - CYBER DEFENSE")
    print("      IPsec VPN Protocol Analyzer & AI Intelligence Platform (SIH26160)")
    print("="*70)
    print("  [+] Service starting on: http://127.0.0.1:8000")
    print("  [+] Open the URL in your web browser (Chrome, Edge, Firefox, Brave)")
    print("  [+] Press CTRL+C to stop the service")
    print("="*70 + "\n")

    uvicorn.run(app, host="127.0.0.1", port=8000)
