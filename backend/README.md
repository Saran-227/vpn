# Backend

FastAPI integration layer for the SIH26 IPsec VPN Analyzer. The standardized contract lives in `app/schemas/dashboard.py`.

## Run
```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

REST: `GET /api/health`, `/api/vpn/status`, `/api/metrics/current`, `/api/metrics/history`, `/api/security/current`, `/api/security/history`, `/api/events`, `/api/dashboard`.

WebSocket: `/ws/dashboard` sends a complete dashboard snapshot every 2 seconds in mock mode.

Set `CORS_ORIGINS` to a comma-separated list of allowed frontend origins. The default is `http://localhost:5173`.
