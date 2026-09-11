# SIH26 — IPsec VPN Analyzer Dashboard

A real integration-ready security dashboard: React/Vite frontend + FastAPI backend + WebSocket live telemetry + adapter boundaries for Asim and Sermistha.

The implementation follows the requested architecture and data-driven approach: the frontend consumes a standardized backend contract rather than internal feature-extractor/security-engine schemas. fileciteturn0file0L219-L239

## Architecture

```text
Asim Feature Extractor ──> AsimAdapter ─┐
                                       ├─> Standardized contract ─> FastAPI ─> React
Sermistha Security Engine -> SermisthaAdapter ─┘                         │
                                                                         └─ WebSocket
MockDataProvider (development/demo) ─────────────────────────────────────┘
```

The adapter boundaries intentionally do not guess either teammate's final schema, matching the requirement to swap real data in without rewriting the frontend. fileciteturn0file0L781-L827

## Project structure

```text
ipsec-vpn-dashboard/
├── backend/
│   ├── app/
│   │   ├── api/routes/       # REST routes
│   │   ├── integrations/     # mock + Asim/Sermistha adapters
│   │   ├── schemas/          # standardized Pydantic contract
│   │   ├── services/
│   │   └── main.py
│   ├── tests/
│   └── requirements.txt
├── frontend/
│   ├── src/components/
│   ├── src/hooks/
│   ├── src/pages/
│   ├── src/services/
│   ├── src/styles/
│   └── package.json
└── README.md
```

## Run locally

### Backend

```bash
cd backend
python -m venv .venv
# Windows PowerShell
.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
copy .env.example .env   # Windows
npm run dev
```

Open `http://localhost:5173`.

The requested local split is frontend `5173` and backend `8000`; CORS is restricted to `http://localhost:5173` by default. fileciteturn0file0L871-L885

## Environment

Frontend `.env`:

```text
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000/ws/dashboard
VITE_DATA_MODE=MOCK
```

The API and WebSocket URLs are environment-driven rather than hard-coded in components. fileciteturn0file0L891-L907

Backend:

```text
CORS_ORIGINS=http://localhost:5173
```

## Mock mode

The backend starts with `MockDataProvider`. It continuously produces realistic telemetry, packet-rate fluctuations, traffic bursts, risk changes, anomalies and event-feed entries. This is specifically intended to make the demo work before Asim and Sermistha are integrated. fileciteturn0file0L389-L449

The WebSocket sends a fresh complete dashboard state every 2 seconds. The frontend reconnects automatically with exponential backoff and changes its live status to `RECONNECTING` when the socket drops. This fulfills the requested real-time behavior and failure handling. fileciteturn0file0L453-L501 fileciteturn0file0L1002-L1027

## REST API

- `GET /api/health`
- `GET /api/vpn/status`
- `GET /api/metrics/current`
- `GET /api/metrics/history`
- `GET /api/security/current`
- `GET /api/security/history`
- `GET /api/events`
- `GET /api/dashboard`

`GET /api/dashboard` is the primary aggregation endpoint and returns VPN, metrics, security, events, history, timestamp and current mode. The standardized contract is defined in `backend/app/schemas/dashboard.py`, following the requested contract shape. fileciteturn0file0L281-L333 fileciteturn0file0L831-L865

## WebSocket

`ws://localhost:8000/ws/dashboard`

Example payload shape:

```json
{
  "timestamp": "2026-09-09T12:00:00Z",
  "vpn": {"status":"CONNECTED"},
  "metrics": {"packets_per_second":842},
  "security": {"risk_score":22,"risk_level":"LOW","anomaly_detected":false},
  "events": [],
  "history": [],
  "mode":"MOCK"
}
```

## Real integration mode

Do **not** change React components when teammate schemas arrive.

1. Implement `AsimAdapter.adapt()` using Asim's actual final feature schema.
2. Implement `SermisthaAdapter.adapt()` using Sermistha's actual security-result schema.
3. Make `DashboardService` source those adapters instead of `MockDataProvider`.
4. Return the same Pydantic standardized contract.
5. Keep `/api/dashboard` and `/ws/dashboard` stable.

This preserves the central requirement that the frontend should not need to be rewritten when the complete pipeline is integrated. fileciteturn0file0L1092-L1107

## Testing

Backend tests cover health, dashboard contract, metrics and security endpoints:

```bash
cd backend
pytest
```

The frontend is validated by the production Vite build:

```bash
cd frontend
npm run build
```

## Design notes

The UI uses an original Apple-inspired visual language rather than copying Apple's page design: system typography, generous spacing, restrained glass surfaces, subtle borders, soft depth, responsive layouts and minimal motion. It follows the requested premium/security-product direction. fileciteturn0file0L61-L80 fileciteturn0file0L86-L119
