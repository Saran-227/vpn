# SIH26 — IPsec VPN Analyzer Dashboard

A standalone React/Vite security dashboard for IPsec VPN tunnel monitoring.
Runs entirely in the browser with hardcoded demo data — no backend required.

## Architecture

```text
src/data/mockData.js  (hardcoded demo data)
        │
        ▼
src/hooks/useDashboardData.js  (data hook)
        │
        ▼
App.jsx  →  Dashboard / About  →  Components
```

When a backend is ready, add `src/adapters/backendAdapter.js` and wire it
into `useDashboardData.js`. No component changes needed.

## Project structure

```text
frontend/
├── src/
│   ├── adapters/          # TODO: add backendAdapter.js here when ready
│   ├── components/        # UI components (props-only, no data fetching)
│   ├── data/
│   │   └── mockData.js    # hardcoded demo data — single source of truth
│   ├── hooks/
│   │   └── useDashboardData.js
│   ├── pages/
│   │   ├── Dashboard.jsx
│   │   └── About.jsx
│   └── styles/
│       └── index.css
├── package.json
└── vite.config.js
```

## Run locally

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. No `.env` file needed — the app runs fully offline.

## Frontend data models

| Export | Shape |
|---|---|
| `vpnStatus` | `{ status, endpointA, endpointAIp, endpointB, endpointBIp, uptimeSeconds, protocol, encryption, authMethod, peerIp, uptimeLabel }` |
| `metrics` | `{ packetsPerSecond, activeFlows, avgPacketSize, inboundBps, outboundBps, bandwidthBps }` |
| `security` | `{ riskScore, riskLevel, anomalyDetected, findings[] }` |
| `events` | `{ timestamp, title, description, severity, category }[]` |
| `chartData` | `{ timestamp, packetsPerSecond, riskScore }[]` |
| `endpoints` | `{ peerIp, protocol, encryption, authMethod, uptimeLabel }` |

## Backend integration (future)

1. Create `src/adapters/backendAdapter.js` with mapping functions:
   `mapVpnStatus`, `mapMetrics`, `mapSecurity`, `mapEvents`, `mapChartData`, `mapEndpoints`
2. In `useDashboardData.js`, replace static imports with fetch/WebSocket calls
   and pipe raw responses through the adapter functions.
3. No changes needed in any component.

## Design

Apple-inspired visual language: system typography, glassmorphism surfaces,
subtle depth, responsive layout, minimal motion.
