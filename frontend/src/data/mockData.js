/**
 * mockData.js — Hardcoded Design Language System data layer
 *
 * All dashboard data lives here. Components receive this via props.
 *
 * TODO (backend integration): Replace the exports below with real API/WebSocket
 * responses shaped to the same interfaces. The component props contracts are
 * intentionally identical to the backend's DashboardState Pydantic schema so
 * that swapping in live data requires zero component changes.
 *
 * Integration points:
 *   - vpn      → GET /api/vpn/status        or ws/dashboard .vpn
 *   - metrics  → GET /api/metrics/current   or ws/dashboard .metrics
 *   - security → GET /api/security/current  or ws/dashboard .security
 *   - events   → GET /api/events            or ws/dashboard .events
 *   - history  → GET /api/metrics/history   or ws/dashboard .history
 */

// ─── VPN Status ───────────────────────────────────────────────────────────────
// Interface: { status, endpoint_a, endpoint_a_ip, endpoint_b, endpoint_b_ip,
//              uptime_seconds, protocol, encryption, auth, peer_ip, uptime }
export const MOCK_VPN = {
  status: 'CONNECTED',
  endpoint_a: 'Delhi-HQ',
  endpoint_a_ip: '10.0.0.1',
  endpoint_b: 'Washington-DC',
  endpoint_b_ip: '203.0.113.42',
  uptime_seconds: 1_234_567,
  protocol: 'IKEv2/ESP',
  encryption: 'AES-256-GCM',
  auth: 'RSA-4096',
  peer_ip: '203.0.113.42',
  uptime: '14d 6h 32m',
}

// ─── Metrics ──────────────────────────────────────────────────────────────────
// Interface: { packets_per_second, active_flows, average_packet_size,
//              inbound_bps, outbound_bps, bytes_per_second }
export const MOCK_METRICS = {
  packets_per_second: 842,
  active_flows: 37,
  average_packet_size: 512,
  inbound_bps: 1_240_000,
  outbound_bps: 890_000,
  bytes_per_second: 431_000,
}

// ─── Security ─────────────────────────────────────────────────────────────────
// Interface: { risk_score, risk_level, anomaly_detected, findings[] }
// risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export const MOCK_SECURITY = {
  risk_score: 22,
  risk_level: 'LOW',
  anomaly_detected: false,
  findings: [],
}

// ─── Events ───────────────────────────────────────────────────────────────────
// Interface: { timestamp, title, description, severity, type }[]
// severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
// type: 'FLOW' | 'AUTH' | 'ANOMALY' | 'SYSTEM' | 'THREAT'
const _now = Date.now()
export const MOCK_EVENTS = [
  {
    timestamp: new Date(_now - 12_000).toISOString(),
    title: 'IKEv2 SA Established',
    description: 'Security association negotiated successfully with peer 203.0.113.42.',
    severity: 'INFO',
    type: 'AUTH',
  },
  {
    timestamp: new Date(_now - 45_000).toISOString(),
    title: 'Traffic Burst Detected',
    description: 'Inbound packet rate spiked to 1,840 pps for 8 s — within normal bounds.',
    severity: 'LOW',
    type: 'FLOW',
  },
  {
    timestamp: new Date(_now - 120_000).toISOString(),
    title: 'Cipher Renegotiation',
    description: 'AES-256-GCM re-keying completed. New session keys applied.',
    severity: 'INFO',
    type: 'SYSTEM',
  },
  {
    timestamp: new Date(_now - 310_000).toISOString(),
    title: 'Elevated Outbound Flow',
    description: 'Outbound flows exceeded baseline by 2.4× for 30 s. Auto-resolved.',
    severity: 'MEDIUM',
    type: 'ANOMALY',
  },
  {
    timestamp: new Date(_now - 600_000).toISOString(),
    title: 'Replay Attack Probe',
    description: 'ESP replay window violation detected from 198.51.100.7. Packet dropped.',
    severity: 'HIGH',
    type: 'THREAT',
  },
  {
    timestamp: new Date(_now - 900_000).toISOString(),
    title: 'Tunnel Keepalive OK',
    description: 'DPD keepalive round-trip 4 ms. Tunnel health nominal.',
    severity: 'INFO',
    type: 'SYSTEM',
  },
  {
    timestamp: new Date(_now - 1_200_000).toISOString(),
    title: 'Auth Failure (×3)',
    description: 'Three consecutive IKE_AUTH failures from 192.0.2.88. Source rate-limited.',
    severity: 'HIGH',
    type: 'AUTH',
  },
]

// ─── History (chart data) ─────────────────────────────────────────────────────
// Interface: { timestamp, packets_per_second, risk_score }[]
// 60 points × 2 s = last 2 minutes of telemetry
function buildHistory() {
  const points = []
  const base = Date.now() - 60 * 2_000
  let pps = 820, risk = 22
  for (let i = 0; i < 60; i++) {
    pps  = Math.max(200,  Math.min(1800, pps  + (Math.random() - 0.48) * 80))
    risk = Math.max(5,    Math.min(55,   risk + (Math.random() - 0.50) * 4))
    points.push({
      timestamp: new Date(base + i * 2_000).toISOString(),
      packets_per_second: Math.round(pps),
      risk_score: Math.round(risk),
    })
  }
  return points
}

export const MOCK_HISTORY = buildHistory()

// ─── Aggregated dashboard state ───────────────────────────────────────────────
// Mirrors the backend DashboardState contract exactly.
// TODO (backend integration): Replace this object with the parsed JSON from
// GET /api/dashboard or the WebSocket ws/dashboard message payload.
export const MOCK_DASHBOARD = {
  timestamp: new Date().toISOString(),
  vpn: MOCK_VPN,
  metrics: MOCK_METRICS,
  security: MOCK_SECURITY,
  events: MOCK_EVENTS,
  history: MOCK_HISTORY,
  mode: 'MOCK',
}
