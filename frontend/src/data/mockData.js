/**
 * mockData.js — Frontend-owned hardcoded demo data
 *
 * These are the canonical frontend data models. Components depend only on
 * these shapes — never on a backend schema.
 *
 * TODO (backend adapter): When your friend's backend is ready, create a
 * separate file  src/adapters/backendAdapter.js  that imports the raw API
 * response and maps it to these same exported shapes. Nothing in this file
 * or in any component should change.
 *
 * Adapter entry point (do not touch components):
 *   src/adapters/backendAdapter.js
 *     import { mapVpnStatus, mapMetrics, mapSecurity, mapEvents, mapChartData } from './backendAdapter'
 */

// ─── VPN Status ───────────────────────────────────────────────────────────────
// { status, endpointA, endpointAIp, endpointB, endpointBIp,
//   uptimeSeconds, protocol, encryption, authMethod, peerIp, uptimeLabel }
export const vpnStatus = {
  status: 'CONNECTED',
  endpointA: 'Delhi-HQ',
  endpointAIp: '10.0.0.1',
  endpointB: 'Washington-DC',
  endpointBIp: '203.0.113.42',
  uptimeSeconds: 1_234_567,
  protocol: 'IKEv2/ESP',
  encryption: 'AES-256-GCM',
  authMethod: 'RSA-4096',
  peerIp: '203.0.113.42',
  uptimeLabel: '14d 6h 32m',
}

// ─── Metrics ──────────────────────────────────────────────────────────────────
// { packetsPerSecond, activeFlows, avgPacketSize, inboundBps, outboundBps, bandwidthBps }
export const metrics = {
  packetsPerSecond: 842,
  activeFlows: 37,
  avgPacketSize: 512,
  inboundBps: 1_240_000,
  outboundBps: 890_000,
  bandwidthBps: 431_000,
}

// ─── Security ─────────────────────────────────────────────────────────────────
// { riskScore, riskLevel, anomalyDetected, findings[] }
// riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export const security = {
  riskScore: 22,
  riskLevel: 'LOW',
  anomalyDetected: false,
  findings: [],
}

// ─── Events ───────────────────────────────────────────────────────────────────
// { timestamp, title, description, severity, category }[]
// severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
// category: 'FLOW' | 'AUTH' | 'ANOMALY' | 'SYSTEM' | 'THREAT'
const _now = Date.now()
export const events = [
  {
    timestamp: new Date(_now - 12_000).toISOString(),
    title: 'IKEv2 SA Established',
    description: 'Security association negotiated successfully with peer 203.0.113.42.',
    severity: 'INFO',
    category: 'AUTH',
  },
  {
    timestamp: new Date(_now - 45_000).toISOString(),
    title: 'Traffic Burst Detected',
    description: 'Inbound packet rate spiked to 1,840 pps for 8 s — within normal bounds.',
    severity: 'LOW',
    category: 'FLOW',
  },
  {
    timestamp: new Date(_now - 120_000).toISOString(),
    title: 'Cipher Renegotiation',
    description: 'AES-256-GCM re-keying completed. New session keys applied.',
    severity: 'INFO',
    category: 'SYSTEM',
  },
  {
    timestamp: new Date(_now - 310_000).toISOString(),
    title: 'Elevated Outbound Flow',
    description: 'Outbound flows exceeded baseline by 2.4× for 30 s. Auto-resolved.',
    severity: 'MEDIUM',
    category: 'ANOMALY',
  },
  {
    timestamp: new Date(_now - 600_000).toISOString(),
    title: 'Replay Attack Probe',
    description: 'ESP replay window violation detected from 198.51.100.7. Packet dropped.',
    severity: 'HIGH',
    category: 'THREAT',
  },
  {
    timestamp: new Date(_now - 900_000).toISOString(),
    title: 'Tunnel Keepalive OK',
    description: 'DPD keepalive round-trip 4 ms. Tunnel health nominal.',
    severity: 'INFO',
    category: 'SYSTEM',
  },
  {
    timestamp: new Date(_now - 1_200_000).toISOString(),
    title: 'Auth Failure (×3)',
    description: 'Three consecutive IKE_AUTH failures from 192.0.2.88. Source rate-limited.',
    severity: 'HIGH',
    category: 'AUTH',
  },
]

// ─── Chart Data ───────────────────────────────────────────────────────────────
// { timestamp, packetsPerSecond, riskScore }[]
// 60 points × 2 s = last 2 minutes of telemetry
function buildChartData() {
  const points = []
  const base = Date.now() - 60 * 2_000
  let pps = 820, risk = 22
  for (let i = 0; i < 60; i++) {
    pps  = Math.max(200,  Math.min(1800, pps  + (Math.random() - 0.48) * 80))
    risk = Math.max(5,    Math.min(55,   risk + (Math.random() - 0.50) * 4))
    points.push({
      timestamp: new Date(base + i * 2_000).toISOString(),
      packetsPerSecond: Math.round(pps),
      riskScore: Math.round(risk),
    })
  }
  return points
}

export const chartData = buildChartData()

// ─── Endpoints (Tunnel Intelligence panel) ────────────────────────────────────
// { peerIp, protocol, encryption, authMethod, uptimeLabel }
// Derived from vpnStatus for display — kept separate so the globe panel
// doesn't reach into vpnStatus directly.
export const endpoints = {
  peerIp: vpnStatus.peerIp,
  protocol: vpnStatus.protocol,
  encryption: vpnStatus.encryption,
  authMethod: vpnStatus.authMethod,
  uptimeLabel: vpnStatus.uptimeLabel,
}
