import Header from '../components/Header'
import GlassCard from '../components/GlassCard'
import SecurityScore from '../components/SecurityScore'
import VPNStatus from '../components/VPNStatus'
import MetricsPanel from '../components/MetricsPanel'
import EventFeed from '../components/EventFeed'
import { TrafficChart, RiskChart } from '../components/TrafficChart'
import RotatingEarth from '../components/RotatingEarth'
import ScrollReveal from '../components/ScrollReveal'
import SystemStatus from '../components/SystemStatus'

// TODO (backend adapter): Restore loading/error/retry states here once
// useDashboardData is wired to the live backend through backendAdapter.js.
//
//   if (!vpnStatus) return (
//     <>
//       <Header connection={connection} theme={theme} toggleTheme={toggleTheme}/>
//       <main className="shell">
//         <div className="loading">
//           <div className="spinner"/>
//           <h2>Initializing secure telemetry</h2>
//           <p>{error || 'Connecting to the analyzer backend…'}</p>
//           {error && <button onClick={retry}><RefreshCw size={15}/> Retry</button>}
//         </div>
//       </main>
//     </>
//   )

// Props contract:
//   vpnStatus   — { status, endpointA, endpointAIp, endpointB, endpointBIp,
//                   uptimeSeconds, protocol, encryption, authMethod, peerIp, uptimeLabel }
//   metrics     — { packetsPerSecond, activeFlows, avgPacketSize, inboundBps, outboundBps, bandwidthBps }
//   security    — { riskScore, riskLevel, anomalyDetected, findings[] }
//   events      — { timestamp, title, description, severity, category }[]
//   chartData   — { timestamp, packetsPerSecond, riskScore }[]
//   endpoints   — { peerIp, protocol, encryption, authMethod, uptimeLabel }
//   connection  — 'MOCK' | 'LIVE' | 'RECONNECTING' | 'CONNECTING'

export default function Dashboard({
  vpnStatus, metrics, security, events, chartData, endpoints,
  connection, theme, toggleTheme,
}) {
  return (
    <>
      <Header connection={connection} mode="MOCK" theme={theme} toggleTheme={toggleTheme} />
      <main className="shell">

        {/* Hero */}
        <div id="top">
          <ScrollReveal>
            <div className="hero">
              <div>
                <h1>
                  Network<br />
                  Security{" "}
                  <span className="hero-title-accent">
                    Intelligence.
                  </span>
                </h1>
              </div>
            </div>
          </ScrollReveal>
        </div>

        {/* Card 1 — Security Posture + Tunnel Status */}
        <div id="security">
          <ScrollReveal>
            <GlassCard className="combo-card">
              <div className="combo-half">
                {/* TODO (backend adapter): security mapped via mapSecurity() */}
                <SecurityScore
                  score={security.riskScore}
                  level={security.riskLevel}
                  anomaly={security.anomalyDetected}
                />
              </div>
              <div className="combo-divider" />
              <div className="combo-half">
                {/* TODO (backend adapter): vpnStatus mapped via mapVpnStatus() */}
                <VPNStatus vpn={vpnStatus} />
              </div>
            </GlassCard>
          </ScrollReveal>
        </div>

        {/* Card 2 — Telemetry metrics + Traffic chart */}
        <div id="traffic">
          <ScrollReveal>
            <GlassCard className="telem-card">
              {/* TODO (backend adapter): metrics mapped via mapMetrics() */}
              <MetricsPanel metrics={metrics} inline />
              <div className="telem-divider" />
              {/* TODO (backend adapter): chartData mapped via mapChartData() */}
              <TrafficChart history={chartData} inline />
            </GlassCard>
          </ScrollReveal>
        </div>

        {/* Card 3 — Security Trend */}
        <ScrollReveal>
          {/* TODO (backend adapter): chartData.riskScore and security.riskLevel from adapter */}
          <RiskChart history={chartData} level={security.riskLevel} />
        </ScrollReveal>

        {/* Card 4 — Globe + Tunnel Intelligence */}
        <div id="vpn">
          <ScrollReveal>
            <GlassCard className="globe-combo">
              <div className="globe-combo-left">
                <div className="card-title-row">
                  <h3>Global Threat Map</h3>
                  <span className="live-badge"><span className="live-dot" />LIVE</span>
                </div>
                <p style={{ fontSize: 11, color: 'var(--text-secondary)', margin: '4px 0 0', lineHeight: 1.5 }}>
                  Real-time IPsec tunnel endpoints across the globe.
                </p>
                <div className="globe-wrap"><RotatingEarth size={300} /></div>
                <div className="globe-hint">Drag to rotate · Scroll to zoom</div>
              </div>
              <div className="combo-divider" />
              <div className="globe-combo-right">
                <div className="card-title-row"><h3>Tunnel Intelligence</h3></div>
                {/* TODO (backend adapter): endpoints mapped via mapEndpoints() in backendAdapter.js */}
                <div className="globe-rows">
                  {[
                    { label: 'Active Endpoints', value: endpoints.peerIp },
                    { label: 'Tunnel Protocol', value: endpoints.protocol },
                    { label: 'Encryption', value: endpoints.encryption },
                    { label: 'Auth Method', value: endpoints.authMethod },
                    { label: 'Uptime', value: endpoints.uptimeLabel },
                    { label: 'Bytes Transferred', value: `${(metrics.bandwidthBps / 1000 * 86400).toFixed(0)} MB/day` },
                    {
                      label: 'Threat Level', value: security.riskLevel,
                      color: security.riskLevel === 'LOW' ? '#00ff88' : security.riskLevel === 'MEDIUM' ? '#fbbf24' : '#f87171',
                    },
                    {
                      label: 'Anomalies', value: security.anomalyDetected ? 'DETECTED' : 'None',
                      color: security.anomalyDetected ? '#f87171' : '#00ff88',
                    },
                  ].map(({ label, value, color }) => (
                    <div key={label} className="globe-stat-row">
                      <span className="globe-stat-label">{label}</span>
                      <span className="globe-stat-value" style={{ color: color || 'var(--text-primary)' }}>{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </GlassCard>
          </ScrollReveal>
        </div>

        {/* Card 5 — Event Stream */}
        <div id="events">
          <ScrollReveal>
            {/* TODO (backend adapter): events mapped via mapEvents() in backendAdapter.js */}
            <EventFeed events={events} />
          </ScrollReveal>
        </div>

        <footer>IPsec VPN Analyzer · SIH26 · Integration-ready telemetry layer</footer>
      </main>
    </>
  )
}
