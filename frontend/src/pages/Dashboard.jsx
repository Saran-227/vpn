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
import { AlertCircle, RefreshCw } from 'lucide-react'

export default function Dashboard({ data, connection, error, retry, theme, toggleTheme }) {
  if (!data) return (
    <>
      <Header connection={connection} mode="MOCK" theme={theme} toggleTheme={toggleTheme}/>
      <main className="shell">
        <div className="loading">
          <div className="spinner"/>
          <h2>Initializing secure telemetry</h2>
          <p>{error || 'Connecting to the analyzer backend…'}</p>
          {error && <button onClick={retry}><RefreshCw size={15}/> Retry</button>}
        </div>
      </main>
    </>
  )

  const { vpn, metrics, security, events, history, mode } = data

  return (
    <>
      <Header connection={connection} mode={mode} theme={theme} toggleTheme={toggleTheme}/>
      <main className="shell">

        {/* Hero */}
        <div id="top">
          <ScrollReveal>
            <div className="hero">
              <div>
                <span className="eyebrow">SECURITY OPERATIONS · IPSEC · REAL-TIME</span>
                <h1>Network Security<br/>Intelligence.</h1>
                <p>Live telemetry from the VPN tunnel and behavioral security engine.</p>
              </div>
              <div className="hero-right">
                <SystemStatus security={security} events={events}/>
                <div className="timestamp">Updated {new Date(data.timestamp).toLocaleTimeString()}</div>
              </div>
            </div>
          </ScrollReveal>
        </div>

        {error && (
          <div className="error-banner">
            <AlertCircle size={16}/><span>{error} · Live stream will keep retrying.</span>
          </div>
        )}

        {/* Card 1 — Security Posture + Tunnel Status side by side */}
        <div id="security">
        <ScrollReveal>
          <GlassCard className="combo-card">
            <div className="combo-half">
              <SecurityScore score={security.risk_score} level={security.risk_level} anomaly={security.anomaly_detected}/>
            </div>
            <div className="combo-divider"/>
            <div className="combo-half">
              <VPNStatus vpn={vpn}/>
            </div>
          </GlassCard>
        </ScrollReveal>
        </div>

        {/* Card 2 — Telemetry metrics + Traffic chart */}
        <div id="traffic">
        <ScrollReveal>
          <GlassCard className="telem-card">
            <MetricsPanel metrics={metrics} inline/>
            <div className="telem-divider"/>
            <TrafficChart history={history} inline/>
          </GlassCard>
        </ScrollReveal>
        </div>

        {/* Card 3 — Security Trend */}
        <ScrollReveal>
          <RiskChart history={history} level={security.risk_level}/>
        </ScrollReveal>

        {/* Card 4 — Globe + Tunnel Intelligence */}
        <div id="vpn">
        <ScrollReveal>
          <GlassCard className="globe-combo">
            <div className="globe-combo-left">
              <div className="card-title-row">
                <h3>Global Threat Map</h3>
                <span className="live-badge"><span className="live-dot"/>LIVE</span>
              </div>
              <p style={{fontSize:11,color:'var(--text-secondary)',margin:'4px 0 0',lineHeight:1.5}}>
                Real-time IPsec tunnel endpoints across the globe.
              </p>
              <div className="globe-wrap"><RotatingEarth size={300}/></div>
              <div className="globe-hint">Drag to rotate · Scroll to zoom</div>
            </div>
            <div className="combo-divider"/>
            <div className="globe-combo-right">
              <div className="card-title-row"><h3>Tunnel Intelligence</h3></div>
              <div className="globe-rows">
                {[
                  { label: 'Active Endpoints',  value: vpn.peer_ip || '203.0.113.42' },
                  { label: 'Tunnel Protocol',   value: vpn.protocol || 'IKEv2/ESP' },
                  { label: 'Encryption',        value: vpn.encryption || 'AES-256-GCM' },
                  { label: 'Auth Method',       value: vpn.auth || 'RSA-4096' },
                  { label: 'Uptime',            value: vpn.uptime || '14d 6h 32m' },
                  { label: 'Bytes Transferred', value: `${(metrics.bytes_per_second/1000*86400).toFixed(0)} MB/day` },
                  { label: 'Threat Level',      value: security.risk_level,
                    color: security.risk_level==='LOW' ? '#00ff88' : security.risk_level==='MEDIUM' ? '#fbbf24' : '#f87171' },
                  { label: 'Anomalies',         value: security.anomaly_detected ? 'DETECTED' : 'None',
                    color: security.anomaly_detected ? '#f87171' : '#00ff88' },
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
          <EventFeed events={events}/>
        </ScrollReveal>
        </div>

        <footer>IPsec VPN Analyzer · SIH26 · Integration-ready telemetry layer</footer>
      </main>
    </>
  )
}
