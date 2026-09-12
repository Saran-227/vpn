import { useState } from 'react'
import { Download, Check } from 'lucide-react'
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
  const [downloading, setDownloading] = useState(false)
  const [downloaded, setDownloaded] = useState(false)

  const handleDownloadReport = () => {
    setDownloading(true)
    const reportData = {
      title: 'IPsec VPN Security & Telemetry Audit Report',
      generatedAt: new Date().toISOString(),
      systemStatus: {
        connection: connection || 'MOCK',
        threatLevel: security?.riskLevel || 'LOW',
        riskScore: security?.riskScore || 0,
        anomalyDetected: !!security?.anomalyDetected,
      },
      telemetry: {
        packetsPerSecond: metrics?.packetsPerSecond || 0,
        activeFlows: metrics?.activeFlows || 0,
        avgPacketSize: metrics?.avgPacketSize || 0,
        inboundBps: metrics?.inboundBps || 0,
        outboundBps: metrics?.outboundBps || 0,
        bandwidthBps: metrics?.bandwidthBps || 0,
      },
      vpnInfrastructure: {
        peerIp: endpoints?.peerIp || vpnStatus?.peerIp || 'N/A',
        protocol: endpoints?.protocol || vpnStatus?.protocol || 'N/A',
        encryption: endpoints?.encryption || vpnStatus?.encryption || 'N/A',
        authMethod: endpoints?.authMethod || vpnStatus?.authMethod || 'N/A',
        uptime: endpoints?.uptimeLabel || vpnStatus?.uptimeLabel || 'N/A',
      },
      recentEvents: events || [],
    }

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `ipsec-vpn-security-report-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.json`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)

    setTimeout(() => {
      setDownloading(false)
      setDownloaded(true)
      setTimeout(() => setDownloaded(false), 3000)
    }, 500)
  }

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
                    Dashboard.
                  </span>
                </h1>
              </div>
            </div>
          </ScrollReveal>
        </div>

        {/* Traffic & Metrics and Threat Assessment 50/50 Split */}
        <div id="traffic">
          <ScrollReveal>
            <GlassCard className="combo-card">
              <div className="combo-row flex flex-row">
                {/* Left Half: Traffic & Metrics */}
                <div className="combo-half traffic-half">
                  <MetricsPanel metrics={metrics} inline />
                </div>

                <div className="combo-divider" />

                {/* Right Half: Threat Assessment */}
                <div className="combo-half threat-half" id="security">
                  <SecurityScore
                    score={security.riskScore}
                    level={security.riskLevel}
                    anomaly={security.anomalyDetected}
                    inline
                  />
                </div>
              </div>

              {/* Bottom of this section */}
              <div className="combo-footer-divider" />
              <div className="report-action-wrap">
                <button
                  className={`download-report-btn ${downloaded ? 'downloaded' : ''}`}
                  onClick={handleDownloadReport}
                  disabled={downloading}
                  id="download-report-btn"
                  aria-label="Download Security and Telemetry Report"
                >
                  {downloaded ? (
                    <>
                      <Check size={15} className="btn-icon check-icon" />
                      <span>Report Downloaded</span>
                    </>
                  ) : (
                    <>
                      <Download size={15} className={`btn-icon ${downloading ? 'spin-icon' : ''}`} />
                      <span>{downloading ? 'Generating Report…' : 'Download Telemetry & Security Report'}</span>
                    </>
                  )}
                </button>
              </div>
            </GlassCard>
          </ScrollReveal>
        </div>
        {/* Card 3 — Globe + Encrypted Connection */}
        <div id="vpn">
          <ScrollReveal>
            <GlassCard className="globe-combo">
              <div className="globe-combo-left">
                <div className="card-title-row">
                  <div>
                    <div className="section-kicker">GEO TELEMETRY</div>
                    <h3>Global Threat Map</h3>
                  </div>
                  <span className="live-badge"><span className="live-dot" />LIVE</span>
                </div>
                <div className="globe-wrap"><RotatingEarth size={260} /></div>
                <div className="globe-hint">Drag to rotate · Scroll to zoom</div>
              </div>

              <div className="combo-divider" />

              <div className="">
                {/* TODO (backend adapter): vpnStatus mapped via mapVpnStatus() */}
                <VPNStatus vpn={vpnStatus} inline />
              </div>

              <div className="combo-divider" />
              <div className="intel-events-row flex flex-row">
                {/* Left Half: Tunnel Intelligence */}
                <div className="intel-half">
                  <div className="card-title-row">
                    <div>
                      <div className="section-kicker">INFRASTRUCTURE</div>
                      <h3>Tunnel Intelligence</h3>
                    </div>
                  </div>
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

                <div className="combo-divider" />

                {/* Right Half: Recent Security Events */}
                <div className="events-half">
                  {/* TODO (backend adapter): events mapped via mapEvents() in backendAdapter.js */}
                  <EventFeed events={events} inline />
                </div>
              </div>

            </GlassCard>
          </ScrollReveal>
        </div>

        {/* Card 5 — Security Trend */}
        <ScrollReveal>
          {/* TODO (backend adapter): chartData.riskScore and security.riskLevel from adapter */}
          <RiskChart history={chartData} level={security.riskLevel} />
        </ScrollReveal>

        <footer>IPsec VPN Analyzer · SIH26 · Integration-ready telemetry layer</footer>
      </main>
    </>
  )
}
