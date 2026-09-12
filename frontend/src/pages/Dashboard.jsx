import React, { useState } from 'react'
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

// Specialized Cyber Defense & AI Intelligence Components
import PcapIngestion from '../components/PcapIngestion'
import CryptoAuditPanel from '../components/CryptoAuditPanel'
import TrafficIntelligencePanel from '../components/TrafficIntelligencePanel'
import TimelineSlices from '../components/TimelineSlices'
import TournamentModal from '../components/TournamentModal'

export default function Dashboard({
  vpnStatus,
  metrics,
  security,
  events,
  chartData,
  endpoints,
  connection,
  theme,
  toggleTheme,
  samples,
  selectedSample,
  activeFilename,
  isAnalyzing,
  error,
  tournamentData,
  onSelectSample,
  onUploadFile,
  auditData,
  ikeDetails,
  aiData,
  execSummary
}) {
  const [isTournamentOpen, setIsTournamentOpen] = useState(false)

  return (
    <>
      <Header
        connection={connection}
        mode={connection === 'LIVE' ? 'AIR-GAPPED OFFLINE' : 'OFFLINE DEMO'}
        theme={theme}
        toggleTheme={toggleTheme}
        onOpenTournament={() => setIsTournamentOpen(true)}
      />

      <main className="shell">

        {/* Hero Section */}
        <div id="top">
          <ScrollReveal>
            <div className="hero">
              <div>
                <span className="eyebrow">NATIONAL TECHNICAL RESEARCH ORGANISATION · SIH26160</span>
                <h1>IPsec VPN Intelligence<br />&amp; Security Audit.</h1>
                <p>Automated RFC cryptographic compliance dissector &amp; AI-powered encrypted traffic classifier.</p>
              </div>
              <div className="hero-right">
                <SystemStatus security={security} events={events} />
                <div className="timestamp">
                  {isAnalyzing ? (
                    <span style={{ color: 'var(--accent-blue)' }}>Analyzing capture payload...</span>
                  ) : (
                    <span>Last Analyzed: {new Date().toLocaleTimeString()}</span>
                  )}
                </div>
              </div>
            </div>
          </ScrollReveal>
        </div>

        {/* Ingestion Section: Drag & Drop + Curated Scenarios */}
        <div id="ingestion">
          <ScrollReveal>
            <PcapIngestion
              samples={samples}
              selectedSample={selectedSample}
              onSelectSample={onSelectSample}
              onUploadFile={onUploadFile}
              isAnalyzing={isAnalyzing}
              activeFilename={activeFilename}
            />
          </ScrollReveal>
        </div>

        {/* Security Posture + Tunnel Status */}
        <div id="security">
          <ScrollReveal>
            <GlassCard className="combo-card">
              <div className="combo-half">
                <SecurityScore
                  score={security?.riskScore}
                  level={security?.riskLevel}
                  anomaly={security?.anomalyDetected}
                  postureLabel={security?.postureLabel}
                  complianceStatus={security?.complianceStatus}
                />
              </div>
              <div className="combo-divider" />
              <div className="combo-half">
                <VPNStatus vpn={vpnStatus} />
              </div>
            </GlassCard>
          </ScrollReveal>
        </div>

        {/* Deterministic Cryptographic Audit Panel (NIST SP 800-77 Rev. 1) */}
        <div id="audit">
          <ScrollReveal>
            <CryptoAuditPanel
              auditData={auditData}
              ikeDetails={ikeDetails}
              execSummary={execSummary}
            />
          </ScrollReveal>
        </div>

        {/* AI Encrypted Traffic Intelligence Panel */}
        <div id="ai-telemetry">
          <ScrollReveal>
            <TrafficIntelligencePanel aiData={aiData} />
          </ScrollReveal>
        </div>

        {/* Sliding Window Temporal Breakdown (1.5s slices) */}
        <div id="timeline">
          <ScrollReveal>
            <TimelineSlices slices={aiData?.temporal_window_breakdown || []} />
          </ScrollReveal>
        </div>

        {/* Telemetry Metrics & Traffic Throughput Chart */}
        <div id="traffic">
          <ScrollReveal>
            <GlassCard className="telem-card">
              <MetricsPanel metrics={metrics} inline />
              <div className="telem-divider" />
              <TrafficChart history={chartData} inline />
            </GlassCard>
          </ScrollReveal>
        </div>

        {/* Security Risk Trend Chart */}
        <ScrollReveal>
          <RiskChart history={chartData} level={security?.riskLevel} />
        </ScrollReveal>

        {/* Global Threat Map (3D Globe) + Tunnel Intelligence */}
        <div id="vpn">
          <ScrollReveal>
            <GlassCard className="globe-combo">
              <div className="globe-combo-left">
                <div className="card-title-row">
                  <h3>Global Threat Map</h3>
                  <span className="live-badge"><span className="live-dot" />LIVE</span>
                </div>
                <p style={{ fontSize: 11, color: 'var(--text-secondary)', margin: '4px 0 0', lineHeight: 1.5 }}>
                  Real-time IPsec tunnel telemetry &amp; intercept endpoints across the network.
                </p>
                <div className="globe-wrap"><RotatingEarth size={300} /></div>
                <div className="globe-hint">Drag to rotate · Scroll to zoom</div>
              </div>
              <div className="combo-divider" />
              <div className="globe-combo-right">
                <div className="card-title-row"><h3>Tunnel Telemetry</h3></div>
                <div className="globe-rows">
                  {[
                    { label: 'Active SPI Pair',    value: endpoints?.peerIp || 'None' },
                    { label: 'Tunnel Protocol',     value: endpoints?.protocol || 'ESP' },
                    { label: 'Encryption Cipher',   value: endpoints?.encryption || 'AES-256-GCM' },
                    { label: 'Authentication',      value: endpoints?.authMethod || 'PSK' },
                    { label: 'Captured Packets',    value: endpoints?.uptimeLabel || '557 Packets' },
                    { label: 'Data Throughput',     value: `${((metrics?.bandwidthBps || 0) / 1000).toFixed(1)} KB/s` },
                    {
                      label: 'Threat Level',
                      value: security?.riskLevel || 'LOW',
                      color: security?.riskLevel === 'LOW' ? '#00ff88' : security?.riskLevel === 'MEDIUM' ? '#fbbf24' : '#f87171',
                    },
                    {
                      label: 'Anomalies',
                      value: security?.anomalyDetected ? 'DETECTED' : 'None',
                      color: security?.anomalyDetected ? '#f87171' : '#00ff88',
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

        {/* Security Event & Vulnerability Stream */}
        <div id="events">
          <ScrollReveal>
            <EventFeed events={events} />
          </ScrollReveal>
        </div>

        <footer>
          National Technical Research Organisation (NTRO) · Smart India Hackathon 2026 · Problem Statement SIH26160
        </footer>
      </main>

      {/* 9-Model AI Tournament Modal */}
      <TournamentModal
        isOpen={isTournamentOpen}
        onClose={() => setIsTournamentOpen(false)}
        tournamentData={tournamentData}
      />
    </>
  )
}
