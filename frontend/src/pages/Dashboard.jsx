import React, { useState } from 'react'
import Header from '../components/Header'
import GlassCard from '../components/GlassCard'
import SecurityScore from '../components/SecurityScore'
import ScrollReveal from '../components/ScrollReveal'

// Specialized NTRO Cyber Defense & AI Intelligence Components
import PcapIngestion from '../components/PcapIngestion'
import CryptoAuditPanel from '../components/CryptoAuditPanel'
import TrafficIntelligencePanel from '../components/TrafficIntelligencePanel'
import TimelineSlices from '../components/TimelineSlices'
import TournamentModal from '../components/TournamentModal'

export default function Dashboard({
  security,
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
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.6rem',
                  padding: '0.5rem 0.85rem',
                  borderRadius: 'var(--radius-sm)',
                  background: 'var(--glass-bg)',
                  border: '1px solid var(--glass-border)'
                }}>
                  <div style={{
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    background: 'var(--accent-green)',
                    boxShadow: '0 0 10px var(--accent-green)'
                  }} />
                  <div>
                    <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                      Air-Gapped ML Core Active
                    </div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                      Champion: HistGradientBoosting (80.5%)
                    </div>
                  </div>
                </div>
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

        {/* Executive Security Summary & Wiretap Session Telemetry */}
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
                <div className="card-title-row">
                  <div>
                    <div className="section-kicker">WIRETAP TELEMETRY &amp; SESSION METRICS</div>
                    <h3 style={{ margin: '2px 0 0', fontSize: '1rem', fontWeight: 700 }}>
                      Active Capture Profiling
                    </h3>
                  </div>
                  <span className="live-badge">
                    <span className="live-dot" />
                    {isAnalyzing ? 'INGESTING' : 'ANALYZED'}
                  </span>
                </div>

                <div style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(2, 1fr)',
                  gap: '0.75rem',
                  marginTop: '1rem'
                }}>
                  <div style={{
                    padding: '0.65rem 0.85rem',
                    background: 'var(--glass-inner)',
                    borderRadius: 'var(--radius-xs)',
                    border: '1px solid var(--border)'
                  }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Target PCAP</div>
                    <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--accent-blue)', wordBreak: 'break-all', marginTop: 2 }}>
                      {activeFilename || execSummary?.target_pcap || 'sih26_asim_golden.pcap'}
                    </div>
                  </div>

                  <div style={{
                    padding: '0.65rem 0.85rem',
                    background: 'var(--glass-inner)',
                    borderRadius: 'var(--radius-xs)',
                    border: '1px solid var(--border)'
                  }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Total Packets</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
                      {execSummary?.total_packets || 557} frames
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginLeft: 4 }}>
                        ({execSummary?.esp_packets || 553} ESP)
                      </span>
                    </div>
                  </div>

                  <div style={{
                    padding: '0.65rem 0.85rem',
                    background: 'var(--glass-inner)',
                    borderRadius: 'var(--radius-xs)',
                    border: '1px solid var(--border)'
                  }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Session Duration</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
                      {execSummary?.session_duration_sec ? `${execSummary.session_duration_sec.toFixed(1)}s` : '142.1s'}
                    </div>
                  </div>

                  <div style={{
                    padding: '0.65rem 0.85rem',
                    background: 'var(--glass-inner)',
                    borderRadius: 'var(--radius-xs)',
                    border: '1px solid var(--border)'
                  }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Average Throughput</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
                      {((aiData?.average_bytes_sec || 15800) / 1024).toFixed(1)} KB/s
                    </div>
                  </div>
                </div>

                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginTop: '0.85rem',
                  padding: '0.5rem 0.75rem',
                  background: 'var(--glass-inner)',
                  borderRadius: 'var(--radius-xs)',
                  border: '1px solid var(--border)'
                }}>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Active SPI Pair:</span>
                  <span style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: 'var(--accent-blue)', fontWeight: 600 }}>
                    {execSummary?.spi_pair || '0xc56d1914 <-> 0xcd0440ee'}
                  </span>
                </div>
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
