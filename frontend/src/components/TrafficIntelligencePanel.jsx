import React from 'react'
import GlassCard from './GlassCard'
import { Cpu, Activity, Zap, Layers, BarChart3, AlertCircle } from 'lucide-react'

export default function TrafficIntelligencePanel({ aiData }) {
  const tc = aiData?.traffic_classification || {}
  const op = aiData?.operational_mode || {}
  const kf = aiData?.key_flow_metrics || {}
  const fdr = aiData?.flow_dynamics_reconciliation

  const predProfile = tc.display_profile || tc.predicted_primary_profile || 'UNKNOWN'
  const confidence = (tc.confidence_score || 0) * 100
  const isConcurrent = tc.is_concurrent_traffic || false
  const activeApps = tc.active_applications || [predProfile]

  const mode = op.predicted_mode || 'UNKNOWN'
  const modeConf = (op.confidence_score || 0) * 100

  const rankedClasses = tc.ranked_classes || []

  return (
    <GlassCard className="traffic-intelligence-card">
      <div className="card-title-row">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div className="icon-wrapper" style={{ width: 32, height: 32 }}>
            <Cpu size={16} color="var(--accent-blue)" />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600 }}>AI Encrypted Traffic Intelligence</h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Statistical &amp; behavioral inference without decrypting ESP payloads
            </span>
          </div>
        </div>
        <span style={{
          fontSize: '0.7rem',
          fontWeight: 700,
          padding: '4px 8px',
          borderRadius: 'var(--radius-xs)',
          background: 'rgba(52, 211, 153, 0.15)',
          color: 'var(--accent-green)',
          border: '1px solid rgba(52, 211, 153, 0.3)',
          fontFamily: 'monospace'
        }}>
          HistGradientBoosting (80.5%)
        </span>
      </div>

      {/* Hero Prediction Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
        gap: '0.85rem',
        marginTop: '1rem'
      }}>
        {/* Application Profile */}
        <div style={{
          padding: '1rem',
          background: 'var(--glass-inner)',
          border: '1px solid var(--glass-inner-border)',
          borderRadius: 'var(--radius-sm)'
        }}>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Predicted Application Profile
          </span>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
            {predProfile.toUpperCase()}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '6px' }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--accent-blue)', fontWeight: 600 }}>
              {confidence.toFixed(1)}% Confidence
            </span>
            {isConcurrent && (
              <span style={{
                fontSize: '0.68rem',
                padding: '2px 6px',
                borderRadius: '4px',
                background: 'rgba(192, 132, 252, 0.2)',
                color: '#c084fc',
                fontWeight: 700
              }}>
                CONCURRENT MULTI-APP
              </span>
            )}
          </div>
          {isConcurrent && (
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Decomposed Sub-streams: <strong>{activeApps.join(' + ')}</strong>
            </div>
          )}
        </div>

        {/* Operational Mode */}
        <div style={{
          padding: '1rem',
          background: 'var(--glass-inner)',
          border: '1px solid var(--glass-inner-border)',
          borderRadius: 'var(--radius-sm)'
        }}>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Operational Encapsulation Mode
          </span>
          <div style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
            {mode.toUpperCase()}
          </div>
          <div style={{ fontSize: '0.78rem', color: 'var(--accent-green)', fontWeight: 600, marginTop: '6px' }}>
            {modeConf.toFixed(1)}% Confidence (ExtraTrees Classifier)
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
            {op.evidence || 'Distinguishes Gateway-to-Gateway vs Host-to-Host'}
          </div>
        </div>
      </div>

      {/* Flow Dynamics vs Payload Profile Reconciliation Alert Card */}
      {fdr && (
        <div style={{
          marginTop: '1rem',
          padding: '1rem',
          background: 'rgba(147, 197, 253, 0.08)',
          border: '1px solid rgba(147, 197, 253, 0.3)',
          borderRadius: 'var(--radius-sm)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--accent-blue)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Zap size={15} color="var(--accent-blue)" /> Flow Dynamics &amp; Payload Reconciliation
            </span>
            <span style={{
              fontSize: '0.65rem',
              fontWeight: 700,
              padding: '2px 6px',
              borderRadius: '4px',
              background: 'rgba(147, 197, 253, 0.2)',
              color: 'var(--accent-blue)',
              fontFamily: 'monospace'
            }}>
              BIMODAL CONCURRENCY RESOLVED
            </span>
          </div>

          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
            {fdr.resolution || fdr.issue_description}
          </div>

          {fdr.substreams && (
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '0.5rem',
              marginTop: '0.75rem'
            }}>
              <div style={{ padding: '0.6rem 0.8rem', background: 'rgba(255,255,255,0.03)', borderRadius: 'var(--radius-xs)' }}>
                <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>VoIP Voice Sub-stream</span>
                <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--accent-green)' }}>
                  {fdr.substreams.voice_substream?.percentage}% ({fdr.substreams.voice_substream?.packet_count} pkts)
                </div>
                <div style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>
                  {fdr.substreams.voice_substream?.frame_size_range} • {fdr.substreams.voice_substream?.traffic_type}
                </div>
              </div>

              <div style={{ padding: '0.6rem 0.8rem', background: 'rgba(255,255,255,0.03)', borderRadius: 'var(--radius-xs)' }}>
                <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>MTU Data / Padding Sub-stream</span>
                <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--accent-blue)' }}>
                  {fdr.substreams.data_substream?.percentage}% ({fdr.substreams.data_substream?.packet_count} pkts)
                </div>
                <div style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>
                  {fdr.substreams.data_substream?.frame_size_range} • {fdr.substreams.data_substream?.traffic_type}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Multi-Class Probability Vector */}
      <div style={{ marginTop: '1.25rem' }}>
        <div style={{
          fontSize: '0.75rem',
          fontWeight: 700,
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
          color: 'var(--text-muted)',
          marginBottom: '0.6rem'
        }}>
          Multi-Class Probability Distribution (8 Classes)
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
          {rankedClasses.map((item) => {
            const pct = (item.probability * 100).toFixed(1)
            return (
              <div key={item.class} style={{ display: 'grid', gridTemplateColumns: '70px 1fr 50px', alignItems: 'center', gap: '0.75rem' }}>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', textTransform: 'capitalize' }}>
                  {item.class}
                </span>
                <div style={{
                  height: 6,
                  borderRadius: 3,
                  background: 'rgba(255, 255, 255, 0.08)',
                  overflow: 'hidden'
                }}>
                  <div style={{
                    width: `${pct}%`,
                    height: '100%',
                    background: Number(pct) > 30 ? 'var(--accent-blue)' : 'rgba(147, 197, 253, 0.45)',
                    borderRadius: 3,
                    transition: 'width 0.4s ease'
                  }} />
                </div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'right', fontFamily: 'monospace' }}>
                  {pct}%
                </span>
              </div>
            )
          })}
        </div>
      </div>

      {/* Flow Dynamics Grid (48 Signal Features) */}
      <div style={{ marginTop: '1.25rem' }}>
        <div style={{
          fontSize: '0.75rem',
          fontWeight: 700,
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
          color: 'var(--text-muted)',
          marginBottom: '0.6rem'
        }}>
          Extracted Flow Dynamics (ESP Encrypted Data Plane)
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))',
          gap: '0.5rem'
        }}>
          {[
            { label: 'Mean Packet Size', val: `${kf.mean_packet_length || 0} B` },
            { label: 'Size Dispersion', val: `± ${kf.packet_length_std || 0} B` },
            { label: 'Mean IAT Pacing', val: `${kf.mean_iat_ms || 0} ms` },
            { label: 'Burstiness Index', val: kf.burstiness_index || 0 },
            { label: 'Small Packets (<250B)', val: `${((kf.small_packet_ratio || 0) * 100).toFixed(1)}%` },
            { label: 'Large MTU (>900B)', val: `${((kf.large_packet_ratio || 0) * 100).toFixed(1)}%` }
          ].map((item, i) => (
            <div
              key={i}
              style={{
                padding: '0.6rem 0.75rem',
                background: 'var(--glass-inner)',
                border: '1px solid var(--glass-inner-border)',
                borderRadius: 'var(--radius-sm)',
                display: 'flex',
                flexDirection: 'column'
              }}
            >
              <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: '2px' }}>{item.label}</span>
              <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>{item.val}</span>
            </div>
          ))}
        </div>
      </div>
    </GlassCard>
  )
}
