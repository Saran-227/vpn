import React from 'react'
import GlassCard from './GlassCard'
import { Clock, Radio, Shield, Activity } from 'lucide-react'

export default function TimelineSlices({ slices = [] }) {
  if (!slices || slices.length === 0) return null

  return (
    <GlassCard className="timeline-slices-card">
      <div className="card-title-row">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div className="icon-wrapper" style={{ width: 32, height: 32 }}>
            <Clock size={16} color="var(--accent-blue)" />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600 }}>Sliding Window Temporal Breakdown</h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              1.5s sliding window slices separating IKE control plane from active ESP tunnel streams
            </span>
          </div>
        </div>
        <span style={{
          fontSize: '0.7rem',
          fontFamily: 'monospace',
          color: 'var(--text-muted)'
        }}>
          {slices.length} Windows
        </span>
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(170px, 1fr))',
        gap: '0.65rem',
        marginTop: '1rem',
        maxHeight: '280px',
        overflowY: 'auto',
        paddingRight: '4px'
      }}>
        {slices.map((slice, i) => {
          const isCtrl = slice.is_control_plane
          const isMixed = slice.predicted_class === 'voip+bulk' || slice.predicted_class === 'mixed'

          return (
            <div
              key={i}
              style={{
                padding: '0.65rem 0.75rem',
                borderRadius: 'var(--radius-sm)',
                background: isCtrl
                  ? 'rgba(147, 197, 253, 0.06)'
                  : isMixed
                    ? 'rgba(192, 132, 252, 0.08)'
                    : 'var(--glass-inner)',
                border: `1px solid ${
                  isCtrl
                    ? 'rgba(147, 197, 253, 0.25)'
                    : isMixed
                      ? 'rgba(192, 132, 252, 0.25)'
                      : 'var(--glass-inner-border)'
                }`,
                display: 'flex',
                flexDirection: 'column',
                gap: '2px'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.7rem', fontFamily: 'monospace', color: 'var(--text-muted)' }}>
                  +{slice.time_offset_sec.toFixed(1)}s
                </span>
                <span style={{
                  fontSize: '0.65rem',
                  fontWeight: 700,
                  padding: '1px 5px',
                  borderRadius: '3px',
                  background: isCtrl ? 'var(--accent-soft)' : isMixed ? 'rgba(192,132,252,0.2)' : 'var(--green-soft)',
                  color: isCtrl ? 'var(--accent-blue)' : isMixed ? '#c084fc' : 'var(--accent-green)'
                }}>
                  {isCtrl ? 'SIGNALING' : `${(slice.confidence * 100).toFixed(0)}%`}
                </span>
              </div>

              <div style={{
                fontSize: '0.82rem',
                fontWeight: 600,
                color: isCtrl ? 'var(--accent-blue)' : isMixed ? '#c084fc' : 'var(--text-primary)',
                marginTop: '3px'
              }}>
                {slice.predicted_class.toUpperCase()}
              </div>

              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                {slice.packet_count} pkts ({slice.duration_sec}s)
              </div>
            </div>
          )
        })}
      </div>
    </GlassCard>
  )
}
