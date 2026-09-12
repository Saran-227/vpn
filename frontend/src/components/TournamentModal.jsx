import React from 'react'
import { Trophy, X, Award, CheckCircle } from 'lucide-react'

export default function TournamentModal({ isOpen, onClose, tournamentData }) {
  if (!isOpen) return null

  const leaderboard = tournamentData?.leaderboard || []
  const champion = tournamentData?.champion || 'HistGradientBoosting'
  const testAcc = ((tournamentData?.test_accuracy || 0.805) * 100).toFixed(1)

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(5, 10, 30, 0.82)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1.5rem'
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: 'rgba(15, 25, 65, 0.88)',
          border: '1px solid var(--border-strong)',
          borderRadius: 'var(--radius-card)',
          boxShadow: '0 20px 60px rgba(0, 0, 40, 0.6), 0 0 40px rgba(147, 197, 253, 0.15)',
          maxWidth: '860px',
          width: '100%',
          maxHeight: '90vh',
          overflowY: 'auto',
          padding: '1.75rem'
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--separator)', paddingBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{
              width: 36,
              height: 36,
              borderRadius: '50%',
              background: 'linear-gradient(135deg, rgba(251, 191, 36, 0.25), rgba(251, 191, 36, 0.05))',
              border: '1px solid rgba(251, 191, 36, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <Trophy size={18} color="var(--accent-amber)" />
            </div>
            <div>
              <h2 style={{ margin: 0, fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                AI Model Tournament &amp; Multi-Model Benchmark
              </h2>
              <p style={{ margin: '2px 0 0', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                5-Fold Stratified Cross-Validation on 48 Signal Features (1,202 Dataset Vectors)
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '4px',
              borderRadius: 'var(--radius-xs)'
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Champion Callout */}
        <div style={{
          margin: '1.25rem 0',
          padding: '1rem',
          borderRadius: 'var(--radius-sm)',
          background: 'linear-gradient(135deg, rgba(147, 197, 253, 0.12), rgba(52, 211, 153, 0.08))',
          border: '1px solid var(--border-strong)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <div>
            <div style={{ fontSize: '0.72rem', color: 'var(--accent-blue)', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.08em' }}>
              CHAMPION ARCHITECTURE
            </div>
            <div style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
              {champion}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Highest generalization accuracy on non-linear feature interactions and overlapping traffic classes
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: 'var(--accent-green)', fontFamily: 'monospace' }}>
              {testAcc}%
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Held-Out Test Accuracy</div>
          </div>
        </div>

        {/* Leaderboard Table */}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--separator)', color: 'var(--text-muted)', fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                <th style={{ padding: '0.6rem 0.5rem' }}>Rank</th>
                <th style={{ padding: '0.6rem 0.5rem' }}>Model Architecture</th>
                <th style={{ padding: '0.6rem 0.5rem' }}>Paradigm</th>
                <th style={{ padding: '0.6rem 0.5rem' }}>5-Fold CV Acc</th>
                <th style={{ padding: '0.6rem 0.5rem' }}>Test Acc (20%)</th>
                <th style={{ padding: '0.6rem 0.5rem' }}>Test F1</th>
                <th style={{ padding: '0.6rem 0.5rem' }}>Train Time</th>
              </tr>
            </thead>
            <tbody>
              {leaderboard.map((m, idx) => {
                const isTop = idx === 0
                return (
                  <tr
                    key={m.model || idx}
                    style={{
                      borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
                      background: isTop ? 'rgba(147, 197, 253, 0.06)' : 'transparent',
                      color: isTop ? 'var(--text-primary)' : 'var(--text-secondary)'
                    }}
                  >
                    <td style={{ padding: '0.7rem 0.5rem', fontWeight: 700 }}>
                      {idx === 0 ? '🥇 1' : idx === 1 ? '🥈 2' : idx === 2 ? '🥉 3' : `${idx + 1}`}
                    </td>
                    <td style={{ padding: '0.7rem 0.5rem', fontWeight: isTop ? 700 : 500, color: isTop ? 'var(--accent-blue)' : 'inherit' }}>
                      {m.model}
                    </td>
                    <td style={{ padding: '0.7rem 0.5rem', color: 'var(--text-muted)' }}>
                      {m.type || 'Supervised'}
                    </td>
                    <td style={{ padding: '0.7rem 0.5rem', fontFamily: 'monospace' }}>
                      {(m.cv_accuracy * 100).toFixed(2)}%
                    </td>
                    <td style={{ padding: '0.7rem 0.5rem', fontFamily: 'monospace', fontWeight: 600, color: isTop ? 'var(--accent-green)' : 'inherit' }}>
                      {(m.test_accuracy * 100).toFixed(2)}%
                    </td>
                    <td style={{ padding: '0.7rem 0.5rem', fontFamily: 'monospace' }}>
                      {m.test_f1 ? m.test_f1.toFixed(4) : '--'}
                    </td>
                    <td style={{ padding: '0.7rem 0.5rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                      {m.train_time_sec ? `${m.train_time_sec.toFixed(1)}s` : '--'}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* Operational Mode Note */}
        <div style={{
          marginTop: '1.25rem',
          padding: '0.75rem 1rem',
          borderRadius: 'var(--radius-xs)',
          background: 'var(--glass-inner)',
          border: '1px solid var(--glass-inner-border)',
          fontSize: '0.75rem',
          color: 'var(--text-secondary)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <span>
            <strong>Operational Mode Classifier:</strong> Extra Trees Ensemble reached <strong>95.44% Accuracy</strong> distinguishing Tunnel vs. Transport mode.
          </span>
          <span style={{ color: 'var(--accent-green)', fontWeight: 600 }}>95.4% Precision</span>
        </div>
      </div>
    </div>
  )
}
