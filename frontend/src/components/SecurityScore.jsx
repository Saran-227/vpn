import { useRef, useEffect, useState } from 'react'
import GlassCard from './GlassCard'

const reduced = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches

const FLASH_SHADOW = {
  low:      '0 0 0 1px rgba(0,255,136,0.35),  0 0 24px rgba(0,255,136,0.18)',
  medium:   '0 0 0 1px rgba(251,191,36,0.35),  0 0 24px rgba(251,191,36,0.18)',
  high:     '0 0 0 1px rgba(251,191,36,0.35),  0 0 24px rgba(251,191,36,0.18)',
  critical: '0 0 0 1px rgba(248,113,113,0.35), 0 0 24px rgba(248,113,113,0.18)',
}

function useRiskFlash(level) {
  const prev = useRef(level)
  const timer = useRef(null)
  const [flash, setFlash] = useState(null)

  useEffect(() => {
    if (prev.current === level) return
    prev.current = level
    if (reduced()) return
    clearTimeout(timer.current)
    setFlash(level.toLowerCase())
    timer.current = setTimeout(() => setFlash(null), 700)
    return () => clearTimeout(timer.current)
  }, [level])

  return flash
}

function useAnimatedScore(target) {
  const [display, setDisplay] = useState(target)
  const raf = useRef(null)
  const from = useRef(target)

  useEffect(() => {
    if (reduced()) { from.current = target; setDisplay(target); return }
    cancelAnimationFrame(raf.current)
    const start = from.current
    const delta = target - start
    if (delta === 0) return
    const duration = 600
    const t0 = performance.now()
    const tick = (now) => {
      const p = Math.min((now - t0) / duration, 1)
      const eased = 1 - Math.pow(1 - p, 3) // ease-out cubic
      const val = start + delta * eased
      setDisplay(val)
      if (p < 1) raf.current = requestAnimationFrame(tick)
      else from.current = target
    }
    raf.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf.current)
  }, [target])

  return display
}

function ScoreInner({ displayScore, animated, level, anomaly }) {
  const riskClass = level.toLowerCase()
  return (
    <div className="score-inner-wrap">
      <div className="card-title-row">
        <div>
          <div className="section-kicker">SECURITY POSTURE</div>
          <h3>Threat Assessment</h3>
        </div>
        <span className={`status-badge risk-badge-${riskClass}`}>
          <span /> {level}
        </span>
      </div>

      <div className={`score-wrap risk-${riskClass}`}>
        <div className={`score-ring risk-${riskClass}`} style={{ '--score': animated }}>
          <div className="score-inner">
            <strong>{displayScore}</strong>
            <span>/ 100</span>
          </div>
        </div>
        <div className="score-copy">
          <div className="score-status-tag">
            {anomaly ? 'ANOMALY DETECTED' : 'SYSTEM HEALTHY'}
          </div>
          <p>{anomaly ? 'Behavioral anomaly detected in active tunnels' : 'All cryptographic & traffic parameters nominal'}</p>
          <div className="risk-scale">
            <span>LOW</span>
            <i />
            <span>CRIT</span>
          </div>
        </div>
      </div>
    </div>
  )
}

// Props: score — number (0–100), level — riskLevel string, anomaly — boolean, inline — boolean
// TODO (backend adapter): props come from mapSecurity() in backendAdapter.js
export default function SecurityScore({ score, level, anomaly, inline }) {
  const animated = useAnimatedScore(score)
  const displayScore = Math.round(animated)
  const flash = useRiskFlash(level)

  const cardStyle = flash
    ? { boxShadow: FLASH_SHADOW[flash], transition: 'box-shadow 0.15s ease-out' }
    : { transition: 'box-shadow 0.7s ease-out' }

  if (inline) {
    return (
      <div className="score-card-inline">
        <ScoreInner displayScore={displayScore} animated={animated} level={level} anomaly={anomaly} />
      </div>
    )
  }

  return (
    <GlassCard className="score-card" style={cardStyle}>
      <ScoreInner displayScore={displayScore} animated={animated} level={level} anomaly={anomaly} />
    </GlassCard>
  )
}