import { useRef, useState, useEffect } from 'react'
import { AlertTriangle, Info, ShieldAlert, Activity } from 'lucide-react'
import GlassCard from './GlassCard'
import useScrollReveal from '../hooks/useScrollReveal'

function ago(timestamp) {
  const seconds = Math.max(0, Math.round((Date.now() - new Date(timestamp).getTime()) / 1000))
  return seconds < 60 ? `${seconds}s ago` : `${Math.round(seconds / 60)}m ago`
}

const LIVE_COLOR = {
  info:     'rgba(56,189,248,0.06)',
  low:      'rgba(56,189,248,0.06)',
  medium:   'rgba(251,191,36,0.09)',
  high:     'rgba(255,107,53,0.10)',
  critical: 'rgba(255,77,109,0.12)',
}

export default function EventFeed({ events = [] }) {
  const [cardRef, cardRevealed] = useScrollReveal()
  const initialKeysRef = useRef(null)
  const [liveKeys, setLiveKeys] = useState(new Set())

  const visible = events.slice(0, 7)

  useEffect(() => {
    if (!cardRevealed) return
    if (initialKeysRef.current === null) {
      initialKeysRef.current = new Set(visible.map((e, i) => `${e.timestamp}-${i}`))
    }
  }, [cardRevealed])

  useEffect(() => {
    if (initialKeysRef.current === null) return
    const newLive = new Set()
    visible.forEach((e, i) => {
      const key = `${e.timestamp}-${i}`
      if (!initialKeysRef.current.has(key)) newLive.add(key)
    })
    if (newLive.size) setLiveKeys(prev => new Set([...prev, ...newLive]))
  }, [events])

  return (
    <GlassCard className="events-card">
      <div className="card-title-row">
        <div>
          <div className="section-kicker">EVENT STREAM</div>
          <h3>Recent security events</h3>
        </div>
        <span className="event-count">{events.length} events</span>
      </div>

      <div className="events-list" ref={cardRef}>
        {visible.map((event, index) => {
          const Icon =
            event.severity === 'HIGH' || event.severity === 'CRITICAL'
              ? ShieldAlert
              : event.severity === 'MEDIUM'
                ? AlertTriangle
                : event.type === 'FLOW'
                  ? Activity
                  : Info

          const severity = String(event.severity || 'INFO').toLowerCase()
          const key = `${event.timestamp}-${index}`
          const isLive = liveKeys.has(key)
          const staggerDelay = cardRevealed && !isLive ? index * 60 : 0

          return (
            <div
              className={`event sev-${severity}${isLive ? ' event-live' : ''}`}
              key={key}
              style={
                isLive
                  ? { '--live-color': LIVE_COLOR[severity] ?? LIVE_COLOR.info }
                  : cardRevealed
                    ? { animation: `event-row-in 550ms cubic-bezier(0.22,1,0.36,1) ${staggerDelay}ms both` }
                    : undefined
              }
            >
              <span className={`event-icon sev-${severity}`}>
                <Icon size={15} />
              </span>
              <div className="event-main">
                <b>{event.title}</b>
                <span>{event.description}</span>
              </div>
              <div className="event-side">
                <em className={`severity-pill sev-${severity}`}>{event.severity}</em>
                <small>{ago(event.timestamp)}</small>
              </div>
            </div>
          )
        })}
      </div>
    </GlassCard>
  )
}
