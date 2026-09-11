import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts'
import { useRef, useEffect, useState } from 'react'
import GlassCard from './GlassCard'

// Fires for 600 ms when risk level changes, then settles — mirrors useRiskFlash in SecurityScore
function useRiskTransition(level) {
  const prev = useRef(level)
  const timer = useRef(null)
  const [transitioning, setTransitioning] = useState(false)
  useEffect(() => {
    if (prev.current === level) return
    prev.current = level
    if (typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    clearTimeout(timer.current)
    setTransitioning(true)
    timer.current = setTimeout(() => setTransitioning(false), 600)
    return () => clearTimeout(timer.current)
  }, [level])
  return transitioning
}

function shortTime(value) {
  return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

const TOOLTIP = {
  contentStyle: {
    background: 'rgba(10, 20, 60, 0.90)',
    border: '1px solid rgba(255, 255, 255, 0.16)',
    borderRadius: 14,
    color: 'rgba(255,255,255,0.90)',
    backdropFilter: 'blur(16px)',
    WebkitBackdropFilter: 'blur(16px)',
    fontSize: 12,
    padding: '10px 14px',
  },
  labelStyle: { color: 'rgba(255,255,255,0.55)', marginBottom: 4, fontSize: 11 },
  itemStyle: { color: 'rgba(255,255,255,0.90)', fontWeight: 600 },
  cursor: { stroke: 'rgba(147, 197, 253, 0.25)', strokeWidth: 1, strokeDasharray: '4 3' },
}

const noMotion = () =>
  typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches

function LiveDot({ cx, cy, index, dataLength, color }) {
  if (index !== dataLength - 1) return null
  return (
    <g>
      {!noMotion() && (
        <circle cx={cx} cy={cy} r={8} fill={color} opacity={0}
          style={{ animation: 'live-point-pulse 2.4s ease-out infinite' }} />
      )}
      <circle cx={cx} cy={cy} r={4} fill="#ffffff" stroke={color} strokeWidth={2} />
    </g>
  )
}

function TrafficInner({ history }) {
  const data = history.map(item => ({ ...item, time: shortTime(item.timestamp) }))
  const liveDot = (props) => <LiveDot {...props} dataLength={data.length} color="#93c5fd" />
  return (
    <div className="tc-inner">
      <div className="card-title-row">
        <div>
          <div className="section-kicker">NETWORK ACTIVITY</div>
          <h3>Packet rate</h3>
        </div>
        <span className="live-badge"><span className="live-dot" />LIVE</span>
      </div>
      <div className="chart">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <defs>
              <linearGradient id="packetFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%"  stopColor="#93c5fd" stopOpacity="0.22" />
                <stop offset="100%" stopColor="#93c5fd" stopOpacity="0" />
              </linearGradient>
            </defs>
            <CartesianGrid vertical={false} stroke="rgba(255,255,255,0.08)" strokeDasharray="0" />
            <XAxis dataKey="time" hide />
            <YAxis width={44} tick={{ fill: 'rgba(255,255,255,0.40)', fontSize: 10, fontWeight: 500 }} axisLine={false} tickLine={false} />
            <Tooltip {...TOOLTIP} formatter={v => [`${v} pkt/s`, 'Rate']} />
            <Area type="monotone" dataKey="packets_per_second" stroke="#93c5fd" strokeWidth={2}
              fill="url(#packetFill)" dot={liveDot} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

export function TrafficChart({ history = [], inline }) {
  if (inline) return <TrafficInner history={history}/>
  return (
    <GlassCard className="chart-card traffic">
      <TrafficInner history={history}/>
    </GlassCard>
  )
}

export function RiskChart({ history = [], level = 'LOW' }) {
  const data = history.map(item => ({ ...item, time: shortTime(item.timestamp) }))
  const liveDot = (props) => <LiveDot {...props} dataLength={data.length} color="#f87171" />
  const transitioning = useRiskTransition(level)
  const riskKey = level.toLowerCase()

  return (
    <GlassCard
      className="chart-card risk-chart"
      data-risk={riskKey}
      data-risk-transition={transitioning ? 'true' : undefined}
    >
      <div className="card-title-row">
        <div>
          <div className="section-kicker">SECURITY TREND</div>
          <h3>Risk score</h3>
        </div>
        <span className="chart-caption">Last 2 min</span>
      </div>
      <div className="chart">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <defs>
              <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%"  stopColor="#f87171" stopOpacity="0.3" />
                <stop offset="100%" stopColor="#f87171" stopOpacity="0" />
              </linearGradient>
            </defs>
            <CartesianGrid vertical={false} stroke="rgba(255,255,255,0.08)" strokeDasharray="0" />
            <XAxis dataKey="time" hide />
            <YAxis domain={[0, 100]} width={44} tick={{ fill: 'rgba(255,255,255,0.40)', fontSize: 10, fontWeight: 500 }} axisLine={false} tickLine={false} />
            <Tooltip {...TOOLTIP} formatter={v => [`${v}/100`, 'Risk']} />
            <Area
              type="monotone"
              dataKey="risk_score"
              stroke="#f87171"
              strokeWidth={2}
              fill="url(#riskFill)"
              dot={liveDot}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </GlassCard>
  )
}
