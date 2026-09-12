import { useRef, useEffect, useState } from 'react'
import { ArrowDownToLine, ArrowUpFromLine, Box, Database } from 'lucide-react'
import GlassCard from './GlassCard'
import useAnimatedNumber from '../hooks/useAnimatedNumber'

const fmtBytes = n =>
  n >= 1e9 ? `${(n / 1e9).toFixed(2)} GB`
  : n >= 1e6 ? `${(n / 1e6).toFixed(1)} MB`
  : n >= 1e3 ? `${(n / 1e3).toFixed(1)} KB`
  : `${Math.round(n)}`

const reduced = () =>
  typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches

// Fires 'true' for 380ms when the displayed value changes by more than `threshold`
function useValueFlash(value, threshold = 0.5) {
  const prev = useRef(value)
  const timer = useRef(null)
  const [flash, setFlash] = useState(false)
  useEffect(() => {
    if (Math.abs(value - prev.current) < threshold) { prev.current = value; return }
    prev.current = value
    if (reduced()) return
    clearTimeout(timer.current)
    setFlash(true)
    timer.current = setTimeout(() => setFlash(false), 380)
    return () => clearTimeout(timer.current)
  }, [value, threshold])
  return flash
}

function StatCell({ icon, label, value, flash }) {
  return (
    <div className="stat-cell">
      <div className="stat-cell-head">
        <span className="stat-icon">{icon}</span>
        <span className="stat-label">{label}</span>
      </div>
      <b className="stat-value" data-flash={flash ? 'true' : undefined}>{value}</b>
    </div>
  )
}

export default function StatsGrid({ metrics }) {
  const flows    = useAnimatedNumber(metrics.active_flows, 400)
  const avgPkt   = useAnimatedNumber(metrics.average_packet_size, 400)
  const inbound  = useAnimatedNumber(metrics.inbound_bps, 400)
  const outbound = useAnimatedNumber(metrics.outbound_bps, 400)

  const flashFlows    = useValueFlash(flows, 0.5)
  const flashAvgPkt   = useValueFlash(avgPkt, 0.5)
  const flashInbound  = useValueFlash(inbound, 50)
  const flashOutbound = useValueFlash(outbound, 50)

  return (
    <GlassCard className="stats-card">
      <div className="section-kicker">TELEMETRY</div>
      <h3>Traffic statistics</h3>
      <div className="stat-grid">
        <StatCell icon={<Box size={14} />}             label="Active flows" value={Math.round(flows)}              flash={flashFlows} />
        <StatCell icon={<Database size={14} />}        label="Avg. packet"  value={`${Math.round(avgPkt)} B`}     flash={flashAvgPkt} />
        <StatCell icon={<ArrowDownToLine size={14} />} label="Inbound"      value={`${fmtBytes(inbound)}/s`}      flash={flashInbound} />
        <StatCell icon={<ArrowUpFromLine size={14} />} label="Outbound"     value={`${fmtBytes(outbound)}/s`}     flash={flashOutbound} />
      </div>
    </GlassCard>
  )
}
