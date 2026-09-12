import { Activity, Gauge, Network, Zap } from 'lucide-react'
import GlassCard from './GlassCard'
import useAnimatedNumber from '../hooks/useAnimatedNumber'

const icons = { score: Gauge, packets: Zap, flows: Network, bytes: Activity }

function AnimatedValue({ raw, format }) {
  const animated = useAnimatedNumber(raw, 500)
  return <>{format(animated)}</>
}

export default function MetricCard({ kind, label, value, unit, detail, rawValue, formatValue }) {
  const Icon = icons[kind] || Activity
  const displayed = rawValue != null
    ? <AnimatedValue raw={rawValue} format={formatValue || (n => Math.round(n).toLocaleString())} />
    : value

  return (
    <GlassCard className="metric-card">
      <div className="metric-head"><span>{label}</span><span className="metric-icon"><Icon size={17} /></span></div>
      <div className="metric-value">{displayed}<small>{unit}</small></div>
      <div className="metric-detail">{detail}</div>
    </GlassCard>
  )
}
