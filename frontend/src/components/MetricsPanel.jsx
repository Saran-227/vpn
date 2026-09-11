import { Zap, Network, ArrowDownToLine, ArrowUpFromLine, Database, Box } from 'lucide-react'
import GlassCard from './GlassCard'
import useAnimatedNumber from '../hooks/useAnimatedNumber'

const fmtBytes = n =>
  n >= 1e9 ? `${(n/1e9).toFixed(2)} GB`
  : n >= 1e6 ? `${(n/1e6).toFixed(1)} MB`
  : n >= 1e3 ? `${(n/1e3).toFixed(1)} KB`
  : `${Math.round(n)}`

function Row({ icon: Icon, label, value }) {
  return (
    <div className="mp-row">
      <span className="mp-row-icon"><Icon size={13}/></span>
      <span className="mp-row-label">{label}</span>
      <span className="mp-row-value">{value}</span>
    </div>
  )
}

function Inner({ metrics }) {
  const pps      = useAnimatedNumber(metrics.packets_per_second, 500)
  const flows    = useAnimatedNumber(metrics.active_flows, 400)
  const avgPkt   = useAnimatedNumber(metrics.average_packet_size, 400)
  const inbound  = useAnimatedNumber(metrics.inbound_bps, 400)
  const outbound = useAnimatedNumber(metrics.outbound_bps, 400)

  return (
    <div className="mp-inner">
      <div className="section-kicker">TELEMETRY</div>
      <h3>Traffic &amp; Metrics</h3>
      <div className="mp-hero">
        <div className="mp-big">
          <Zap size={15} style={{color:'var(--accent-blue)'}}/>
          <strong>{Math.round(pps).toLocaleString()}</strong>
          <small>pps</small>
        </div>
        <div className="mp-big">
          <Network size={15} style={{color:'var(--accent-blue)'}}/>
          <strong>{Math.round(flows)}</strong>
          <small>flows</small>
        </div>
      </div>
      <div className="mp-rows">
        <Row icon={Database}        label="Avg. packet" value={`${Math.round(avgPkt)} B`} />
        <Row icon={ArrowDownToLine} label="Inbound"     value={`${fmtBytes(inbound)}/s`} />
        <Row icon={ArrowUpFromLine} label="Outbound"    value={`${fmtBytes(outbound)}/s`} />
        <Row icon={Box}             label="Bandwidth"   value={`${Math.round(metrics.bytes_per_second/1000).toLocaleString()} KB/s`} />
      </div>
    </div>
  )
}

export default function MetricsPanel({ metrics, inline }) {
  if (inline) return <Inner metrics={metrics}/>
  return <GlassCard className="mp-card"><Inner metrics={metrics}/></GlassCard>
}
