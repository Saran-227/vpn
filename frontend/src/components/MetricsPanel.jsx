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
      <div className="mp-row-left">
        <span className="mp-row-icon"><Icon size={13}/></span>
        <span className="mp-row-label">{label}</span>
      </div>
      <span className="mp-row-value">{value}</span>
    </div>
  )
}

// Props: metrics — { packetsPerSecond, activeFlows, avgPacketSize,
//                    inboundBps, outboundBps, bandwidthBps }
// TODO (backend adapter): metrics is mapped via mapMetrics() in backendAdapter.js
function Inner({ metrics }) {
  const pps      = useAnimatedNumber(metrics.packetsPerSecond, 500)
  const flows    = useAnimatedNumber(metrics.activeFlows, 400)
  const avgPkt   = useAnimatedNumber(metrics.avgPacketSize, 400)
  const inbound  = useAnimatedNumber(metrics.inboundBps, 400)
  const outbound = useAnimatedNumber(metrics.outboundBps, 400)

  return (
    <div className="mp-inner">
      <div className="card-title-row" style={{ marginBottom: 12 }}>
        <div>
          <div className="section-kicker">TELEMETRY</div>
          <h3>Traffic &amp; Metrics</h3>
        </div>
      </div>

      <div className="mp-hero">
        <div className="mp-big">
          <div className="mp-big-head">
            <Zap size={13} style={{ color: 'var(--accent-blue)' }} />
            <span>Rate</span>
          </div>
          <div className="mp-big-val">
            <strong>{Math.round(pps).toLocaleString()}</strong>
            <small>pps</small>
          </div>
        </div>
        <div className="mp-big">
          <div className="mp-big-head">
            <Network size={13} style={{ color: 'var(--accent-blue)' }} />
            <span>Flows</span>
          </div>
          <div className="mp-big-val">
            <strong>{Math.round(flows)}</strong>
            <small>active</small>
          </div>
        </div>
      </div>

      <div className="mp-rows">
        <Row icon={Database}        label="Avg. packet" value={`${Math.round(avgPkt)} B`} />
        <Row icon={ArrowDownToLine} label="Inbound"     value={`${fmtBytes(inbound)}/s`} />
        <Row icon={ArrowUpFromLine} label="Outbound"    value={`${fmtBytes(outbound)}/s`} />
        <Row icon={Box}             label="Bandwidth"   value={`${Math.round(metrics.bandwidthBps/1000).toLocaleString()} KB/s`} />
      </div>
    </div>
  )
}

export default function MetricsPanel({ metrics, inline }) {
  if (inline) return <Inner metrics={metrics}/>
  return <GlassCard className="mp-card"><Inner metrics={metrics}/></GlassCard>
}
