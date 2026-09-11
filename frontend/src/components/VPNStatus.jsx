import { LockKeyhole, Server, Clock3 } from 'lucide-react'
import GlassCard from './GlassCard'

function fmt(s) {
  const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), sec = s % 60
  return `${h}h ${m}m ${sec}s`
}

const PACKETS = [0, 1, 2]

export default function VPNStatus({ vpn }) {
  const connected = vpn.status === 'CONNECTED'

  return (
    <GlassCard className="vpn-card">
      <div className="card-title-row">
        <div>
          <div className="section-kicker">TUNNEL STATUS</div>
          <h3>Encrypted connection</h3>
        </div>
        <span className="status-badge"><span /> {vpn.status}</span>
      </div>

      <div className="tunnel">
        <div className="endpoint">
          <span className="endpoint-icon"><Server size={17} /></span>
          <div><b>Endpoint A</b><span>{vpn.endpoint_a}</span></div>
        </div>

        <div className="tunnel-track" data-active={String(connected)}>
          {connected && PACKETS.map(i => (
            <span key={i} className="tunnel-packet" style={{ '--i': i }} />
          ))}
        </div>

        <div className="endpoint">
          <span className="endpoint-icon"><LockKeyhole size={17} /></span>
          <div><b>{vpn.tunnel}</b><span>{vpn.endpoint_b}</span></div>
        </div>
      </div>

      <div className="vpn-meta">
        <span><Clock3 size={14} /> Uptime {fmt(vpn.uptime_seconds)}</span>
        <span>{vpn.protocol}</span>
        <span>{vpn.encryption}</span>
      </div>
    </GlassCard>
  )
}
