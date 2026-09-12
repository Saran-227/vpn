import { Monitor, Clock3 } from 'lucide-react'
import GlassCard from './GlassCard'

function fmt(s) {
  const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), sec = s % 60
  return `${h}h ${m}m ${sec}s`
}

const PACKETS = [0, 1, 2]

function Computer({ label, ip }) {
  return (
    <div className="vpn-computer">
      <div className="vpn-monitor">
        <Monitor size={38} strokeWidth={1.4} />
      </div>
      <span className="vpn-computer-label">{label}</span>
      <span className="vpn-computer-ip">{ip}</span>
    </div>
  )
}

// Props: vpn — { status, endpointA, endpointAIp, endpointB, endpointBIp,
//                 uptimeSeconds, protocol, encryption }
// TODO (backend adapter): vpn is mapped via mapVpnStatus() in backendAdapter.js
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
        <Computer label={vpn.endpointA} ip={vpn.endpointAIp} />

        <div className="tunnel-track" data-active={String(connected)}>
          {connected && PACKETS.map(i => (
            <span key={i} className="tunnel-packet" style={{ '--i': i }} />
          ))}
        </div>

        <Computer label={vpn.endpointB} ip={vpn.endpointBIp} />
      </div>

      <div className="vpn-meta">
        <span><Clock3 size={14} /> Uptime {fmt(vpn.uptimeSeconds)}</span>
        <span>{vpn.protocol}</span>
        <span>{vpn.encryption}</span>
      </div>
    </GlassCard>
  )
}