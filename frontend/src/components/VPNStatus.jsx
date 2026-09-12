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

function VPNInner({ vpn }) {
  const connected = vpn.status === 'CONNECTED'

  return (
    <div className="vpn-inner-wrap">
      <div className="card-title-row">
        <div>
          <div className="section-kicker">TUNNEL STATUS</div>
          <h3>Encrypted Connection</h3>
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
        <span><Clock3 size={13} /> {fmt(vpn.uptimeSeconds)}</span>
        <span>{vpn.protocol}</span>
        <span>{vpn.encryption}</span>
        {vpn.authMethod && <span>{vpn.authMethod}</span>}
      </div>
    </div>
  )
}

// Props: vpn — { status, endpointA, endpointAIp, endpointB, endpointBIp,
//                 uptimeSeconds, protocol, encryption }, inline — boolean
// TODO (backend adapter): vpn is mapped via mapVpnStatus() in backendAdapter.js
export default function VPNStatus({ vpn, inline }) {
  if (inline) {
    return (
      <div className="vpn-card-inline">
        <VPNInner vpn={vpn} />
      </div>
    )
  }

  return (
    <GlassCard className="vpn-card">
      <VPNInner vpn={vpn} />
    </GlassCard>
  )
}