import Header from '../components/Header'
import GlassCard from '../components/GlassCard'
import MetricCard from '../components/MetricCard'
import SecurityScore from '../components/SecurityScore'
import SystemStatus from '../components/SystemStatus'
import VPNStatus from '../components/VPNStatus'
import StatsGrid from '../components/StatsGrid'
import EventFeed from '../components/EventFeed'
import {TrafficChart,RiskChart} from '../components/TrafficChart'
import RotatingEarth from '../components/RotatingEarth'
import ScrollReveal from '../components/ScrollReveal'
import NetworkBackground from '../components/NetworkBackground'
import {AlertCircle, RefreshCw, Globe, Wifi, Shield, Activity} from 'lucide-react'

export default function Dashboard({data,connection,error,retry,theme,toggleTheme}){
 if(!data) return <><Header connection={connection} mode="MOCK" theme={theme} toggleTheme={toggleTheme}/><main className="shell"><div className="loading"><div className="spinner"/><h2>Initializing secure telemetry</h2><p>{error||'Connecting to the analyzer backend…'}</p>{error&&<button onClick={retry}><RefreshCw size={15}/> Retry</button>}</div></main></>
 const {vpn,metrics,security,events,history,mode}=data
 return <><Header connection={connection} mode={mode} theme={theme} toggleTheme={toggleTheme}/><main className="shell">
 <div id="top"><ScrollReveal><div className="hero"><div><span className="eyebrow">SECURITY OPERATIONS · IPSEC · REAL-TIME</span><h1>Network Security<br/>Intelligence.</h1><p>Live telemetry from the VPN tunnel and behavioral security engine. Built for clarity under pressure.</p></div><div className="hero-right"><SystemStatus security={security} events={events}/><div className="timestamp">Updated {new Date(data.timestamp).toLocaleTimeString()}</div></div></div></ScrollReveal></div>
 {error&&<div className="error-banner"><AlertCircle size={16}/><span>{error} · Live stream will keep retrying.</span></div>}
 <div className="top-grid">
  <section id="security"><ScrollReveal delay={0} contents><SecurityScore score={security.risk_score} level={security.risk_level} anomaly={security.anomaly_detected}/></ScrollReveal></section>
  <section id="vpn"><ScrollReveal delay={80} contents><VPNStatus vpn={vpn}/></ScrollReveal></section>
  <div className="metric-stack">
   <ScrollReveal delay={160}><MetricCard kind="packets" label="Packets / sec" rawValue={Math.round(metrics.packets_per_second)} formatValue={n => Math.round(n).toLocaleString()} unit="pps" detail={`${Math.round(metrics.bytes_per_second/1000).toLocaleString()} KB/s sustained`}/></ScrollReveal>
   <ScrollReveal delay={240}><MetricCard kind="flows" label="Active flows" rawValue={metrics.active_flows} unit="" detail={`${metrics.average_packet_size} B average packet`}/></ScrollReveal>
  </div>
 </div>
 <section id="traffic"><ScrollReveal><TrafficChart history={history}/></ScrollReveal></section>
 <div className="globe-section">
  <ScrollReveal delay={0} contents><GlassCard className="globe-card">
   <div className="card-title-row"><h3>Global Threat Map</h3><span className="live-badge"><span className="live-dot"/>LIVE</span></div>
   <p style={{fontSize:11,color:'var(--text-secondary)',margin:'4px 0 0',lineHeight:1.5}}>Real-time IPsec tunnel endpoints across the globe. Drag to rotate.</p>
   <div className="globe-wrap"><RotatingEarth size={300}/></div>
   <div className="globe-hint">Drag to rotate · Scroll to zoom</div>
  </GlassCard></ScrollReveal>
  <ScrollReveal delay={80} contents><GlassCard className="globe-stats">
   <div className="card-title-row"><h3>Tunnel Intelligence</h3></div>
   {[
    {label:'Active Endpoints', value: vpn.peer_ip || '203.0.113.42'},
    {label:'Tunnel Protocol',  value: vpn.protocol || 'IKEv2/ESP'},
    {label:'Encryption',       value: vpn.encryption || 'AES-256-GCM'},
    {label:'Auth Method',      value: vpn.auth || 'RSA-4096'},
    {label:'Uptime',           value: vpn.uptime || '14d 6h 32m'},
    {label:'Bytes Transferred',value: `${(metrics.bytes_per_second/1000*86400).toFixed(0)} MB/day`},
    {label:'Threat Level',     value: security.risk_level,
     color: security.risk_level==='LOW' ? '#00ff88' : security.risk_level==='MEDIUM' ? '#fbbf24' : '#f87171'},
    {label:'Anomalies',        value: security.anomaly_detected ? 'DETECTED' : 'None',
     color: security.anomaly_detected ? '#f87171' : '#00ff88'},
   ].map(({label,value,color})=>(
    <div key={label} className="globe-stat-row">
     <span className="globe-stat-label">{label}</span>
     <span className="globe-stat-value" style={{color: color || 'var(--text-primary)'}}>{value}</span>
    </div>
   ))}
  </GlassCard></ScrollReveal>
 </div>
 <div className="lower-grid">
  <ScrollReveal delay={0} contents><StatsGrid metrics={metrics}/></ScrollReveal>
  <ScrollReveal delay={80} contents><RiskChart history={history} level={security.risk_level}/></ScrollReveal>
 </div>
 <section id="events"><ScrollReveal><EventFeed events={events}/></ScrollReveal></section>
 <footer>IPsec VPN Analyzer · SIH26 · Integration-ready telemetry layer</footer></main></>
}
