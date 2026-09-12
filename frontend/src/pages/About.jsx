import { Link } from 'react-router-dom'
import Header from '../components/Header'
import GlassCard from '../components/GlassCard'
import ScrollReveal from '../components/ScrollReveal'
import NetworkBackground from '../components/NetworkBackground'
import {
  ShieldCheck, Activity, Globe, Zap, Lock, Radio,
  ArrowRight, Database, Server, Code2, Layers,
  AlertTriangle, CheckCircle, Clock, ChevronLeft,
  Wifi, BarChart2, FileText, Eye, Cpu, GitBranch,
} from 'lucide-react'

/* ── Data ──────────────────────────────────────────────────────────────── */

const FEATURES = [
  { icon: <Activity size={16}/>, title: 'Real-time Monitoring', desc: 'Live packet-rate, byte-rate and flow telemetry streamed every 2 seconds via WebSocket.' }, // TODO: update desc when live
  { icon: <ShieldCheck size={16}/>, title: 'Security Risk Score', desc: 'Continuous 0–100 risk score with LOW / MEDIUM / HIGH / CRITICAL classification.' },
  { icon: <Wifi size={16}/>, title: 'Tunnel Status', desc: 'IKEv2/ESP tunnel health, endpoint IPs, encryption cipher and live uptime counter.' },
  { icon: <BarChart2 size={16}/>, title: 'Traffic Analytics', desc: 'Inbound/outbound split, packet-rate history chart and risk-trend chart over 60 data points.' },
  { icon: <AlertTriangle size={16}/>, title: 'Security Events', desc: 'Severity-tagged event feed (INFO → CRITICAL) with live-in animation for new entries.' },
  { icon: <Globe size={16}/>, title: 'Global Threat Map', desc: 'Interactive D3-powered rotating globe showing active IPsec tunnel endpoints.' },
  { icon: <Radio size={16}/>, title: 'WebSocket Updates', desc: 'Auto-reconnecting WebSocket with exponential backoff and RECONNECTING status indicator.' },
  { icon: <GitBranch size={16}/>, title: 'Adapter Architecture', desc: 'AsimAdapter and SermisthaAdapter boundaries isolate teammate schemas from the React frontend.' },
  { icon: <Database size={16}/>, title: 'Mock Mode', desc: 'Realistic synthetic telemetry with traffic bursts, anomalies and risk fluctuations — no backend required.' },
]

const TECH_FRONTEND = [
  { icon: '⚛️', name: 'React 18', cat: 'UI Framework' },
  { icon: '⚡', name: 'Vite', cat: 'Build Tool' },
  { icon: '🔀', name: 'React Router v7', cat: 'Routing' },
  { icon: '📊', name: 'Recharts', cat: 'Charts' },
  { icon: '🌍', name: 'D3.js v7', cat: 'Globe / SVG' },
  { icon: '🎨', name: 'Lucide React', cat: 'Icons' },
]

const TECH_BACKEND = [
  { icon: '🐍', name: 'Python 3', cat: 'Language' },
  { icon: '🚀', name: 'FastAPI', cat: 'API Framework' },
  { icon: '🦄', name: 'Uvicorn', cat: 'ASGI Server' },
  { icon: '✅', name: 'Pydantic v2', cat: 'Schema / Validation' },
  { icon: '🔌', name: 'WebSocket', cat: 'Real-time Transport' },
  { icon: '🧪', name: 'Pytest + HTTPX', cat: 'Testing' },
]

const IPSEC_CONCEPTS = [
  { tag: 'IPsec', title: 'IP Security', body: 'A suite of protocols that authenticate and encrypt each IP packet in a communication session. Operates at the network layer, making it transparent to applications.' },
  { tag: 'IKEv2', title: 'Internet Key Exchange v2', body: 'The protocol used to set up a Security Association (SA) in the IPsec suite. Handles mutual authentication and negotiates cryptographic keys between endpoints.' },
  { tag: 'ESP', title: 'Encapsulating Security Payload', body: 'Provides confidentiality, data-origin authentication and replay protection. Encrypts the payload of each packet using the negotiated cipher (e.g. AES-256-GCM).' },
  { tag: 'AES-256-GCM', title: 'Encryption Cipher', body: 'Advanced Encryption Standard with 256-bit keys in Galois/Counter Mode. Provides both encryption and authentication in a single pass — the industry standard for VPN tunnels.' },
]

const TEAM = [
  { initials: 'A', name: 'Asim', role: 'Feature Extractor', badge: 'ML / Packet Analysis', color: '#93c5fd' },
  { initials: 'S', name: 'Sermistha', role: 'Security Engine', badge: 'Risk Assessment', color: '#34d399' },
  { initials: 'Sa', name: 'Saran', role: 'Endpoint A', badge: 'Network / VPN', color: '#fbbf24' },
  { initials: 'Sh', name: 'Shrey', role: 'Endpoint B', badge: 'Infrastructure', color: '#f87171' },
]

const STATUS = {
  done: [
    'FastAPI REST + WebSocket backend',
    'Pydantic standardized contract',
    'MockDataProvider with realistic telemetry',
    'React dashboard with glassmorphism UI',
    'Real-time WebSocket with auto-reconnect',
    'Security risk score + event feed',
    'Traffic + risk history charts',
    'D3 rotating globe (Global Threat Map)',
    'Adapter boundary stubs (Asim + Sermistha)',
    'Backend test suite (pytest + httpx)',
  ],
  ready: [
    'AsimAdapter.adapt() — awaiting final feature schema',
    'SermisthaAdapter.adapt() — awaiting security-engine schema',
    'DATA_MODE=REAL env switch in DashboardService',
    'Frontend requires zero changes on integration',
  ],
  future: [
    'Historical session replay and audit log export',
    'Multi-tunnel support with per-tunnel dashboards',
    'Alert notification system (email / webhook)',
    'ML-based anomaly baseline auto-calibration',
    'Role-based access control for the dashboard',
  ],
}

const FAQ = [
  { q: 'What does this dashboard actually show?', a: 'Live IPsec VPN telemetry: packet rates, byte throughput, tunnel health, a security risk score, anomaly detection, a security event feed and a global threat map — all updated every 2 seconds via WebSocket.' },
  { q: 'What is Mock Mode?', a: 'When DATA_MODE=MOCK (the default), the backend\'s MockDataProvider generates realistic synthetic telemetry including traffic bursts, risk fluctuations and anomaly events. The full dashboard works without any real VPN infrastructure.' },
  { q: 'Who are Asim and Sermistha?', a: 'Asim is building the feature extractor that processes raw packet captures. Sermistha is building the security assessment engine that produces risk scores and findings. Each has a dedicated adapter class (AsimAdapter, SermisthaAdapter) that maps their output to the standardized Pydantic contract without touching the React frontend.' },
  { q: 'Will the frontend need to change when real data is integrated?', a: 'No. The adapter pattern ensures the frontend only ever consumes the standardized DashboardState contract. Only the adapter adapt() methods need to be implemented.' },
  { q: 'What is IPsec and why does it need monitoring?', a: 'IPsec is a network-layer security protocol suite used to encrypt and authenticate IP traffic in VPN tunnels. Monitoring is critical to detect anomalous traffic patterns, cipher negotiation failures, replay attacks and unexpected tunnel drops in real time.' },
  { q: 'How does the WebSocket reconnection work?', a: 'The useDashboardData hook connects to ws://localhost:8000/ws/dashboard. On disconnect it retries with exponential backoff (up to 30 s). The header badge changes to RECONNECTING during the retry window.' },
]

/* ── Component ─────────────────────────────────────────────────────────── */

// TODO (backend adapter): connection prop will reflect live WebSocket state
// ('LIVE' | 'RECONNECTING' | 'CONNECTING') once backendAdapter.js is wired in.
export default function About({ connection }) {
  return (
    <>
      <Header connection={connection ?? 'MOCK'} mode="MOCK" theme="dark" toggleTheme={() => {}} />
      <NetworkBackground />
      <main className="about-shell">

        {/* Back */}
        <ScrollReveal>
          <Link to="/" className="about-back-btn">
            <ChevronLeft size={14} /> Back to Dashboard
          </Link>
        </ScrollReveal>

        {/* ── Hero ── */}
        <ScrollReveal delay={60}>
          <div className="about-hero">
            <span className="eyebrow">SIH 2026 · SMART INDIA HACKATHON · SECURITY TRACK</span>
            <h1>IPsec VPN<br/><em>Analyzer</em></h1>
            <p className="about-tagline">
              A real-time network security intelligence dashboard for IPsec VPN tunnels —
              built with a React frontend, FastAPI backend and a clean adapter architecture
              ready for ML-powered threat detection.
            </p>
            <div className="about-hero-badges">
              <span className="about-badge green"><CheckCircle size={12}/>Integration-Ready</span>
              <span className="about-badge blue"><Radio size={12}/>WebSocket Live</span>
              <span className="about-badge amber"><Zap size={12}/>Mock Mode Active</span>
            </div>
          </div>
        </ScrollReveal>

        {/* ── Problem Statement ── */}
        <ScrollReveal delay={80}>
          <div className="about-section">
            <div className="about-section-label"><AlertTriangle size={13}/>Problem Statement</div>
            <GlassCard>
              <p className="about-problem-text">
                <strong>IPsec VPN tunnels are critical infrastructure</strong> for secure enterprise and government communications,
                yet most existing monitoring tools provide only static snapshots or require expensive commercial SIEM platforms.
                Security teams lack a <strong>real-time, unified view</strong> of tunnel health, encrypted traffic behaviour and
                emerging threats across their VPN fabric.
              </p>
              <p className="about-problem-text" style={{marginTop:14}}>
                The challenge is to build an <strong>intelligent VPN analyzer</strong> that ingests raw packet-level features,
                applies a security assessment engine to detect anomalies and risk, and presents actionable intelligence
                through a live dashboard — while keeping the data pipeline modular so that ML components can be
                swapped in without rewriting the visualization layer.
              </p>
            </GlassCard>
          </div>
        </ScrollReveal>

        {/* ── Our Solution ── */}
        <ScrollReveal delay={80}>
          <div className="about-section">
            <div className="about-section-label"><CheckCircle size={13}/>Our Solution</div>
            <GlassCard>
              <p className="about-problem-text">
                We built a <strong>full-stack, integration-ready dashboard</strong> that separates concerns cleanly:
                a standardized Pydantic contract sits between the ML pipeline and the React UI, so neither side
                needs to know the other's internal schema.
              </p>
              <div className="about-solution-grid">
                <div className="about-solution-item">
                  <div className="about-solution-icon"><Layers size={16}/></div>
                  <div>
                    <b>Adapter Pattern</b>
                    <span>AsimAdapter and SermisthaAdapter translate teammate outputs into a single DashboardState contract.</span>
                  </div>
                </div>
                <div className="about-solution-item">
                  <div className="about-solution-icon"><Radio size={16}/></div>
                  <div>
                    <b>WebSocket Streaming</b>
                    <span>FastAPI pushes a complete dashboard snapshot every 2 seconds. The frontend reconnects automatically.</span>
                  </div>
                </div>
                <div className="about-solution-item">
                  <div className="about-solution-icon"><Eye size={16}/></div>
                  <div>
                    <b>Live Risk Intelligence</b>
                    <span>Continuous risk scoring, anomaly detection and severity-tagged event feed with real-time animations.</span>
                  </div>
                </div>
                <div className="about-solution-item">
                  <div className="about-solution-icon"><Database size={16}/></div>
                  <div>
                    <b>Mock-First Development</b>
                    <span>Realistic synthetic telemetry lets the full dashboard run and demo before any ML component is ready.</span>
                  </div>
                </div>
              </div>
            </GlassCard>
          </div>
        </ScrollReveal>

        {/* ── Key Features ── */}
        <ScrollReveal delay={80}>
          <div className="about-section">
            <div className="about-section-label"><Zap size={13}/>Key Features</div>
            <div className="about-features-grid">
              {FEATURES.map(f => (
                <div key={f.title} className="about-feature-card glass-card">
                  <div className="about-feature-icon">{f.icon}</div>
                  <b>{f.title}</b>
                  <p>{f.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </ScrollReveal>

        {/* ── Architecture ── */}
        <ScrollReveal delay={80}>
          <div className="about-section">
            <div className="about-section-label"><GitBranch size={13}/>Architecture</div>
            <GlassCard>
              <div className="about-arch">
                {/* Sources */}
                <div className="arch-group">
                  <span className="arch-group-label">Data Sources</span>
                  <div className="arch-node">
                    <div className="arch-node-icon"><Cpu size={16}/></div>
                    <b>Asim</b>
                    <span>Feature Extractor</span>
                  </div>
                  <div className="arch-node" style={{marginTop:10}}>
                    <div className="arch-node-icon"><ShieldCheck size={16}/></div>
                    <b>Sermistha</b>
                    <span>Security Engine</span>
                  </div>
                </div>

                <div className="arch-arrow"><ArrowRight size={18}/></div>

                {/* Adapters */}
                <div className="arch-group">
                  <span className="arch-group-label">Adapters</span>
                  <div className="arch-node">
                    <div className="arch-node-icon"><Code2 size={16}/></div>
                    <b>AsimAdapter</b>
                    <span>adapt()</span>
                  </div>
                  <div className="arch-node" style={{marginTop:10}}>
                    <div className="arch-node-icon"><Code2 size={16}/></div>
                    <b>SermisthaAdapter</b>
                    <span>adapt()</span>
                  </div>
                </div>

                <div className="arch-arrow"><ArrowRight size={18}/></div>

                {/* Contract */}
                <div className="arch-group">
                  <span className="arch-group-label">Contract</span>
                  <div className="arch-node">
                    <div className="arch-node-icon"><FileText size={16}/></div>
                    <b>DashboardState</b>
                    <span>Pydantic Schema</span>
                  </div>
                </div>

                <div className="arch-arrow"><ArrowRight size={18}/></div>

                {/* Backend */}
                <div className="arch-group">
                  <span className="arch-group-label">Backend</span>
                  <div className="arch-node">
                    <div className="arch-node-icon"><Server size={16}/></div>
                    <b>FastAPI</b>
                    <span>REST + WebSocket</span>
                  </div>
                </div>

                <div className="arch-arrow"><ArrowRight size={18}/></div>

                {/* Frontend */}
                <div className="arch-group">
                  <span className="arch-group-label">Frontend</span>
                  <div className="arch-node">
                    <div className="arch-node-icon"><Activity size={16}/></div>
                    <b>React Dashboard</b>
                    <span>Vite · port 5173</span>
                  </div>
                </div>
              </div>

              <p style={{fontSize:11,color:'var(--text-muted)',textAlign:'center',marginTop:20,marginBottom:0,letterSpacing:'.2px'}}>
                The frontend only consumes the standardized contract — teammate schemas never reach React components.
              </p>
            </GlassCard>
          </div>
        </ScrollReveal>

        {/* ── Technology Stack ── */}
        <ScrollReveal delay={80}>
          <div className="about-section">
            <div className="about-section-label"><Layers size={13}/>Technology Stack</div>
            <GlassCard>
              <p style={{fontSize:11,color:'var(--text-muted)',margin:'0 0 16px',letterSpacing:'.2px'}}>FRONTEND</p>
              <div className="about-tech-grid">
                {TECH_FRONTEND.map(t => (
                  <div key={t.name} className="about-tech-item">
                    <div className="about-tech-icon">{t.icon}</div>
                    <b>{t.name}</b>
                    <span>{t.cat}</span>
                  </div>
                ))}
              </div>
              <p style={{fontSize:11,color:'var(--text-muted)',margin:'24px 0 16px',letterSpacing:'.2px'}}>BACKEND</p>
              <div className="about-tech-grid">
                {TECH_BACKEND.map(t => (
                  <div key={t.name} className="about-tech-item">
                    <div className="about-tech-icon">{t.icon}</div>
                    <b>{t.name}</b>
                    <span>{t.cat}</span>
                  </div>
                ))}
              </div>
            </GlassCard>
          </div>
        </ScrollReveal>

        {/* ── IPsec Explainer ── */}
        <ScrollReveal delay={80}>
          <div className="about-section">
            <div className="about-section-label"><Lock size={13}/>IPsec Explained</div>
            <div className="about-ipsec-grid">
              {IPSEC_CONCEPTS.map(c => (
                <div key={c.tag} className="about-ipsec-item">
                  <h4><span className="ipsec-tag">{c.tag}</span>{c.title}</h4>
                  <p>{c.body}</p>
                </div>
              ))}
            </div>
          </div>
        </ScrollReveal>

        {/* ── Team ── */}
        <ScrollReveal delay={80}>
          <div className="about-section">
            <div className="about-section-label"><Eye size={13}/>Team</div>
            <div className="about-team-grid">
              {TEAM.map(m => (
                <div key={m.name} className="about-team-card glass-card">
                  <div className="about-team-avatar" style={{color: m.color, borderColor: m.color+'44', background: m.color+'18'}}>
                    {m.initials}
                  </div>
                  <b>{m.name}</b>
                  <span>{m.role}</span>
                  <div style={{marginTop:10}}>
                    <span className="about-badge" style={{fontSize:9,padding:'3px 10px'}}>{m.badge}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </ScrollReveal>

        {/* ── Project Status ── */}
        <ScrollReveal delay={80}>
          <div className="about-section">
            <div className="about-section-label"><CheckCircle size={13}/>Project Status</div>
            <GlassCard>
              <div className="about-status-grid">
                <div className="about-status-col">
                  <h4><span className="about-status-dot green"/>Implemented</h4>
                  <ul className="about-status-list">
                    {STATUS.done.map(s => <li key={s}>{s}</li>)}
                  </ul>
                </div>
                <div className="about-status-col">
                  <h4><span className="about-status-dot amber"/>Integration-Ready</h4>
                  <ul className="about-status-list">
                    {STATUS.ready.map(s => <li key={s}>{s}</li>)}
                  </ul>
                </div>
                <div className="about-status-col">
                  <h4><span className="about-status-dot blue"/>Future Work</h4>
                  <ul className="about-status-list">
                    {STATUS.future.map(s => <li key={s}>{s}</li>)}
                  </ul>
                </div>
              </div>
            </GlassCard>
          </div>
        </ScrollReveal>

        {/* ── FAQ ── */}
        <ScrollReveal delay={80}>
          <div className="about-section">
            <div className="about-section-label"><FileText size={13}/>FAQ</div>
            <GlassCard>
              <div className="about-faq">
                {FAQ.map(f => (
                  <div key={f.q} className="about-faq-item">
                    <b>{f.q}</b>
                    <p>{f.a}</p>
                  </div>
                ))}
              </div>
            </GlassCard>
          </div>
        </ScrollReveal>

        {/* ── Footer ── */}
        <ScrollReveal delay={80}>
          <GlassCard className="about-footer" style={{marginTop:48}}>
            <div className="about-footer-title">IPsec VPN Analyzer</div>
            <div className="about-footer-sub">
              Smart India Hackathon 2026 · Security Track · Integration-ready telemetry layer
            </div>
            <div style={{marginTop:16}}>
              <Link to="/" className="about-back-btn">
                <Activity size={13}/> Open Dashboard
              </Link>
            </div>
          </GlassCard>
        </ScrollReveal>

      </main>
    </>
  )
}
