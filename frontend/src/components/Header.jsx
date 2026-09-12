import React, { useState, useEffect } from 'react'
import { ShieldCheck, Trophy, Printer, SunMoon, Radio } from 'lucide-react'

const NAV_ITEMS = [
  { label: 'OVERVIEW', href: '#top' },
  { label: 'INGESTION', href: '#ingestion' },
  { label: 'SECURITY AUDIT', href: '#audit' },
  { label: 'AI TELEMETRY', href: '#ai-telemetry' },
  { label: 'TIMELINE', href: '#timeline' },
]

export default function Header({ connection = 'LIVE', mode = 'OFFLINE SECURE', onOpenTournament }) {
  const [active, setActive] = useState('#top')

  useEffect(() => {
    const ids = NAV_ITEMS.map(n => n.href.slice(1))
    const observer = new IntersectionObserver(
      entries => {
        entries.forEach(e => {
          if (e.isIntersecting) setActive(`#${e.target.id}`)
        })
      },
      { rootMargin: '-60px 0px -60% 0px', threshold: 0 }
    )
    ids.forEach(id => {
      const el = document.getElementById(id)
      if (el) observer.observe(el)
    })
    return () => observer.disconnect()
  }, [])

  const handleNav = (href) => {
    const el = document.querySelector(href)
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <header className="topbar">
      <div className="brand" onClick={() => handleNav('#top')} style={{ cursor: 'pointer' }}>
        <div className="brand-mark"><ShieldCheck size={21} /></div>
        <div>
          <div className="brand-title">NTRO IPsec <em>Intelligence</em></div>
          <div className="brand-sub">SIH26160 · Automated Cryptographic Audit &amp; AI Classifier</div>
        </div>
      </div>

      <nav className="nav-links" aria-label="Dashboard navigation">
        {NAV_ITEMS.map(({ label, href }) => (
          <button
            key={label}
            className={`nav-link${active === href ? ' active' : ''}`}
            onClick={() => handleNav(href)}
          >
            {label}
          </button>
        ))}
      </nav>

      <div className="top-actions">
        {onOpenTournament && (
          <button
            onClick={onOpenTournament}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              padding: '0.4rem 0.75rem',
              borderRadius: 'var(--radius-xs)',
              background: 'linear-gradient(135deg, rgba(251,191,36,0.15), rgba(251,191,36,0.05))',
              border: '1px solid rgba(251,191,36,0.3)',
              color: 'var(--accent-amber)',
              fontSize: '0.75rem',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            <Trophy size={14} />
            <span>AI Tournament</span>
          </button>
        )}

        <button
          onClick={() => window.print()}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.35rem',
            padding: '0.4rem 0.75rem',
            borderRadius: 'var(--radius-xs)',
            background: 'var(--glass-inner)',
            border: '1px solid var(--border)',
            color: 'var(--text-primary)',
            fontSize: '0.75rem',
            fontWeight: 600,
            cursor: 'pointer'
          }}
          title="Print or export advisory report"
        >
          <Printer size={14} />
          <span>Export Advisory</span>
        </button>
      </div>
    </header>
  )
}
