import { ShieldCheck, Radio, SunMoon } from 'lucide-react'

const NAV_ITEMS = [
  { label: 'HOME',     href: '#top' },
  { label: 'SECURITY', href: '#security' },
  { label: 'TRAFFIC',  href: '#traffic' },
  { label: 'EVENTS',   href: '#events' },
  { label: 'VPN',      href: '#vpn' },
]

export default function Header({ connection, mode, theme, toggleTheme }) {
  const handleNav = (href) => {
    const el = document.querySelector(href)
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <header className="topbar">
      <div className="brand">
        <div className="brand-mark"><ShieldCheck size={21} /></div>
        <div>
          <div className="brand-title">IPsec VPN <em>Analyzer</em></div>
          <div className="brand-sub">Real-time Network Security Intelligence</div>
        </div>
      </div>

      <nav className="nav-links" aria-label="Dashboard navigation">
        {NAV_ITEMS.map(({ label, href }) => (
          <button
            key={label}
            className={`nav-link${href === '#top' ? ' active' : ''}`}
            onClick={() => handleNav(href)}
          >
            {label}
          </button>
        ))}
      </nav>

      <div className="top-actions">
        <span className={`live-badge live-pill ${connection.toLowerCase()}`}>
          <span className="live-dot" />{connection}
        </span>
        <span className="mode-pill"><Radio size={14} />{mode} DATA</span>
        <button
          className="icon-button"
          onClick={toggleTheme}
          title={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}
          aria-label="Toggle theme"
        >
          <SunMoon size={17} />
        </button>
      </div>
    </header>
  )
}
