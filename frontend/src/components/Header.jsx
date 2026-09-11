import { ShieldCheck, Radio, SunMoon } from 'lucide-react'
import { useState, useEffect } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'

const NAV_ITEMS = [
  { label: 'HOME',     href: '#top' },
  { label: 'SECURITY', href: '#security' },
  { label: 'TRAFFIC',  href: '#traffic' },
  { label: 'EVENTS',   href: '#events' },
  { label: 'VPN',      href: '#vpn' },
]

export default function Header({ connection, mode, theme, toggleTheme }) {
  const [active, setActive] = useState('#top')
  const location = useLocation()
  const navigate = useNavigate()
  const isAbout = location.pathname === '/about'

  useEffect(() => {
    if (isAbout) return
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
  }, [isAbout])

  const handleNav = (href) => {
    if (isAbout) {
      navigate('/')
      setTimeout(() => {
        const el = document.querySelector(href)
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
      }, 100)
    } else {
      const el = document.querySelector(href)
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
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
            className={`nav-link${!isAbout && active === href ? ' active' : ''}`}
            onClick={() => handleNav(href)}
          >
            {label}
          </button>
        ))}
        <Link
          to="/about"
          className={`nav-link${isAbout ? ' active' : ''}`}
        >
          ABOUT
        </Link>
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
