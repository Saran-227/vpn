import { useState, useEffect } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import GlassSurface from './GlassSurface'

const NAV_ITEMS = [
  { label: 'HOME', href: '#top' },
  { label: 'SECURITY', href: '#security' },
  { label: 'TRAFFIC', href: '#traffic' },
  { label: 'VPN', href: '#vpn' },
  { label: 'EVENTS', href: '#events' },
]

export default function Header() {
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
      <GlassSurface
        width="auto"
        height="auto"
        borderRadius={50}
        borderWidth={0.06}
        brightness={50}
        opacity={0.75}
        blur={12}
        backgroundOpacity={0.03}
        saturation={1.2}
        className="nav-glass-pill"
        style={{
          border: '2px solid rgba(255, 255, 255, 0.20)',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.35)',
        }}
      >
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
      </GlassSurface>
    </header>
  )
}
