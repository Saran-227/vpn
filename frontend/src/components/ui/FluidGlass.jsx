import React, { useCallback, useEffect, useId, useRef, useState } from 'react'
import { Link } from 'react-router-dom'

const polarDisplacementMap = "data:image/jpeg;base64,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"

function ChromaticFluidFilter({ id, scale = 32, aberration = 2.0, width = 460, height = 64 }) {
  return (
    <svg style={{ position: 'absolute', width, height, pointerEvents: 'none', visibility: 'hidden' }} aria-hidden="true">
      <defs>
        <filter id={id} x="-20%" y="-20%" width="140%" height="140%" colorInterpolationFilters="sRGB">
          <feImage
            x="0"
            y="0"
            width="100%"
            height="100%"
            result="MAP"
            href={polarDisplacementMap}
            preserveAspectRatio="xMidYMid slice"
          />
          {/* Red Channel */}
          <feDisplacementMap
            in="SourceGraphic"
            in2="MAP"
            scale={scale * -1}
            xChannelSelector="R"
            yChannelSelector="G"
            result="R_DISP"
          />
          <feColorMatrix
            in="R_DISP"
            type="matrix"
            values="1 0 0 0 0
                    0 0 0 0 0
                    0 0 0 0 0
                    0 0 0 1 0"
            result="R_CH"
          />
          {/* Green Channel */}
          <feDisplacementMap
            in="SourceGraphic"
            in2="MAP"
            scale={scale * (-1 - aberration * 0.05)}
            xChannelSelector="R"
            yChannelSelector="G"
            result="G_DISP"
          />
          <feColorMatrix
            in="G_DISP"
            type="matrix"
            values="0 0 0 0 0
                    0 1 0 0 0
                    0 0 0 0 0
                    0 0 0 1 0"
            result="G_CH"
          />
          {/* Blue Channel */}
          <feDisplacementMap
            in="SourceGraphic"
            in2="MAP"
            scale={scale * (-1 - aberration * 0.10)}
            xChannelSelector="R"
            yChannelSelector="G"
            result="B_DISP"
          />
          <feColorMatrix
            in="B_DISP"
            type="matrix"
            values="0 0 0 0 0
                    0 0 0 0 0
                    0 0 1 0 0
                    0 0 0 1 0"
            result="B_CH"
          />
          {/* Blend Channels with smooth Gaussian falloff */}
          <feBlend in="G_CH" in2="B_CH" mode="screen" result="GB_COMB" />
          <feBlend in="R_CH" in2="GB_COMB" mode="screen" result="RGB_COMB" />
          <feGaussianBlur in="RGB_COMB" stdDeviation="0.35" result="SMOOTH" />
          <feBlend in="SourceGraphic" in2="SMOOTH" mode="normal" />
        </filter>
      </defs>
    </svg>
  )
}

/**
 * FluidGlass - Authentic 3D liquid lens glass navigation pill with buttery smooth
 * physics-based spring interpolation (lerp), caustic top glare, and responsive button feedback.
 */
export default function FluidGlass({
  navItems = [
    { label: 'HOME', href: '#top' },
    { label: 'SECURITY', href: '#security' },
    { label: 'TRAFFIC', href: '#traffic' },
    { label: 'VPN', href: '#vpn' },
    { label: 'EVENTS', href: '#events' },
  ],
  active = '#top',
  onNav,
  isAbout = false,
  children,
  className = '',
  style = {},
  displacementScale = 30,
  blurAmount = 26,
  saturation = 140,
  cornerRadius = 999
}) {
  const containerRef = useRef(null)
  const filterId = useId().replace(/:/g, '_')
  
  // Damped position state for butter-smooth gliding glare
  const [glarePos, setGlarePos] = useState({ x: 220, y: 15, normalizedX: 0, normalizedY: 0 })
  const targetPosRef = useRef({ x: 220, y: 15, normalizedX: 0, normalizedY: 0 })
  const currentPosRef = useRef({ x: 220, y: 15, normalizedX: 0, normalizedY: 0 })
  const animationFrameRef = useRef(null)

  const [isHovered, setIsHovered] = useState(false)
  const [pillDimensions, setPillDimensions] = useState({ width: 440, height: 60 })

  // Butter-smooth Lerp Loop
  useEffect(() => {
    let activeLoop = true

    const animate = () => {
      if (!activeLoop) return

      const damping = 0.12 // Smooth fluid elasticity
      const current = currentPosRef.current
      const target = targetPosRef.current

      current.x += (target.x - current.x) * damping
      current.y += (target.y - current.y) * damping
      current.normalizedX += (target.normalizedX - current.normalizedX) * damping
      current.normalizedY += (target.normalizedY - current.normalizedY) * damping

      setGlarePos({
        x: current.x,
        y: current.y,
        normalizedX: current.normalizedX,
        normalizedY: current.normalizedY
      })

      animationFrameRef.current = requestAnimationFrame(animate)
    }

    animationFrameRef.current = requestAnimationFrame(animate)

    return () => {
      activeLoop = false
      if (animationFrameRef.current) cancelAnimationFrame(animationFrameRef.current)
    }
  }, [])

  const handleMouseMove = useCallback((e) => {
    if (!containerRef.current) return
    const rect = containerRef.current.getBoundingClientRect()
    const x = e.clientX - rect.left
    const y = e.clientY - rect.top
    const centerX = rect.width / 2
    const centerY = rect.height / 2

    targetPosRef.current = {
      x,
      y,
      normalizedX: ((x - centerX) / rect.width) * 100,
      normalizedY: ((y - centerY) / rect.height) * 100
    }
  }, [])

  const handleMouseEnter = useCallback(() => {
    setIsHovered(true)
  }, [])

  const handleMouseLeave = useCallback(() => {
    setIsHovered(false)
    targetPosRef.current = {
      x: pillDimensions.width / 2,
      y: 15,
      normalizedX: 0,
      normalizedY: 0
    }
  }, [pillDimensions.width])

  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const updateSize = () => {
      const rect = el.getBoundingClientRect()
      if (rect.width && rect.height) {
        const width = Math.round(rect.width)
        const height = Math.round(rect.height)
        setPillDimensions({ width, height })
        targetPosRef.current.x = width / 2
        currentPosRef.current.x = width / 2
      }
    }
    updateSize()
    window.addEventListener('resize', updateSize)
    return () => window.removeEventListener('resize', updateSize)
  }, [])

  return (
    <div
      ref={containerRef}
      className={`fluid-glass-pill ${className}`}
      onMouseMove={handleMouseMove}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      style={{
        position: 'relative',
        display: 'inline-flex',
        alignItems: 'center',
        minHeight: '58px',
        padding: '8px 14px',
        borderRadius: `${cornerRadius}px`,
        overflow: 'hidden',
        backdropFilter: `blur(${blurAmount}px) saturate(${saturation}%)`,
        WebkitBackdropFilter: `blur(${blurAmount}px) saturate(${saturation}%)`,
        background: 'radial-gradient(ellipse 90% 70% at 50% 15%, rgba(255, 255, 255, 0.16) 0%, rgba(255, 255, 255, 0.07) 55%, rgba(200, 220, 245, 0.03) 100%)',
        border: '1px solid rgba(255, 255, 255, 0.20)',
        boxShadow: isHovered
          ? '0 18px 44px rgba(8, 26, 58, 0.32), 0 4px 12px rgba(12, 36, 72, 0.12), inset 0 2px 2px rgba(255, 255, 255, 0.45), inset 0 -2px 4px rgba(0, 0, 0, 0.18)'
          : '0 12px 34px rgba(8, 26, 58, 0.22), 0 2px 8px rgba(12, 36, 72, 0.08), inset 0 1.5px 1px rgba(255, 255, 255, 0.35), inset 0 -1.5px 3px rgba(0, 0, 0, 0.12)',
        transition: 'box-shadow 0.4s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.4s ease, transform 0.4s cubic-bezier(0.16, 1, 0.3, 1)',
        transform: isHovered ? 'translateY(-1px) scale(1.006)' : 'translateY(0) scale(1)',
        willChange: 'transform, box-shadow',
        ...style
      }}
    >
      <ChromaticFluidFilter
        id={filterId}
        scale={displacementScale}
        aberration={2.0}
        width={pillDimensions.width}
        height={pillDimensions.height}
      />

      {/* Internal Spherical Caustics Layer */}
      <span
        aria-hidden="true"
        style={{
          position: 'absolute',
          inset: 0,
          pointerEvents: 'none',
          borderRadius: `${cornerRadius}px`,
          background: 'radial-gradient(ellipse 75% 65% at 50% 65%, rgba(140, 195, 255, 0.10) 0%, rgba(220, 160, 100, 0.05) 45%, transparent 80%)',
          mixBlendMode: 'screen',
          opacity: 0.85,
          transition: 'opacity 0.4s ease'
        }}
      />

      {/* 3D Liquid Glass Top Specular Glare Bubble with Damped Motion */}
      <span
        aria-hidden="true"
        style={{
          position: 'absolute',
          top: '2px',
          left: `calc(${glarePos.x}px - 75px)`,
          width: '150px',
          height: '24px',
          borderRadius: '50%',
          pointerEvents: 'none',
          background: 'radial-gradient(ellipse 55% 50% at 50% 30%, rgba(255, 255, 255, 0.96) 0%, rgba(255, 235, 190, 0.80) 28%, rgba(255, 150, 80, 0.40) 55%, rgba(255, 80, 30, 0.12) 75%, transparent 100%)',
          filter: 'blur(1.8px)',
          mixBlendMode: 'screen',
          transform: isHovered ? 'scale(1.12)' : 'scale(0.95)',
          opacity: isHovered ? 0.95 : 0.65,
          transition: 'transform 0.4s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.4s cubic-bezier(0.16, 1, 0.3, 1)',
          willChange: 'left, transform, opacity'
        }}
      />

      {/* Iridescent Rainbow Edge Ring with Chromatic Dispersion */}
      <span
        aria-hidden="true"
        style={{
          position: 'absolute',
          inset: 0,
          pointerEvents: 'none',
          borderRadius: `${cornerRadius}px`,
          padding: '1.5px',
          WebkitMask: 'linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0)',
          WebkitMaskComposite: 'xor',
          maskComposite: 'exclude',
          background: `linear-gradient(${125 + glarePos.normalizedX * 0.9}deg, rgba(255, 255, 255, 0.85) 0%, rgba(255, 180, 120, 0.6) 22%, rgba(130, 220, 200, 0.55) 48%, rgba(140, 180, 255, 0.75) 75%, rgba(255, 255, 255, 0.85) 100%)`,
          opacity: 0.8,
          transition: 'opacity 0.4s ease'
        }}
      />

      {/* Interactive Navigation Content */}
      <div style={{ position: 'relative', zIndex: 3, display: 'inline-flex', alignItems: 'center' }}>
        {children ? (
          children
        ) : (
          <nav className="nav-links" aria-label="Dashboard navigation" style={{ gap: '6px' }}>
            {navItems.map(({ label, href }) => (
              <button
                key={label}
                className={`nav-link${!isAbout && active === href ? ' active' : ''}`}
                onClick={() => onNav && onNav(href)}
                style={{
                  padding: '7px 15px',
                  fontSize: '11.5px',
                  fontWeight: 650,
                  letterSpacing: '0.9px',
                  transition: 'all 0.28s cubic-bezier(0.22, 1, 0.36, 1)'
                }}
              >
                {label}
              </button>
            ))}
            <Link
              to="/about"
              className={`nav-link${isAbout ? ' active' : ''}`}
              style={{
                padding: '7px 15px',
                fontSize: '11.5px',
                fontWeight: 650,
                letterSpacing: '0.9px',
                transition: 'all 0.28s cubic-bezier(0.22, 1, 0.36, 1)'
              }}
            >
              ABOUT
            </Link>
          </nav>
        )}
      </div>
    </div>
  )
}
