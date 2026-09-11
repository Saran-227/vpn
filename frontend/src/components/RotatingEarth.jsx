import { useEffect, useRef, useState } from 'react'
import * as d3 from 'd3'

// Real VPN hub cities — used only as visualization reference nodes, not fabricated threat data
const ENDPOINTS = [
  { label: 'New York',    lng: -74.0,  lat: 40.7  },
  { label: 'London',      lng:  -0.1,  lat: 51.5  },
  { label: 'Frankfurt',   lng:   8.7,  lat: 50.1  },
  { label: 'Singapore',   lng: 103.8,  lat:  1.3  },
  { label: 'Tokyo',       lng: 139.7,  lat: 35.7  },
  { label: 'São Paulo',   lng: -46.6,  lat: -23.5 },
  { label: 'Mumbai',      lng:  72.9,  lat: 19.1  },
  { label: 'Sydney',      lng: 151.2,  lat: -33.9 },
  { label: 'Johannesburg',lng:  28.0,  lat: -26.2 },
  { label: 'Toronto',     lng: -79.4,  lat: 43.7  },
]

// ── DEMO TUNNEL ROUTE ───────────────────────────────────────────────────────
// Static reference visualization. Replace source/target with real endpoint
// geolocation data when available. Not derived from vpn.peer_ip or any live feed.
const DEMO_TUNNEL = {
  source: { name: 'Delhi',     lat: 28.6139, lng: 77.2090 },
  target: { name: 'Bangalore', lat: 12.9716, lng: 77.5946 },
}
// ─────────────────────────────────────────────────────────────────────────────

// Arc pairs between endpoints (index pairs)
const ARC_PAIRS = [
  [0, 1], [1, 2], [0, 3], [3, 4], [1, 6], [3, 6],
  [4, 7], [0, 9], [2, 8], [5, 0], [6, 3], [7, 4],
]

export default function RotatingEarth({ size = 320 }) {
  const canvasRef = useRef(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    const dpr = window.devicePixelRatio || 1
    const S = size

    canvas.width  = S * dpr
    canvas.height = S * dpr
    canvas.style.width  = `${S}px`
    canvas.style.height = `${S}px`
    ctx.scale(dpr, dpr)

    const cx = S / 2, cy = S / 2
    let radius = S / 2 - 12

    const projection = d3.geoOrthographic()
      .scale(radius)
      .translate([cx, cy])
      .clipAngle(90)

    const path = d3.geoPath().projection(projection).context(ctx)

    // Start centered on India so the Delhi→Bangalore demo tunnel is immediately visible
    const rotation = [-77, -20]
    let landFeatures = null
    const allDots = []

    // Packet state: one packet per arc
    const packets = ARC_PAIRS.map(() => ({ t: Math.random() }))

    // Demo tunnel packet state — two staggered packets on the Delhi→Bangalore route
    const demoPackets = [{ t: 0.0 }, { t: 0.5 }]

    // ── helpers ──────────────────────────────────────────────────────────────

    const inPolygon = (pt, ring) => {
      let inside = false
      for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
        const [xi, yi] = ring[i], [xj, yj] = ring[j]
        if ((yi > pt[1]) !== (yj > pt[1]) && pt[0] < ((xj - xi) * (pt[1] - yi)) / (yj - yi) + xi)
          inside = !inside
      }
      return inside
    }

    const inFeature = (pt, f) => {
      const g = f.geometry
      const polys = g.type === 'Polygon' ? [g.coordinates] : g.coordinates
      for (const poly of polys) {
        if (inPolygon(pt, poly[0]) && !poly.slice(1).some(h => inPolygon(pt, h))) return true
      }
      return false
    }

    // Great-circle interpolator for arc drawing
    const interpolate = d3.geoInterpolate

    // Check if a [lng,lat] point is on the visible hemisphere
    const isVisible = ([lng, lat]) => {
      const [rx, ry] = projection.rotate()
      const lambda = (lng + rx) * Math.PI / 180
      const phi    = lat * Math.PI / 180
      const phiR   = ry  * Math.PI / 180
      return Math.cos(phi) * Math.cos(phiR) * Math.cos(lambda) +
             Math.sin(phi) * Math.sin(phiR) > 0
    }

    // ── render ───────────────────────────────────────────────────────────────

    const render = () => {
      ctx.clearRect(0, 0, S, S)

      // Outer atmospheric glow (multi-layer)
      for (const [r0, r1, a] of [
        [radius + 2,  radius + 28, 0.14],
        [radius + 2,  radius + 14, 0.22],
      ]) {
        const g = ctx.createRadialGradient(cx, cy, r0, cx, cy, r1)
        g.addColorStop(0, `rgba(79,143,217,${a})`)
        g.addColorStop(1, 'rgba(79,143,217,0)')
        ctx.beginPath()
        ctx.arc(cx, cy, r1, 0, 2 * Math.PI)
        ctx.fillStyle = g
        ctx.fill()
      }

      // Ocean
      ctx.beginPath()
      ctx.arc(cx, cy, radius, 0, 2 * Math.PI)
      const ocean = ctx.createRadialGradient(cx - radius * 0.3, cy - radius * 0.3, 0, cx, cy, radius)
      ocean.addColorStop(0, '#c8e0f4')
      ocean.addColorStop(1, '#a0c8e8')
      ctx.fillStyle = ocean
      ctx.fill()

      if (!landFeatures) {
        // Globe border while loading
        ctx.beginPath()
        ctx.arc(cx, cy, radius, 0, 2 * Math.PI)
        ctx.strokeStyle = 'rgba(79,143,217,0.4)'
        ctx.lineWidth = 1.5
        ctx.stroke()
        return
      }

      // Graticule
      const graticule = d3.geoGraticule()()
      ctx.beginPath()
      path(graticule)
      ctx.strokeStyle = 'rgba(79,143,217,0.12)'
      ctx.lineWidth = 0.4
      ctx.stroke()

      // Land fill
      ctx.beginPath()
      landFeatures.features.forEach(f => path(f))
      ctx.fillStyle = 'rgba(79,143,217,0.12)'
      ctx.fill()

      // Land outline — two passes for glow effect
      for (const [color, width] of [
        ['rgba(79,143,217,0.20)', 2.5],
        ['rgba(79,143,217,0.70)', 0.8],
      ]) {
        ctx.beginPath()
        landFeatures.features.forEach(f => path(f))
        ctx.strokeStyle = color
        ctx.lineWidth = width
        ctx.stroke()
      }

      // Network dots (on land)
      allDots.forEach(([lng, lat]) => {
        const p = projection([lng, lat])
        if (!p) return
        ctx.beginPath()
        ctx.arc(p[0], p[1], 1.1, 0, 2 * Math.PI)
        ctx.fillStyle = 'rgba(0,255,136,0.55)'
        ctx.fill()
      })

      // Connection arcs + traveling packets
      ARC_PAIRS.forEach(([ai, bi], idx) => {
        const a = ENDPOINTS[ai], b = ENDPOINTS[bi]
        const aVis = isVisible([a.lng, a.lat])
        const bVis = isVisible([b.lng, b.lat])
        if (!aVis && !bVis) return

        const interp = interpolate([a.lng, a.lat], [b.lng, b.lat])
        const steps = 60
        const pts = []
        for (let i = 0; i <= steps; i++) {
          const p = projection(interp(i / steps))
          if (p) pts.push(p)
        }
        if (pts.length < 2) return

        // Arc line
        ctx.beginPath()
        ctx.moveTo(pts[0][0], pts[0][1])
        pts.slice(1).forEach(p => ctx.lineTo(p[0], p[1]))
        ctx.strokeStyle = 'rgba(79,143,217,0.30)'
        ctx.lineWidth = 0.8
        ctx.stroke()

        // Traveling packet
        const t = packets[idx].t
        const pi = Math.min(Math.floor(t * (pts.length - 1)), pts.length - 2)
        const frac = t * (pts.length - 1) - pi
        const px = pts[pi][0] + (pts[pi + 1][0] - pts[pi][0]) * frac
        const py = pts[pi][1] + (pts[pi + 1][1] - pts[pi][1]) * frac

        // Packet glow
        const pg = ctx.createRadialGradient(px, py, 0, px, py, 5)
        pg.addColorStop(0, 'rgba(79,143,217,0.85)')
        pg.addColorStop(1, 'rgba(79,143,217,0)')
        ctx.beginPath()
        ctx.arc(px, py, 5, 0, 2 * Math.PI)
        ctx.fillStyle = pg
        ctx.fill()

        // Packet core
        ctx.beginPath()
        ctx.arc(px, py, 1.8, 0, 2 * Math.PI)
        ctx.fillStyle = '#ffffff'
        ctx.fill()
      })

      // ── DEMO TUNNEL: Delhi → Bangalore ──────────────────────────────────
      const dSrc = DEMO_TUNNEL.source
      const dTgt = DEMO_TUNNEL.target
      const srcCoord = [dSrc.lng, dSrc.lat]
      const tgtCoord = [dTgt.lng, dTgt.lat]
      const srcVis = isVisible(srcCoord)
      const tgtVis = isVisible(tgtCoord)

      if (srcVis || tgtVis) {
        // Build projected arc points
        const dInterp = d3.geoInterpolate(srcCoord, tgtCoord)
        const STEPS = 80
        const dPts = []
        for (let i = 0; i <= STEPS; i++) {
          const p = projection(dInterp(i / STEPS))
          if (p) dPts.push({ p, t: i / STEPS })
        }

        if (dPts.length >= 2) {
          // Outer red glow
          ctx.beginPath()
          ctx.moveTo(dPts[0].p[0], dPts[0].p[1])
          dPts.slice(1).forEach(({ p }) => ctx.lineTo(p[0], p[1]))
          ctx.strokeStyle = 'rgba(255,60,60,0.25)'
          ctx.lineWidth = 8
          ctx.lineJoin = 'round'
          ctx.lineCap = 'round'
          ctx.stroke()

          // Mid glow
          ctx.beginPath()
          ctx.moveTo(dPts[0].p[0], dPts[0].p[1])
          dPts.slice(1).forEach(({ p }) => ctx.lineTo(p[0], p[1]))
          ctx.strokeStyle = 'rgba(255,80,80,0.55)'
          ctx.lineWidth = 3
          ctx.stroke()

          // Bright red core
          ctx.beginPath()
          ctx.moveTo(dPts[0].p[0], dPts[0].p[1])
          dPts.slice(1).forEach(({ p }) => ctx.lineTo(p[0], p[1]))
          ctx.strokeStyle = '#ff3c3c'
          ctx.lineWidth = 1.8
          ctx.stroke()

          // Traveling packets
          demoPackets.forEach(pk => {
            // Find the projected point at packet's t position
            const raw = projection(dInterp(pk.t))
            if (!raw) return

            // Trail
            for (let tr = 1; tr <= 4; tr++) {
              const trailT = Math.max(0, pk.t - tr * 0.025)
              const trailP = projection(dInterp(trailT))
              if (!trailP) continue
              ctx.beginPath()
              ctx.arc(trailP[0], trailP[1], 1.2 - tr * 0.2, 0, 2 * Math.PI)
              ctx.fillStyle = `rgba(255,60,60,${0.35 - tr * 0.07})`
              ctx.fill()
            }

            // Packet glow halo
            const halo = ctx.createRadialGradient(raw[0], raw[1], 0, raw[0], raw[1], 5)
            halo.addColorStop(0, 'rgba(255,80,80,0.90)')
            halo.addColorStop(1, 'rgba(255,60,60,0)')
            ctx.beginPath()
            ctx.arc(raw[0], raw[1], 5, 0, 2 * Math.PI)
            ctx.fillStyle = halo
            ctx.fill()

            // Packet core
            ctx.beginPath()
            ctx.arc(raw[0], raw[1], 2, 0, 2 * Math.PI)
            ctx.fillStyle = '#ffffff'
            ctx.fill()
          })

          // Midpoint label "IPsec Tunnel"
          const midIdx = Math.floor(dPts.length / 2)
          const mid = dPts[midIdx].p
          ctx.font = '500 8px system-ui, sans-serif'
          ctx.fillStyle = 'rgba(58,127,193,0.70)'
          ctx.textAlign = 'center'
          ctx.fillText('IPsec Tunnel', mid[0], mid[1] - 6)
        }

        // Endpoint node helper
        const drawDemoNode = (coord, label) => {
          if (!isVisible(coord)) return
          const p = projection(coord)
          if (!p) return

          // Outer glow
          const eg = ctx.createRadialGradient(p[0], p[1], 0, p[0], p[1], 10)
          eg.addColorStop(0, 'rgba(255,60,60,0.6)')
          eg.addColorStop(1, 'rgba(255,60,60,0)')
          ctx.beginPath()
          ctx.arc(p[0], p[1], 10, 0, 2 * Math.PI)
          ctx.fillStyle = eg
          ctx.fill()

          // Node core
          ctx.beginPath()
          ctx.arc(p[0], p[1], 4, 0, 2 * Math.PI)
          ctx.fillStyle = '#ff3c3c'
          ctx.shadowColor = '#ff3c3c'
          ctx.shadowBlur = 10
          ctx.fill()
          ctx.shadowBlur = 0

          // Label
          ctx.font = 'bold 9px system-ui, sans-serif'
          ctx.fillStyle = '#ffaaaa'
          ctx.textAlign = 'center'
          ctx.fillText(label, p[0], p[1] - 12)
        }

        drawDemoNode(srcCoord, dSrc.name)
        drawDemoNode(tgtCoord, dTgt.name)
      }
      // ── end DEMO TUNNEL ───────────────────────────────────────────────────

      // Endpoint nodes
      ENDPOINTS.forEach(({ lng, lat }) => {
        if (!isVisible([lng, lat])) return
        const p = projection([lng, lat])
        if (!p) return

        // Outer glow ring
        const eg = ctx.createRadialGradient(p[0], p[1], 0, p[0], p[1], 8)
        eg.addColorStop(0, 'rgba(0,255,136,0.5)')
        eg.addColorStop(1, 'rgba(0,255,136,0)')
        ctx.beginPath()
        ctx.arc(p[0], p[1], 8, 0, 2 * Math.PI)
        ctx.fillStyle = eg
        ctx.fill()

        // Node core
        ctx.beginPath()
        ctx.arc(p[0], p[1], 2.5, 0, 2 * Math.PI)
        ctx.fillStyle = '#00ff88'
        ctx.shadowColor = '#00ff88'
        ctx.shadowBlur = 6
        ctx.fill()
        ctx.shadowBlur = 0
      })

      // Globe border
      ctx.beginPath()
      ctx.arc(cx, cy, radius, 0, 2 * Math.PI)
      ctx.strokeStyle = 'rgba(79,143,217,0.35)'
      ctx.lineWidth = 1.5
      ctx.stroke()

      // Inner highlight arc (top-left specular)
      ctx.beginPath()
      ctx.arc(cx, cy, radius - 1, Math.PI * 1.1, Math.PI * 1.6)
      ctx.strokeStyle = 'rgba(255,255,255,0.35)'
      ctx.lineWidth = 3
      ctx.stroke()
    }

    // ── data load ────────────────────────────────────────────────────────────

    const load = async () => {
      try {
        const res = await fetch(
          'https://raw.githubusercontent.com/martynafford/natural-earth-geojson/refs/heads/master/110m/physical/ne_110m_land.json'
        )
        if (!res.ok) throw new Error()
        landFeatures = await res.json()

        landFeatures.features.forEach(f => {
          const [[minLng, minLat], [maxLng, maxLat]] = d3.geoBounds(f)
          const step = 5
          for (let lng = minLng; lng <= maxLng; lng += step)
            for (let lat = minLat; lat <= maxLat; lat += step)
              if (inFeature([lng, lat], f)) allDots.push([lng, lat])
        })
      } catch {
        setError(true)
      }
    }

    // ── interaction ──────────────────────────────────────────────────────────

    let dragging = false, startX, startY, startRot

    // ── animation loop ───────────────────────────────────────────────────────

    let lastTime = 0
    const timer = d3.timer(elapsed => {
      const dt = elapsed - lastTime
      lastTime = elapsed

      if (!dragging) rotation[0] += 0.12 * (dt / 16.67)
      projection.rotate(rotation)

      // Advance packets
      packets.forEach(pk => {
        pk.t += 0.004 * (dt / 16.67)
        if (pk.t > 1) pk.t -= 1
      })

      // Advance demo tunnel packets (slightly faster for visual distinction)
      demoPackets.forEach(pk => {
        pk.t += 0.006 * (dt / 16.67)
        if (pk.t > 1) pk.t -= 1
      })

      render()
    })

    const getXY = e => e.touches
      ? [e.touches[0].clientX, e.touches[0].clientY]
      : [e.clientX, e.clientY]

    const onDown = e => {
      dragging = true
      ;[startX, startY] = getXY(e)
      startRot = [...rotation]
    }
    const onMove = e => {
      if (!dragging) return
      const [x, y] = getXY(e)
      rotation[0] = startRot[0] + (x - startX) * 0.5
      rotation[1] = Math.max(-90, Math.min(90, startRot[1] - (y - startY) * 0.5))
      projection.rotate(rotation)
    }
    const onUp = () => { dragging = false }

    const onWheel = e => {
      e.preventDefault()
      radius = Math.max(60, Math.min(S / 2 - 4, radius - e.deltaY * 0.3))
      projection.scale(radius)
    }

    canvas.addEventListener('mousedown',  onDown)
    canvas.addEventListener('touchstart', onDown, { passive: true })
    window.addEventListener('mousemove',  onMove)
    window.addEventListener('touchmove',  onMove, { passive: true })
    window.addEventListener('mouseup',    onUp)
    window.addEventListener('touchend',   onUp)
    canvas.addEventListener('wheel',      onWheel, { passive: false })

    load()

    return () => {
      timer.stop()
      canvas.removeEventListener('mousedown',  onDown)
      canvas.removeEventListener('touchstart', onDown)
      window.removeEventListener('mousemove',  onMove)
      window.removeEventListener('touchmove',  onMove)
      window.removeEventListener('mouseup',    onUp)
      window.removeEventListener('touchend',   onUp)
      canvas.removeEventListener('wheel',      onWheel)
    }
  }, [size])

  if (error) return (
    <div style={{ color: 'var(--text-muted)', fontSize: 11, textAlign: 'center', padding: 20 }}>
      Globe unavailable
    </div>
  )

  return (
    <canvas
      ref={canvasRef}
      style={{ cursor: 'grab', borderRadius: '50%', display: 'block' }}
    />
  )
}
