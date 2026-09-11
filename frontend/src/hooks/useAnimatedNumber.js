import { useRef, useEffect, useState } from 'react'

const reduced = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches

export default function useAnimatedNumber(target, duration = 500) {
  const [display, setDisplay] = useState(target)
  const raf = useRef(null)
  const current = useRef(target)

  useEffect(() => {
    if (reduced()) { current.current = target; setDisplay(target); return }
    cancelAnimationFrame(raf.current)
    const start = current.current
    const delta = target - start
    if (delta === 0) return
    const t0 = performance.now()
    const tick = (now) => {
      const p = Math.min((now - t0) / duration, 1)
      const eased = 1 - Math.pow(1 - p, 3)
      current.current = start + delta * eased
      setDisplay(current.current)
      if (p < 1) raf.current = requestAnimationFrame(tick)
      else current.current = target
    }
    raf.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf.current)
  }, [target, duration])

  return display
}
