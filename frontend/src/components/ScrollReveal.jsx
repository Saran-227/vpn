import useScrollReveal from '../hooks/useScrollReveal'

export default function ScrollReveal({ children, delay = 0, className = '', contents = false }) {
  const [ref, revealed] = useScrollReveal()
  const cls = [
    'scroll-reveal',
    revealed ? 'revealed' : '',
    contents ? 'sr-contents' : '',
    className,
  ].filter(Boolean).join(' ')

  return (
    <div ref={ref} className={cls} style={{ '--reveal-delay': `${delay}ms` }}>
      {children}
    </div>
  )
}
