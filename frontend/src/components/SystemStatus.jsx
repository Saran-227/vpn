// Derives overall system state from the existing standardised contract fields.
// When Sermistha's security engine is integrated, populate security.findings
// with real Finding objects — this component needs no changes.

const STATES = {
  threat:   { label: 'Threat detected',    key: 'threat'   },
  anomaly:  { label: 'Anomaly detected',   key: 'anomaly'  },
  elevated: { label: 'Elevated activity',  key: 'elevated' },
  normal:   { label: 'Monitoring normally',key: 'normal'   },
}

// Props: security — { riskLevel, anomalyDetected, findings[] }
//         events   — { severity, category }[]
// TODO (backend adapter): both props mapped via backendAdapter.js
function deriveState(security, events) {
  const level    = security.riskLevel
  const anomaly  = security.anomalyDetected
  const findings = security.findings ?? []

  const hasCriticalFinding = findings.some(f => f.severity === 'CRITICAL')
  const hasHighFinding     = findings.some(f => f.severity === 'HIGH')
  const recentCritical     = events.slice(0, 5).some(e => e.severity === 'CRITICAL')

  if (level === 'CRITICAL' || hasCriticalFinding || recentCritical) return STATES.threat
  if (level === 'HIGH'     || anomaly || hasHighFinding)            return STATES.anomaly
  if (level === 'MEDIUM')                                           return STATES.elevated
  return STATES.normal
}

export default function SystemStatus({ security, events = [] }) {
  const state = deriveState(security, events)
  return (
    <div className={`sys-status sys-status--${state.key}`} aria-label={`System status: ${state.label}`}>
      <span className="sys-status__dot" />
      <span className="sys-status__label">SYSTEM STATUS</span>
      <span className="sys-status__sep" aria-hidden="true" />
      <span className="sys-status__text">{state.label}</span>
    </div>
  )
}
