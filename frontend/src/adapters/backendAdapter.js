/**
 * backendAdapter.js
 * Translates raw FastAPI evaluation reports into clean frontend models for the DLS.
 */

export function mapBackendReport(rawReport) {
  if (!rawReport) return null

  const exec = rawReport.executive_summary || {}
  const audit = rawReport.cryptographic_audit || {}
  const ike = rawReport.ike_protocol_details || {}
  const ai = rawReport.ai_traffic_intelligence || {}
  const tc = ai.traffic_classification || {}
  const kf = ai.key_flow_metrics || {}
  const op = ai.operational_mode || {}
  const suite = audit.negotiated_suite || {}

  // 1. VPN / SA Status
  const vpnStatus = {
    status: exec.compliance_status === 'FAIL' ? 'VULNERABLE' : 'ACTIVE',
    endpointA: 'VPN Initiator (Host)',
    endpointAIp: '172.28.0.2',
    endpointB: 'VPN Responder (Gateway)',
    endpointBIp: '172.28.0.3',
    uptimeSeconds: exec.session_duration_sec || 0,
    protocol: ike.ike_version ? `IKEv${ike.ike_version} / ESP` : 'ESP-Only (Wiretap)',
    encryption: suite.encryption || exec.predicted_cipher || 'AES-256-GCM',
    authMethod: exec.auth_method || 'Pre-Shared Key (PSK)',
    peerIp: exec.spi_pair || '0xc56d1914 <-> 0xcd0440ee',
    uptimeLabel: `${exec.session_duration_sec || 0}s (${exec.active_payload_duration_sec || 0}s payload)`
  }

  // 2. Telemetry Metrics
  const throughput = ai.average_bytes_sec || 0
  const metrics = {
    packetsPerSecond: (exec.session_duration_sec && exec.session_duration_sec > 0)
      ? Math.round(exec.total_packets / exec.session_duration_sec)
      : Math.round(exec.total_packets || 0),
    activeFlows: kf.esp_spi_count || 2,
    avgPacketSize: Math.round(kf.mean_packet_length || 0),
    inboundBps: Math.round(throughput * 0.48),
    outboundBps: Math.round(throughput * 0.52),
    bandwidthBps: Math.round(throughput * 8)
  }

  // 3. Security Score & Posture
  const security = {
    riskScore: exec.risk_score !== undefined ? exec.risk_score : 100,
    riskLevel: exec.risk_level || 'LOW',
    complianceStatus: exec.compliance_status || 'PASS',
    postureLabel: exec.nist_sp800_77_posture || 'COMPLIANT DEFENSE POSTURE',
    anomalyDetected: exec.compliance_status === 'FAIL' || (audit.violations && audit.violations.length > 0),
    findings: (audit.violations || []).map(v => `${v.title}: ${v.description}`)
  }

  // 4. Events / Threat Feed
  const events = (audit.violations || []).map((v, i) => ({
    timestamp: new Date(Date.now() - (i + 1) * 30000).toLocaleTimeString(),
    title: v.title,
    description: v.description,
    severity: v.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
    category: v.cwe || 'CRYPTO_RISK'
  }))

  if (events.length === 0) {
    events.push({
      timestamp: new Date().toLocaleTimeString(),
      title: 'NIST SP 800-77 Rev. 1 Compliant',
      description: 'Clean cryptographic verification across Phase 1 and Phase 2 proposals.',
      severity: 'LOW',
      category: 'AUDIT_PASS'
    })
    events.push({
      timestamp: new Date(Date.now() - 60000).toLocaleTimeString(),
      title: `AI Classification: ${tc.display_profile || tc.predicted_primary_profile || 'VOIP'}`,
      description: `Inference confidence: ${((tc.confidence_score || 0.95) * 100).toFixed(1)}%. Mode: ${op.predicted_mode || 'tunnel'}.`,
      severity: 'LOW',
      category: 'AI_TELEMETRY'
    })
  }

  // 5. Chart Data (synthetic progression based on temporal slices or metrics)
  const slices = ai.temporal_window_breakdown || []
  const chartData = slices.length > 0
    ? slices.map(s => ({
        timestamp: `+${s.time_offset_sec.toFixed(1)}s`,
        packetsPerSecond: Math.round(s.packet_count / (s.duration_sec || 1.5)),
        riskScore: security.riskScore
      }))
    : [
        { timestamp: '00:00', packetsPerSecond: 20, riskScore: security.riskScore },
        { timestamp: '00:05', packetsPerSecond: 65, riskScore: security.riskScore },
        { timestamp: '00:10', packetsPerSecond: 80, riskScore: security.riskScore },
        { timestamp: '00:15', packetsPerSecond: 45, riskScore: security.riskScore },
      ]

  // 6. Endpoints
  const endpoints = {
    peerIp: exec.spi_pair || '172.28.0.2 ↔ 172.28.0.3',
    protocol: ike.ike_version ? `IKEv${ike.ike_version} (UDP 500/4500)` : 'Native ESP',
    encryption: suite.encryption || 'AES-256-GCM (256 bits)',
    authMethod: exec.auth_method || 'Pre-Shared Key (PSK)',
    uptimeLabel: `${exec.total_packets || 0} Total Packets (${exec.esp_packets || 0} ESP)`
  }

  return {
    rawReport,
    vpnStatus,
    metrics,
    security,
    events,
    chartData,
    endpoints,
    auditData: audit,
    ikeDetails: ike,
    aiData: ai,
    execSummary: exec
  }
}
