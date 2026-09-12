import { useState, useEffect } from 'react'
import { fetchHealth, fetchSamples, analyzeSample, analyzeUpload, fetchTournament } from '../services/api'
import { mapBackendReport } from '../adapters/backendAdapter'
import {
  vpnStatus as mockVpnStatus,
  metrics as mockMetrics,
  security as mockSecurity,
  events as mockEvents,
  chartData as mockChartData,
  endpoints as mockEndpoints,
} from '../data/mockData'

export function useDashboardData() {
  const [connection, setConnection] = useState('CONNECTING')
  const [samples, setSamples] = useState([])
  const [selectedSample, setSelectedSample] = useState(null)
  const [activeFilename, setActiveFilename] = useState('')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [error, setError] = useState(null)
  const [tournamentData, setTournamentData] = useState(null)

  // Mapped telemetry state
  const [dashboardData, setDashboardData] = useState({
    vpnStatus: mockVpnStatus,
    metrics: mockMetrics,
    security: mockSecurity,
    events: mockEvents,
    chartData: mockChartData,
    endpoints: mockEndpoints,
    auditData: null,
    ikeDetails: null,
    aiData: null,
    execSummary: null
  })

  // Initialize live connection and fetch initial data
  useEffect(() => {
    let mounted = true

    async function init() {
      try {
        const [health, sampleList, tournament] = await Promise.all([
          fetchHealth().catch(() => null),
          fetchSamples().catch(() => []),
          fetchTournament().catch(() => null)
        ])

        if (!mounted) return

        if (health && health.status === 'ONLINE') {
          setConnection('LIVE')
          setSamples(sampleList || [])
          setTournamentData(tournament)

          // Auto-load the golden capture or first sample
          const defaultSample = sampleList?.find(s => s.id === 'secure_voip') || sampleList?.[0]
          if (defaultSample) {
            setSelectedSample(defaultSample)
            setActiveFilename(defaultSample.pcap)
            loadSampleAnalysis(defaultSample.pcap)
          }
        } else {
          setConnection('MOCK')
        }
      } catch (err) {
        if (mounted) {
          console.warn('Backend unavailable, running in offline demo mode:', err)
          setConnection('MOCK')
        }
      }
    }

    init()
    return () => { mounted = false }
  }, [])

  async function loadSampleAnalysis(pcapFilename) {
    setIsAnalyzing(true)
    setError(null)
    try {
      const report = await analyzeSample(pcapFilename)
      const mapped = mapBackendReport(report)
      if (mapped) {
        setDashboardData(mapped)
      }
    } catch (err) {
      console.error('Failed to analyze sample:', err)
      setError(err.message)
    } finally {
      setIsAnalyzing(false)
    }
  }

  async function handleSelectSample(sample) {
    setSelectedSample(sample)
    setActiveFilename(sample.pcap)
    await loadSampleAnalysis(sample.pcap)
  }

  async function handleUploadFile(file) {
    setIsAnalyzing(true)
    setSelectedSample(null)
    setActiveFilename(file.name)
    setError(null)
    try {
      const report = await analyzeUpload(file)
      const mapped = mapBackendReport(report)
      if (mapped) {
        setDashboardData(mapped)
      }
    } catch (err) {
      console.error('Failed to analyze uploaded file:', err)
      setError(err.message)
    } finally {
      setIsAnalyzing(false)
    }
  }

  return {
    ...dashboardData,
    connection,
    samples,
    selectedSample,
    activeFilename,
    isAnalyzing,
    error,
    tournamentData,
    onSelectSample: handleSelectSample,
    onUploadFile: handleUploadFile
  }
}
