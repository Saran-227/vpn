/**
 * API Service for NTRO IPsec Intelligence Platform
 * Communicates with FastAPI backend on http://127.0.0.1:8000
 */

const API_BASE = '/api'

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`)
  if (!res.ok) throw new Error(`Health check failed: ${res.statusText}`)
  return res.json()
}

export async function fetchSamples() {
  const res = await fetch(`${API_BASE}/samples`)
  if (!res.ok) throw new Error(`Failed to fetch samples: ${res.statusText}`)
  return res.json()
}

export async function analyzeSample(pcapFilename) {
  const res = await fetch(`${API_BASE}/analyze/sample`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pcap_filename: pcapFilename })
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Analysis failed: ${res.statusText}`)
  }
  return res.json()
}

export async function analyzeUpload(file) {
  const formData = new FormData()
  formData.append('file', file)
  const res = await fetch(`${API_BASE}/analyze/upload`, {
    method: 'POST',
    body: formData
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Upload analysis failed: ${res.statusText}`)
  }
  return res.json()
}

export async function fetchTournament() {
  const res = await fetch(`${API_BASE}/tournament`)
  if (!res.ok) throw new Error(`Failed to fetch leaderboard: ${res.statusText}`)
  return res.json()
}
