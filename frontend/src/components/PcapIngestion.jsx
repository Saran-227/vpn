import React, { useState, useRef } from 'react'
import GlassCard from './GlassCard'
import { Upload, FileCode, CheckCircle, AlertTriangle, Play, Loader2 } from 'lucide-react'

export default function PcapIngestion({
  samples = [],
  selectedSample,
  onSelectSample,
  onUploadFile,
  isAnalyzing = false,
  activeFilename = ''
}) {
  const [dragActive, setDragActive] = useState(false)
  const [selectedFile, setSelectedFile] = useState(null)
  const fileInputRef = useRef(null)

  const handleDrag = (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }

  const handleDrop = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0]
      if (file.name.endsWith('.pcap') || file.name.endsWith('.pcapng')) {
        setSelectedFile(file)
        if (onUploadFile) onUploadFile(file)
      } else {
        alert('Please upload a .pcap or .pcapng file')
      }
    }
  }

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0]
      setSelectedFile(file)
      if (onUploadFile) onUploadFile(file)
    }
  }

  return (
    <GlassCard className="pcap-ingestion-card">
      <div className="card-title-row">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div className="icon-wrapper" style={{ width: 32, height: 32 }}>
            <Upload size={16} color="var(--accent-blue)" />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600 }}>Capture Ingestion &amp; Testbed Scenarios</h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Evaluate unencrypted IKE handshakes &amp; encrypted ESP application flows
            </span>
          </div>
        </div>
        {activeFilename && (
          <div style={{
            fontSize: '0.75rem',
            fontFamily: 'monospace',
            padding: '4px 10px',
            background: 'var(--glass-inner)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-xs)',
            color: 'var(--accent-blue)'
          }}>
            Active: {activeFilename}
          </div>
        )}
      </div>

      <div className="ingestion-grid" style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(280px, 1fr) minmax(320px, 1.4fr)',
        gap: '1.25rem',
        marginTop: '1rem'
      }}>
        {/* Drop Zone */}
        <div
          className={`drop-zone ${dragActive ? 'drag-active' : ''}`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          style={{
            border: `1.5px dashed ${dragActive ? 'var(--accent-blue)' : 'var(--glass-border)'}`,
            borderRadius: 'var(--radius-inner)',
            padding: '1.5rem 1rem',
            textAlign: 'center',
            cursor: 'pointer',
            background: dragActive ? 'rgba(147, 197, 253, 0.08)' : 'var(--glass-inner)',
            transition: 'all 0.2s ease',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.5rem'
          }}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".pcap,.pcapng"
            style={{ display: 'none' }}
            onChange={handleFileChange}
          />
          <div style={{
            width: 44,
            height: 44,
            borderRadius: '50%',
            background: 'var(--icon-bg)',
            border: '1px solid var(--icon-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            {isAnalyzing ? (
              <Loader2 size={22} className="spin" color="var(--accent-blue)" />
            ) : (
              <FileCode size={22} color="var(--accent-blue)" />
            )}
          </div>
          <div style={{ fontWeight: 600, fontSize: '0.88rem', color: 'var(--text-primary)' }}>
            {selectedFile ? selectedFile.name : 'Drop .pcap / .pcapng capture here'}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            {selectedFile ? `${(selectedFile.size / 1024).toFixed(1)} KB · Click to change` : 'or click to browse local files'}
          </div>
        </div>

        {/* Curated Scenarios */}
        <div>
          <div style={{
            fontSize: '0.75rem',
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: '0.08em',
            color: 'var(--text-muted)',
            marginBottom: '0.6rem'
          }}>
            1-Click Benchmark Scenarios (Testbed Captures)
          </div>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))',
            gap: '0.5rem'
          }}>
            {samples.map((sample) => {
              const isSelected = selectedSample?.id === sample.id || activeFilename === sample.pcap
              const isVuln = sample.tag === 'CRITICAL_FAIL'
              const isWiretap = sample.tag === 'WIRETAP'
              const isMixed = sample.tag === 'CONCURRENT'

              return (
                <button
                  key={sample.id}
                  disabled={isAnalyzing}
                  onClick={() => onSelectSample(sample)}
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'flex-start',
                    padding: '0.65rem 0.75rem',
                    borderRadius: 'var(--radius-sm)',
                    background: isSelected ? 'rgba(147, 197, 253, 0.15)' : 'var(--glass-inner)',
                    border: `1px solid ${isSelected ? 'var(--border-strong)' : 'var(--glass-inner-border)'}`,
                    color: 'var(--text-primary)',
                    textAlign: 'left',
                    transition: 'all 0.18s ease',
                    boxShadow: isSelected ? '0 0 16px rgba(147,197,253,0.2)' : 'none'
                  }}
                >
                  <div style={{ display: 'flex', width: '100%', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>{sample.title.split('(')[0]}</span>
                    <span style={{
                      fontSize: '0.65rem',
                      fontWeight: 700,
                      padding: '2px 6px',
                      borderRadius: '4px',
                      background: isVuln ? 'var(--red-soft)' : isMixed ? 'rgba(192, 132, 252, 0.15)' : isWiretap ? 'var(--amber-soft)' : 'var(--green-soft)',
                      color: isVuln ? 'var(--accent-red)' : isMixed ? '#c084fc' : isWiretap ? 'var(--accent-amber)' : 'var(--accent-green)'
                    }}>
                      {sample.tag}
                    </span>
                  </div>
                  <span style={{
                    fontSize: '0.7rem',
                    color: 'var(--text-muted)',
                    marginTop: '4px',
                    display: '-webkit-box',
                    WebkitLineClamp: 1,
                    WebkitBoxOrient: 'vertical',
                    overflow: 'hidden'
                  }}>
                    {sample.description}
                  </span>
                </button>
              )
            })}
          </div>
        </div>
      </div>
    </GlassCard>
  )
}
