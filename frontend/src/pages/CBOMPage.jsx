import React, { useEffect, useState } from 'react'
import api from '../api/client'
import toast from 'react-hot-toast'

export default function CBOMPage() {
  const [scans, setScans] = useState([])
  const [cbom, setCbom] = useState(null)
  const [loading, setLoading] = useState(false)
  const [selectedScan, setSelectedScan] = useState('')

  useEffect(() => {
    api.get('/scans').then(r => setScans(r.data.filter(s => s.status === 'COMPLETED'))).catch(() => {})
  }, [])

  const loadCBOM = async (scanId) => {
    setLoading(true)
    setSelectedScan(scanId)
    try { const r = await api.get(`/scans/${scanId}/cbom`); setCbom(r.data) } catch { setCbom(null); toast.error('CBOM not available') } finally { setLoading(false) }
  }

  const download = (format) => {
    if (!cbom) return
    const content = format === 'xml' ? objToXml(cbom, 'bom') : JSON.stringify(cbom, null, 2)
    const type = format === 'xml' ? 'application/xml' : 'application/json'
    const blob = new Blob([content], { type })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `cbom-${selectedScan}.${format}`; a.click()
    toast.success(`CBOM downloaded as ${format.toUpperCase()}`)
  }

  const objToXml = (obj, tag) => {
    const content = JSON.stringify(obj, null, 2)
    return `<?xml version="1.0" encoding="UTF-8"?>\n<bom xmlns="http://cyclonedx.org/schema/bom/1.4">\n${content}\n</bom>`
  }

  return (
    <div className="scroll-fade">
      <div className="page-header">
        <div>
          <h1 className="page-title">CBOM</h1>
          <p className="page-subtitle">Cryptographic Bill of Materials — CycloneDX Format</p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <select className="form-select" style={{ width: 240 }} value={selectedScan}
            onChange={e => { if (e.target.value) loadCBOM(e.target.value) }}>
            <option value="">— Select a scan —</option>
            {scans.map(s => <option key={s.scan_id} value={s.scan_id}>{s.org_name}</option>)}
          </select>
          {cbom && (
            <>
              <button className="btn btn-secondary" onClick={() => download('json')}>⬇ JSON</button>
              <button className="btn btn-secondary" onClick={() => download('xml')}>⬇ XML</button>
            </>
          )}
        </div>
      </div>

      {!selectedScan ? (
        <div className="card empty-state"><p>Select a completed scan to view the CBOM.</p></div>
      ) : loading ? (
        <div style={{ textAlign: 'center', padding: 60 }}><span className="loading-spinner" /></div>
      ) : !cbom ? (
        <div className="card empty-state"><p>CBOM not yet generated for this scan.</p></div>
      ) : (
        <>
          {/* CBOM Header */}
          <div className="card" style={{ marginBottom: 20, borderLeft: '3px solid var(--accent-cyan)' }}>
            <div className="grid-3" style={{ gap: 16 }}>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>FORMAT</div>
                <div style={{ fontWeight: 700, fontSize: 16 }}>{cbom.bomFormat}</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Spec v{cbom.specVersion}</div>
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>TOTAL ASSETS</div>
                <div style={{ fontWeight: 700, fontSize: 28, color: 'var(--accent-cyan)' }}>{cbom.cryptoProperties?.totalAssets || 0}</div>
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>OVERALL HNDL</div>
                <div style={{ fontWeight: 700, fontSize: 28, color: cbom.cryptoProperties?.overallHndlScore > 6 ? '#ef4444' : '#f59e0b' }}>
                  {cbom.cryptoProperties?.overallHndlScore?.toFixed(1) || '0.0'}
                </div>
              </div>
            </div>
            <div style={{ marginTop: 16, display: 'flex', gap: 12 }}>
              <span style={{ fontSize: 12 }}>🔴 Vulnerable: <strong>{cbom.cryptoProperties?.quantumVulnerableCount || 0}</strong></span>
              <span style={{ fontSize: 12 }}>🟢 PQC Ready: <strong>{cbom.cryptoProperties?.pqcReadyCount || 0}</strong></span>
              <span style={{ fontSize: 12 }}>🔢 Serial: <span className="mono" style={{ fontSize: 10 }}>{cbom.serialNumber}</span></span>
            </div>
          </div>

          {/* Components */}
          {cbom.components?.length > 0 && (
            <div className="card" style={{ marginBottom: 20 }}>
              <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 16, color: 'var(--text-secondary)' }}>COMPONENTS ({cbom.components.length})</h3>
              <div className="table-wrapper">
                <table>
                  <thead><tr><th>Component</th><th>Type</th><th>HNDL Score</th><th>PQC Ready</th><th>CDN</th></tr></thead>
                  <tbody>
                    {cbom.components.map((c, i) => {
                      const props = c.cryptoProperties?.relatedCryptoMaterialProperties || {}
                      return (
                        <tr key={i}>
                          <td><span style={{ fontWeight: 600 }}>{c.name}</span></td>
                          <td><span className="tag">{c.type}</span></td>
                          <td style={{ fontWeight: 700, color: props.hndlScore > 6 ? '#ef4444' : props.hndlScore > 3 ? '#f97316' : '#10b981' }}>{props.hndlScore?.toFixed(2) || '—'}</td>
                          <td>{props.isPQC ? '✅' : '❌'}</td>
                          <td>{props.isCDN ? '🛡️' : '—'}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Vulnerabilities */}
          {cbom.vulnerabilities?.length > 0 && (
            <div className="card">
              <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 16, color: 'var(--text-secondary)' }}>VULNERABILITIES ({cbom.vulnerabilities.length})</h3>
              <div className="table-wrapper">
                <table>
                  <thead><tr><th>CWE/ID</th><th>Description</th><th>HNDL Score</th></tr></thead>
                  <tbody>
                    {cbom.vulnerabilities.map((v, i) => (
                      <tr key={i}>
                        <td className="mono" style={{ color: 'var(--accent-orange)' }}>{v.id}</td>
                        <td style={{ fontSize: 12 }}>{v.description?.slice(0, 100)}{v.description?.length > 100 ? '…' : ''}</td>
                        <td style={{ fontWeight: 700, color: '#ef4444' }}>{v.ratings?.[0]?.score?.toFixed(1) || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Raw JSON */}
          <div className="card" style={{ marginTop: 20 }}>
            <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 12, color: 'var(--text-secondary)' }}>RAW CYCLONEDX JSON</h3>
            <pre style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)', overflowX: 'auto', maxHeight: 400, background: 'rgba(0,0,0,0.3)', padding: 16, borderRadius: 8, whiteSpace: 'pre-wrap' }}>
              {JSON.stringify(cbom, null, 2)}
            </pre>
          </div>
        </>
      )}
    </div>
  )
}
