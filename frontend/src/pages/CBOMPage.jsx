import React, { useEffect, useState } from 'react'
import api from '../api/client'
import toast from 'react-hot-toast'

/* ── Helpers ───────────────────────────────────────────────────── */

function AlgoBadge({ algo }) {
  if (!algo || algo === 'UNKNOWN' || algo === '') return <span style={{ color: 'var(--text-muted)' }}>Unknown</span>
  const isQuantumSafe = ['CRYSTALS-KYBER','CRYSTALS-DILITHIUM','FALCON','SPHINCS+','Ed25519','Ed448'].includes(algo)
  const color = isQuantumSafe ? '#10b981' : '#ef4444'
  return (
    <span style={{
      fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
      color, background: `${color}15`, padding: '2px 7px',
      borderRadius: 6, border: `1px solid ${color}35`,
    }}>{algo}</span>
  )
}

function KeySizeBadge({ keySize }) {
  if (!keySize) return <span style={{ color: 'var(--text-muted)' }}>—</span>
  const color = keySize < 2048 ? '#ef4444' : keySize < 3072 ? '#f97316' : '#10b981'
  return (
    <span style={{ fontWeight: 700, fontSize: 12, color }}>{keySize}-bit</span>
  )
}

function IssuerCell({ issuer }) {
  if (!issuer) return <span style={{ color: 'var(--text-muted)' }}>—</span>
  if (typeof issuer === 'object') {
    const name = issuer.organizationName || issuer.commonName || '—'
    return <span style={{ fontSize: 12 }}>{name}</span>
  }
  return <span style={{ fontSize: 12 }}>{issuer}</span>
}

export default function CBOMPage() {
  const [scans, setScans]           = useState([])
  const [cbom, setCbom]             = useState(null)
  const [loading, setLoading]       = useState(false)
  const [selectedScan, setSelectedScan] = useState('')
  const [expandedComp, setExpandedComp] = useState(null)

  useEffect(() => {
    api.get('/scans').then(r => setScans(r.data.filter(s => s.status === 'COMPLETED'))).catch(() => {})
  }, [])

  const loadCBOM = async (scanId) => {
    setLoading(true)
    setSelectedScan(scanId)
    setExpandedComp(null)
    try { const r = await api.get(`/scans/${scanId}/cbom`); setCbom(r.data) }
    catch { setCbom(null); toast.error('CBOM not available') }
    finally { setLoading(false) }
  }

  const download = (format) => {
    if (!cbom) return
    const content = format === 'xml' ? objToXml(cbom) : JSON.stringify(cbom, null, 2)
    const type    = format === 'xml' ? 'application/xml' : 'application/json'
    const blob    = new Blob([content], { type })
    const url     = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `cbom-${selectedScan}.${format}`; a.click()
    toast.success(`CBOM downloaded as ${format.toUpperCase()}`)
  }

  const objToXml = (obj) =>
    `<?xml version="1.0" encoding="UTF-8"?>\n<bom xmlns="http://cyclonedx.org/schema/bom/1.4">\n${JSON.stringify(obj, null, 2)}\n</bom>`

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
          {/* ── CBOM Header KPIs ──────────────────────────────── */}
          <div className="card" style={{ marginBottom: 20, borderLeft: '3px solid var(--accent-cyan)' }}>
            <div className="grid-3" style={{ gap: 16 }}>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>FORMAT</div>
                <div style={{ fontWeight: 700, fontSize: 16 }}>{cbom.bomFormat}</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Spec v{cbom.specVersion}</div>
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>TOTAL ASSETS</div>
                <div style={{ fontWeight: 700, fontSize: 28, color: 'var(--accent-cyan)' }}>
                  {cbom.cryptoProperties?.totalAssets || 0}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>OVERALL HNDL</div>
                <div style={{
                  fontWeight: 700, fontSize: 28,
                  color: cbom.cryptoProperties?.overallHndlScore > 6 ? '#ef4444' : '#f59e0b',
                }}>
                  {cbom.cryptoProperties?.overallHndlScore?.toFixed(1) || '0.0'}
                </div>
              </div>
            </div>
            <div style={{ marginTop: 16, display: 'flex', gap: 16, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 12 }}>🔴 Quantum Vulnerable: <strong>{cbom.cryptoProperties?.quantumVulnerableCount || 0}</strong></span>
              <span style={{ fontSize: 12 }}>🟢 PQC Ready: <strong>{cbom.cryptoProperties?.pqcReadyCount || 0}</strong></span>
              <span style={{ fontSize: 12 }}>🔢 Serial: <span className="mono" style={{ fontSize: 10 }}>{cbom.serialNumber}</span></span>
            </div>
          </div>

          {/* ── Components (assets) ───────────────────────────── */}
          {cbom.components?.length > 0 && (
            <div className="card" style={{ marginBottom: 20 }}>
              <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 16, color: 'var(--text-secondary)' }}>
                COMPONENTS ({cbom.components.length})
              </h3>
              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th>Component</th>
                      <th>Algorithm</th>
                      <th>Key Size</th>
                      <th>Issuer</th>
                      <th>HNDL Score</th>
                      <th>PQC</th>
                      <th>CDN</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cbom.components.map((c, i) => {
                      const props    = c.cryptoProperties?.relatedCryptoMaterialProperties || {}
                      const certProp = c.cryptoProperties?.certificateProperties || {}
                      const algoProp = c.cryptoProperties?.algorithmProperties?.[0] || {}

                      // Best source for algorithm: certificateProperties > algorithmProperties > parameterSetIdentifier
                      const algo    = certProp.signatureAlgorithmRef || algoProp.primitive || '—'
                      const keySize = certProp.keySize || null
                      const issuer  = certProp.issuerName || null

                      const expanded = expandedComp === i
                      return (
                        <React.Fragment key={i}>
                          <tr
                            style={{ cursor: 'pointer' }}
                            onClick={() => setExpandedComp(expanded ? null : i)}
                          >
                            <td>
                              <div style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>{c.name}</div>
                              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{c.description}</div>
                            </td>
                            <td><AlgoBadge algo={algo} /></td>
                            <td><KeySizeBadge keySize={keySize} /></td>
                            <td><IssuerCell issuer={issuer} /></td>
                            <td style={{ fontWeight: 700, color: props.hndlScore > 6 ? '#ef4444' : props.hndlScore > 3 ? '#f97316' : '#10b981' }}>
                              {props.hndlScore?.toFixed(2) || '—'}
                            </td>
                            <td style={{ fontSize: 16 }}>{props.isPQC ? '✅' : '❌'}</td>
                            <td>{props.isCDN ? '🛡️' : '—'}</td>
                          </tr>

                          {/* Expanded: cipher suites */}
                          {expanded && c.cryptoProperties?.algorithmProperties?.length > 0 && (
                            <tr>
                              <td colSpan={7} style={{ background: 'rgba(0,0,0,0.2)', padding: '10px 16px' }}>
                                <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 8, letterSpacing: 1 }}>
                                  CIPHER SUITES
                                </div>
                                {c.cryptoProperties.algorithmProperties.map((alg, j) => (
                                  <div key={j} style={{
                                    display: 'flex', gap: 12, alignItems: 'center',
                                    fontSize: 12, padding: '4px 0',
                                    borderBottom: '1px solid rgba(255,255,255,0.04)',
                                  }}>
                                    <span className="mono" style={{ fontSize: 11, flex: 1 }}>{alg.parameterSetIdentifier || '—'}</span>
                                    <span style={{ color: '#94a3b8', fontSize: 11 }}>{alg.tlsVersion || ''}</span>
                                    <span style={{ color: '#93c5fd', fontFamily: 'var(--font-mono)', fontSize: 10 }}>{alg.keyExchange || ''}</span>
                                    <span style={{ color: alg.quantumVulnerable ? '#ef4444' : '#10b981', fontWeight: 700, fontSize: 11 }}>
                                      {alg.quantumVulnerable ? '⚠ Vuln' : '✓ Safe'}
                                    </span>
                                  </div>
                                ))}
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Vulnerabilities ───────────────────────────────── */}
          {cbom.vulnerabilities?.length > 0 && (
            <div className="card" style={{ marginBottom: 20 }}>
              <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 16, color: 'var(--text-secondary)' }}>
                VULNERABILITIES ({cbom.vulnerabilities.length})
              </h3>
              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th>CWE/ID</th>
                      <th>Description</th>
                      <th>Severity</th>
                      <th>HNDL Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cbom.vulnerabilities.map((v, i) => (
                      <tr key={i}>
                        <td className="mono" style={{ color: 'var(--accent-orange)' }}>{v.id}</td>
                        <td style={{ fontSize: 12 }}>{v.description?.slice(0, 120)}{v.description?.length > 120 ? '…' : ''}</td>
                        <td>
                          <span className={`badge badge-${(v.ratings?.[0]?.severity || 'medium').toLowerCase()}`}>
                            {v.ratings?.[0]?.severity || '—'}
                          </span>
                        </td>
                        <td style={{ fontWeight: 700, color: '#ef4444' }}>{v.ratings?.[0]?.score?.toFixed(1) || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Raw JSON ─────────────────────────────────────── */}
          <div className="card" style={{ marginTop: 20 }}>
            <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 12, color: 'var(--text-secondary)' }}>RAW CYCLONEDX JSON</h3>
            <pre style={{
              fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)',
              overflowX: 'auto', maxHeight: 400,
              background: 'rgba(0,0,0,0.3)', padding: 16, borderRadius: 8, whiteSpace: 'pre-wrap',
            }}>
              {JSON.stringify(cbom, null, 2)}
            </pre>
          </div>
        </>
      )}
    </div>
  )
}
