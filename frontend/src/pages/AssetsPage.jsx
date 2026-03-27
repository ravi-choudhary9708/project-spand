import React, { useEffect, useState } from 'react'
import api from '../api/client'

/* ── Helpers ─────────────────────────────────────────── */
function HNDLBar({ score }) {
  const s = score || 0
  const color = s >= 7.5 ? '#ef4444' : s >= 5 ? '#f97316' : s >= 2.5 ? '#f59e0b' : '#10b981'
  return (
    <div className="hndl-bar">
      <span style={{ color, fontWeight: 700, minWidth: 28 }}>{s.toFixed(1)}</span>
      <div className="hndl-track"><div className="hndl-fill" style={{ width: `${s * 10}%`, background: color }} /></div>
    </div>
  )
}

const pqcColor = (r) =>
  ({ 'Quantum Safe': '#10b981', 'Partially Safe': '#f59e0b', 'Vulnerable': '#f97316', 'Critical Risk': '#ef4444' })[r] || '#6b7280'

/** Badge for scan_method field (openssl_cli / python_ssl / testssl) */
function ScanMethodBadge({ method }) {
  if (!method) return null
  const map = {
    openssl_cli: { label: 'OpenSSL CLI', color: '#10b981', bg: 'rgba(16,185,129,0.12)' },
    python_ssl:  { label: 'Python SSL',  color: '#f59e0b', bg: 'rgba(245,158,11,0.12)' },
    testssl:     { label: 'testssl.sh',  color: '#3b82f6', bg: 'rgba(59,130,246,0.12)' },
  }
  const m = map[method] || { label: method, color: '#94a3b8', bg: 'rgba(148,163,184,0.1)' }
  return (
    <span style={{
      fontSize: 10, fontWeight: 600, padding: '2px 7px',
      borderRadius: 20, background: m.bg, color: m.color,
      border: `1px solid ${m.color}40`, letterSpacing: 0.3,
    }}>{m.label}</span>
  )
}

/** One info row inside the detail panel */
function InfoRow({ label, value, mono }) {
  if (!value && value !== 0) return null
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: 12 }}>
      <span style={{ color: 'var(--text-muted)' }}>{label}</span>
      <span style={{ fontWeight: 600, fontFamily: mono ? 'var(--font-mono)' : undefined, fontSize: mono ? 11 : 12 }}>{value}</span>
    </div>
  )
}

/* ── Certificate card ────────────────────────────────── */
function CertCard({ c }) {
  const algo    = c.algorithm || 'Unknown'
  const keySize = c.key_size  ? `${c.key_size}-bit` : '—'
  const issuer  = typeof c.issuer === 'object'
    ? (c.issuer?.organizationName || c.issuer?.commonName || 'Unknown')
    : (c.issuer || 'Unknown')
  const subject = typeof c.subject === 'object'
    ? (c.subject?.commonName || c.subject?.organizationName || '—')
    : (c.subject || '—')

  const isUnknownAlgo = algo === 'UNKNOWN' || algo === 'Unknown'
  const algoColor = isUnknownAlgo ? '#6b7280' : '#00d4ff'

  return (
    <div style={{
      padding: '10px 12px',
      background: 'rgba(0,0,0,0.25)',
      border: '1px solid rgba(255,255,255,0.07)',
      borderRadius: 10,
      marginBottom: 8,
    }}>
      {/* Subject */}
      <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-primary)', marginBottom: 6 }}>{subject}</div>

      {/* Algorithm + key size — highlighted */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
          color: algoColor, background: `${algoColor}18`,
          padding: '2px 8px', borderRadius: 6,
          border: `1px solid ${algoColor}35`,
        }}>
          {algo}
        </span>
        {c.key_size && (
          <span style={{
            fontSize: 11, fontWeight: 600,
            color: c.key_size < 2048 ? '#ef4444' : c.key_size < 3072 ? '#f97316' : '#10b981',
            background: 'rgba(255,255,255,0.05)',
            padding: '2px 8px', borderRadius: 6,
          }}>
            {keySize}
          </span>
        )}
      </div>

      <InfoRow label="Issuer"   value={issuer} />
      <InfoRow label="Expires"  value={c.expires_at ? new Date(c.expires_at).toLocaleDateString() : '—'} />
      <InfoRow label="HNDL"     value={c.hndl_score != null ? c.hndl_score.toFixed(2) : '—'} />
    </div>
  )
}

/* ── Cipher suite row ─────────────────────────────────── */
function CipherRow({ s }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      fontSize: 12, padding: '6px 0',
      borderBottom: '1px solid rgba(255,255,255,0.05)',
    }}>
      <div>
        <span className="mono" style={{ fontSize: 11 }}>{s.name || '—'}</span>
        {s.tls_version && (
          <span style={{ marginLeft: 8, fontSize: 10, color: 'var(--text-muted)' }}>{s.tls_version}</span>
        )}
        {s.port && (
          <span style={{ marginLeft: 6, fontSize: 10, color: 'var(--accent-purple)' }}>:{s.port}</span>
        )}
      </div>
      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
        {s.key_exchange && s.key_exchange !== 'UNKNOWN' && (
          <span style={{ fontSize: 10, color: '#93c5fd', fontFamily: 'var(--font-mono)' }}>{s.key_exchange}</span>
        )}
        <span style={{ color: s.is_quantum_vulnerable ? '#ef4444' : '#10b981', fontWeight: 700, fontSize: 11 }}>
          {s.is_quantum_vulnerable ? '⚠ Vuln' : '✓ Safe'}
        </span>
      </div>
    </div>
  )
}

/* ── Asset detail panel ──────────────────────────────── */
function AssetDetail({ asset, onClose }) {
  const tlsData = asset.tls_data || {}
  const scanMethod = tlsData.scan_method || null

  return (
    <div className="card scroll-fade" style={{ maxHeight: '82vh', overflowY: 'auto' }}>
      {/* Header */}
      <div className="flex-between" style={{ marginBottom: 14 }}>
        <div>
          <h3 style={{ fontWeight: 700, color: 'var(--accent-cyan)', fontSize: 15 }}>{asset.domain}</h3>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
            {(asset.resolved_ips || []).join(' · ')}
          </div>
        </div>
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 20, lineHeight: 1 }}>×</button>
      </div>

      {/* Scan method badge */}
      {scanMethod && (
        <div style={{ marginBottom: 12 }}>
          <span style={{ fontSize: 10, color: 'var(--text-muted)', marginRight: 6 }}>Scan method:</span>
          <ScanMethodBadge method={scanMethod} />
        </div>
      )}

      {/* KPI grid */}
      <div className="grid-2" style={{ gap: 10, marginBottom: 16 }}>
        {[
          ['HNDL Score', asset.hndl_score?.toFixed(2)],
          ['Protocol',   asset.protocol],
          ['PQC Status', asset.pqc_readiness],
          ['Category',   asset.service_category],
        ].map(([k, v]) => (
          <div key={k} style={{ background: 'rgba(255,255,255,0.03)', padding: '8px 10px', borderRadius: 8 }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2 }}>{k}</div>
            <div style={{ fontWeight: 700, fontSize: 13, color: k === 'PQC Status' ? pqcColor(v) : undefined }}>{v || '—'}</div>
          </div>
        ))}
      </div>

      {/* Open ports */}
      {asset.open_ports?.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 6, letterSpacing: 1 }}>OPEN PORTS</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {asset.open_ports.map((p, i) => (
              <span key={i} style={{
                fontSize: 11, padding: '2px 8px', borderRadius: 6,
                background: 'rgba(59,130,246,0.1)', color: '#93c5fd',
                border: '1px solid rgba(59,130,246,0.2)', fontFamily: 'var(--font-mono)',
              }}>
                {p.port}/{p.service || '?'}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Certificates */}
      {asset.certificates?.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 8, letterSpacing: 1 }}>
            CERTIFICATES ({asset.certificates.length})
          </div>
          {asset.certificates.map((c, i) => <CertCard key={c.cert_id || i} c={c} />)}
        </div>
      )}

      {/* Cipher suites */}
      {asset.cipher_suites?.length > 0 && (
        <div>
          <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 6, letterSpacing: 1 }}>
            CIPHER SUITES ({asset.cipher_suites.length})
          </div>
          {asset.cipher_suites.map((s, i) => <CipherRow key={s.suite_id || i} s={s} />)}
        </div>
      )}
    </div>
  )
}

/* ── Main page ───────────────────────────────────────── */
export default function AssetsPage() {
  const [data, setData]     = useState({ assets: [], total: 0 })
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState(null)
  const [filter, setFilter]   = useState({ min_hndl: '', pqc_readiness: '' })

  useEffect(() => { loadAssets() }, [filter])

  const loadAssets = async () => {
    setLoading(true)
    const params = {}
    if (filter.min_hndl)     params.min_hndl = filter.min_hndl
    if (filter.pqc_readiness) params.pqc_readiness = filter.pqc_readiness
    try { const r = await api.get('/assets', { params }); setData(r.data) } catch {} finally { setLoading(false) }
  }

  const loadAssetDetail = async (a) => {
    try { const r = await api.get(`/assets/${a.asset_id}`); setSelected(r.data) } catch { setSelected(a) }
  }

  return (
    <div className="scroll-fade">
      <div className="page-header">
        <div>
          <h1 className="page-title">Asset Inventory</h1>
          <p className="page-subtitle">{data.total} cryptographic assets indexed</p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <select className="form-select" style={{ width: 160 }} value={filter.pqc_readiness}
            onChange={e => setFilter({ ...filter, pqc_readiness: e.target.value })}>
            <option value="">All Readiness</option>
            <option value="Quantum Safe">Quantum Safe</option>
            <option value="Partially Safe">Partially Safe</option>
            <option value="Vulnerable">Vulnerable</option>
            <option value="Critical">Critical</option>
          </select>
          <input className="form-input" style={{ width: 140 }} type="number" placeholder="Min HNDL" value={filter.min_hndl}
            onChange={e => setFilter({ ...filter, min_hndl: e.target.value })} />
        </div>
      </div>

      <div className={selected ? 'grid-2' : ''}>
        <div>
          {loading
            ? <div style={{ textAlign: 'center', padding: 60 }}><span className="loading-spinner" /></div>
            : data.assets.length === 0
            ? <div className="card empty-state"><p>🖥️ No assets found. Run a scan first.</p></div>
            : (
              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th>Domain</th>
                      <th>Protocol</th>
                      <th>Algorithm</th>
                      <th>Key Size</th>
                      <th>HNDL Score</th>
                      <th>PQC Readiness</th>
                      <th>CDN</th>
                      <th>Findings</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.assets.map(a => {
                      /* Best-effort algorithm/key_size from first cert */
                      const firstCert = a.certificates?.[0]
                      const algo    = firstCert?.algorithm  || a.algorithm  || '—'
                      const keySize = firstCert?.key_size   || a.key_size

                      const isUnknownAlgo = algo === 'UNKNOWN' || algo === '—'
                      const algoColor = isUnknownAlgo ? '#6b7280' : '#00d4ff'

                      return (
                        <tr key={a.asset_id} onClick={() => loadAssetDetail(a)} style={{ cursor: 'pointer' }}>
                          <td>
                            <div style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>{a.domain}</div>
                            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{(a.resolved_ips || []).join(', ')}</div>
                          </td>
                          <td><span className="tag">{a.protocol || '—'}</span></td>

                          {/* Algorithm — real value from scanner */}
                          <td>
                            <span style={{
                              fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
                              color: algoColor,
                            }}>
                              {algo}
                            </span>
                          </td>

                          {/* Key size — real value from OpenSSL */}
                          <td>
                            {keySize
                              ? <span style={{
                                  fontWeight: 600, fontSize: 12,
                                  color: keySize < 2048 ? '#ef4444' : keySize < 3072 ? '#f97316' : '#10b981',
                                }}>
                                  {keySize}-bit
                                </span>
                              : <span style={{ color: 'var(--text-muted)' }}>—</span>
                            }
                          </td>

                          <td><HNDLBar score={a.hndl_score || 0} /></td>
                          <td>
                            <span style={{ color: pqcColor(a.pqc_readiness), fontWeight: 600, fontSize: 12 }}>
                              {a.pqc_readiness || '—'}
                            </span>
                          </td>
                          <td>{a.is_cdn ? '🛡️ CDN' : '—'}</td>
                          <td><span style={{ fontWeight: 700 }}>{a.findings_count}</span></td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )
          }
        </div>

        {selected && (
          <AssetDetail asset={selected} onClose={() => setSelected(null)} />
        )}
      </div>
    </div>
  )
}
