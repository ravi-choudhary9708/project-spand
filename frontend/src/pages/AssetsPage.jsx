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
    openssl_cli:   { label: 'OpenSSL CLI (real)', color: '#10b981', bg: 'rgba(16,185,129,0.12)' },
    python_ssl:    { label: 'Python SSL (real)',  color: '#10b981', bg: 'rgba(16,185,129,0.12)' },
    python_ssl_real: { label: 'Python SSL (real)', color: '#10b981', bg: 'rgba(16,185,129,0.12)' },
    python_ssl_inferred: { label: 'Python SSL (approx)', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)' },
    tls_scan:      { label: 'TLS cipher (real)',  color: '#10b981', bg: 'rgba(16,185,129,0.12)' },
    origin_bypass: { label: 'Origin Bypass (real)', color: '#10b981', bg: 'rgba(16,185,129,0.12)' },
    ct_logs_issuer_inferred: { label: 'CT logs (approx)', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)' },
    default:       { label: 'Default (no data)', color: '#6b7280', bg: 'rgba(107,114,128,0.12)' },
    testssl:       { label: 'testssl.sh',  color: '#3b82f6', bg: 'rgba(59,130,246,0.12)' },
    "testssl+openssl_cli": { label: 'testssl + OpenSSL',  color: '#3b82f6', bg: 'rgba(59,130,246,0.12)' },
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

/** Badge for network_type (public / internal / cdn_protected / restricted) */
function NetworkBadge({ type }) {
  const map = {
    internal:      { label: 'internal',      color: '#ef4444', icon: '🔒' },
    cdn_protected: { label: 'cdn_protected', color: '#10b981', icon: '🛡️' },
    restricted:    { label: 'restricted',    color: '#f59e0b', icon: '🚧' },
    public:        { label: 'public',        color: '#3b82f6', icon: '🌐' },
  }
  const m = map[type] || { label: type || 'public', color: '#94a3b8', icon: '🌐' }
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, padding: '2px 8px',
      borderRadius: 6, background: `${m.color}15`, color: m.color,
      border: `1px solid ${m.color}40`, textTransform: 'uppercase',
      display: 'inline-flex', alignItems: 'center', gap: 4
    }}>
      <span style={{ fontSize: 12 }}>{m.icon}</span> {m.label}
    </span>
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
function CertCard({ c, scanMethod }) {
  const algo    = c.algorithm || 'Unknown'
  const keySize = c.key_size  ? `${c.key_size}-bit` : '—'
  const issuer  = typeof c.issuer === 'object'
    ? (c.issuer?.organizationName || c.issuer?.commonName || 'Unknown')
    : (c.issuer || 'Unknown')
  const subject = typeof c.subject === 'object'
    ? (c.subject?.commonName || c.subject?.organizationName || '—')
    : (c.subject || '—')

  const isDefault = scanMethod === 'default'
  const isApprox  = scanMethod === 'ct_logs_issuer_inferred'
  const suffix = isDefault ? ' (default)' : isApprox ? ' (approx)' : ''

  const isUnknownAlgo = algo === 'UNKNOWN' || algo === 'Unknown' || isDefault
  const algoColor = isUnknownAlgo ? '#6b7280' : isApprox ? '#f59e0b' : '#00d4ff'

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
          {suffix && <span style={{ fontSize: 9, opacity: 0.8, marginLeft: 4, fontWeight: 'normal' }}>{suffix}</span>}
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

/* ── HNDL color helper ───────────────────────────────── */
const hndlColor = (s) => {
  if (!s && s !== 0) return '#6b7280'
  if (s >= 7.5) return '#ef4444'
  if (s >= 5) return '#f97316'
  if (s >= 2.5) return '#f59e0b'
  return '#10b981'
}

/* ── Detail KPI card ─────────────────────────────────── */
function DetailKpi({ label, value, color }) {
  return (
    <div style={{
      padding: '10px 12px',
      background: 'rgba(0,0,0,0.25)',
      border: '1px solid rgba(255,255,255,0.07)',
      borderRadius: 10,
    }}>
      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4, letterSpacing: 0.5, textTransform: 'uppercase' }}>{label}</div>
      <div style={{ fontSize: 14, fontWeight: 700, color: color || 'var(--text-primary)', wordBreak: 'break-word' }}>{value || '—'}</div>
    </div>
  )
}

/* ── Asset detail panel ──────────────────────────────── */
function AssetDetail({ asset, onClose }) {
  const tlsData = asset.tls_data || {}
  const scanMethod = asset.scan_method || tlsData.scan_method || null

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
        <DetailKpi label="Avg HNDL" value={asset.hndl_score?.toFixed(2)} color={hndlColor(asset.hndl_score)} />
        <DetailKpi label="Server" value={asset.server_software || "Unknown"} color="#3b82f6" />
        <DetailKpi label="CDN Provider" value={asset.cdn_provider || "None / Direct"} color="#8b5cf6" />
        <DetailKpi label="Network" value={asset.network_type?.toUpperCase()} color={asset.network_type === 'internal' ? '#ef4444' : '#10b981'} />
        <DetailKpi label="Category" value={asset.service_category?.replace('_', ' ').toUpperCase()} color="#f59e0b" />
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
          {asset.certificates.map((c, i) => <CertCard key={c.cert_id || i} c={c} scanMethod={scanMethod} />)}
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

      {/* PQC Proxy Wrapper — only for quantum-vulnerable assets */}
      {(() => {
        const algo = (asset.certificates?.[0]?.algorithm || asset.algorithm || '').toUpperCase()
        const isVuln = /RSA|ECDSA|ECC|DHE|DH\b|DSA|ECDHE/.test(algo)
        if (!isVuln) return null
        return (
          <div style={{
            marginTop: 16, padding: 16,
            background: 'linear-gradient(135deg, rgba(139,92,246,0.08), rgba(0,212,255,0.05))',
            border: '1px solid rgba(139,92,246,0.2)',
            borderRadius: 12,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
              <span style={{ fontSize: 18 }}>🛡️</span>
              <div>
                <div style={{ fontSize: 12, fontWeight: 700, color: '#a78bfa' }}>PQC SIDECAR PROXY</div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>Deploy quantum-safe wrapper without changing legacy code</div>
              </div>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 12, lineHeight: 1.6 }}>
              Generate a ready-to-deploy Docker config that wraps <strong>{asset.domain}</strong> in ML-KEM (Kyber) TLS termination.
              The legacy server stays untouched.
            </div>
            <button
              className="btn btn-primary"
              style={{
                fontSize: 11, padding: '8px 16px', borderRadius: 8, width: '100%',
                background: 'linear-gradient(135deg, #8b5cf6, #3b82f6)',
                border: 'none', fontWeight: 700,
              }}
              onClick={async (e) => {
                e.stopPropagation()
                try {
                  const res = await api.get(`/proxy/generate/${asset.asset_id}`, { responseType: 'blob' })
                  const url = URL.createObjectURL(res.data)
                  const a = document.createElement('a')
                  a.href = url
                  a.download = `pqc-proxy-${asset.domain.replace(/\./g, '-')}.zip`
                  a.click()
                  URL.revokeObjectURL(url)
                } catch (err) {
                  console.error('Failed to generate PQC config:', err)
                  alert('Failed to generate PQC proxy config. Check permissions.')
                }
              }}
            >
              ⬇️ Download PQC Proxy Config
            </button>
          </div>
        )
      })()}
    </div>
  )
}

/* ── Main page ───────────────────────────────────────── */
export default function AssetsPage() {
  const [data, setData]     = useState({ assets: [], total: 0 })
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState(null)
  const [filter, setFilter]   = useState({ min_hndl: '', pqc_readiness: '' })
  const [page, setPage]       = useState(1)
  const pageSize = 50;

  useEffect(() => { loadAssets() }, [filter, page])

  const loadAssets = async () => {
    setLoading(true)
    const params = {
      limit: pageSize,
      offset: (page - 1) * pageSize
    }
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
            onChange={e => { setFilter({ ...filter, pqc_readiness: e.target.value }); setPage(1); }}>
            <option value="">All Readiness</option>
            <option value="Quantum Safe">Quantum Safe</option>
            <option value="Partially Safe">Partially Safe</option>
            <option value="Vulnerable">Vulnerable</option>
            <option value="Critical">Critical</option>
          </select>
          <input className="form-input" style={{ width: 140 }} type="number" placeholder="Min HNDL" value={filter.min_hndl}
            onChange={e => { setFilter({ ...filter, min_hndl: e.target.value }); setPage(1); }} />
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
                      <th>Network</th>
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

                      const isDefault = a.scan_method === 'default'
                      const isApprox  = a.scan_method === 'ct_logs_issuer_inferred'
                      const suffix = isDefault ? ' (default)' : isApprox ? ' (approx)' : ''

                      const isUnknownAlgo = algo === 'UNKNOWN' || algo === '—' || isDefault
                      const algoColor = isUnknownAlgo ? '#6b7280' : isApprox ? '#f59e0b' : '#00d4ff'

                      return (
                        <tr key={a.asset_id} onClick={() => loadAssetDetail(a)} style={{ cursor: 'pointer' }}>
                          <td>
                            <div style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>{a.domain}</div>
                            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{(a.resolved_ips || []).join(', ')}</div>
                          </td>
                          <td><span className="tag">{a.protocol || '—'}</span></td>
                          <td><NetworkBadge type={a.network_type} /></td>

                          {/* Algorithm — real value from scanner */}
                          <td>
                            <span style={{
                              fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
                              color: algoColor,
                            }}>
                              {algo}
                              {suffix && <span style={{ fontSize: 9, opacity: 0.8, marginLeft: 4, fontWeight: 'normal' }}>{suffix}</span>}
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
                {data.total > pageSize && (
                  <div style={{ 
                    padding: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', 
                    borderTop: '1px solid rgba(255,255,255,0.05)', backgroundColor: 'rgba(0,0,0,0.15)' 
                  }}>
                    <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                      Showing {(page - 1) * pageSize + 1} to {Math.min(page * pageSize, data.total)} of {data.total} assets
                    </div>
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                      <button 
                        onClick={() => setPage(p => Math.max(1, p - 1))} 
                        disabled={page === 1}
                        style={{ padding: '6px 12px', fontSize: 13, borderRadius: 6, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: page === 1 ? '#6b7280' : 'var(--text-primary)', cursor: page === 1 ? 'not-allowed' : 'pointer', opacity: page === 1 ? 0.5 : 1 }}>
                        Prev
                      </button>
                      
                      {Array.from({ length: Math.ceil(data.total / pageSize) || 1 }, (_, i) => i + 1)
                        .filter(p => p === 1 || p === Math.ceil(data.total / pageSize) || Math.abs(p - page) <= 2)
                        .map((p, i, arr) => (
                          <React.Fragment key={p}>
                            {i > 0 && arr[i - 1] !== p - 1 && <span style={{ padding: '0 4px', color: '#6b7280' }}>...</span>}
                            <button 
                              onClick={() => setPage(p)}
                              style={{ 
                                padding: '6px 12px', fontSize: 13, borderRadius: 6, border: '1px solid',
                                borderColor: page === p ? 'var(--accent-cyan)' : 'rgba(255,255,255,0.1)',
                                background: page === p ? 'rgba(0, 212, 255, 0.1)' : 'transparent',
                                color: page === p ? 'var(--accent-cyan)' : 'var(--text-primary)',
                                cursor: 'pointer',
                                fontWeight: page === p ? 600 : 400
                              }}>
                              {p}
                            </button>
                          </React.Fragment>
                        ))
                      }
                      
                      <button 
                        onClick={() => setPage(p => Math.min(Math.ceil(data.total / pageSize), p + 1))} 
                        disabled={page === Math.ceil(data.total / pageSize)}
                        style={{ padding: '6px 12px', fontSize: 13, borderRadius: 6, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: page === Math.ceil(data.total / pageSize) ? '#6b7280' : 'var(--text-primary)', cursor: page === Math.ceil(data.total / pageSize) ? 'not-allowed' : 'pointer', opacity: page === Math.ceil(data.total / pageSize) ? 0.5 : 1 }}>
                        Next
                      </button>
                    </div>
                  </div>
                )}
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
