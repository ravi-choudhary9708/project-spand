import React, { useEffect, useState } from 'react'
import api from '../api/client'

function HNDLBar({ score }) {
  const color = score >= 7.5 ? '#ef4444' : score >= 5 ? '#f97316' : score >= 2.5 ? '#f59e0b' : '#10b981'
  return (
    <div className="hndl-bar">
      <span style={{ color, fontWeight: 700, minWidth: 28 }}>{score?.toFixed(1)}</span>
      <div className="hndl-track"><div className="hndl-fill" style={{ width: `${score * 10}%`, background: color }} /></div>
    </div>
  )
}

export default function AssetsPage() {
  const [data, setData] = useState({ assets: [], total: 0 })
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState(null)
  const [filter, setFilter] = useState({ min_hndl: '', pqc_readiness: '' })

  useEffect(() => { loadAssets() }, [filter])

  const loadAssets = async () => {
    setLoading(true)
    const params = {}
    if (filter.min_hndl) params.min_hndl = filter.min_hndl
    if (filter.pqc_readiness) params.pqc_readiness = filter.pqc_readiness
    try { const r = await api.get('/assets', { params }); setData(r.data) } catch {} finally { setLoading(false) }
  }

  const loadAssetDetail = async (a) => {
    try { const r = await api.get(`/assets/${a.asset_id}`); setSelected(r.data) } catch { setSelected(a) }
  }

  const pqcColor = (r) => ({ 'Quantum Safe': '#10b981', 'Partially Safe': '#f59e0b', 'Vulnerable': '#f97316', 'Critical Risk': '#ef4444' })[r] || '#6b7280'

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
          {loading ? <div style={{ textAlign: 'center', padding: 60 }}><span className="loading-spinner" /></div>
            : data.assets.length === 0 ? (
              <div className="card empty-state">
                <p>🖥️ No assets found. Run a scan first.</p>
              </div>
            ) : (
              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr><th>Domain</th><th>Protocol</th><th>HNDL Score</th><th>PQC Readiness</th><th>CDN</th><th>Findings</th></tr>
                  </thead>
                  <tbody>
                    {data.assets.map(a => (
                      <tr key={a.asset_id} onClick={() => loadAssetDetail(a)} style={{ cursor: 'pointer' }}>
                        <td>
                          <div style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>{a.domain}</div>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{(a.resolved_ips || []).join(', ')}</div>
                        </td>
                        <td><span className="tag">{a.protocol || '—'}</span></td>
                        <td><HNDLBar score={a.hndl_score || 0} /></td>
                        <td><span style={{ color: pqcColor(a.pqc_readiness), fontWeight: 600, fontSize: 12 }}>{a.pqc_readiness || '—'}</span></td>
                        <td>{a.is_cdn ? '🛡️ CDN' : '—'}</td>
                        <td><span style={{ fontWeight: 700 }}>{a.findings_count}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
        </div>

        {selected && (
          <div className="card scroll-fade" style={{ maxHeight: '80vh', overflowY: 'auto' }}>
            <div className="flex-between" style={{ marginBottom: 16 }}>
              <h3 style={{ fontWeight: 700 }}>{selected.domain}</h3>
              <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 18 }}>×</button>
            </div>
            <div className="grid-2" style={{ gap: 12, marginBottom: 16 }}>
              {[['HNDL Score', selected.hndl_score?.toFixed(2)], ['Protocol', selected.protocol], ['PQC', selected.pqc_readiness], ['Category', selected.service_category]].map(([k, v]) => (
                <div key={k} style={{ background: 'rgba(255,255,255,0.03)', padding: 10, borderRadius: 8 }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2 }}>{k}</div>
                  <div style={{ fontWeight: 700, fontSize: 14 }}>{v || '—'}</div>
                </div>
              ))}
            </div>
            {selected.certificates?.length > 0 && (
              <div>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8 }}>CERTIFICATES</div>
                {selected.certificates.map(c => (
                  <div key={c.cert_id} style={{ padding: '8px 10px', background: 'rgba(255,255,255,0.03)', borderRadius: 8, marginBottom: 8 }}>
                    <div style={{ fontSize: 12, fontWeight: 600 }}>{c.subject}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Issuer: {c.issuer}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Algorithm: {c.algorithm} ({c.key_size}-bit)</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Expires: {c.expires_at ? new Date(c.expires_at).toLocaleDateString() : '—'}</div>
                  </div>
                ))}
              </div>
            )}
            {selected.cipher_suites?.length > 0 && (
              <div style={{ marginTop: 12 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8 }}>CIPHER SUITES</div>
                {selected.cipher_suites.map(s => (
                  <div key={s.suite_id} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, padding: '4px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                    <span className="mono">{s.name}</span>
                    <span style={{ color: s.is_quantum_vulnerable ? '#ef4444' : '#10b981' }}>{s.is_quantum_vulnerable ? '⚠️ Vuln' : '✅ Safe'}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
