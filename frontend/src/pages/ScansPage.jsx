import React, { useEffect, useState } from 'react'
import api from '../api/client'
import toast from 'react-hot-toast'

function ScanStatusBadge({ status }) {
  const map = { COMPLETED: 'badge-safe', RUNNING: 'badge-medium', FAILED: 'badge-critical', PENDING: 'badge-info', CANCELLED: 'badge-info' }
  return <span className={`badge ${map[status] || 'badge-info'}`}>{status}</span>
}

function NewScanModal({ onClose, onCreated }) {
  const [form, setForm] = useState({ org_name: '', targets: '', authorized: false, full_scan: true })
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!form.authorized) { toast.error('You must confirm authorization to scan.'); return }
    setLoading(true)
    try {
      const targets = form.targets.split('\n').map(t => t.trim()).filter(Boolean)
      const res = await api.post('/scans', { org_name: form.org_name, target_assets: targets, authorized: true, full_scan: form.full_scan })
      toast.success('Scan started!')
      onCreated(res.data)
      onClose()
    } catch (e) {
      toast.error(e.response?.data?.detail || 'Failed to start scan')
    } finally { setLoading(false) }
  }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 }}>
      <div className="card scroll-fade" style={{ width: 520, maxHeight: '90vh', overflowY: 'auto' }}>
        <div className="flex-between" style={{ marginBottom: 20 }}>
          <h2 style={{ fontSize: 18, fontWeight: 700 }}>🔍 New Scan</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 20 }}>×</button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Organization Name *</label>
            <input className="form-input" placeholder="Punjab National Bank" value={form.org_name}
              onChange={e => setForm({ ...form, org_name: e.target.value })} required />
          </div>
          <div className="form-group">
            <label className="form-label">Target Assets (one per line) *</label>
            <textarea className="form-textarea" rows={6} placeholder={"example.com\napi.example.com\n192.168.1.1"}
              value={form.targets} onChange={e => setForm({ ...form, targets: e.target.value })} required style={{ resize: 'vertical' }} />
            <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{form.full_scan ? 'System will auto-discover subdomains, mail servers, and related assets.' : 'Only the exact URLs above will be scanned — no subdomain discovery.'}</p>
          </div>
          <div className="form-group">
            <label className="form-checkbox">
              <input type="checkbox" checked={form.full_scan} onChange={e => setForm({ ...form, full_scan: e.target.checked })} />
              <span style={{ fontSize: 13 }}>🏢 Full Organizational Scan</span>
            </label>
            <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, marginLeft: 22 }}>
              {form.full_scan
                ? 'Discovers subdomains, scans all ports, and mines CT/SPF/DNS records for complete coverage.'
                : 'Scans only the exact domains/IPs you entered — faster but less comprehensive.'}
            </p>
          </div>
          <div className="form-group">
            <label className="form-checkbox">
              <input type="checkbox" checked={form.authorized} onChange={e => setForm({ ...form, authorized: e.target.checked })} />
              <span style={{ fontSize: 13 }}>I confirm authorization to scan these assets</span>
            </label>
          </div>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
            <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? <span className="loading-spinner" /> : '🚀'} Start Scan
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function ScansPage() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [selected, setSelected] = useState(null)
  const [findings, setFindings] = useState([])
  const [assets, setAssets] = useState([])

  useEffect(() => {
    loadScans();
    const interval = setInterval(() => {
      api.get('/scans').then(r => setScans(r.data)).catch(() => {});
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadScans = async () => {
    try { const r = await api.get('/scans'); setScans(r.data); } catch {} finally { setLoading(false); }
  }

  useEffect(() => {
    if (selected) {
      const updated = scans.find(s => s.scan_id === selected.scan_id);
      if (updated) {
        if ((selected.status === 'RUNNING' || selected.status === 'PENDING') && updated.status === 'COMPLETED') {
          selectScan(updated);
        } else if (updated.progress !== selected.progress || updated.status !== selected.status || updated.current_step !== selected.current_step) {
          setSelected(updated);
          // Fetch findings and assets live if progress changed while running
          if (updated.status === 'RUNNING' || updated.status === 'PENDING') {
            api.get(`/scans/${updated.scan_id}/findings`).then(r => setFindings(r.data)).catch(() => {});
            api.get(`/scans/${updated.scan_id}/assets`).then(r => setAssets(r.data)).catch(() => {});
          }
        }
      }
    }
  }, [scans]);

  const selectScan = async (scan) => {
    setSelected(scan)
    try { 
      const [fRes, aRes] = await Promise.all([
        api.get(`/scans/${scan.scan_id}/findings`),
        api.get(`/scans/${scan.scan_id}/assets`)
      ]);
      setFindings(fRes.data)
      setAssets(aRes.data)
    } catch { 
      setFindings([])
      setAssets([]) 
    }
  }

  const cancelScan = async (scanId) => {
    try { await api.delete(`/scans/${scanId}`); toast.success('Scan cancelled'); loadScans() } catch { toast.error('Failed to cancel') }
  }

  const downloadCBOM = async (scanId) => {
    try {
      const r = await api.get(`/scans/${scanId}/cbom`)
      const blob = new Blob([JSON.stringify(r.data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = url; a.download = `cbom-${scanId}.json`; a.click()
    } catch { toast.error('CBOM not ready yet') }
  }

  return (
    <div className="scroll-fade">
      <div className="page-header">
        <div>
          <h1 className="page-title">Scan Management</h1>
          <p className="page-subtitle">Initiate and monitor cryptographic scans</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>＋ New Scan</button>
      </div>

      {showModal && <NewScanModal onClose={() => setShowModal(false)} onCreated={() => loadScans()} />}

      {loading ? (
        <div style={{ textAlign: 'center', padding: 60 }}><span className="loading-spinner" style={{ width: 32, height: 32 }} /></div>
      ) : scans.length === 0 ? (
        <div className="card empty-state">
          <p style={{ fontSize: 16, marginBottom: 12 }}>🔍 No scans yet</p>
          <p>Click "New Scan" to scan your first asset.</p>
        </div>
      ) : (
        <div className="grid-2">
          <div>
            <div className="table-wrapper">
              <table>
                <thead><tr><th>Organization</th><th>Status</th><th>Progress</th><th>Assets</th><th>Actions</th></tr></thead>
                <tbody>
                  {scans.map(scan => (
                    <tr key={scan.scan_id} onClick={() => selectScan(scan)} style={{ cursor: 'pointer' }}>
                      <td>
                        <div style={{ fontWeight: 600 }}>{scan.org_name}</div>
                        <div className="mono" style={{ fontSize: 10, color: 'var(--text-muted)' }}>{scan.scan_id.slice(0, 8)}…</div>
                      </td>
                      <td><ScanStatusBadge status={scan.status} /></td>
                      <td>
                        <div style={{ fontSize: 12 }}>{scan.progress}%</div>
                        <div className="progress-bar" style={{ width: 80 }}>
                          <div className="progress-fill" style={{ width: `${scan.progress}%` }} />
                        </div>
                      </td>
                      <td style={{ fontWeight: 600 }}>{scan.asset_count}</td>
                      <td>
                        <div style={{ display: 'flex', gap: 6 }}>
                          {scan.status === 'COMPLETED' && (
                            <button className="btn btn-secondary" style={{ padding: '4px 8px', fontSize: 11 }}
                              onClick={(e) => { e.stopPropagation(); downloadCBOM(scan.scan_id) }}>CBOM</button>
                          )}
                          {(scan.status === 'RUNNING' || scan.status === 'PENDING') && (
                            <button className="btn btn-danger" style={{ padding: '4px 8px', fontSize: 11 }}
                              onClick={(e) => { e.stopPropagation(); cancelScan(scan.scan_id) }}>Cancel</button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {selected && (
            <div className="card scroll-fade">
              <h3 style={{ fontWeight: 700, marginBottom: 4 }}>{selected.org_name}</h3>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>Scan details & findings</div>
              <div>
                <strong style={{ fontSize: 12, color: 'var(--text-secondary)' }}>TARGETS</strong>
                {(selected.target_assets || []).map(t => <div key={t} className="mono" style={{ fontSize: 12, color: 'var(--accent-cyan)', marginTop: 4 }}>{t}</div>)}
              </div>
              {selected.status === 'RUNNING' && (
                <div style={{ marginTop: 16 }}>
                  <div className="flex-between" style={{ fontSize: 12, marginBottom: 4 }}>
                    <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>
                      {selected.current_step || 'Scanning…'}
                    </span>
                    <span>{selected.progress}%</span>
                  </div>
                  <div className="progress-bar"><div className="progress-fill" style={{ width: `${selected.progress}%` }} /></div>
                </div>
              )}
              {findings.length > 0 && (
                <div style={{ marginTop: 20 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8 }}>TOP FINDINGS ({findings.length})</div>
                  {findings.slice(0, 5).map(f => (
                    <div key={f.finding_id} style={{ padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: 13, fontWeight: 500 }}>{f.title}</span>
                        <span className={`badge badge-${f.severity.toLowerCase()}`}>{f.severity}</span>
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>HNDL: {f.hndl_score?.toFixed(1)} | {f.asset_domain}</div>
                    </div>
                  ))}
                </div>
              )}

              {assets?.length > 0 && (
                <div style={{ marginTop: 20 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8 }}>ASSET CRYPTOGRAPHIC PROFILES</div>
                  {assets.map(a => (
                    <div key={a.asset_id} style={{ marginBottom: 12, padding: "10px 12px", background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid rgba(255,255,255,0.05)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                        <strong style={{ fontSize: 13 }}>{a.domain}</strong>
                        <span className={`badge ${a.is_pqc ? 'badge-safe' : 'badge-critical'}`} style={{ fontSize: 10 }}>{a.protocol}</span>
                      </div>
                      
                      {a.hndl_breakdown && Object.keys(a.hndl_breakdown).length > 0 && (
                        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 8, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                          <span style={{ color: 'var(--accent-cyan)' }}>HNDL Breakdown:</span>
                          <span>Alg: <strong style={{ color: 'white' }}>{a.hndl_breakdown.algorithm_risk}</strong></span>
                          <span>Key: <strong style={{ color: 'white' }}>{a.hndl_breakdown.key_size_risk}</strong></span>
                          <span>TLS: <strong style={{ color: 'white' }}>{a.hndl_breakdown.tls_version_risk}</strong></span>
                          <span>Expiry: <strong style={{ color: 'white' }}>{a.hndl_breakdown.expiry_risk}</strong></span>
                          <span>Sens Wt: <strong style={{ color: 'white' }}>{a.hndl_breakdown.w_sensitivity ?? a.hndl_breakdown.data_sensitivity}</strong></span>
                          {a.hndl_breakdown.bcs !== undefined && <span>BCS: <strong style={{ color: 'white' }}>{a.hndl_breakdown.bcs}</strong></span>}
                          {a.hndl_breakdown.m_shelf !== undefined && <span>Shelf: <strong style={{ color: 'white' }}>{a.hndl_breakdown.m_shelf}x</strong></span>}
                          {a.hndl_breakdown.m_pfs !== undefined && <span>PFS: <strong style={{ color: 'white' }}>{a.hndl_breakdown.m_pfs}x</strong></span>}
                        </div>
                      )}

                      {a.cipher_suites?.length > 0 && (
                        <div style={{ fontSize: 11 }}>
                          <div style={{ color: 'var(--text-secondary)', marginBottom: 4 }}>Supported Cipher Suites ({a.cipher_suites.length}):</div>
                          <div style={{ maxHeight: 120, overflowY: 'auto' }}>
                            {a.cipher_suites.map(cs => (
                               <div key={cs.suite_id} style={{ display: 'flex', justifyContent: 'space-between', padding: '3px 0', borderBottom: '1px dotted rgba(255,255,255,0.1)' }}>
                                 <span style={{ color: 'var(--text-muted)' }}>{cs.name} <span style={{ opacity: 0.5 }}>({cs.tls_version})</span></span>
                                 <span style={{ color: cs.is_quantum_vulnerable ? 'var(--error-red)' : 'var(--success-green)' }}>
                                   {cs.key_exchange} (Risk: {cs.quantum_risk})
                                 </span>
                               </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
