import React, { useEffect, useState } from 'react'
import api from '../api/client'

export default function FindingsPage() {
  const [scans, setScans] = useState([])
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(false)
  const [selectedScan, setSelectedScan] = useState('')
  const [selected, setSelected] = useState(null)
  const [severityFilter, setSeverityFilter] = useState('')

  useEffect(() => {
    api.get('/scans').then(r => setScans(r.data.filter(s => s.status === 'COMPLETED'))).catch(() => {})
  }, [])

  const loadFindings = async (scanId) => {
    setLoading(true)
    setSelectedScan(scanId)
    try { const r = await api.get(`/scans/${scanId}/findings`); setFindings(r.data) } catch { setFindings([]) } finally { setLoading(false) }
  }

  const filtered = severityFilter ? findings.filter(f => f.severity === severityFilter) : findings
  const sevColor = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#f59e0b', LOW: '#10b981', INFO: '#3b82f6' }

  return (
    <div className="scroll-fade">
      <div className="page-header">
        <div>
          <h1 className="page-title">Findings</h1>
          <p className="page-subtitle">Cryptographic vulnerabilities & quantum risks</p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <select className="form-select" style={{ width: 220 }} value={selectedScan}
            onChange={e => { if (e.target.value) loadFindings(e.target.value) }}>
            <option value="">— Select a scan —</option>
            {scans.map(s => <option key={s.scan_id} value={s.scan_id}>{s.org_name} ({s.asset_count} assets)</option>)}
          </select>
          <select className="form-select" style={{ width: 140 }} value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}>
            <option value="">All Severities</option>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>

      {!selectedScan ? (
        <div className="card empty-state"><p>Select a completed scan to view findings.</p></div>
      ) : loading ? (
        <div style={{ textAlign: 'center', padding: 60 }}><span className="loading-spinner" /></div>
      ) : filtered.length === 0 ? (
        <div className="card empty-state"><p>✅ No findings for this scan.</p></div>
      ) : (
        <div className={selected ? 'grid-2' : ''}>
          <div>
            <div style={{ marginBottom: 12, fontSize: 13, color: 'var(--text-muted)' }}>{filtered.length} findings</div>
            <div className="table-wrapper">
              <table>
                <thead><tr><th>Finding</th><th>Asset</th><th>Severity</th><th>HNDL</th></tr></thead>
                <tbody>
                  {filtered.map(f => (
                    <tr key={f.finding_id} onClick={() => setSelected(f)} style={{ cursor: 'pointer', background: selected?.finding_id === f.finding_id ? 'rgba(0,212,255,0.05)' : '' }}>
                      <td>
                        <div style={{ fontWeight: 600, fontSize: 13 }}>{f.title}</div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{f.type} · {f.cwe_id}</div>
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>{f.asset_domain}</td>
                      <td><span className={`badge badge-${f.severity.toLowerCase()}`}>{f.severity}</span></td>
                      <td style={{ fontWeight: 700, color: sevColor[f.severity] || '#fff' }}>{f.hndl_score?.toFixed(1)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {selected && (
            <div className="card scroll-fade" style={{ maxHeight: '80vh', overflowY: 'auto' }}>
              <div className="flex-between" style={{ marginBottom: 12 }}>
                <span className={`badge badge-${selected.severity.toLowerCase()}`}>{selected.severity}</span>
                <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 18 }}>×</button>
              </div>
              <h3 style={{ fontWeight: 700, marginBottom: 4 }}>{selected.title}</h3>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 16 }}>{selected.cwe_id} · {selected.type}</div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16, lineHeight: 1.6 }}>{selected.description}</div>

              <div style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 8, padding: 14, marginBottom: 16 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: '#ef4444', marginBottom: 6 }}>⚠️ QUANTUM RISK</div>
                <div style={{ fontSize: 13 }}>HNDL Score: <strong style={{ color: sevColor[selected.severity] }}>{selected.hndl_score?.toFixed(2)}</strong></div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>Quantum Risk Score: {selected.quantum_risk?.toFixed(2)}</div>
              </div>

              {selected.compliance_tags?.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 8 }}>COMPLIANCE VIOLATIONS</div>
                  {selected.compliance_tags.map((t, i) => (
                    <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, padding: '4px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                      <span style={{ color: '#93c5fd' }}>{t.framework}</span>
                      <span style={{ fontFamily: 'monospace', color: 'var(--text-muted)' }}>{t.control_ref}</span>
                    </div>
                  ))}
                </div>
              )}

              {selected.remediation_plan?.length > 0 && (
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent-green)', marginBottom: 8 }}>🛡️ REMEDIATION PLAYBOOK</div>
                  {selected.remediation_plan[0].steps?.map((step, i) => (
                    <div key={i} style={{ fontSize: 12, padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{step}</div>
                  ))}
                  {selected.remediation_plan[0].pqc_alternative && (
                    <div style={{ marginTop: 10, padding: 10, background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.2)', borderRadius: 8, fontSize: 12 }}>
                      <span style={{ fontWeight: 600, color: '#10b981' }}>PQC Alternative: </span>
                      <span>{selected.remediation_plan[0].pqc_alternative}</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
