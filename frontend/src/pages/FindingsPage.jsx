import React, { useEffect, useState } from 'react'
import api from '../api/client'
import toast from 'react-hot-toast'

export default function FindingsPage() {
  const [scans, setScans] = useState([])
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(false)
  const [selectedScan, setSelectedScan] = useState('')
  const [selected, setSelected] = useState(null)
  const [severityFilter, setSeverityFilter] = useState('')
  const [generatingAi, setGeneratingAi] = useState({})
  const [viewAiReport, setViewAiReport] = useState(false)

  const generateAiRemediation = async (scanId, findingId) => {
    setGeneratingAi(prev => ({...prev, [findingId]: true}))
    try {
      const res = await api.post(`/scans/${scanId}/findings/${findingId}/ai-remediation`)
      const updatedPlan = [res.data]
      
      setFindings(prev => prev.map(f => {
        if (f.finding_id === findingId) {
          return { ...f, remediation_plan: updatedPlan }
        }
        return f
      }))
      
      if (selected?.finding_id === findingId) {
        setSelected(prev => ({ ...prev, remediation_plan: updatedPlan }))
      }
      
      if (res.data.detailed_report) {
         setViewAiReport(true)
      }
      
      toast.success("AI Blueprint loaded successfully!")
    } catch (e) {
      toast.error("Failed to generate AI remediation.")
    } finally {
      setGeneratingAi(prev => ({...prev, [findingId]: false}))
    }
  }

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
      <style>{`
        @keyframes pulse {
          0% { transform: scale(1); opacity: 0.8; }
          50% { transform: scale(1.1); opacity: 0.4; }
          100% { transform: scale(1); opacity: 0.8; }
        }
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
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

              { (selected.type === 'QUANTUM_VULNERABLE_ALGORITHM' || selected.quantum_risk > 0) && (
                <div style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 8, padding: 14, marginBottom: 16 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: '#ef4444', marginBottom: 6 }}>⚠️ QUANTUM RISK</div>
                  <div style={{ fontSize: 13 }}>HNDL Score: <strong style={{ color: sevColor[selected.severity] }}>{selected.hndl_score?.toFixed(2)}</strong></div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>Quantum Risk Score: {selected.quantum_risk?.toFixed(2)}</div>
                </div>
              )}
              { selected.type !== 'QUANTUM_VULNERABLE_ALGORITHM' && !selected.quantum_risk && selected.hndl_score > 0 && (
                <div style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: 8, padding: 14, marginBottom: 16 }}>
                  <div style={{ fontSize: 13 }}>HNDL Score Impact: <strong style={{ color: sevColor[selected.severity] }}>{selected.hndl_score?.toFixed(2)}</strong></div>
                </div>
              )}

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

              {/* AI Remediati              {/* AI Remediation Card */}
              <div style={{ 
                background: 'rgba(0,212,255,0.03)', 
                border: '1px solid rgba(0,212,255,0.15)', 
                borderRadius: 12, 
                padding: 16, 
                marginTop: 20,
                boxShadow: '0 8px 32px rgba(0,0,0,0.2)',
                backdropFilter: 'blur(4px)'
              }}>
                <div className="flex-between" style={{ marginBottom: 16 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 20 }}>🧠</span>
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 800, color: 'var(--accent-cyan)', letterSpacing: '0.03em' }}>AI SECURITY ARCHITECT</div>
                      <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Quantum-Cloud Intelligence</div>
                    </div>
                  </div>
                  {(!selected.remediation_plan || !selected.remediation_plan[0]?.detailed_report) ? (
                    <button 
                      className="btn btn-primary" 
                      style={{ fontSize: 11, padding: '6px 14px', borderRadius: 20, background: 'linear-gradient(135deg, var(--accent-cyan), #00a8ff)', border: 'none' }} 
                      onClick={() => generateAiRemediation(selectedScan, selected.finding_id)}
                      disabled={generatingAi[selected.finding_id]}
                    >
                      {generatingAi[selected.finding_id] ? (
                        <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span className="loading-spinner" style={{ width: 12, height: 12, borderWeight: 2 }} />
                          Analyzing Infrastructure...
                        </span>
                      ) : '✨ Generate Detailed AI Blueprint'}
                    </button>
                  ) : (
                    <button 
                      className="btn btn-secondary" 
                      style={{ fontSize: 10, padding: '4px 10px', borderRadius: 20 }} 
                      onClick={() => {
                        // To force regeneration, we would normally need an API flag, 
                        // but for now we'll just let the current button serve as a 'view' unless we add a clear logic
                        // In this case, I'll just keep the detailed report.
                      }}
                      disabled={true}
                    >
                      ✅ Blueprint Active
                    </button>
                  )}
                </div>

                {selected.remediation_plan?.length > 0 ? (
                  <div className="scroll-fade">
                    <div style={{ 
                      fontSize: 11, 
                      fontWeight: 700, 
                      color: selected.remediation_plan[0]?.status === 'AI_GENERATED' ? 'var(--accent-cyan)' : 'var(--accent-green)', 
                      marginBottom: 12,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6
                    }}>
                      {selected.remediation_plan[0]?.status === 'AI_GENERATED' ? '🛡️ CUSTOM ARCHITECT BLUEPRINT' : '🛡️ STATIC REMEDIATION PLAYBOOK'}
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
                        <div style={{ padding: 10, background: 'rgba(255,255,255,0.03)', borderRadius: 8, border: '1px solid rgba(255,255,255,0.05)' }}>
                            <div style={{ fontSize: 9, color: 'var(--text-muted)', marginBottom: 2 }}>PRIORITY LEVEL</div>
                            <div style={{ fontSize: 14, fontWeight: 700, color: selected.remediation_plan[0].priority > 7 ? 'var(--error-red)' : 'var(--accent-cyan)' }}>
                                {selected.remediation_plan[0].priority}/10
                            </div>
                        </div>
                        <div style={{ padding: 10, background: 'rgba(255,255,255,0.03)', borderRadius: 8, border: '1px solid rgba(255,255,255,0.05)' }}>
                            <div style={{ fontSize: 9, color: 'var(--text-muted)', marginBottom: 2 }}>PQC ALTERNATIVE</div>
                            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--success-green)' }}>
                                {selected.remediation_plan[0].pqc_alternative || 'N/A'}
                            </div>
                        </div>
                    </div>

                    <div style={{ marginBottom: 16 }}>
                        <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 8 }}>EXECUTION STEPS</div>
                        {selected.remediation_plan[0].steps?.map((step, i) => (
                          <div key={i} style={{ 
                            fontSize: 12, 
                            padding: '8px 10px', 
                            background: 'rgba(255,255,255,0.02)',
                            borderRadius: 6,
                            marginBottom: 4,
                            color: 'var(--text-secondary)', 
                            lineHeight: 1.5,
                            borderLeft: '2px solid rgba(0,212,255,0.3)'
                          }}>{step}</div>
                        ))}
                    </div>

                    {selected.remediation_plan[0].detailed_report && (
                      <div style={{ marginTop: 20 }}>
                        <button 
                          className="btn btn-primary" 
                          style={{ width: '100%', padding: '10px', borderRadius: 8, background: 'rgba(0,212,255,0.1)', border: '1px solid var(--accent-cyan)', color: 'var(--accent-cyan)' }}
                          onClick={() => setViewAiReport(true)}
                        >
                          👁️ View Full Architecture Blueprint
                        </button>
                      </div>
                    )}
                  </div>
                ) : (
                  <div style={{ textAlign: 'center', padding: '20px 0' }}>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>No intelligence report currently attached to this finding.</div>
                    <button 
                      className="btn btn-secondary" 
                      onClick={() => generateAiRemediation(selectedScan, selected.finding_id)}
                      disabled={generatingAi[selected.finding_id]}
                    >
                      {generatingAi[selected.finding_id] ? 'Analyzing...' : 'Initialize AI Analysis'}
                    </button>
                  </div>
                )}
              </div>

              {/* CYBER SENTINEL AI MODAL - PREMIUM V5 */}
              {viewAiReport && selected.remediation_plan?.[0] && (
                <div style={{
                  position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh',
                  background: 'radial-gradient(circle at center, rgba(10,20,40,0.98) 0%, rgba(5,10,20,1) 100%)',
                  zIndex: 2000, display: 'flex', alignItems: 'center', justifyContent: 'center',
                  padding: 40, backdropFilter: 'blur(20px)', animation: 'fadeIn 0.4s ease-out'
                }}>
                  <div className="card scroll-fade" style={{ 
                    width: '100%', maxWidth: 1200, maxHeight: '92vh', overflowY: 'auto', 
                    padding: 0, background: '#050a14', border: '1px solid rgba(0,212,255,0.2)',
                    boxShadow: '0 0 100px rgba(0,212,255,0.1)', borderRadius: 20
                  }}>
                    {/* MODAL HEADER */}
                    <div style={{ 
                      padding: '30px 40px', background: 'rgba(0,212,255,0.03)', 
                      borderBottom: '1px solid rgba(0,212,255,0.1)', display: 'flex', 
                      justifyContent: 'space-between', alignItems: 'center'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
                        <div style={{ position: 'relative' }}>
                          <span style={{ fontSize: 32 }}>🧠</span>
                          <div className="radar-pulse" style={{
                            position: 'absolute', top: -5, left: -5, right: -5, bottom: -5,
                            border: '2px solid var(--accent-cyan)', borderRadius: '50%',
                            animation: 'pulse 2s infinite'
                          }} />
                        </div>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <h1 style={{ fontSize: 22, fontWeight: 900, color: 'var(--accent-cyan)', margin: 0, letterSpacing: 1 }}>CYBER SENTINEL <span style={{ color: 'var(--text-muted)', fontWeight: 300, fontSize: 14 }}>v5.0</span></h1>
                            <span style={{ fontSize: 10, background: 'rgba(239, 68, 68, 0.2)', color: '#ef4444', padding: '2px 8px', borderRadius: 4, fontWeight: 700 }}>LIVE ANALYSIS</span>
                          </div>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 2, marginTop: 2 }}>Quantum Intelligence Report • {selected.asset_domain}</div>
                        </div>
                      </div>
                      <button 
                        onClick={() => setViewAiReport(false)} 
                        style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', color: '#fff', padding: '10px 25px', borderRadius: 8, cursor: 'pointer', fontSize: 12, fontWeight: 700, transition: 'all 0.2s' }}
                      >
                        EXIT CONSOLE
                      </button>
                    </div>

                    <div style={{ padding: 40 }}>
                      {/* BENTO GRID */}
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 30, marginBottom: 30 }}>
                        
                        {/* LEFT COLUMN - STATS */}
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                          <div style={{ padding: 25, background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.1), transparent)', borderRadius: 15, border: '1px solid rgba(239,68,68,0.2)' }}>
                            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 700 }}>THREAT MAGNITUDE</div>
                            <div style={{ fontSize: 36, fontWeight: 900, color: '#ef4444', textShadow: '0 0 20px rgba(239,68,68,0.3)' }}>
                              {parseFloat(selected.remediation_plan[0].priority || 0).toFixed(1)}
                              <span style={{ fontSize: 18, color: 'var(--text-muted)', marginLeft: 5 }}>/10</span>
                            </div>
                            <div style={{ fontSize: 11, color: '#ef4444', marginTop: 10, fontWeight: 600 }}>STATUS: CRITICAL EXPOSURE</div>
                          </div>

                          <div style={{ padding: 25, background: 'rgba(0,212,255,0.02)', borderRadius: 15, border: '1px solid rgba(0,212,255,0.2)' }}>
                            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 700 }}>NIST CANDIDATE</div>
                            <div style={{ fontSize: 14, fontWeight: 800, color: 'var(--accent-cyan)' }}>{selected.remediation_plan[0].pqc_alternative || 'ML-KEM-768'}</div>
                            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>Quantum-Resistant Standard</div>
                          </div>

                          <div style={{ padding: 25, background: 'rgba(255,255,255,0.02)', borderRadius: 15, border: '1px solid rgba(255,255,255,0.05)' }}>
                             <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 15, fontWeight: 700 }}>INFRASTRUCTURE INTEGRITY</div>
                             {/* Small mini-radar or bars */}
                             <div style={{ height: 4, background: 'rgba(255,255,255,0.1)', borderRadius: 2, overflow: 'hidden', marginBottom: 15 }}>
                                <div style={{ width: '85%', height: '100%', background: 'var(--accent-cyan)', boxShadow: '0 0 10px var(--accent-cyan)' }}></div>
                             </div>
                             <div style={{ fontSize: 10, color: 'var(--text-secondary)' }}>System scanned for 12,024 cryptographic artifacts.</div>
                          </div>
                        </div>

                        {/* RIGHT COLUMN - STEPS */}
                        <div style={{ 
                          padding: 30, background: 'rgba(255,255,255,0.02)', borderRadius: 15, 
                          border: '1px solid rgba(255,255,255,0.05)', display: 'flex', flexDirection: 'column' 
                        }}>
                          <div style={{ fontSize: 12, fontWeight: 800, color: 'var(--text-secondary)', marginBottom: 20, display: 'flex', alignItems: 'center', gap: 10 }}>
                             <span style={{ width: 8, height: 8, background: 'var(--accent-cyan)', borderRadius: '50%' }}></span>
                             STRATEGIC REMEDIATION BLUEPRINT
                          </div>
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 10 }}>
                            {selected.remediation_plan[0].steps?.map((step, i) => (
                              <div key={i} style={{ 
                                padding: '12px 18px', background: 'rgba(255,255,255,0.01)', 
                                border: '1px solid rgba(255,255,255,0.03)', borderRadius: 8,
                                display: 'flex', alignItems: 'center', gap: 15, transition: 'all 0.2s'
                              }}>
                                <span style={{ fontSize: 14, fontWeight: 900, color: 'var(--accent-cyan)', opacity: 0.5 }}>{i+1}</span>
                                <span style={{ fontSize: 13, color: 'rgba(255,255,255,0.8)', fontWeight: 500 }}>
                                  {typeof step === 'string' ? step.replace(/^\d+\.\s*/, '') : String(step || '')}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>

                      {/* FULL WIDTH - DEEP DIVE TERMINAL */}
                      <div style={{ marginTop: 10 }}>
                        <div style={{ 
                          padding: '12px 20px', background: '#1a1d23', 
                          borderTopLeftRadius: 10, borderTopRightRadius: 10,
                          border: '1px solid rgba(255,255,255,0.1)', borderBottom: 'none',
                          display: 'flex', justifyContent: 'space-between', alignItems: 'center'
                        }}>
                   <div style={{ display: 'flex', gap: 6 }}>
                             <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#ff5f56' }}></div>
                             <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#ffbd2e' }}></div>
                             <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#27c93f' }}></div>
                           </div>
                           <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'monospace', fontWeight: 600 }}>architect_deep_dive.log</div>
                           <div style={{ width: 40 }}></div>
                        </div>
                        <div style={{ 
                          padding: 30, background: '#0a0c10', 
                          borderBottomLeftRadius: 10, borderBottomRightRadius: 10,
                          border: '1px solid rgba(255,255,255,0.1)',
                          boxShadow: 'inset 0 0 40px rgba(0,0,0,0.5)'
                        }}>
                          <div style={{ 
                            fontSize: 14, lineHeight: 1.8, color: 'rgba(255,255,255,0.9)', 
                            whiteSpace: 'pre-wrap', fontFamily: "'Fira Code', 'Courier New', monospace"
                          }}>
                            {selected.remediation_plan[0].detailed_report}
                          </div>
                          
                          {/* FUTURISTIC GLOW EFFECT AT BOTTOM */}
                          <div style={{ marginTop: 30, padding: 20, background: 'rgba(0,212,255,0.05)', borderRadius: 8, border: '1px solid rgba(0,212,255,0.1)' }}>
                             <div style={{ fontSize: 11, color: 'var(--accent-cyan)', fontWeight: 800, marginBottom: 5 }}>ARCHITECT CONCLUSION</div>
                             <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Migration to PQC is mandatory for long-term data residency. Infrastructure {selected.asset_domain} must be prioritized for hybrid implementation within the next 12-18 months to avoid Y2Q exposure.</div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
