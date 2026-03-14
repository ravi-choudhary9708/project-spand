import React, { useEffect, useState } from 'react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, RadialBarChart, RadialBar } from 'recharts'
import api from '../api/client'

const SEVERITY_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#10b981' }
const PQC_COLORS = { 'Quantum Safe': '#10b981', 'Partially Safe': '#f59e0b', 'Vulnerable': '#f97316', 'Critical Risk': '#ef4444' }

function MetricCard({ title, value, sub, color, icon }) {
  return (
    <div className="card" style={{ borderLeft: `3px solid ${color || 'var(--accent-cyan)'}` }}>
      <div className="flex-between" style={{ marginBottom: 8 }}>
        <span className="card-title">{title}</span>
        <span style={{ fontSize: 20 }}>{icon}</span>
      </div>
      <div className="card-value" style={{ color: color || 'var(--text-primary)' }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>{sub}</div>}
    </div>
  )
}

export default function DashboardPage() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/dashboard').then(r => { setData(r.data); setLoading(false) }).catch(() => setLoading(false))
  }, [])

  if (loading) return <div style={{ textAlign: 'center', padding: 80 }}><span className="loading-spinner" style={{ width: 40, height: 40, border: '3px solid rgba(255,255,255,0.1)', borderTopColor: 'var(--accent-cyan)' }} /></div>
  if (!data) return <div className="empty-state"><p>Failed to load dashboard data.</p></div>

  const { overview, pqc_breakdown, findings_summary, compliance, hndl_distribution, protocol_distribution, recent_scans } = data

  const pqcPie = [
    { name: 'Quantum Safe', value: pqc_breakdown.quantum_safe },
    { name: 'Partially Safe', value: pqc_breakdown.partially_safe },
    { name: 'Vulnerable', value: pqc_breakdown.vulnerable },
    { name: 'Critical Risk', value: pqc_breakdown.critical },
  ].filter(d => d.value > 0)

  const findingsBars = [
    { name: 'Critical', count: findings_summary.critical, fill: '#ef4444' },
    { name: 'High', count: findings_summary.high, fill: '#f97316' },
    { name: 'Medium', count: findings_summary.medium, fill: '#f59e0b' },
    { name: 'Low', count: findings_summary.low, fill: '#10b981' },
  ]

  return (
    <div className="scroll-fade">
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Dashboard</h1>
          <p className="page-subtitle">Cryptographic inventory & PQC readiness overview</p>
        </div>
        <span className="badge badge-info">Live</span>
      </div>

      <div className="metric-grid">
        <MetricCard title="Total Assets" value={overview.total_assets} icon="🖥️" color="var(--accent-cyan)" sub="Inventoried" />
        <MetricCard title="Avg HNDL Score" value={overview.avg_hndl_score.toFixed(1)} icon="⚠️" color={overview.avg_hndl_score > 6 ? '#ef4444' : overview.avg_hndl_score > 3 ? '#f97316' : '#10b981'} sub="0-10 scale" />
        <MetricCard title="PQC Readiness" value={`${overview.pqc_readiness_percentage}%`} icon="🛡️" color="var(--accent-green)" sub="Quantum safe assets" />
        <MetricCard title="Total Findings" value={findings_summary.total} icon="🔍" color="var(--accent-orange)" sub={`${findings_summary.critical} critical`} />
        <MetricCard title="Completed Scans" value={overview.completed_scans} icon="✅" color="var(--accent-blue)" sub={`${overview.running_scans} running`} />
      </div>

      <div className="grid-2" style={{ marginBottom: 20 }}>
        {/* PQC Pie */}
        <div className="card">
          <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 16, color: 'var(--text-secondary)' }}>PQC READINESS BREAKDOWN</h3>
          {pqcPie.length === 0 ? (
            <div className="empty-state" style={{ padding: 20 }}><p>No scan data yet</p></div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
              <ResponsiveContainer width={160} height={160}>
                <PieChart>
                  <Pie data={pqcPie} cx={80} cy={80} innerRadius={45} outerRadius={75} dataKey="value">
                    {pqcPie.map((entry, i) => (
                      <Cell key={i} fill={PQC_COLORS[entry.name] || '#666'} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div style={{ flex: 1 }}>
                {pqcPie.map(item => (
                  <div key={item.name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ width: 10, height: 10, borderRadius: '50%', background: PQC_COLORS[item.name] }} />
                      <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{item.name}</span>
                    </div>
                    <span style={{ fontWeight: 700, color: PQC_COLORS[item.name] }}>{item.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Findings Bar */}
        <div className="card">
          <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 16, color: 'var(--text-secondary)' }}>FINDINGS BY SEVERITY</h3>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={findingsBars} barSize={32}>
              <XAxis dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--bg-border)', borderRadius: 8 }} />
              <Bar dataKey="count" radius={[4,4,0,0]}>
                {findingsBars.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Compliance + Recent Scans row */}
      <div className="grid-2">
        <div className="card">
          <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 16, color: 'var(--text-secondary)' }}>COMPLIANCE VIOLATIONS</h3>
          {Object.entries(compliance).map(([fw, count]) => (
            <div key={fw} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{fw}</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 80, height: 6, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${Math.min(count * 10, 100)}%`, height: '100%', background: count > 5 ? '#ef4444' : count > 2 ? '#f97316' : '#10b981', borderRadius: 3 }} />
                </div>
                <span style={{ fontWeight: 700, fontSize: 13, minWidth: 24, textAlign: 'right', color: count > 0 ? '#ef4444' : '#10b981' }}>{count}</span>
              </div>
            </div>
          ))}
        </div>

        <div className="card">
          <h3 style={{ fontSize: 14, fontWeight: 700, marginBottom: 16, color: 'var(--text-secondary)' }}>RECENT SCANS</h3>
          {recent_scans.length === 0 ? <div className="empty-state" style={{ padding: 20 }}><p>No scans yet. Start your first scan!</p></div> : (
            recent_scans.map(scan => (
              <div key={scan.scan_id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{scan.org_name}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{new Date(scan.started_at).toLocaleDateString()}</div>
                </div>
                <span className={`status-dot dot-${scan.status.toLowerCase()}`} style={{ width: 10, height: 10, borderRadius: '50%', background: scan.status === 'COMPLETED' ? '#10b981' : scan.status === 'RUNNING' ? '#f59e0b' : scan.status === 'FAILED' ? '#ef4444' : '#6b7280' }} />
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
