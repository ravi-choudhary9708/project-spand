import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'
import toast from 'react-hot-toast'
import { useAuth } from '../App'

export default function LoginPage() {
  const [form, setForm] = useState({ username: '', password: '' })
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const { login } = useAuth()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    try {
      const data = new URLSearchParams({ username: form.username, password: form.password })
      const res = await api.post('/auth/login', data, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } })
      login(res.data.user, res.data.access_token)
      toast.success(`Welcome, ${res.data.user.username}!`)
      navigate('/')
    } catch {
      toast.error('Invalid credentials')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-card scroll-fade">
        <div className="login-logo">
          <div style={{ fontSize: 48, marginBottom: 12 }}>🔐</div>
          <h1>QPS Scanner</h1>
          <p>Quantum-Proof Systems Scanner</p>
          <div style={{ marginTop: 10, display: 'flex', gap: 6, justifyContent: 'center', flexWrap: 'wrap' }}>
            <span className="badge badge-info">Team Spand</span>
            <span className="badge badge-safe">PSB Hackathon 2026</span>
          </div>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Username</label>
            <input className="form-input" type="text" placeholder="admin" value={form.username}
              onChange={e => setForm({ ...form, username: e.target.value })} required autoFocus />
          </div>
          <div className="form-group">
            <label className="form-label">Password</label>
            <input className="form-input" type="password" placeholder="••••••••" value={form.password}
              onChange={e => setForm({ ...form, password: e.target.value })} required />
          </div>
          <button className="btn btn-primary" type="submit" style={{ width: '100%', justifyContent: 'center', marginTop: 8 }} disabled={loading}>
            {loading ? <span className="loading-spinner" /> : '🚀'} Sign In
          </button>
        </form>

        <div style={{ marginTop: 24, padding: 16, background: 'rgba(0,212,255,0.05)', borderRadius: 10, border: '1px solid rgba(0,212,255,0.15)' }}>
          <p style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 600 }}>DEFAULT CREDENTIALS</p>
          {[['admin', 'admin123', 'ADMIN'], ['analyst', 'analyst123', 'ANALYST'], ['compliance', 'comply123', 'COMPLIANCE']].map(([u, p, r]) => (
            <div key={u} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
              <span className="mono" style={{ color: 'var(--accent-cyan)' }}>{u}</span>
              <span className="mono" style={{ color: 'var(--text-muted)' }}>{p}</span>
              <span className="badge badge-info" style={{ fontSize: 9 }}>{r}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
