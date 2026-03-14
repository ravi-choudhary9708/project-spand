import React, { useState } from 'react'
import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import ScansPage from './pages/ScansPage'
import AssetsPage from './pages/AssetsPage'
import FindingsPage from './pages/FindingsPage'
import CBOMPage from './pages/CBOMPage'
import './index.css'

function ProtectedRoute({ children }) {
  const token = localStorage.getItem('token')
  if (!token) return <Navigate to="/login" replace />
  return children
}

function Sidebar() {
  const user = JSON.parse(localStorage.getItem('user') || '{}')
  const nav = [
    { to: '/', label: 'Dashboard', icon: '📊', exact: true },
    { to: '/scans', label: 'Scans', icon: '🔍' },
    { to: '/assets', label: 'Assets', icon: '🖥️' },
    { to: '/findings', label: 'Findings', icon: '⚠️' },
    { to: '/cbom', label: 'CBOM', icon: '📋' },
  ]

  const logout = () => {
    localStorage.clear()
    window.location.href = '/login'
  }

  return (
    <div className="sidebar">
      <div className="sidebar-logo">
        <h1>🔐 QPS Scanner</h1>
        <div className="tagline">Quantum-Proof Systems</div>
        <div className="badge-hackathon">PSB Hackathon 2026 · Team Spand</div>
      </div>

      <div className="nav-section">
        <div className="nav-section-label">Navigation</div>
        {nav.map(({ to, label, icon, exact }) => (
          <NavLink key={to} to={to} end={exact}
            className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}>
            <span>{icon}</span> {label}
          </NavLink>
        ))}
      </div>

      <div style={{ marginTop: 'auto', padding: '16px 24px', borderTop: '1px solid var(--bg-border)' }}>
        <div style={{ marginBottom: 10 }}>
          <div style={{ fontWeight: 600, fontSize: 13 }}>{user.username || 'User'}</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{user.role}</div>
        </div>
        <button className="btn btn-secondary" style={{ width: '100%', justifyContent: 'center', fontSize: 12 }} onClick={logout}>
          🚪 Logout
        </button>
      </div>
    </div>
  )
}

function AppLayout({ children }) {
  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content">{children}</main>
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Toaster position="top-right" toastOptions={{
        style: { background: 'var(--bg-card)', color: 'var(--text-primary)', border: '1px solid var(--bg-border)' }
      }} />
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/" element={<ProtectedRoute><AppLayout><DashboardPage /></AppLayout></ProtectedRoute>} />
        <Route path="/scans" element={<ProtectedRoute><AppLayout><ScansPage /></AppLayout></ProtectedRoute>} />
        <Route path="/assets" element={<ProtectedRoute><AppLayout><AssetsPage /></AppLayout></ProtectedRoute>} />
        <Route path="/findings" element={<ProtectedRoute><AppLayout><FindingsPage /></AppLayout></ProtectedRoute>} />
        <Route path="/cbom" element={<ProtectedRoute><AppLayout><CBOMPage /></AppLayout></ProtectedRoute>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
