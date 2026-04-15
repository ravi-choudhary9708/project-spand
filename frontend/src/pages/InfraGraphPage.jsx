import React, { useEffect, useState, useRef, useCallback, useMemo } from 'react'
import api from '../api/client'
import ForceGraph2D from 'react-force-graph-2d'

// ─── Color Palette ───────────────────────────────────────────────────────────
const COLORS = {
  org: '#818cf8',        // indigo
  domainLow: '#34d399',  // green
  domainMed: '#fb923c',  // orange
  domainHigh: '#f87171', // red
  publicIp: '#60a5fa',   // blue
  internalIp: '#fb923c', // orange
  cdn: '#a78bfa',        // purple
  tlsPort: '#34d399',    // green
  nonTlsPort: '#94a3b8', // gray
  bg: '#1a1a2e',
  panel: '#252540',
  border: '#3a3a55',
  text: '#e2e8f0',
  muted: '#94a3b8',
}

function hndlColor(h) {
  if (h <= 3) return COLORS.domainLow
  if (h <= 7) return COLORS.domainMed
  return COLORS.domainHigh
}

function nodeColor(n) {
  if (n.type === 'organization') return COLORS.org
  if (n.type === 'domain') return hndlColor(n.hndl || 0)
  if (n.type === 'ip') return n.is_internal ? COLORS.internalIp : n.is_cdn ? COLORS.cdn : COLORS.publicIp
  if (n.type === 'port') return n.is_tls ? COLORS.tlsPort : COLORS.nonTlsPort
  return COLORS.muted
}

function nodeRadius(n) {
  if (n.type === 'organization') return 24
  if (n.type === 'domain') return 10
  if (n.type === 'ip') return 6
  if (n.type === 'port') return 4
  return 5
}

const CHARGE = { organization: -800, domain: -200, ip: -80, port: -30 }

const LAYOUT_MODES = [
  { value: 'force', label: 'Force-directed' },
  { value: 'radial', label: 'Radial tiers' },
  { value: 'cluster', label: 'Cluster' },
]

const NODE_TYPES = [
  { key: 'organization', label: 'Organization', color: COLORS.org },
  { key: 'domain-low', label: 'Domain (Low HNDL)', color: COLORS.domainLow },
  { key: 'domain-high', label: 'Domain (Critical)', color: COLORS.domainHigh },
  { key: 'domain-med', label: 'Domain (Med HNDL)', color: COLORS.domainMed },
  { key: 'ip-public', label: 'Public IP', color: COLORS.publicIp },
  { key: 'ip-internal', label: 'Internal IP', color: COLORS.internalIp },
  { key: 'cdn', label: 'CDN Protected', color: COLORS.cdn },
  { key: 'port-tls', label: 'TLS Port', color: COLORS.tlsPort },
  { key: 'port-nontls', label: 'Non-TLS Port', color: COLORS.nonTlsPort },
]

function getFilterKey(n) {
  if (n.type === 'organization') return 'organization'
  if (n.type === 'domain') {
    if ((n.hndl || 0) >= 7) return 'domain-high'
    if ((n.hndl || 0) > 3) return 'domain-med'
    return 'domain-low'
  }
  if (n.type === 'ip') {
    if (n.is_cdn) return 'cdn'
    return n.is_internal ? 'ip-internal' : 'ip-public'
  }
  if (n.type === 'port') return n.is_tls ? 'port-tls' : 'port-nontls'
  return 'organization'
}

// ─── Panel Component ─────────────────────────────────────────────────────────
function Panel({ title, children, style }) {
  return (
    <div style={{
      background: COLORS.panel, border: `1px solid ${COLORS.border}`,
      borderRadius: 10, padding: '12px 14px', ...style,
    }}>
      {title && <div style={{ fontWeight: 700, fontSize: 13, color: COLORS.text, marginBottom: 8 }}>{title}</div>}
      {children}
    </div>
  )
}

// ─── Main Component ──────────────────────────────────────────────────────────
export default function InfraGraphPage() {
  const [scans, setScans] = useState([])
  const [selectedScan, setSelectedScan] = useState('')
  const [graphData, setGraphData] = useState({ nodes: [], links: [] })
  const [loading, setLoading] = useState(false)
  const [hoveredNode, setHoveredNode] = useState(null)
  const [layoutMode, setLayoutMode] = useState('force')
  const [linkDistance, setLinkDistance] = useState(50)
  const [hiddenTypes, setHiddenTypes] = useState(new Set())
  const [dims, setDims] = useState({ w: 800, h: 600 })
  const containerRef = useRef(null)
  const graphRef = useRef(null)

  // Load scans
  useEffect(() => {
    api.get('/scans').then(r => {
      const completed = r.data.filter(s => s.status === 'COMPLETED')
      setScans(completed)
      if (completed.length > 0) setSelectedScan(completed[0].scan_id)
    }).catch(() => {})
  }, [])

  // Load graph data
  useEffect(() => {
    if (!selectedScan) return
    setLoading(true)
    api.get(`/scans/${selectedScan}/graph`).then(r => {
      setGraphData(r.data)
      setLoading(false)
      setTimeout(() => { graphRef.current?.zoomToFit(600, 80) }, 1200)
    }).catch(() => setLoading(false))
  }, [selectedScan])

  // Resize
  useEffect(() => {
    const update = () => {
      if (containerRef.current) setDims({ w: containerRef.current.offsetWidth, h: containerRef.current.offsetHeight })
    }
    update()
    window.addEventListener('resize', update)
    return () => window.removeEventListener('resize', update)
  }, [])

  // Apply custom forces when layout or linkDistance changes
  useEffect(() => {
    const fg = graphRef.current
    if (!fg) return

    if (layoutMode === 'force') {
      fg.d3Force('charge')?.strength(n => CHARGE[n.type] || -50)
      fg.d3Force('link')?.distance(linkDistance)
      fg.d3Force('center')?.strength(0.05)
      fg.d3ReheatSimulation()
    }
  }, [layoutMode, linkDistance, graphData])

  // Filter
  const filtered = useMemo(() => {
    if (hiddenTypes.size === 0) return graphData
    const nodes = graphData.nodes.filter(n => !hiddenTypes.has(getFilterKey(n)))
    const ids = new Set(nodes.map(n => n.id))
    const links = graphData.links.filter(l => {
      const s = typeof l.source === 'object' ? l.source.id : l.source
      const t = typeof l.target === 'object' ? l.target.id : l.target
      return ids.has(s) && ids.has(t)
    })
    return { nodes, links }
  }, [graphData, hiddenTypes])

  // Stats
  const stats = useMemo(() => {
    const d = graphData.nodes.filter(n => n.type === 'domain')
    const ips = graphData.nodes.filter(n => n.type === 'ip')
    return {
      critical: d.filter(n => (n.hndl || 0) >= 7).length,
      internal: ips.filter(n => n.is_internal).length,
      cdn: d.filter(n => n.is_cdn).length,
      total: graphData.nodes.length,
    }
  }, [graphData])

  // Toggle filter
  const toggleType = (key) => {
    setHiddenTypes(prev => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  // ─── Canvas paint ──────────────────────────────────────────────────────────
  const paintNode = useCallback((node, ctx, globalScale) => {
    const r = nodeRadius(node)
    const col = nodeColor(node)
    const dimmed = hiddenTypes.size > 0 && hiddenTypes.has(getFilterKey(node))

    ctx.globalAlpha = dimmed ? 0.15 : 1

    if (node.type === 'organization') {
      // Outer glow
      ctx.beginPath()
      ctx.arc(node.x, node.y, r + 6, 0, 2 * Math.PI)
      ctx.fillStyle = col + '22'
      ctx.fill()
      // Main circle
      ctx.beginPath()
      ctx.arc(node.x, node.y, r, 0, 2 * Math.PI)
      ctx.fillStyle = col
      ctx.fill()
      ctx.strokeStyle = '#fff'
      ctx.lineWidth = 2
      ctx.stroke()
      // Label
      ctx.font = 'bold 11px Inter, sans-serif'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      ctx.fillStyle = '#fff'
      const lbl = node.label || ''
      ctx.fillText(lbl.length > 12 ? lbl.slice(0, 10) + '…' : lbl, node.x, node.y)
    } else if (node.type === 'ip') {
      // Square
      ctx.fillStyle = col
      ctx.fillRect(node.x - r, node.y - r, r * 2, r * 2)
      if (node.is_internal) {
        ctx.strokeStyle = '#f87171'
        ctx.lineWidth = 1.5
        ctx.strokeRect(node.x - r - 1.5, node.y - r - 1.5, r * 2 + 3, r * 2 + 3)
      }
    } else if (node.type === 'port') {
      // Diamond
      ctx.beginPath()
      ctx.moveTo(node.x, node.y - r)
      ctx.lineTo(node.x + r, node.y)
      ctx.lineTo(node.x, node.y + r)
      ctx.lineTo(node.x - r, node.y)
      ctx.closePath()
      ctx.fillStyle = col
      ctx.fill()
    } else {
      // Domain circle
      ctx.beginPath()
      ctx.arc(node.x, node.y, r, 0, 2 * Math.PI)
      ctx.fillStyle = col
      ctx.fill()
      if (node.is_cdn) {
        ctx.beginPath()
        ctx.arc(node.x, node.y, r + 3, 0, 2 * Math.PI)
        ctx.strokeStyle = COLORS.cdn
        ctx.lineWidth = 1.5
        ctx.stroke()
      }
    }

    // Labels for domain nodes (only when zoomed in enough or always small)
    if (node.type === 'domain' && globalScale > 0.8) {
      ctx.font = '5px Inter, sans-serif'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'top'
      ctx.fillStyle = 'rgba(255,255,255,0.7)'
      const l = node.label || ''
      ctx.fillText(l.length > 22 ? l.slice(0, 20) + '…' : l, node.x, node.y + r + 2)
    }

    // IP/port labels only at high zoom
    if ((node.type === 'ip' || node.type === 'port') && globalScale > 2.5) {
      ctx.font = '4px Inter, sans-serif'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'top'
      ctx.fillStyle = 'rgba(255,255,255,0.6)'
      ctx.fillText(node.label || '', node.x, node.y + r + 2)
    }

    ctx.globalAlpha = 1
  }, [hiddenTypes])

  // ─── Layout mode props ─────────────────────────────────────────────────────
  const layoutProps = useMemo(() => {
    if (layoutMode === 'radial') {
      return { dagMode: 'radialout', dagLevelDistance: 90 }
    }
    if (layoutMode === 'cluster') {
      return { dagMode: 'td', dagLevelDistance: 70 }
    }
    return { dagMode: null, dagLevelDistance: undefined }
  }, [layoutMode])

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', background: COLORS.bg, fontFamily: 'Inter, sans-serif' }}>
      {/* Header bar */}
      <div style={{ padding: '12px 20px', borderBottom: `1px solid ${COLORS.border}`, display: 'flex', alignItems: 'center', gap: 14, flexShrink: 0 }}>
        <h1 style={{ fontSize: 18, fontWeight: 700, color: COLORS.text, margin: 0 }}>Infrastructure Graph</h1>
        <select
          value={selectedScan} onChange={e => setSelectedScan(e.target.value)}
          style={{ background: COLORS.panel, color: COLORS.text, border: `1px solid ${COLORS.border}`, borderRadius: 6, padding: '5px 10px', fontSize: 12, cursor: 'pointer', marginLeft: 'auto', minWidth: 200 }}
        >
          {scans.map(s => <option key={s.scan_id} value={s.scan_id}>{s.org_name} — {s.asset_count} assets</option>)}
        </select>
      </div>

      {/* Main area */}
      <div ref={containerRef} style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
        {loading ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
            <span className="loading-spinner" style={{ width: 32, height: 32 }} />
          </div>
        ) : filtered.nodes.length === 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: COLORS.muted }}>
            {scans.length === 0 ? 'No completed scans. Run a scan first.' : 'No nodes to display.'}
          </div>
        ) : (
          <ForceGraph2D
            ref={graphRef}
            graphData={filtered}
            width={dims.w}
            height={dims.h}
            backgroundColor={COLORS.bg}
            nodeCanvasObject={paintNode}
            nodePointerAreaPaint={(node, color, ctx) => {
              const s = nodeRadius(node) + 5
              ctx.fillStyle = color
              ctx.fillRect(node.x - s, node.y - s, s * 2, s * 2)
            }}
            linkColor={() => 'rgba(148,163,184,0.12)'}
            linkWidth={0.6}
            linkDirectionalParticles={1}
            linkDirectionalParticleWidth={1.2}
            linkDirectionalParticleSpeed={0.003}
            linkDirectionalParticleColor={() => 'rgba(129,140,248,0.35)'}
            onNodeHover={node => { setHoveredNode(node || null); if (containerRef.current) containerRef.current.style.cursor = node ? 'pointer' : 'default' }}
            onNodeClick={(node) => {
              if (graphRef.current) {
                graphRef.current.centerAt(node.x, node.y, 400)
                graphRef.current.zoom(4, 400)
              }
            }}
            onNodeDragEnd={node => { node.fx = node.x; node.fy = node.y }}
            onBackgroundClick={() => graphRef.current?.zoomToFit(400, 80)}
            cooldownTicks={250}
            d3AlphaDecay={0.008}
            d3VelocityDecay={0.2}
            d3AlphaMin={0.001}
            onEngineStop={() => graphRef.current?.zoomToFit(400, 80)}
            {...layoutProps}
          />
        )}

        {/* ─── LEFT PANELS ──────────────────────────────────────────────── */}
        <div style={{ position: 'absolute', top: 16, left: 16, display: 'flex', flexDirection: 'column', gap: 10, zIndex: 10, width: 190 }}>
          {/* Filter nodes */}
          <Panel title="Filter nodes">
            {NODE_TYPES.map(t => (
              <div
                key={t.key}
                onClick={() => toggleType(t.key)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8, padding: '3px 0',
                  cursor: 'pointer', opacity: hiddenTypes.has(t.key) ? 0.35 : 1,
                  transition: 'opacity 0.2s',
                }}
              >
                <span style={{ width: 10, height: 10, borderRadius: t.key.startsWith('ip') ? 2 : '50%', background: t.color, display: 'inline-block', flexShrink: 0 }} />
                <span style={{ fontSize: 11, color: COLORS.muted }}>{t.label}</span>
              </div>
            ))}
          </Panel>

          {/* Layout mode */}
          <Panel title="Layout">
            <select
              value={layoutMode} onChange={e => setLayoutMode(e.target.value)}
              style={{ width: '100%', background: COLORS.bg, color: COLORS.text, border: `1px solid ${COLORS.border}`, borderRadius: 6, padding: '5px 8px', fontSize: 12, cursor: 'pointer' }}
            >
              {LAYOUT_MODES.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
            </select>
          </Panel>

          {/* Link strength slider */}
          <Panel title="Link strength">
            <input
              type="range" min={20} max={150} value={linkDistance}
              onChange={e => setLinkDistance(Number(e.target.value))}
              style={{ width: '100%', accentColor: COLORS.org }}
            />
          </Panel>
        </div>

        {/* ─── TOP-RIGHT: Scan Summary ───────────────────────────────────── */}
        <Panel title="Scan summary" style={{ position: 'absolute', top: 16, right: 16, zIndex: 10, width: 180 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px 16px' }}>
            <div>
              <div style={{ fontSize: 22, fontWeight: 700, color: COLORS.domainHigh }}>{stats.critical}</div>
              <div style={{ fontSize: 10, color: COLORS.muted }}>Critical</div>
            </div>
            <div>
              <div style={{ fontSize: 22, fontWeight: 700, color: COLORS.internalIp }}>{stats.internal}</div>
              <div style={{ fontSize: 10, color: COLORS.muted }}>Internal IPs</div>
            </div>
            <div>
              <div style={{ fontSize: 22, fontWeight: 700, color: COLORS.cdn }}>{stats.cdn}</div>
              <div style={{ fontSize: 10, color: COLORS.muted }}>CDN nodes</div>
            </div>
            <div>
              <div style={{ fontSize: 22, fontWeight: 700, color: COLORS.text }}>{stats.total}</div>
              <div style={{ fontSize: 10, color: COLORS.muted }}>Total nodes</div>
            </div>
          </div>
        </Panel>

        {/* ─── HOVER TOOLTIP ─────────────────────────────────────────────── */}
        {hoveredNode && (
          <Panel style={{ position: 'absolute', bottom: 16, right: 16, zIndex: 10, minWidth: 220, maxWidth: 280 }}>
            <div style={{ fontWeight: 700, fontSize: 13, color: COLORS.text, marginBottom: 6, wordBreak: 'break-all' }}>
              {hoveredNode.label}
            </div>
            <div style={{ fontSize: 11, color: COLORS.muted, display: 'flex', flexDirection: 'column', gap: 3 }}>
              <span>Type: <strong style={{ color: nodeColor(hoveredNode) }}>{hoveredNode.type}</strong></span>
              {hoveredNode.type === 'domain' && (
                <>
                  <span>HNDL: <strong style={{ color: hndlColor(hoveredNode.hndl) }}>{hoveredNode.hndl}</strong></span>
                  <span>Protocol: <strong style={{ color: COLORS.text }}>{hoveredNode.protocol}</strong></span>
                  <span>Algorithm: <strong style={{ color: COLORS.text }}>{hoveredNode.algorithm}{hoveredNode.key_size ? `-${hoveredNode.key_size}` : ''}</strong></span>
                  <span>Network: <strong style={{ color: hoveredNode.network_type === 'internal' ? COLORS.internalIp : COLORS.domainLow }}>{hoveredNode.network_type}</strong></span>
                  <span>PQC: <strong style={{ color: hoveredNode.is_pqc ? COLORS.domainLow : COLORS.domainHigh }}>{hoveredNode.pqc_readiness}</strong></span>
                  {hoveredNode.is_cdn && <span>CDN: <strong style={{ color: COLORS.cdn }}>{hoveredNode.cdn_provider || 'Yes'}</strong></span>}
                  {hoveredNode.service_category && <span>Service: <strong style={{ color: COLORS.text }}>{hoveredNode.service_category}</strong></span>}
                </>
              )}
              {hoveredNode.type === 'ip' && (
                <>
                  {hoveredNode.is_internal && <span style={{ color: COLORS.internalIp, fontWeight: 600 }}>⚠ Internal / RFC 1918</span>}
                  {hoveredNode.is_cdn && <span style={{ color: COLORS.cdn }}>CDN-Protected</span>}
                </>
              )}
              {hoveredNode.type === 'port' && (
                <span>TLS: <strong style={{ color: hoveredNode.is_tls ? COLORS.tlsPort : COLORS.nonTlsPort }}>{hoveredNode.is_tls ? 'Yes' : 'No'}</strong></span>
              )}
            </div>
          </Panel>
        )}

        {/* ─── BOTTOM-LEFT: Legend ────────────────────────────────────────── */}
        <Panel title="Legend" style={{ position: 'absolute', bottom: 16, left: 16, zIndex: 10 }}>
          {NODE_TYPES.map(t => (
            <div key={t.key} style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '2px 0' }}>
              <span style={{
                width: 10, height: 10, display: 'inline-block', flexShrink: 0,
                background: t.color,
                borderRadius: t.key.startsWith('port') ? 0 : t.key.startsWith('ip') ? 2 : '50%',
                transform: t.key.startsWith('port') ? 'rotate(45deg)' : 'none',
              }} />
              <span style={{ fontSize: 11, color: COLORS.muted }}>{t.label}</span>
            </div>
          ))}
        </Panel>
      </div>
    </div>
  )
}
