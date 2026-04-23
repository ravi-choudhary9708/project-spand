
import { useEffect, useRef, useState } from 'react'

const KEY_PREFIX = 'hintv3_'
const TIP_MS     = 6000   // ms each tip stays visible

export default function OnboardingHint({ hintKey, icon, title, tips }) {
  const [visible,  setVisible]  = useState(false)
  const [idx,      setIdx]      = useState(0)
  const [progress, setProgress] = useState(100)
  const rafRef   = useRef(null)
  const timerRef = useRef(null)

  // ── Mount: show if never seen ────────────────────────────────
  useEffect(() => {
    const isDismissed = localStorage.getItem(KEY_PREFIX + hintKey + '_dismissed')
    if (isDismissed) return

    const views = parseInt(localStorage.getItem(KEY_PREFIX + hintKey + '_views') || '0', 10)
    if (views >= 5) return

    // Increment views and show
    localStorage.setItem(KEY_PREFIX + hintKey + '_views', (views + 1).toString())
    const t = setTimeout(() => setVisible(true), 500)
    return () => clearTimeout(t)
  }, [hintKey])

  // ── Per-tip countdown + advance ──────────────────────────────
  useEffect(() => {
    if (!visible) return

    const start = performance.now()

    // Smooth progress bar
    const tick = (now) => {
      const pct = Math.max(0, 100 - ((now - start) / TIP_MS) * 100)
      setProgress(pct)
      if (pct > 0) rafRef.current = requestAnimationFrame(tick)
    }
    rafRef.current = requestAnimationFrame(tick)

    // Advance or dismiss after TIP_MS
    timerRef.current = setTimeout(() => {
      setIdx(prev => {
        const next = prev + 1
        if (next >= tips.length) {
          // All tips done — just hide (it counts as 1 view)
          setVisible(false)
          return prev
        }
        return next
      })
      setProgress(100)
    }, TIP_MS)

    return () => {
      clearTimeout(timerRef.current)
      cancelAnimationFrame(rafRef.current)
    }
  }, [visible, idx, hintKey, tips.length])

  const dismiss = () => {
    clearTimeout(timerRef.current)
    cancelAnimationFrame(rafRef.current)
    localStorage.setItem(KEY_PREFIX + hintKey + '_dismissed', '1')
    setVisible(false)
  }

  if (!visible) return null
  const tip = tips[idx] || tips[0]

  return (
    <div style={{
      position:      'fixed',
      bottom:        24,
      right:         24,
      zIndex:        99999,
      width:         320,
      background:    'linear-gradient(135deg,rgba(13,20,38,0.97),rgba(17,24,39,0.97))',
      border:        '1px solid rgba(0,212,255,0.22)',
      borderRadius:  14,
      boxShadow:     '0 10px 40px rgba(0,0,0,0.55)',
      backdropFilter:'blur(20px)',
      overflow:      'hidden',
      animation:     'toastIn 0.38s cubic-bezier(0.34,1.56,0.64,1) both',
    }}>
      <style>{`
        @keyframes toastIn {
          from { opacity:0; transform:translateY(20px) scale(0.95); }
          to   { opacity:1; transform:translateY(0) scale(1); }
        }
        @keyframes tipIn {
          from { opacity:0; transform:translateX(8px); }
          to   { opacity:1; transform:translateX(0); }
        }
      `}</style>

      {/* ── Header ─────────────────────────────────────────────── */}
      <div style={{
        display:'flex', alignItems:'center', justifyContent:'space-between',
        padding:'10px 12px 8px',
        borderBottom:'1px solid rgba(255,255,255,0.05)',
      }}>
        <div style={{ display:'flex', alignItems:'center', gap:7 }}>
          <span style={{ fontSize:14 }}>{icon}</span>
          <span style={{
            fontSize:10, fontWeight:800, color:'var(--accent-cyan)',
            letterSpacing:0.8, textTransform:'uppercase',
          }}>{title}</span>
        </div>

        <div style={{ display:'flex', alignItems:'center', gap:8 }}>
          {/* Pill-shaped step indicators */}
          <div style={{ display:'flex', gap:3, alignItems:'center' }}>
            {tips.map((_, i) => (
              <div key={i} style={{
                height:4,
                width: i === idx ? 16 : 4,
                borderRadius:99,
                background: i === idx
                  ? 'linear-gradient(90deg,#00d4ff,#8b5cf6)'
                  : 'rgba(255,255,255,0.12)',
                transition:'all 0.3s ease',
                boxShadow: i === idx ? '0 0 6px rgba(0,212,255,0.5)' : 'none',
              }} />
            ))}
          </div>

          <button
            onClick={dismiss}
            style={{
              background:'rgba(255,255,255,0.05)',
              border:'1px solid rgba(255,255,255,0.08)',
              color:'rgba(255,255,255,0.35)',
              borderRadius:6, width:20, height:20, padding:0,
              cursor:'pointer', fontSize:10,
              display:'flex', alignItems:'center', justifyContent:'center',
              transition:'color 0.15s',
            }}
            onMouseEnter={e => e.currentTarget.style.color='#fff'}
            onMouseLeave={e => e.currentTarget.style.color='rgba(255,255,255,0.35)'}
          >✕</button>
        </div>
      </div>

      {/* ── Tip body — keyed so animation fires on change ──────── */}
      <div key={idx} style={{
        padding:'12px 14px 11px',
        display:'flex', alignItems:'flex-start', gap:10,
        animation:'tipIn 0.22s ease both',
      }}>
        <span style={{ fontSize:16, flexShrink:0, marginTop:1 }}>{tip.icon}</span>
        <span style={{ fontSize:12, color:'rgba(255,255,255,0.8)', lineHeight:1.55 }}>
          {tip.text}
        </span>
      </div>

      {/* ── Countdown bar ──────────────────────────────────────── */}
      <div style={{ height:2, background:'rgba(255,255,255,0.05)' }}>
        <div style={{
          height:'100%',
          width:`${progress}%`,
          background:'linear-gradient(90deg,#00d4ff,#8b5cf6)',
          transition:'width 0.05s linear',
          boxShadow:'0 0 6px rgba(0,212,255,0.35)',
        }} />
      </div>
    </div>
  )
}
