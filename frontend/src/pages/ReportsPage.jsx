// ReportsPage.jsx — QuantumShield
// Comprehensive, print-ready security posture reporting
// Clickable drill-down on cards, charts, and compliance violations

import { useState, useEffect } from "react";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, LabelList,
} from "recharts";
import api from "../api/client";

// ─── Helpers ────────────────────────────────────────────────────────────────

function hndlColor(score) {
  if (score <= 3.0) return "#10b981";
  if (score <= 5.5) return "#f59e0b";
  if (score <= 7.8) return "#f97316";
  return "#ef4444";
}

function hndlLabel(score) {
  if (score <= 3.0) return "Quantum Safe";
  if (score <= 5.5) return "Partially Safe";
  if (score <= 7.8) return "Vulnerable";
  return "Critical Risk";
}

const SEV_COLOR = {
  CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#f59e0b",
  LOW: "#10b981", INFO: "#3b82f6",
};
const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

const PQC_COLORS = {
  "Quantum Safe": "#10b981", "Partially Safe": "#f59e0b",
  "Vulnerable": "#f97316", "Critical Risk": "#ef4444",
};

function formatDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-IN", { dateStyle: "medium", timeStyle: "short" });
}

// ─── Drill-down Modal ───────────────────────────────────────────────────────

function DrillModal({ title, subtitle, onClose, children }) {
  return (
    <div style={modal.overlay} onClick={onClose}>
      <div style={modal.container} onClick={(e) => e.stopPropagation()}>
        <div style={modal.header}>
          <div>
            <h2 style={modal.title}>{title}</h2>
            {subtitle && <p style={modal.subtitle}>{subtitle}</p>}
          </div>
          <button style={modal.closeBtn} onClick={onClose}>✕</button>
        </div>
        <div style={modal.body}>{children}</div>
      </div>
    </div>
  );
}

const modal = {
  overlay: {
    position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
    background: "rgba(0,0,0,0.75)", backdropFilter: "blur(8px)",
    zIndex: 2000, display: "flex", alignItems: "center", justifyContent: "center",
    padding: 40, animation: "fadeIn 0.2s ease",
  },
  container: {
    width: "100%", maxWidth: 900, maxHeight: "85vh",
    background: "#0d1426", border: "1px solid rgba(0,212,255,0.2)",
    borderRadius: 16, overflow: "hidden", display: "flex", flexDirection: "column",
    boxShadow: "0 0 60px rgba(0,212,255,0.08)",
  },
  header: {
    padding: "20px 28px", borderBottom: "1px solid #1e2d47",
    display: "flex", justifyContent: "space-between", alignItems: "center",
    background: "rgba(0,212,255,0.03)",
  },
  title: { fontSize: 17, fontWeight: 700, color: "#f0f6ff", margin: 0 },
  subtitle: { fontSize: 12, color: "#64748b", margin: "4px 0 0" },
  closeBtn: {
    background: "rgba(255,255,255,0.06)", border: "1px solid #1e2d47",
    color: "#94a3b8", width: 34, height: 34, borderRadius: 8,
    cursor: "pointer", fontSize: 14, display: "flex", alignItems: "center", justifyContent: "center",
  },
  body: { padding: "20px 28px", overflowY: "auto", flex: 1 },
};

// ─── Section Header ─────────────────────────────────────────────────────────

function SectionHeader({ number, title, subtitle }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 20 }}>
      <div style={{
        fontSize: 13, fontWeight: 800, color: "var(--accent-cyan)",
        background: "rgba(0,212,255,0.08)", border: "1px solid rgba(0,212,255,0.2)",
        borderRadius: 8, width: 36, height: 36,
        display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
      }}>{number}</div>
      <div>
        <h2 style={{ fontSize: 18, fontWeight: 700, color: "var(--text-primary)", margin: 0 }}>{title}</h2>
        {subtitle && <p style={{ fontSize: 12, color: "var(--text-muted)", margin: "2px 0 0" }}>{subtitle}</p>}
      </div>
    </div>
  );
}

// ─── Main ───────────────────────────────────────────────────────────────────

export default function ReportsPage() {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState("");
  const [loading, setLoading] = useState(false);
  const [reportTitle, setReportTitle] = useState("Quantum Security Posture Report");

  const [scanMeta, setScanMeta] = useState(null);
  const [assets, setAssets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [dashStats, setDashStats] = useState(null);

  // Drill-down state
  const [drill, setDrill] = useState(null); // { type, title, subtitle, data }

  const user = (() => {
    try { return JSON.parse(localStorage.getItem("user") || "null"); }
    catch { return null; }
  })();

  useEffect(() => {
    api.get("/scans").then((r) => setScans(r.data.filter((s) => s.status === "COMPLETED"))).catch(() => {});
    api.get("/dashboard/stats").then((r) => setDashStats(r.data)).catch(() => {});
  }, []);

  const loadReport = async (scanId) => {
    setSelectedScan(scanId);
    if (!scanId) return;
    setLoading(true);
    try {
      const [scanRes, assetsRes, findingsRes] = await Promise.all([
        api.get(`/scans/${scanId}`),
        api.get(`/scans/${scanId}/assets`),
        api.get(`/scans/${scanId}/findings`),
      ]);
      setScanMeta(scanRes.data);
      setAssets(assetsRes.data);
      setFindings(findingsRes.data);
    } catch (e) {
      console.error("Failed to load report data:", e);
    } finally {
      setLoading(false);
    }
  };

  // ── Computed ─────────────────────────────────────────────────────────────

  const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  findings.forEach((f) => { if (sevCounts[f.severity] !== undefined) sevCounts[f.severity]++; });

  const sevData = Object.entries(sevCounts)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({ name: k, value: v, color: SEV_COLOR[k] }));

  // PQC grouping
  const pqcGroups = {};
  assets.forEach((a) => {
    const label = a.pqc_readiness || "Vulnerable";
    if (!pqcGroups[label]) pqcGroups[label] = [];
    pqcGroups[label].push(a);
  });
  const pqcData = Object.entries(pqcGroups)
    .map(([name, items]) => ({ name, value: items.length, color: PQC_COLORS[name] || "#f97316" }))
    .filter((d) => d.value > 0);

  // Algorithm grouping
  const algoGroups = {};
  assets.forEach((a) => {
    (a.certificates || []).forEach((c) => {
      const algo = c.algorithm || "Unknown";
      if (!algoGroups[algo]) algoGroups[algo] = [];
      algoGroups[algo].push({ ...a, _cert: c });
    });
  });
  const algoData = Object.entries(algoGroups).map(([k, v]) => ({
    algorithm: k, count: v.length,
    isVuln: /RSA|ECDSA|DHE|DH\b|DSA|ECC/i.test(k),
  }));

  // Compliance
  const complianceMap = {};
  const complianceFindings = {};
  findings.forEach((f) => {
    (f.compliance_tags || []).forEach((t) => {
      if (!complianceMap[t.framework]) {
        complianceMap[t.framework] = { total: 0, non_compliant: 0 };
        complianceFindings[t.framework] = [];
      }
      complianceMap[t.framework].total++;
      if (t.status === "NON_COMPLIANT") {
        complianceMap[t.framework].non_compliant++;
        complianceFindings[t.framework].push({ ...f, _tag: t });
      }
    });
  });

  const topFindings = [...findings]
    .sort((a, b) => (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0))
    .slice(0, 20);

  const avgHndl = scanMeta?.avg_hndl ?? 0;
  const pqcPct = scanMeta?.pqc_ready_pct ?? 0;
  const totalAssets = scanMeta?.asset_count ?? assets.length;

  // ── Drill-down handlers ──────────────────────────────────────────────────

  const drillSeverity = (sev) => {
    const items = findings.filter((f) => f.severity === sev);
    setDrill({
      title: `${sev} Findings`,
      subtitle: `${items.length} finding(s) with ${sev} severity`,
      type: "findings",
      data: items,
    });
  };

  const drillPqc = (pqcLabel) => {
    const items = pqcGroups[pqcLabel] || [];
    setDrill({
      title: `${pqcLabel} Assets`,
      subtitle: `${items.length} asset(s) classified as "${pqcLabel}"`,
      type: "assets",
      data: items,
    });
  };

  const drillAlgo = (algo) => {
    const items = algoGroups[algo] || [];
    setDrill({
      title: `Algorithm: ${algo}`,
      subtitle: `${items.length} asset(s) using ${algo}`,
      type: "assets",
      data: items,
    });
  };

  const drillCompliance = (fw) => {
    const items = complianceFindings[fw] || [];
    setDrill({
      title: `${fw} Violations`,
      subtitle: `${items.length} non-compliant finding(s)`,
      type: "compliance",
      data: items,
    });
  };

  // ── Executive summary text ───────────────────────────────────────────────

  const genExecSummary = () => {
    const riskLevel = hndlLabel(avgHndl);
    let urgency = "";
    if (sevCounts.CRITICAL > 0) urgency += `There are ${sevCounts.CRITICAL} critical finding(s) requiring immediate attention. `;
    if (sevCounts.HIGH > 0) urgency += `${sevCounts.HIGH} high-severity issue(s) should be addressed in the near term. `;
    return (
      `This report summarizes the cryptographic security posture of ${scanMeta?.org_name || "the organization"} ` +
      `based on the latest QuantumShield scan. ${totalAssets} asset(s) were analyzed, yielding ${findings.length} finding(s). ` +
      `The average HNDL risk score is ${avgHndl.toFixed(1)}/10, classified as "${riskLevel}". ` +
      `Currently, ${pqcPct.toFixed(0)}% of assets are quantum-safe. ${urgency}` +
      `Migration to Post-Quantum Cryptography (PQC) is recommended for all critical infrastructure.`
    );
  };

  // ── Recommendations ──────────────────────────────────────────────────────

  const genRecommendations = () => {
    const recs = [];
    if (sevCounts.CRITICAL > 0) recs.push({ priority: "CRITICAL", title: "Remediate Critical Vulnerabilities Immediately", desc: `${sevCounts.CRITICAL} critical finding(s) expose the organization to immediate cryptographic risk. Prioritize migration within 30 days.` });
    if (pqcPct < 50) recs.push({ priority: "HIGH", title: "Accelerate PQC Migration", desc: `Only ${pqcPct.toFixed(0)}% of assets are quantum-safe. Target 80% PQC readiness within 12 months.` });
    if (avgHndl > 5.0) recs.push({ priority: "HIGH", title: "Reduce HNDL Risk Score", desc: `Average HNDL of ${avgHndl.toFixed(1)}/10 indicates significant harvest-now-decrypt-later risk. Replace RSA/ECDSA with ML-KEM hybrid modes.` });
    if (sevCounts.HIGH > 0) recs.push({ priority: "MEDIUM", title: "Address High-Severity Findings", desc: `${sevCounts.HIGH} high-severity finding(s) should be remediated within 90 days.` });
    const hasCompliance = Object.values(complianceMap).some((v) => v.non_compliant > 0);
    if (hasCompliance) recs.push({ priority: "HIGH", title: "Resolve Compliance Violations", desc: `Non-compliance detected. Address violations to meet NIST-PQC, RBI, and CERT-IN mandates.` });
    if (recs.length === 0) recs.push({ priority: "INFO", title: "Maintain Current Posture", desc: "All assets meet current quantum-readiness standards. Continue periodic scanning." });
    return recs;
  };

  // ─── Render ─────────────────────────────────────────────────────────────

  return (
    <div className="scroll-fade">
      {/* Controls */}
      <div className="report-controls no-print">
        <div className="page-header">
          <div>
            <h1 className="page-title">Reports</h1>
            <p className="page-subtitle">Generate comprehensive security posture reports</p>
          </div>
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <select className="form-select" style={{ width: 250 }} value={selectedScan}
              onChange={(e) => { if (e.target.value) loadReport(e.target.value); }} id="report-scan-selector">
              <option value="">— Select a completed scan —</option>
              {scans.map((s) => <option key={s.scan_id} value={s.scan_id}>{s.org_name} ({s.asset_count} assets)</option>)}
            </select>
            {selectedScan && scanMeta && (
              <button className="btn btn-primary" onClick={() => window.print()} id="report-print-btn">🖨️ Print Report</button>
            )}
          </div>
        </div>
        {selectedScan && scanMeta && (
          <div style={{ marginBottom: 16 }}>
            <label className="form-label" style={{ marginBottom: 4 }}>Report Title</label>
            <input className="form-input" style={{ maxWidth: 500 }} value={reportTitle}
              onChange={(e) => setReportTitle(e.target.value)} id="report-title-input" />
          </div>
        )}
      </div>

      {/* Empty state */}
      {!selectedScan && (
        <div className="card empty-state">
          <div style={{ fontSize: 48, marginBottom: 16, opacity: 0.3 }}>📄</div>
          <p>Select a completed scan to generate a report.</p>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div style={{ textAlign: "center", padding: 80 }}>
          <span className="loading-spinner" style={{ width: 32, height: 32 }} />
          <p style={{ color: "var(--text-muted)", marginTop: 16 }}>Generating report...</p>
        </div>
      )}

      {/* ─── Report Body ────────────────────────────────────────────── */}
      {selectedScan && scanMeta && !loading && (
        <div className="report-container" id="report-content">

          {/* ══ 1. COVER ══════════════════════════════════════════════ */}
          <div className="report-section report-cover" style={{
            background: "linear-gradient(145deg, #0d1426 0%, #111827 50%, #0d1426 100%)",
            border: "1px solid rgba(0,212,255,0.15)", borderRadius: 20,
            padding: "44px 40px", textAlign: "center", position: "relative",
            boxShadow: "0 0 60px rgba(0,212,255,0.05), 0 4px 24px rgba(0,0,0,0.4)",
          }}>
            <div style={{ position: "absolute", top: 16, right: 20, fontSize: 9, fontWeight: 700, letterSpacing: 2, color: "#ef4444", background: "rgba(239,68,68,0.12)", border: "1px solid rgba(239,68,68,0.3)", padding: "3px 12px", borderRadius: 20 }}>CONFIDENTIAL</div>
            <div style={{ fontSize: 48, marginBottom: 12 }}>🛡️</div>
            <h1 style={{ fontSize: 26, fontWeight: 800, background: "var(--gradient-primary)", WebkitBackgroundClip: "text", backgroundClip: "text", WebkitTextFillColor: "transparent", marginBottom: 8 }}>{reportTitle}</h1>
            <div style={{ fontSize: 18, fontWeight: 600, color: "var(--text-primary)", marginBottom: 24 }}>{scanMeta.org_name}</div>
            <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: 24, flexWrap: "wrap" }}>
              {[
                ["Scan Date", formatDate(scanMeta.created_at)],
                ["Generated By", user?.username || "System"],
                ["Report Date", new Date().toLocaleDateString("en-IN", { dateStyle: "long" })],
              ].map(([label, value], i) => (
                <div key={label} style={{ display: "flex", alignItems: "center", gap: 24 }}>
                  {i > 0 && <div style={{ width: 1, height: 30, background: "var(--bg-border)" }} />}
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 2 }}>
                    <span style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 1, fontWeight: 600 }}>{label}</span>
                    <span style={{ fontSize: 13, color: "var(--text-secondary)", fontWeight: 500 }}>{value}</span>
                  </div>
                </div>
              ))}
            </div>
            <div style={{ marginTop: 24, paddingTop: 16, borderTop: "1px solid var(--bg-border)" }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" }}>SCAN-ID: {scanMeta.scan_id?.slice(0, 8)}… · QuantumShield v2.0</span>
            </div>
          </div>

          {/* ══ 2. EXECUTIVE SUMMARY ══════════════════════════════════ */}
          <div className="report-section" style={{ marginTop: 28 }}>
            <SectionHeader number="01" title="Executive Summary" subtitle="High-level security posture overview" />

            <div style={{ display: "grid", gridTemplateColumns: "200px 1fr", gap: 20, marginBottom: 20 }}>
              {/* Risk gauge — simple text-based instead of SVG to avoid rendering issues */}
              <div className="card" style={{ padding: 24, textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
                <div style={{ fontSize: 42, fontWeight: 900, color: hndlColor(avgHndl), lineHeight: 1 }}>{avgHndl.toFixed(1)}</div>
                <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>/ 10 HNDL</div>
                <div style={{ marginTop: 10, width: "100%", height: 8, background: "rgba(255,255,255,0.08)", borderRadius: 4, overflow: "hidden" }}>
                  <div style={{ width: `${Math.min(avgHndl / 10 * 100, 100)}%`, height: "100%", background: hndlColor(avgHndl), borderRadius: 4, boxShadow: `0 0 8px ${hndlColor(avgHndl)}60` }} />
                </div>
                <div style={{ fontSize: 11, fontWeight: 700, color: hndlColor(avgHndl), marginTop: 8 }}>{hndlLabel(avgHndl)}</div>
              </div>

              {/* KPI grid — CLICKABLE */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <div className="card" style={{ padding: 18, borderLeft: "3px solid #3b82f6" }}>
                  <div style={{ fontSize: 28, fontWeight: 800, color: "#3b82f6" }}>{totalAssets}</div>
                  <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Total Assets</div>
                </div>
                <div className="card" style={{ padding: 18, borderLeft: "3px solid #ef4444", cursor: "pointer" }}
                  onClick={() => drillSeverity("CRITICAL")} title="Click to view critical findings">
                  <div style={{ fontSize: 28, fontWeight: 800, color: "#ef4444" }}>{sevCounts.CRITICAL}</div>
                  <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Critical Findings ↗</div>
                </div>
                <div className="card" style={{ padding: 18, borderLeft: "3px solid #10b981", cursor: pqcGroups["Quantum Safe"]?.length ? "pointer" : "default" }}
                  onClick={() => drillPqc("Quantum Safe")} title="Click to view quantum-safe assets">
                  <div style={{ fontSize: 28, fontWeight: 800, color: "#10b981" }}>{pqcPct.toFixed(0)}%</div>
                  <div style={{ fontSize: 12, color: "var(--text-muted)" }}>PQC Ready ↗</div>
                </div>
                <div className="card" style={{ padding: 18, borderLeft: `3px solid ${hndlColor(avgHndl)}` }}>
                  <div style={{ fontSize: 28, fontWeight: 800, color: hndlColor(avgHndl) }}>{avgHndl.toFixed(1)}</div>
                  <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Avg HNDL Score</div>
                </div>
              </div>
            </div>

            {/* Narrative */}
            <div style={{ background: "rgba(0,212,255,0.03)", border: "1px solid rgba(0,212,255,0.1)", borderRadius: 12, padding: "20px 24px", borderLeft: "3px solid var(--accent-cyan)" }}>
              <p style={{ fontSize: 13, lineHeight: 1.8, color: "var(--text-secondary)", margin: 0 }}>{genExecSummary()}</p>
            </div>
          </div>

          {/* ══ 3. RISK DISTRIBUTION ══════════════════════════════════ */}
          <div className="report-section" style={{ marginTop: 28 }}>
            <SectionHeader number="02" title="Risk Distribution Analysis" subtitle="Severity and quantum-readiness breakdown" />

            {/* Severity + PQC charts */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <div className="card" style={{ padding: 20 }}>
                <h3 style={{ fontSize: 13, fontWeight: 600, color: "var(--text-secondary)", margin: "0 0 12px" }}>Finding Severity</h3>
                {sevData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={200}>
                    <PieChart>
                      <Pie data={sevData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={4}
                        onClick={(entry) => drillSeverity(entry.name)} style={{ cursor: "pointer" }}>
                        {sevData.map((e, i) => <Cell key={i} fill={e.color} />)}
                      </Pie>
                      <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155", fontSize: 12 }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : <p style={{ color: "var(--text-muted)", textAlign: "center", padding: 40, fontSize: 13 }}>No findings data.</p>}
              </div>

              <div className="card" style={{ padding: 20 }}>
                <h3 style={{ fontSize: 13, fontWeight: 600, color: "var(--text-secondary)", margin: "0 0 12px" }}>PQC Readiness</h3>
                {pqcData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={200}>
                    <PieChart>
                      <Pie data={pqcData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={75}
                        onClick={(entry) => drillPqc(entry.name)} style={{ cursor: "pointer" }}
                        label={({ name, value }) => `${name}: ${value}`}>
                        {pqcData.map((e, i) => <Cell key={i} fill={e.color} />)}
                      </Pie>
                      <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155", fontSize: 12 }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : <p style={{ color: "var(--text-muted)", textAlign: "center", padding: 40, fontSize: 13 }}>No asset data.</p>}
              </div>
            </div>

            {/* Clickable severity count cards */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginTop: 16 }}>
              {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                <div key={sev} onClick={() => drillSeverity(sev)}
                  style={{
                    background: `${SEV_COLOR[sev]}10`, border: `1px solid ${SEV_COLOR[sev]}30`,
                    borderRadius: 10, padding: "14px 16px", textAlign: "center",
                    cursor: "pointer", transition: "all 0.2s",
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.transform = "translateY(-2px)"; e.currentTarget.style.boxShadow = `0 4px 16px ${SEV_COLOR[sev]}25`; }}
                  onMouseLeave={(e) => { e.currentTarget.style.transform = ""; e.currentTarget.style.boxShadow = ""; }}>
                  <div style={{ fontSize: 28, fontWeight: 800, color: SEV_COLOR[sev] }}>{sevCounts[sev]}</div>
                  <div style={{ fontSize: 11, fontWeight: 600, color: SEV_COLOR[sev], opacity: 0.8, marginTop: 2, textTransform: "uppercase" }}>{sev} ↗</div>
                </div>
              ))}
            </div>

            {/* Algorithm Distribution — CLICKABLE bars */}
            {algoData.length > 0 && (
              <div className="card" style={{ padding: 20, marginTop: 16 }}>
                <h3 style={{ fontSize: 13, fontWeight: 600, color: "var(--text-secondary)", margin: "0 0 4px" }}>Algorithm Distribution</h3>
                <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 12 }}>Click a bar to view assets using that algorithm</div>
                <ResponsiveContainer width="100%" height={Math.max(180, algoData.length * 45)}>
                  <BarChart data={algoData} layout="vertical" margin={{ top: 5, right: 30, left: 10, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e2d47" />
                    <XAxis type="number" tick={{ fill: "#94a3b8", fontSize: 11 }} />
                    <YAxis type="category" dataKey="algorithm" width={100} tick={{ fill: "#94a3b8", fontSize: 11 }} />
                    <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155", fontSize: 12 }} />
                    <Bar dataKey="count" radius={[0, 6, 6, 0]}
                      onClick={(entry) => drillAlgo(entry.algorithm)} style={{ cursor: "pointer" }}>
                      {algoData.map((e, i) => (
                        <Cell key={i} fill={e.isVuln ? "#ef4444" : "#10b981"} />
                      ))}
                      <LabelList dataKey="count" position="right" style={{ fill: "#94a3b8", fontSize: 11, fontWeight: 600 }} />
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
                <div style={{ display: "flex", gap: 16, marginTop: 8, fontSize: 10, color: "var(--text-muted)" }}>
                  <span><span style={{ color: "#ef4444" }}>■</span> Quantum Vulnerable</span>
                  <span><span style={{ color: "#10b981" }}>■</span> PQC Safe</span>
                </div>
              </div>
            )}
          </div>

          {/* ══ 4. COMPLIANCE MATRIX ══════════════════════════════════ */}
          {Object.keys(complianceMap).length > 0 && (
            <div className="report-section" style={{ marginTop: 28 }}>
              <SectionHeader number="03" title="Compliance Status Matrix" subtitle="Click a framework to view violated rules" />
              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr><th>Framework</th><th>Total Tags</th><th>Non-Compliant</th><th>Compliance Rate</th><th>Status</th></tr>
                  </thead>
                  <tbody>
                    {Object.entries(complianceMap).map(([fw, data]) => {
                      const rate = data.total > 0 ? ((data.total - data.non_compliant) / data.total * 100) : 100;
                      return (
                        <tr key={fw} onClick={() => drillCompliance(fw)}
                          style={{ cursor: "pointer", transition: "background 0.15s" }}
                          onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(0,212,255,0.04)"; }}
                          onMouseLeave={(e) => { e.currentTarget.style.background = ""; }}>
                          <td style={{ fontWeight: 600 }}>{fw} ↗</td>
                          <td>{data.total}</td>
                          <td style={{ color: data.non_compliant > 0 ? "#ef4444" : "#10b981", fontWeight: 700 }}>{data.non_compliant}</td>
                          <td>
                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                              <div style={{ flex: 1, height: 6, background: "rgba(255,255,255,0.08)", borderRadius: 3, overflow: "hidden", maxWidth: 120 }}>
                                <div style={{ width: `${rate}%`, height: "100%", background: rate > 80 ? "#10b981" : rate > 50 ? "#f59e0b" : "#ef4444", borderRadius: 3 }} />
                              </div>
                              <span style={{ fontSize: 12, fontWeight: 600, color: rate > 80 ? "#10b981" : rate > 50 ? "#f59e0b" : "#ef4444" }}>{rate.toFixed(0)}%</span>
                            </div>
                          </td>
                          <td><span className={`badge ${data.non_compliant > 0 ? "badge-critical" : "badge-safe"}`}>{data.non_compliant > 0 ? "NON-COMPLIANT" : "COMPLIANT"}</span></td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ══ 5. ASSET INVENTORY ════════════════════════════════════ */}
          <div className="report-section" style={{ marginTop: 28 }}>
            <SectionHeader number={Object.keys(complianceMap).length > 0 ? "04" : "03"} title="Asset Inventory" subtitle={`${assets.length} assets discovered and analyzed`} />
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr><th>Domain</th><th>Algorithm</th><th>Key Size</th><th>HNDL</th><th>PQC Status</th><th>CDN</th><th>Protocol</th></tr>
                </thead>
                <tbody>
                  {assets.map((a) => {
                    const cert = a.certificates?.[0];
                    return (
                      <tr key={a.asset_id}>
                        <td>
                          <div style={{ fontWeight: 600, fontSize: 13 }}>{a.domain}</div>
                          {a.resolved_ips?.length > 0 && <div className="mono" style={{ fontSize: 10, color: "var(--text-muted)" }}>{a.resolved_ips[0]}</div>}
                        </td>
                        <td>
                          <span className={cert?.algorithm?.match(/RSA|ECDSA|DHE|DH\b|DSA/i) ? "algo-vuln" : cert?.algorithm?.match(/KYBER|DILITHIUM|FALCON|SPHINCS/i) ? "algo-safe" : "algo-unknown"}>
                            {cert?.algorithm || "—"}
                          </span>
                        </td>
                        <td><span className={cert?.key_size < 2048 ? "key-weak" : cert?.key_size < 3072 ? "key-medium" : "key-strong"}>{cert?.key_size ? `${cert.key_size}-bit` : "—"}</span></td>
                        <td style={{ fontWeight: 700, color: hndlColor(a.hndl_score || 0) }}>{a.hndl_score?.toFixed(1) ?? "—"}</td>
                        <td><span className={`badge ${a.pqc_readiness?.toLowerCase().includes("safe") ? "badge-safe" : a.pqc_readiness?.toLowerCase().includes("partial") ? "badge-partial" : "badge-vuln"}`}>{a.pqc_readiness || "Vulnerable"}</span></td>
                        <td style={{ fontSize: 11, color: a.is_cdn ? "#8b5cf6" : "var(--text-muted)" }}>{a.is_cdn ? (a.cdn_provider || "Yes") : "—"}</td>
                        <td><span className="port-chip">{a.protocol || "—"}</span></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* ══ 6. TOP FINDINGS ═══════════════════════════════════════ */}
          {topFindings.length > 0 && (
            <div className="report-section" style={{ marginTop: 28 }}>
              <SectionHeader number={Object.keys(complianceMap).length > 0 ? "05" : "04"} title="Top Security Findings" subtitle={`${findings.length} total — showing top ${topFindings.length} by severity`} />
              <div className="table-wrapper">
                <table>
                  <thead><tr><th>#</th><th>Finding</th><th>Asset</th><th>Severity</th><th>HNDL</th><th>CWE</th></tr></thead>
                  <tbody>
                    {topFindings.map((f, idx) => (
                      <tr key={f.finding_id}>
                        <td style={{ color: "var(--text-muted)", fontWeight: 600 }}>{idx + 1}</td>
                        <td>
                          <div style={{ fontWeight: 600, fontSize: 13 }}>{f.title}</div>
                          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{f.type}</div>
                        </td>
                        <td className="mono" style={{ fontSize: 12 }}>{f.asset_domain}</td>
                        <td><span className={`badge badge-${f.severity.toLowerCase()}`}>{f.severity}</span></td>
                        <td style={{ fontWeight: 700, color: SEV_COLOR[f.severity] || "#fff" }}>{f.hndl_score?.toFixed(1) ?? "—"}</td>
                        <td className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>{f.cwe_id || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ══ 7. RECOMMENDATIONS ════════════════════════════════════ */}
          <div className="report-section" style={{ marginTop: 28 }}>
            <SectionHeader number={Object.keys(complianceMap).length > 0 ? "06" : "05"} title="Recommendations" subtitle="Priority action items for remediation" />
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {genRecommendations().map((rec, i) => (
                <div key={i} style={{
                  background: `${SEV_COLOR[rec.priority] || "#3b82f6"}08`,
                  border: `1px solid ${SEV_COLOR[rec.priority] || "#3b82f6"}25`,
                  borderRadius: 12, padding: "18px 22px",
                  borderLeft: `4px solid ${SEV_COLOR[rec.priority] || "#3b82f6"}`,
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                    <span className={`badge badge-${rec.priority.toLowerCase()}`}>{rec.priority}</span>
                    <h4 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>{rec.title}</h4>
                  </div>
                  <p style={{ fontSize: 13, color: "var(--text-secondary)", margin: 0, lineHeight: 1.7 }}>{rec.desc}</p>
                </div>
              ))}
            </div>
          </div>

          {/* ══ 8. PQC SIDECAR PROXY ═══════════════════════════════ */}
          {(() => {
            const vulnAssets = assets.filter((a) => {
              const algo = (a.certificates?.[0]?.algorithm || a.algorithm || "").toUpperCase();
              return /RSA|ECDSA|ECC|DHE|DH\b|DSA|ECDHE/.test(algo);
            });
            if (vulnAssets.length === 0) return null;
            return (
              <div className="report-section no-print" style={{ marginTop: 28 }}>
                <SectionHeader
                  number={Object.keys(complianceMap).length > 0 ? "07" : "06"}
                  title="PQC Sidecar Proxy"
                  subtitle={`Deploy quantum-safe wrappers for ${vulnAssets.length} vulnerable asset(s)`}
                />
                <div style={{
                  background: "linear-gradient(135deg, rgba(139,92,246,0.06), rgba(0,212,255,0.04))",
                  border: "1px solid rgba(139,92,246,0.2)", borderRadius: 14,
                  padding: "20px 24px", marginBottom: 16,
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
                    <span style={{ fontSize: 22 }}>🛡️</span>
                    <div>
                      <div style={{ fontSize: 14, fontWeight: 700, color: "#a78bfa" }}>Cryptographic Bridge Technology</div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                        Wrap legacy servers in Quantum-Safe TLS (ML-KEM / Kyber) without modifying backend code
                      </div>
                    </div>
                  </div>
                  <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.7, marginBottom: 16 }}>
                    Each config generates a <strong>Docker + Nginx</strong> deployment package using the <strong>Open Quantum Safe (OQS)</strong> project's
                    pre-built PQC image. The proxy terminates quantum-safe TLS on the outside and forwards classical HTTP to your legacy backend.
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                    {vulnAssets.slice(0, 10).map((a) => {
                      const algo = a.certificates?.[0]?.algorithm || a.algorithm || "RSA";
                      return (
                        <div key={a.asset_id} style={{
                          display: "flex", alignItems: "center", justifyContent: "space-between",
                          padding: "10px 14px", background: "rgba(0,0,0,0.2)",
                          border: "1px solid rgba(255,255,255,0.06)", borderRadius: 8,
                        }}>
                          <div>
                            <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-primary)" }}>{a.domain}</div>
                            <div style={{ fontSize: 10, color: "#ef4444" }}>{algo} → ML-KEM-768</div>
                          </div>
                          <button
                            className="btn btn-primary"
                            style={{
                              fontSize: 9, padding: "5px 10px", borderRadius: 6,
                              background: "linear-gradient(135deg, #8b5cf6, #3b82f6)",
                              border: "none", fontWeight: 700, whiteSpace: "nowrap",
                            }}
                            onClick={async () => {
                              try {
                                const res = await api.get(`/proxy/generate/${a.asset_id}`, { responseType: "blob" });
                                const url = URL.createObjectURL(res.data);
                                const el = document.createElement("a");
                                el.href = url;
                                el.download = `pqc-proxy-${a.domain.replace(/\./g, "-")}.zip`;
                                el.click();
                                URL.revokeObjectURL(url);
                              } catch { alert("Failed to generate config."); }
                            }}
                          >
                            ⬇️ Config
                          </button>
                        </div>
                      );
                    })}
                  </div>
                  {vulnAssets.length > 10 && (
                    <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 10, textAlign: "center" }}>
                      + {vulnAssets.length - 10} more vulnerable assets. Use the Assets page for full access.
                    </div>
                  )}
                </div>
              </div>
            );
          })()}

          {/* ══ FOOTER ═══════════════════════════════════════════════ */}
          <div className="report-section" style={{ marginTop: 40, paddingBottom: 20 }}>
            <div style={{ height: 1, background: "linear-gradient(90deg, transparent 0%, var(--accent-cyan) 50%, transparent 100%)", opacity: 0.3, marginBottom: 16 }} />
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
              <div>
                <span style={{ fontWeight: 700, color: "var(--accent-cyan)" }}>QuantumShield</span>
                <span style={{ color: "var(--text-muted)", marginLeft: 8, fontSize: 11 }}>Post-Quantum Cryptographic Assessment Platform</span>
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>Generated: {new Date().toLocaleString("en-IN")} · Scan ID: {scanMeta.scan_id?.slice(0, 8)}</div>
            </div>
            <div style={{ textAlign: "center", marginTop: 12 }}>
              <span style={{ fontSize: 9, color: "var(--text-muted)", letterSpacing: 1, textTransform: "uppercase" }}>
                This report contains confidential security assessment data. Handle according to your organization's information classification policy.
              </span>
            </div>
          </div>
        </div>
      )}

      {/* ─── Drill-down Modal ───────────────────────────────────────── */}
      {drill && (
        <DrillModal title={drill.title} subtitle={drill.subtitle} onClose={() => setDrill(null)}>
          {drill.type === "findings" && (
            <div className="table-wrapper" style={{ border: "1px solid #1e2d47", borderRadius: 10 }}>
              <table>
                <thead><tr><th>Finding</th><th>Asset</th><th>Severity</th><th>HNDL</th><th>CWE</th></tr></thead>
                <tbody>
                  {drill.data.map((f) => (
                    <tr key={f.finding_id}>
                      <td>
                        <div style={{ fontWeight: 600, fontSize: 13 }}>{f.title}</div>
                        <div style={{ fontSize: 11, color: "#64748b" }}>{f.type}</div>
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>{f.asset_domain}</td>
                      <td><span className={`badge badge-${f.severity.toLowerCase()}`}>{f.severity}</span></td>
                      <td style={{ fontWeight: 700, color: SEV_COLOR[f.severity] }}>{f.hndl_score?.toFixed(1) ?? "—"}</td>
                      <td className="mono" style={{ fontSize: 11, color: "#64748b" }}>{f.cwe_id || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {drill.type === "assets" && (
            <div className="table-wrapper" style={{ border: "1px solid #1e2d47", borderRadius: 10 }}>
              <table>
                <thead><tr><th>Domain</th><th>Algorithm</th><th>Key Size</th><th>HNDL</th><th>PQC Status</th></tr></thead>
                <tbody>
                  {drill.data.map((a) => {
                    const cert = a._cert || a.certificates?.[0];
                    return (
                      <tr key={a.asset_id + (cert?.cert_id || "")}>
                        <td style={{ fontWeight: 600, fontSize: 13 }}>{a.domain}</td>
                        <td><span className={cert?.algorithm?.match(/RSA|ECDSA|DHE|DH\b|DSA/i) ? "algo-vuln" : "algo-safe"}>{cert?.algorithm || "—"}</span></td>
                        <td><span className={cert?.key_size < 2048 ? "key-weak" : cert?.key_size < 3072 ? "key-medium" : "key-strong"}>{cert?.key_size ? `${cert.key_size}-bit` : "—"}</span></td>
                        <td style={{ fontWeight: 700, color: hndlColor(a.hndl_score || 0) }}>{a.hndl_score?.toFixed(1) ?? "—"}</td>
                        <td><span className={`badge ${(a.pqc_readiness || "").toLowerCase().includes("safe") ? "badge-safe" : "badge-vuln"}`}>{a.pqc_readiness || "Vulnerable"}</span></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {drill.type === "compliance" && (
            <div className="table-wrapper" style={{ border: "1px solid #1e2d47", borderRadius: 10 }}>
              <table>
                <thead><tr><th>Finding</th><th>Asset</th><th>Control Ref</th><th>Severity</th><th>HNDL</th></tr></thead>
                <tbody>
                  {drill.data.map((f, i) => (
                    <tr key={f.finding_id + "-" + i}>
                      <td>
                        <div style={{ fontWeight: 600, fontSize: 13 }}>{f.title}</div>
                        <div style={{ fontSize: 11, color: "#64748b" }}>{f.type}</div>
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>{f.asset_domain}</td>
                      <td className="mono" style={{ fontSize: 11, color: "#93c5fd" }}>{f._tag?.control_ref || "—"}</td>
                      <td><span className={`badge badge-${f.severity.toLowerCase()}`}>{f.severity}</span></td>
                      <td style={{ fontWeight: 700, color: SEV_COLOR[f.severity] }}>{f.hndl_score?.toFixed(1) ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </DrillModal>
      )}
    </div>
  );
}
