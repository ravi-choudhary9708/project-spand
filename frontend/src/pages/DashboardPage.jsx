// DashboardPage.jsx — QuantumShield
// Place at: frontend/src/pages/DashboardPage.jsx
// Management sees executive summary only.
// Analyst/SOC/Admin sees full technical dashboard.

import { useState, useEffect } from "react";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, LabelList,
} from "recharts";
import api from "../api/client";

const ROLE_MANAGEMENT = "MANAGEMENT";
const ROLE_COMPLIANCE = "COMPLIANCE_OFFICER";

// HNDL colour thresholds
function hndlColor(score) {
  if (score <= 3.0) return "#10b981"; // green — safe
  if (score <= 5.5) return "#f59e0b"; // yellow — partial
  if (score <= 7.8) return "#f97316"; // orange — vulnerable
  return "#ef4444";                    // red — critical
}

function hndlLabel(score) {
  if (score <= 3.0) return "Quantum Safe";
  if (score <= 5.5) return "Partially Safe";
  if (score <= 7.8) return "Vulnerable";
  return "Critical Risk";
}

// ─── Executive (Management) Dashboard ────────────────────────────────────────
function ManagementDashboard({ stats }) {
  const riskColor = hndlColor(stats.avg_hndl || 0);

  return (
    <div style={styles.page}>
      <div style={styles.header}>
        <div>
          <h1 style={styles.title}>📈 Security Executive Summary</h1>
          <p style={styles.subtitle}>QuantumShield — Quantum Threat Overview</p>
        </div>
      </div>

      {/* Big 4 KPI cards */}
      <div style={styles.kpiGrid}>
        <KpiCard
          icon="🖥️"
          label="Total Assets Scanned"
          value={stats.total_assets ?? "—"}
          color="#3b82f6"
        />
        <KpiCard
          icon="⚠️"
          label="Average HNDL Risk"
          value={stats.avg_hndl != null ? `${stats.avg_hndl.toFixed(1)} / 10` : "—"}
          sub={stats.avg_hndl != null ? hndlLabel(stats.avg_hndl) : ""}
          color={riskColor}
        />
        <KpiCard
          icon="🔒"
          label="PQC Ready Assets"
          value={stats.pqc_ready_pct != null ? `${stats.pqc_ready_pct.toFixed(0)}%` : "—"}
          sub="Quantum-Safe"
          color="#10b981"
        />
        <KpiCard
          icon="🚨"
          label="Critical Findings"
          value={stats.critical_findings ?? "—"}
          sub="Needs immediate action"
          color="#ef4444"
        />
      </div>

      {/* Risk summary text for management */}
      <div style={styles.execSummaryBox}>
        <h3 style={{ margin: "0 0 8px 0", color: "#e2e8f0" }}>📋 Summary for Leadership</h3>
        <p style={{ color: "#94a3b8", lineHeight: 1.7, margin: 0 }}>
          Our infrastructure has an average Harvest Now Decrypt Later (HNDL) risk score of{" "}
          <strong style={{ color: riskColor }}>
            {stats.avg_hndl != null ? stats.avg_hndl.toFixed(1) : "N/A"} / 10
          </strong>
          , which is classified as{" "}
          <strong style={{ color: riskColor }}>
            {stats.avg_hndl != null ? hndlLabel(stats.avg_hndl) : "Unknown"}
          </strong>
          . Currently{" "}
          <strong style={{ color: "#10b981" }}>
            {stats.pqc_ready_pct != null ? `${stats.pqc_ready_pct.toFixed(0)}%` : "0%"}
          </strong>{" "}
          of assets are quantum-safe. Immediate migration to Post-Quantum Cryptography (PQC) is
          recommended for all critical banking assets to comply with RBI and NIST guidelines.
        </p>
      </div>

      {/* Compliance status */}
      {stats.compliance && (
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>Regulatory Compliance Status</h3>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 12 }}>
            {Object.entries(stats.compliance).map(([fw, count]) => (
              <div key={fw} style={styles.complianceBadge}>
                <div style={{ fontSize: 13, color: "#94a3b8" }}>{fw}</div>
                <div style={{ fontSize: 22, fontWeight: 700, color: "#ef4444" }}>{count}</div>
                <div style={{ fontSize: 11, color: "#64748b" }}>violations</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Full Technical Dashboard ─────────────────────────────────────────────────
function TechnicalDashboard({ stats, role }) {
  const riskColor = hndlColor(stats.avg_hndl || 0);

  const pieData = [
    { name: "Critical Risk",   value: stats.critical_pct    || 0, color: "#ef4444" },
    { name: "Vulnerable",      value: stats.vulnerable_pct  || 0, color: "#f97316" },
    { name: "Partially Safe",  value: stats.partial_pct     || 0, color: "#f59e0b" },
    { name: "Quantum Safe",    value: stats.pqc_ready_pct   || 0, color: "#10b981" },
  ].filter((d) => d.value > 0);

  const algoData = stats.algo_breakdown || [];

  return (
    <div style={styles.page}>
      <div style={styles.header}>
        <div>
          <h1 style={styles.title}>🛡️ QuantumShield Dashboard</h1>
          <p style={styles.subtitle}>Real-time Cryptographic Risk Intelligence</p>
        </div>
        {stats.last_scan && (
          <div style={styles.lastScan}>
            Last scan: <strong>{new Date(stats.last_scan).toLocaleString()}</strong>
          </div>
        )}
      </div>

      {/* KPI row */}
      <div style={styles.kpiGrid}>
        <KpiCard icon="🖥️" label="Total Assets"       value={stats.total_assets ?? "—"}  color="#3b82f6" />
        <KpiCard icon="⚠️" label="Avg HNDL Score"     value={stats.avg_hndl != null ? stats.avg_hndl.toFixed(2) : "—"} sub={`/ 10 — ${stats.avg_hndl != null ? hndlLabel(stats.avg_hndl) : ""}`} color={riskColor} />
        <KpiCard icon="🔒" label="PQC Ready"           value={stats.pqc_ready_pct != null ? `${stats.pqc_ready_pct.toFixed(0)}%` : "—"} color="#10b981" />
        <KpiCard icon="🚨" label="Critical Findings"   value={stats.critical_findings ?? "—"} color="#ef4444" />
        <KpiCard icon="📜" label="Total Findings"      value={stats.total_findings ?? "—"} color="#f59e0b" />
        <KpiCard icon="🏢" label="Assets Scanned"      value={stats.total_scans ?? "—"} sub="scan jobs" color="#8b5cf6" />
      </div>

      {/* Charts row */}
      <div style={styles.chartsRow}>
        {/* Pie — Risk distribution */}
        <div style={styles.chartCard}>
          <h3 style={styles.cardTitle}>Risk Distribution</h3>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={({ name, value }) => `${name}: ${value.toFixed(0)}%`}>
                  {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
                <Tooltip formatter={(v) => `${v.toFixed(1)}%`} contentStyle={{ background: "#1e293b", border: "1px solid #334155" }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p style={styles.noData}>No scan data yet. Start a scan to see results.</p>
          )}
        </div>

        {/* Bar — Algorithm breakdown (real data from scanner, color-coded by quantum risk) */}
        <div style={styles.chartCard}>
          <h3 style={styles.cardTitle}>Algorithm Exposure</h3>
          <div style={{ fontSize: 11, color: "#64748b", marginBottom: 10, display: "flex", gap: 12 }}>
            <span style={{ color: "#ef4444" }}>■ Quantum Vulnerable</span>
            <span style={{ color: "#10b981" }}>■ PQC Safe</span>
            <span style={{ color: "#6b7280" }}>■ Unknown</span>
          </div>
          {algoData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={algoData} margin={{ top: 5, right: 10, bottom: 5, left: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="algorithm" tick={{ fill: "#94a3b8", fontSize: 11 }} />
                <YAxis tick={{ fill: "#94a3b8", fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ background: "#1e293b", border: "1px solid #334155", fontSize: 12 }}
                  formatter={(v, n, p) => [
                    v,
                    `${p.payload.algorithm} (${p.payload.quantum_vulnerable ? '⚠ Quantum Vulnerable' : '✓ Safe'})`,
                  ]}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {algoData.map((entry, i) => (
                    <Cell
                      key={i}
                      fill={
                        entry.quantum_vulnerable === false ? "#10b981"
                        : entry.quantum_vulnerable === true  ? "#ef4444"
                        : "#6b7280"
                      }
                    />
                  ))}
                  <LabelList dataKey="count" position="top" style={{ fill: "#94a3b8", fontSize: 10 }} />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p style={styles.noData}>No data available. Run a scan to see algorithm details.</p>
          )}
        </div>
      </div>

      {/* NEW: Service Identification Row */}
      <div style={styles.chartsRow}>
        {/* Pie — Service Category */}
        <div style={styles.chartCard}>
          <h3 style={styles.cardTitle}>Service Categories</h3>
          {stats.service_distribution?.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie 
                  data={stats.service_distribution} 
                  dataKey="count" 
                  nameKey="category" 
                  cx="50%" cy="50%" 
                  outerRadius={70} 
                >
                  {stats.service_distribution.map((entry, i) => (
                    <Cell key={i} fill={["#3b82f6", "#8b5cf6", "#f59e0b", "#10b981", "#ef4444"][i % 5]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ background: "#1e293b", border: "1px solid #334155" }} 
                  formatter={(v, n) => [v, n.replace('_', ' ').toUpperCase()]}
                />
                <Legend verticalAlign="bottom" height={36}/>
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p style={styles.noData}>No service category data.</p>
          )}
        </div>

        {/* Bar — Server Software */}
        <div style={styles.chartCard}>
          <h3 style={styles.cardTitle}>Server Software</h3>
          {stats.server_distribution?.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={stats.server_distribution} layout="vertical" margin={{ top: 5, right: 30, left: 40, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis type="number" hide />
                <YAxis dataKey="server" type="category" tick={{ fill: "#94a3b8", fontSize: 11 }} width={80} />
                <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155", fontSize: 12 }} />
                <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]}>
                  {stats.server_distribution.map((entry, i) => (
                    <Cell key={i} fill={["#3b82f6", "#60a5fa", "#93c5fd"][i % 3]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p style={styles.noData}>No server software data.</p>
          )}
        </div>
      </div>

      <div style={styles.chartsRow}>
        {/* Pie — CDN / Load Balancer */}
        <div style={styles.chartCard}>
          <h3 style={styles.cardTitle}>CDN & Infrastructure</h3>
          {stats.cdn_distribution?.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie 
                  data={stats.cdn_distribution} 
                  dataKey="count" 
                  nameKey="provider" 
                  cx="50%" cy="50%" 
                  innerRadius={50}
                  outerRadius={80} 
                  paddingAngle={5}
                >
                  {stats.cdn_distribution.map((entry, i) => (
                    <Cell key={i} fill={["#8b5cf6", "#a78bfa", "#c4b5fd"][i % 3]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: "#1e293b", border: "1px solid #334155" }} />
                <Legend verticalAlign="bottom" height={36}/>
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p style={styles.noData}>No CDN data identified.</p>
          )}
        </div>
      </div>

      {/* Key Size Distribution row (new — surfaced from real scan data) */}
      {stats.key_size_breakdown?.length > 0 && (
        <div style={{ ...styles.chartCard, marginBottom: 24 }}>
          <h3 style={styles.cardTitle}>Key Size Distribution</h3>
          <div style={{ fontSize: 11, color: "#64748b", marginBottom: 10, display: "flex", gap: 12 }}>
            <span style={{ color: "#ef4444" }}>■ Weak (&lt;2048-bit)</span>
            <span style={{ color: "#f97316" }}>■ Medium (2048–3071)</span>
            <span style={{ color: "#10b981" }}>■ Strong (≥3072)</span>
          </div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={stats.key_size_breakdown} margin={{ top: 5, right: 10, bottom: 5, left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="key_size" tick={{ fill: "#94a3b8", fontSize: 11 }} tickFormatter={v => `${v}-bit`} />
              <YAxis tick={{ fill: "#94a3b8", fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: "#1e293b", border: "1px solid #334155", fontSize: 12 }}
                formatter={(v, n, p) => [v, `${p.payload.key_size}-bit`]}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {stats.key_size_breakdown.map((entry, i) => (
                  <Cell
                    key={i}
                    fill={
                      entry.key_size < 2048 ? "#ef4444"
                      : entry.key_size < 3072 ? "#f97316"
                      : "#10b981"
                    }
                  />
                ))}
                <LabelList dataKey="count" position="top" style={{ fill: "#94a3b8", fontSize: 10 }} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Compliance row */}
      {stats.compliance && (
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>Compliance Violations by Framework</h3>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 12 }}>
            {Object.entries(stats.compliance).map(([fw, count]) => (
              <div key={fw} style={styles.complianceBadge}>
                <div style={{ fontSize: 13, color: "#94a3b8" }}>{fw}</div>
                <div style={{ fontSize: 26, fontWeight: 700, color: "#ef4444" }}>{count}</div>
                <div style={{ fontSize: 11, color: "#64748b" }}>violations</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent scans — only for non-compliance roles */}
      {role !== ROLE_COMPLIANCE && stats.recent_scans?.length > 0 && (
        <div style={styles.card}>
          <h3 style={styles.cardTitle}>Recent Scans</h3>
          <table style={styles.table}>
            <thead>
              <tr>
                {["Domain", "Status", "Assets", "Avg HNDL", "PQC %", "Initiated"].map((h) => (
                  <th key={h} style={styles.th}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {stats.recent_scans.map((s) => (
                <tr key={s.scan_id} style={styles.tr}>
                  <td style={styles.td}>{s.target_domain}</td>
                  <td style={styles.td}>
                    <span style={{ color: s.status === "COMPLETED" ? "#10b981" : "#f59e0b" }}>
                      {s.status}
                    </span>
                  </td>
                  <td style={styles.td}>{s.total_assets ?? "—"}</td>
                  <td style={styles.td}>
                    <span style={{ color: hndlColor(s.avg_hndl || 0) }}>
                      {s.avg_hndl != null ? s.avg_hndl.toFixed(1) : "—"}
                    </span>
                  </td>
                  <td style={styles.td}>{s.pqc_ready_pct != null ? `${s.pqc_ready_pct.toFixed(0)}%` : "—"}</td>
                  <td style={styles.td}>{s.initiated_by}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── KPI Card component ───────────────────────────────────────────────────────
function KpiCard({ icon, label, value, sub, color }) {
  return (
    <div style={{ ...styles.kpiCard, borderTop: `3px solid ${color}` }}>
      <div style={{ fontSize: 28, marginBottom: 6 }}>{icon}</div>
      <div style={{ fontSize: 26, fontWeight: 700, color }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: "#64748b", marginTop: 2 }}>{sub}</div>}
      <div style={{ fontSize: 13, color: "#94a3b8", marginTop: 4 }}>{label}</div>
    </div>
  );
}

// ─── Main DashboardPage ───────────────────────────────────────────────────────
export default function DashboardPage() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const user = (() => {
    try { return JSON.parse(localStorage.getItem("user") || "null"); }
    catch { return null; }
  })();
  const role = user?.role || "";

  useEffect(() => {
    api.get("/dashboard/stats")
      .then((res) => setStats(res.data))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div style={styles.centered}>
        <div style={styles.spinner} />
        <p style={{ color: "#64748b", marginTop: 16 }}>Loading dashboard...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div style={styles.centered}>
        <p style={{ color: "#ef4444" }}>⚠️ Failed to load dashboard: {error}</p>
      </div>
    );
  }

  const safeStats = stats || {};

  // Management gets executive view
  if (role === ROLE_MANAGEMENT) {
    return <ManagementDashboard stats={safeStats} />;
  }

  // Everyone else gets technical view
  return <TechnicalDashboard stats={safeStats} role={role} />;
}

// ─── Styles ───────────────────────────────────────────────────────────────────
const styles = {
  page: {
    padding: "24px",
    maxWidth: 1400,
    margin: "0 auto",
  },
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    marginBottom: 24,
    flexWrap: "wrap",
    gap: 12,
  },
  title: {
    margin: 0,
    fontSize: 24,
    fontWeight: 700,
    color: "#e2e8f0",
  },
  subtitle: {
    margin: "4px 0 0 0",
    color: "#64748b",
    fontSize: 14,
  },
  lastScan: {
    fontSize: 13,
    color: "#64748b",
    background: "#1e293b",
    padding: "6px 12px",
    borderRadius: 6,
  },
  kpiGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))",
    gap: 16,
    marginBottom: 24,
  },
  kpiCard: {
    background: "#1e293b",
    border: "1px solid #334155",
    borderRadius: 10,
    padding: "16px",
    textAlign: "center",
  },
  chartsRow: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gap: 16,
    marginBottom: 24,
  },
  chartCard: {
    background: "#1e293b",
    border: "1px solid #334155",
    borderRadius: 10,
    padding: 20,
  },
  card: {
    background: "#1e293b",
    border: "1px solid #334155",
    borderRadius: 10,
    padding: 20,
    marginBottom: 16,
  },
  cardTitle: {
    margin: "0 0 16px 0",
    fontSize: 15,
    fontWeight: 600,
    color: "#e2e8f0",
  },
  complianceBadge: {
    background: "#0f172a",
    border: "1px solid #334155",
    borderRadius: 8,
    padding: "12px 20px",
    textAlign: "center",
    minWidth: 100,
  },
  execSummaryBox: {
    background: "#1e293b",
    border: "1px solid #334155",
    borderRadius: 10,
    padding: 20,
    marginBottom: 24,
  },
  table: {
    width: "100%",
    borderCollapse: "collapse",
    fontSize: 13,
  },
  th: {
    textAlign: "left",
    padding: "8px 12px",
    color: "#64748b",
    borderBottom: "1px solid #334155",
    fontWeight: 600,
  },
  tr: {
    borderBottom: "1px solid #1e293b",
  },
  td: {
    padding: "10px 12px",
    color: "#94a3b8",
  },
  noData: {
    color: "#64748b",
    textAlign: "center",
    padding: "40px 0",
    fontSize: 14,
  },
  centered: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    height: "60vh",
  },
  spinner: {
    width: 36,
    height: 36,
    borderRadius: "50%",
    border: "3px solid #334155",
    borderTop: "3px solid #3b82f6",
    animation: "spin 0.8s linear infinite",
  },
};