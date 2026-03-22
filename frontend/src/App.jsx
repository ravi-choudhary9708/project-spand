// App.jsx — QuantumShield Frontend
// Place at: frontend/src/App.jsx
// Role-based navigation: each role sees only relevant pages

import { useState, useEffect, createContext, useContext } from "react";
import {
  BrowserRouter,
  Routes,
  Route,
  NavLink,
  Navigate,
  useNavigate,
  useLocation,
} from "react-router-dom";

import DashboardPage    from "./pages/DashboardPage";
import ScansPage        from "./pages/ScansPage";
import AssetsPage       from "./pages/AssetsPage";
import FindingsPage     from "./pages/FindingsPage";
import CBOMPage         from "./pages/CBOMPage";
import LoginPage        from "./pages/LoginPage";

// ─── Auth Context ────────────────────────────────────────────────────────────
const AuthContext = createContext(null);

export function useAuth() {
  return useContext(AuthContext);
}

function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("user") || "null");
    } catch {
      return null;
    }
  });

  const login = (userData, token) => {
    localStorage.setItem("token", token);
    localStorage.setItem("user", JSON.stringify(userData));
    setUser(userData);
  };

  const logout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

// ─── Role-based page config ──────────────────────────────────────────────────
// Each entry: which roles can see this nav item
const NAV_ITEMS = [
  {
    to: "/",
    label: "Dashboard",
    icon: "📊",
    exact: true,
    roles: ["ADMIN", "SECURITY_ANALYST", "COMPLIANCE_OFFICER", "SOC_TEAM", "MANAGEMENT"],
  },
  {
    to: "/scans",
    label: "Scans",
    icon: "🔍",
    roles: ["ADMIN", "SECURITY_ANALYST", "SOC_TEAM"],
  },
  {
    to: "/assets",
    label: "Assets",
    icon: "🖥️",
    roles: ["ADMIN", "SECURITY_ANALYST", "SOC_TEAM"],
  },
  {
    to: "/findings",
    label: "Findings",
    icon: "⚠️",
    roles: ["ADMIN", "SECURITY_ANALYST", "COMPLIANCE_OFFICER", "SOC_TEAM"],
  },
  {
    to: "/cbom",
    label: "CBOM",
    icon: "📋",
    roles: ["ADMIN", "SECURITY_ANALYST", "COMPLIANCE_OFFICER"],
  },
];

// Role display config
const ROLE_META = {
  ADMIN:               { label: "Admin",              color: "#ef4444", badge: "🔑" },
  SECURITY_ANALYST:    { label: "Security Analyst",   color: "#3b82f6", badge: "🛡️" },
  COMPLIANCE_OFFICER:  { label: "Compliance Officer", color: "#8b5cf6", badge: "📜" },
  SOC_TEAM:            { label: "SOC Team",           color: "#f59e0b", badge: "🚨" },
  MANAGEMENT:          { label: "Management",         color: "#10b981", badge: "📈" },
};

// ─── Protected Route ──────────────────────────────────────────────────────────
function ProtectedRoute({ children, allowedRoles }) {
  const { user } = useAuth();
  const location = useLocation();

  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (allowedRoles && !allowedRoles.includes(user.role)) {
    return (
      <div style={styles.accessDenied}>
        <div style={styles.accessDeniedCard}>
          <div style={{ fontSize: 48 }}>🚫</div>
          <h2 style={{ color: "#ef4444", margin: "8px 0" }}>Access Denied</h2>
          <p style={{ color: "#94a3b8" }}>
            Your role <strong style={{ color: "#fff" }}>{user.role}</strong> does not have
            permission to view this page.
          </p>
          <NavLink to="/" style={styles.backBtn}>← Back to Dashboard</NavLink>
        </div>
      </div>
    );
  }

  return children;
}

// ─── Sidebar ─────────────────────────────────────────────────────────────────
function Sidebar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [collapsed, setCollapsed] = useState(false);

  const role = user?.role || "";
  const roleMeta = ROLE_META[role] || { label: role, color: "#64748b", badge: "👤" };

  // Filter nav items this role can see
  const visibleNav = NAV_ITEMS.filter((item) => item.roles.includes(role));

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <aside style={{ ...styles.sidebar, width: collapsed ? 64 : 220 }}>
      {/* Logo */}
      <div style={styles.sidebarLogo}>
        {!collapsed && (
          <>
            <span style={{ fontSize: 20 }}>🛡️</span>
            <span style={styles.logoText}>QuantumShield</span>
          </>
        )}
        <button
          style={styles.collapseBtn}
          onClick={() => setCollapsed(!collapsed)}
          title={collapsed ? "Expand" : "Collapse"}
        >
          {collapsed ? "→" : "←"}
        </button>
      </div>

      {/* Role badge */}
      {!collapsed && (
        <div style={{ ...styles.roleBadge, borderColor: roleMeta.color }}>
          <span>{roleMeta.badge}</span>
          <div>
            <div style={{ fontSize: 11, color: "#94a3b8" }}>Logged in as</div>
            <div style={{ fontSize: 12, fontWeight: 600, color: roleMeta.color }}>
              {roleMeta.label}
            </div>
          </div>
        </div>
      )}

      {/* Navigation */}
      <nav style={styles.nav}>
        {visibleNav.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.exact}
            style={({ isActive }) => ({
              ...styles.navLink,
              background: isActive ? "rgba(59,130,246,0.15)" : "transparent",
              color: isActive ? "#3b82f6" : "#94a3b8",
              borderLeft: isActive ? "3px solid #3b82f6" : "3px solid transparent",
            })}
          >
            <span style={{ fontSize: 18 }}>{item.icon}</span>
            {!collapsed && <span style={{ marginLeft: 10, fontSize: 14 }}>{item.label}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Bottom: user info + logout */}
      <div style={styles.sidebarBottom}>
        {!collapsed && (
          <div style={styles.userInfo}>
            <div style={styles.userAvatar}>{(user?.username || "U")[0].toUpperCase()}</div>
            <div>
              <div style={{ fontSize: 13, color: "#e2e8f0", fontWeight: 600 }}>
                {user?.username}
              </div>
              <div style={{ fontSize: 11, color: "#64748b" }}>{user?.email || ""}</div>
            </div>
          </div>
        )}
        <button
          style={{ ...styles.logoutBtn, justifyContent: collapsed ? "center" : "flex-start" }}
          onClick={handleLogout}
          title="Logout"
        >
          <span>🚪</span>
          {!collapsed && <span style={{ marginLeft: 8 }}>Logout</span>}
        </button>
      </div>
    </aside>
  );
}

// ─── App Layout ──────────────────────────────────────────────────────────────
function AppLayout() {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;

  const role = user.role;

  return (
    <div style={styles.appLayout}>
      <Sidebar />
      <main style={styles.mainContent}>
        <Routes>
          {/* Dashboard — all roles */}
          <Route
            path="/"
            element={
              <ProtectedRoute
                allowedRoles={["ADMIN","SECURITY_ANALYST","COMPLIANCE_OFFICER","SOC_TEAM","MANAGEMENT"]}
              >
                <DashboardPage />
              </ProtectedRoute>
            }
          />

          {/* Scans — ADMIN, ANALYST, SOC */}
          <Route
            path="/scans"
            element={
              <ProtectedRoute allowedRoles={["ADMIN","SECURITY_ANALYST","SOC_TEAM"]}>
                <ScansPage />
              </ProtectedRoute>
            }
          />

          {/* Assets — ADMIN, ANALYST, SOC */}
          <Route
            path="/assets"
            element={
              <ProtectedRoute allowedRoles={["ADMIN","SECURITY_ANALYST","SOC_TEAM"]}>
                <AssetsPage />
              </ProtectedRoute>
            }
          />

          {/* Findings — ADMIN, ANALYST, COMPLIANCE, SOC */}
          <Route
            path="/findings"
            element={
              <ProtectedRoute allowedRoles={["ADMIN","SECURITY_ANALYST","COMPLIANCE_OFFICER","SOC_TEAM"]}>
                <FindingsPage />
              </ProtectedRoute>
            }
          />

          {/* CBOM — ADMIN, ANALYST, COMPLIANCE only */}
          <Route
            path="/cbom"
            element={
              <ProtectedRoute allowedRoles={["ADMIN","SECURITY_ANALYST","COMPLIANCE_OFFICER"]}>
                <CBOMPage />
              </ProtectedRoute>
            }
          />

          {/* Catch-all */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}

// ─── Root App ────────────────────────────────────────────────────────────────
export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/*" element={<AppLayout />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

// ─── Inline Styles ────────────────────────────────────────────────────────────
const styles = {
  appLayout: {
    display: "flex",
    height: "100vh",
    background: "#0f172a",
    color: "#e2e8f0",
    overflow: "hidden",
  },
  sidebar: {
    background: "#1e293b",
    borderRight: "1px solid #334155",
    display: "flex",
    flexDirection: "column",
    transition: "width 0.2s ease",
    flexShrink: 0,
    overflow: "hidden",
  },
  sidebarLogo: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "16px 12px",
    borderBottom: "1px solid #334155",
    gap: 8,
  },
  logoText: {
    fontSize: 16,
    fontWeight: 700,
    color: "#3b82f6",
    flex: 1,
  },
  collapseBtn: {
    background: "transparent",
    border: "1px solid #334155",
    color: "#64748b",
    cursor: "pointer",
    borderRadius: 4,
    padding: "2px 6px",
    fontSize: 12,
  },
  roleBadge: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    margin: "12px 10px",
    padding: "8px 10px",
    background: "rgba(255,255,255,0.04)",
    borderRadius: 8,
    border: "1px solid",
    fontSize: 18,
  },
  nav: {
    display: "flex",
    flexDirection: "column",
    gap: 2,
    padding: "8px 6px",
    flex: 1,
  },
  navLink: {
    display: "flex",
    alignItems: "center",
    padding: "10px 10px",
    borderRadius: 6,
    textDecoration: "none",
    transition: "all 0.15s",
    fontWeight: 500,
  },
  sidebarBottom: {
    borderTop: "1px solid #334155",
    padding: "12px 8px",
  },
  userInfo: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    marginBottom: 8,
    padding: "4px 4px",
  },
  userAvatar: {
    width: 32,
    height: 32,
    borderRadius: "50%",
    background: "#3b82f6",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: 14,
    fontWeight: 700,
    color: "#fff",
    flexShrink: 0,
  },
  logoutBtn: {
    display: "flex",
    alignItems: "center",
    width: "100%",
    padding: "8px 10px",
    background: "transparent",
    border: "1px solid #334155",
    borderRadius: 6,
    color: "#94a3b8",
    cursor: "pointer",
    fontSize: 13,
    transition: "all 0.15s",
  },
  mainContent: {
    flex: 1,
    overflow: "auto",
    background: "#0f172a",
  },
  accessDenied: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    height: "100%",
  },
  accessDeniedCard: {
    background: "#1e293b",
    border: "1px solid #334155",
    borderRadius: 12,
    padding: 40,
    textAlign: "center",
    maxWidth: 400,
  },
  backBtn: {
    display: "inline-block",
    marginTop: 16,
    padding: "8px 20px",
    background: "#3b82f6",
    color: "#fff",
    borderRadius: 6,
    textDecoration: "none",
    fontSize: 14,
  },
};