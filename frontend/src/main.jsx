import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  AlertTriangle,
  BookOpen,
  Bot,
  Box,
  Check,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Cloud,
  Code2,
  Coins,
  Database,
  FileArchive,
  FileCode2,
  FileDown,
  FileJson,
  FileText,
  Gauge,
  GitPullRequestArrow,
  LayoutDashboard,
  LockKeyhole,
  Moon,
  Network,
  Plus,
  SearchCode,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Sun,
  User,
  UsersRound,
  X
} from 'lucide-react';
import './styles.css';
import codeSheildLogo from './assets/codesheild-ai-logo.svg';
import seedUsers from './users.json';

const navGroups = [
  {
    label: 'MAIN',
    accessKey: 'main',
    items: [
      [LayoutDashboard, 'Dashboard', 'dashboard'],
      [BookOpen, 'Repositories', 'repositories'],
      [SearchCode, 'Scans', 'scans', true]
    ]
  },
  {
    label: 'CONFIGURATION',
    accessKey: 'configuration',
    items: [
      [ShieldCheck, 'Compliance Rules', 'compliance'],
      [ShieldAlert, 'OWASP Top 10', 'owasp'],
      [Code2, 'Coding Standards', 'standards'],
      [BookOpen, 'Security Playbooks', 'playbooks'],
      [Settings, 'Configurations', 'configurations']
    ]
  },
  {
    label: 'ADMIN',
    accessKey: 'admin',
    items: [
      [UsersRound, 'Users', 'users'],
      [LockKeyhole, 'Roles & Permissions', 'roles'],
      [Database, 'Audit Logs', 'audit'],
      [Settings, 'System Settings', 'system']
    ]
  }
];

const configurationViews = new Set(['compliance', 'owasp', 'standards', 'playbooks', 'configurations']);

const severity = [
  ['Critical', 32, '18%', '#f87171'],
  ['High', 78, '43%', '#fb923c'],
  ['Medium', 45, '25%', '#facc15'],
  ['Low', 18, '10%', '#60a5fa'],
  ['Info', 7, '4%', '#a7b5c8']
];

const riskCategories = [
  ['A01: Broken\nAccess Control', 65, '#fb7185'],
  ['A02: Cryptographic\nInfo Failures', 38, '#f59e0b'],
  ['A03:\nInjection', 28, '#fde047'],
  ['A05: Security\nMisconfig.', 25, '#60a5fa'],
  ['A07: ID &\nAuth Failures', 18, '#4ade80']
];

const topFindings = [
  ['Critical', 'Hardcoded Secret Detected', 'payment-gateway / config/app.js', 23, 'Yes', 'Available', 'Open'],
  ['High', 'SQL Injection Vulnerability', 'user-service / dao/UserDao.java', 88, 'Yes', 'Available', 'Open'],
  ['High', 'Broken Authentication', 'ecommerce-service / controller/Auth.java', 132, 'Yes', 'Available', 'In Progress'],
  ['Medium', 'Security Misconfiguration', 'inventory-service / Dockerfile', 14, 'No', '--', 'Open'],
  ['Low', 'Information Disclosure', 'notification-service / api/notify.py', 67, 'No', '--', 'Closed']
];

const API_BASE = 'http://localhost:8000';
const INGEST_CODE_ENDPOINT = `${API_BASE}/ingest-code`;
const SUMMARY_ENDPOINT = `${API_BASE}/summary`;
const FINOPS_ENDPOINT = `${API_BASE}/finops`;
const AUTH_ENDPOINT = `${API_BASE}/authenticate`;
const USER_ENDPOINT = `${API_BASE}/user`;

const defaultSummary = {
  total_repo: 0,
  total_scan: 0,
  critical_findings_count: 0,
  high_findings_count: 0,
  compliance_score_count: 0,
  repo: [],
  recent_scans: [],
  compliance_trend: [0,0,0,0,0,0,0],
  risk_distribution: [],
  compliance_breakdown: []
};

const defaultFinops = {
  status: 'idle',
  message: '',
  project: '',
  window_days: 30,
  llm_calls: 0,
  prompt_tokens: 0,
  completion_tokens: 0,
  total_tokens: 0,
  prompt_cost: 0,
  completion_cost: 0,
  total_cost: 0,
  currency: 'USD',
  last_updated_at: ''
};

function getStats(summary) {
  return [
    [Box, 'Total Repositories', formatNumber(summary.total_repo), 'Tracked repositories', 'purple'],
    [SearchCode, 'Total Scans', formatNumber(summary.total_scan), 'Completed and queued scans', 'blue'],
    [ShieldAlert, 'Critical Findings', formatNumber(summary.critical_findings_count), 'Immediate blockers', 'red'],
    [Siren, 'High Findings', formatNumber(summary.high_findings_count), 'Priority remediation', 'orange'],
    [ShieldCheck, 'Compliance Score', formatPercent(summary.compliance_score_count), 'Overall score', 'green']
  ];
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

function formatPercent(value) {
  return `${Number(value || 0).toLocaleString()}%`;
}

function formatCurrency(value) {
  return Number(value || 0).toLocaleString(undefined, {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 4,
    maximumFractionDigits: 4
  });
}

function formatCompactNumber(value) {
  return Number(value || 0).toLocaleString(undefined, {
    notation: 'compact',
    maximumFractionDigits: 1
  });
}

function formatRole(role) {
  return canonicalRole(role).split('_').map((part) => part[0].toUpperCase() + part.slice(1)).join(' ');
}

function getPageTitle(scanPage, activeView) {
  if (scanPage) return 'Scan Overview';

  const titles = {
    dashboard: 'Dashboard',
    repositories: 'Repositories',
    scans: 'Scans',
    users: 'Users',
    roles: 'Roles & Permissions',
    audit: 'Audit Logs',
    system: 'System Settings',
    compliance: 'Compliance Rules',
    standards: 'Coding Standards',
    playbooks: 'Security Playbooks',
    configurations: 'Configurations'
  };

  return titles[activeView] || 'Dashboard';
}

function applyLocalScanState(repositories, localScanState) {
  return repositories.map((repo) => {
    const override = localScanState[repo.id] || localScanState[repo.source];
    return override ? { ...repo, scan_status: override } : repo;
  });
}

function triggerBuild(repo, setLocalScanState) {
  const key = repo.id || repo.source;
  setLocalScanState((current) => ({
    ...current,
    [key]: {
      state: 'active',
      message: 'Build triggered by developer. Static analysis is running.'
    }
  }));
}

function roleToAccess(role) {
  const normalizedRole = canonicalRole(role);

  if (normalizedRole === 'super_admin') {
    return {
      main: true,
      configuration: true,
      admin: true,
      canAddRepository: true,
      canTriggerBuild: true,
      canManageUsers: true
    };
  }

  if (normalizedRole === 'developer') {
    return {
      main: true,
      configuration: false,
      admin: false,
      canAddRepository: true,
      canTriggerBuild: true,
      canManageUsers: false
    };
  }

  return {
    main: true,
    configuration: false,
    admin: false,
    canAddRepository: false,
    canTriggerBuild: false,
    canManageUsers: false
  };
}

function normalizeUser(user) {
  const role = canonicalRole(user.role || 'manager');
  const id = user.user_id || user.id || user.username || user.email;

  return {
    id,
    user_id: id,
    name: user.name || user.username || user.email || id,
    username: user.username || user.name || id,
    email: user.email || `${user.username || id}@codesheild.ai`,
    role,
    access: user.access || roleToAccess(role)
  };
}

function canonicalRole(role) {
  return String(role || 'manager').trim().toLowerCase().replace(/\s+/g, '_').replace(/-/g, '_');
}

function apiRole(role) {
  return canonicalRole(role).replace(/_/g, ' ');
}

function extractUsers(result) {
  if (Array.isArray(result)) return result;
  if (Array.isArray(result.users)) return result.users;
  if (Array.isArray(result.data)) return result.data;
  if (result.user) return [result.user];
  return [];
}

function upsertUser(users, nextUser) {
  const exists = users.some((user) => user.id === nextUser.id);
  return exists
    ? users.map((user) => (user.id === nextUser.id ? nextUser : user))
    : [...users, nextUser];
}

function formatApiError(result, fallback) {
  const detail = result.detail || result.message || result.error || fallback;

  if (Array.isArray(detail)) {
    return detail.map((item) => item.msg || item.message || String(item)).join(', ');
  }

  return String(detail);
}

function App() {
  const [authMode, setAuthMode] = useState('login');
  const [authUser, setAuthUser] = useState(() => {
    const saved = localStorage.getItem('secure-guard-user');
    return saved ? JSON.parse(saved) : null;
  });
  const [authToken, setAuthToken] = useState(() => localStorage.getItem('secure-guard-token') || null);
  const [authError, setAuthError] = useState('');
  const [authLoading, setAuthLoading] = useState(false);
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [repoUrl, setRepoUrl] = useState('');
  const [scanFile, setScanFile] = useState(null);
  const [scanPage, setScanPage] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [scanError, setScanError] = useState('');
  const [summary, setSummary] = useState(defaultSummary);
  const [summaryError, setSummaryError] = useState('');
  const [finops, setFinops] = useState(defaultFinops);
  const [finopsError, setFinopsError] = useState('');
  const [finopsLoading, setFinopsLoading] = useState(true);
  const [activeView, setActiveView] = useState('dashboard');
  const [users, setUsers] = useState(seedUsers.map(normalizeUser));
  const [localScanState, setLocalScanState] = useState({});
  const [theme, setTheme] = useState(() => localStorage.getItem('codesheild-theme') || 'dark');

  useEffect(() => {
    if (authUser) {
      localStorage.setItem('secure-guard-user', JSON.stringify(authUser));
    } else {
      localStorage.removeItem('secure-guard-user');
    }
  }, [authUser]);

  useEffect(() => {
    if (authToken) {
      localStorage.setItem('secure-guard-token', authToken);
    } else {
      localStorage.removeItem('secure-guard-token');
    }
  }, [authToken]);

  const loadSummary = async () => {
    try {
      const response = await fetch(SUMMARY_ENDPOINT);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || data.message || 'Unable to load dashboard summary.');
      }

      setSummary({ ...defaultSummary, ...data });
      setSummaryError('');
    } catch (error) {
      setSummaryError(error.message);
    }
  };

  const loadFinops = async (token = authToken) => {
    if (!token) return;

    setFinopsLoading(true);
    try {
      const response = await fetch(FINOPS_ENDPOINT, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(formatApiError(data, 'Unable to load LangSmith FinOps data.'));
      }

      setFinops({ ...defaultFinops, ...data });
      setFinopsError('');
    } catch (error) {
      setFinops(defaultFinops);
      setFinopsError('');
    } finally {
      setFinopsLoading(false);
    }
  };

  useEffect(() => {
    loadSummary();
  }, []);

  useEffect(() => {
    if (authToken) {
      loadFinops(authToken);
    }
  }, [authToken]);

  useEffect(() => {
    localStorage.setItem('codesheild-theme', theme);
  }, [theme]);

  const stats = getStats(summary);
  const currentUser = authUser || users[0];
  const permissions = currentUser.access;
  const repositories = applyLocalScanState(summary.repo || [], localScanState);
  const pageTitle = getPageTitle(scanPage, activeView);
  const showScanAction = permissions.canAddRepository && !scanPage && !configurationViews.has(activeView);

  const loginUser = async ({ username, password }) => {
    setAuthLoading(true);
    setAuthError('');

    try {
      const response = await fetch(AUTH_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const result = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(formatApiError(result, 'Unable to sign in. Please check your credentials.'));
      }

      const user = normalizeUser(result.user || result);
      setAuthUser(user);
      setAuthToken(result.token || null);
      setUsers((current) => upsertUser(current, user));
      setActiveView('dashboard');
      loadSummary();
    } catch (error) {
      setAuthError(error.message);
    } finally {
      setAuthLoading(false);
    }
  };

  const registerUser = async ({ username, password }) => {
    setAuthLoading(true);
    setAuthError('');

    try {
      // Public self-registration - the backend always creates a "manager" account
      // regardless of what's requested, so no auth token is needed here.
      const response = await fetch(USER_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          password,
          role: 'manager'
        })
      });
      const result = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(formatApiError(result, 'Unable to register user.'));
      }

      const user = normalizeUser(result.user || result.created_user || result);
      setUsers((current) => upsertUser(current, user));
      setAuthMode('login');
      setAuthError('Registration complete. Sign in with the new manager account.');
    } catch (error) {
      setAuthError(error.message);
    } finally {
      setAuthLoading(false);
    }
  };

  const loadUsers = async () => {
    if (!permissions.canManageUsers) return;

    try {
      const response = await fetch(USER_ENDPOINT, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      const result = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(formatApiError(result, 'Unable to load users.'));
      }

      setUsers(extractUsers(result).map(normalizeUser));
    } catch (error) {
      setSummaryError(error.message);
    }
  };

  const updateUserRole = async (userId, role) => {
    const previousUsers = users;
    setUsers((current) => current.map((user) => (
      user.id === userId ? { ...user, role, access: roleToAccess(role) } : user
    )));

    try {
      const response = await fetch(USER_ENDPOINT, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`
        },
        body: JSON.stringify({
          user_id: userId,
          role: apiRole(role)
        })
      });
      const result = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(formatApiError(result, 'Unable to update user role.'));
      }

      await loadUsers();
    } catch (error) {
      setUsers(previousUsers);
      setSummaryError(error.message);
    }
  };

  useEffect(() => {
    if (authUser && permissions.canManageUsers && ['users', 'roles'].includes(activeView)) {
      loadUsers();
    }
  }, [activeView, authUser?.id, authToken]);

  if (!authUser) {
    return (
      <AuthScreen
        mode={authMode}
        setMode={setAuthMode}
        error={authError}
        loading={authLoading}
        onLogin={loginUser}
        onRegister={registerUser}
      />
    );
  }

  const openScanModal = () => {
    setScanFile(null);
    setScanError('');
    setIsScanModalOpen(true);
  };

  const startScan = async (event) => {
    event.preventDefault();
    if (!repoUrl.trim() && !scanFile) return;

    if (scanFile && !scanFile.name.toLowerCase().endsWith('.zip')) {
      setScanError('Only .zip files are permitted for uploads.');
      return;
    }

    setIsSubmitting(true);
    setScanError('');

    try {
      const formData = new FormData();
      if (scanFile) {
        formData.append('file', scanFile);
      } else {
        formData.append('github_url', repoUrl.trim());
      }

      const response = await fetch(INGEST_CODE_ENDPOINT, {
        method: 'POST',
        headers: { Authorization: `Bearer ${authToken}` },
        body: formData
      });

      const result = await response.json().catch(() => ({}));

      if (!response.ok) {
        const message = result.detail || result.message || 'Unable to ingest repository. Please verify the link and try again.';
        throw new Error(Array.isArray(message) ? message.map((item) => item.msg || item.message).join(', ') : message);
      }

      const displaySource = scanFile ? scanFile.name : repoUrl.trim();
      setScanPage({
        repoUrl: scanFile ? '' : repoUrl.trim(),
        repoName: scanFile
          ? scanFile.name
          : (repoUrl.trim().replace(/\/$/, '').split('/').slice(-2).join(' / ') || 'New Repository'),
        sourceType: scanFile ? 'zip' : 'github',
        startedAt: new Date().toLocaleString(),
        scanId: result.scan_id || result.id || result.job_id || 'Pending',
        ingestStatus: result.status || result.message || 'Ingestion started'
      });
      setLocalScanState((current) => ({
        ...current,
        [result.repo_id || displaySource]: {
          state: 'active',
          message: 'Repository ingested. Build has been triggered.'
        }
      }));
      setActiveView('dashboard');
      setIsScanModalOpen(false);
      setRepoUrl('');
      setScanFile(null);
      loadSummary();
    } catch (error) {
      setScanError(error.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <main className={`app-shell ${theme === 'light' ? 'light-theme' : 'dark-theme'}`}>
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-shield"><img src={codeSheildLogo} alt="" /></span>
          <div>
            <strong>CodeSheild AI</strong>
            <span>Red-Team Code Auditor</span>
          </div>
        </div>

        <nav className="nav-groups" aria-label="Primary navigation">
          {navGroups.filter((group) => permissions[group.accessKey]).map((group) => (
            <section className="nav-group" key={group.label}>
              <p>{group.label}</p>
              {group.items.map(([Icon, label, view, expandable]) => (
                <button
                  className={`nav-item ${activeView === view && !scanPage ? 'active' : ''}`}
                  key={label}
                  onClick={() => {
                    if (view) {
                      setScanPage(null);
                      setActiveView(view);
                    }
                  }}
                >
                  <Icon size={18} />
                  <span>{label}</span>
                  {expandable ? <ChevronRight size={15} className="nav-chevron" /> : null}
                </button>
              ))}
            </section>
          ))}
        </nav>

      </aside>

      <section className="workspace">
        <header className="topbar">
          <h1>{pageTitle}</h1>
          <div className="topbar-actions">
            <button
              className="icon-btn"
              aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
              title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
              onClick={() => setTheme((current) => (current === 'dark' ? 'light' : 'dark'))}
            >
              {theme === 'dark' ? <Sun size={20} /> : <Moon size={20} />}
            </button>
            <button className="icon-btn" aria-label="Help"><CircleHelp size={20} /></button>
            <div className="user-menu">
              <span><User size={21} /></span>
              <div>
                <strong>{currentUser.name}</strong>
                <small>{formatRole(currentUser.role)}</small>
              </div>
              <button
                className="logout-button"
                onClick={() => {
                  setAuthUser(null);
                  setAuthToken(null);
                  setFinops(defaultFinops);
                  setFinopsError('');
                  setActiveView('dashboard');
                  setScanPage(null);
                }}
              >
                Logout
              </button>
            </div>
          </div>
        </header>

        <section className="content">
          {showScanAction ? (
            <div className="action-row">
              <div />
                <button className="primary-action" onClick={openScanModal}><Plus size={18} /> New Scan</button>
            </div>
          ) : null}

          {scanPage ? (
            <ScanOverviewPage scanPage={scanPage} onBack={() => setScanPage(null)} authToken={authToken} />
          ) : activeView === 'repositories' ? (
            <RepositoriesPage
              repositories={repositories}
              summaryError={summaryError}
              canTriggerBuild={permissions.canTriggerBuild}
              onTriggerBuild={(repo) => triggerBuild(repo, setLocalScanState)}
            />
          ) : activeView === 'scans' ? (
            <ScansPage
              repositories={repositories}
              summaryError={summaryError}
              canTriggerBuild={permissions.canTriggerBuild}
              onTriggerBuild={(repo) => triggerBuild(repo, setLocalScanState)}
            />
          ) : activeView === 'users' && permissions.canManageUsers ? (
            <UsersPage users={users} />
          ) : activeView === 'roles' && permissions.canManageUsers ? (
            <RolesPage users={users} currentUserId={currentUser.id} onUpdateRole={updateUserRole} />
          ) : activeView === 'compliance' ? (
            <CompliancePage authToken={authToken} />
          ) : activeView === 'owasp' ? (
            <OwaspRulesPage authToken={authToken} />
          ) : activeView === 'standards' ? (
            <StandardsPage authToken={authToken} />
          ) : activeView === 'playbooks' ? (
            <PlaybooksPage authToken={authToken} />
          ) : activeView === 'configurations' ? (
            <ConfigurationsPage authToken={authToken} />
          ) : activeView === 'audit' && permissions.canManageUsers ? (
            <AuditLogPage authToken={authToken} />
          ) : activeView === 'compliance_report' ? (
            <ComplianceReportPage summary={summary} />
          ) : activeView !== 'dashboard' ? (
            <PlaceholderPage title={pageTitle} />
          ) : (
            <>
              <section className="stat-grid">
                {stats.map(([Icon, label, value, helper, tone]) => (
                  <article className="stat-card" key={label}>
                    <span className={`stat-icon ${tone}`}><Icon size={24} /></span>
                    <div>
                      <span>{label}</span>
                      <strong>{value}</strong>
                      <small>{helper}</small>
                    </div>
                  </article>
                ))}
              </section>
              {summaryError ? <div className="summary-error"><AlertTriangle size={16} /> {summaryError}</div> : null}

              <section className="dashboard-grid">
            <article className="panel recent-panel">
              <PanelTitle title="Recent Scans" action="View All" onAction={() => setActiveView('scans')} />
              <div className="recent-list">
                {(summary.recent_scans || []).map(([repo, branch, date, status, badge, tone]) => (
                  <div className="recent-item" key={`${repo}-${branch}-${date}`}>
                    <GitPullRequestArrow size={22} />
                    <div>
                      <strong>{repo} <span>({branch})</span></strong>
                      <small className={status === 'Completed' ? 'complete-text' : 'warn-text'}>{status}</small>
                    </div>
                    <time>{date}</time>
                    <mark className={tone}>{badge}</mark>
                  </div>
                ))}
              </div>
            </article>

            <article className="panel severity-panel">
              <PanelTitle title="Findings by Severity" />
              <div className="severity-layout">
                <div className="donut">
                  <div>
                    <strong>180</strong>
                    <span>Total Findings</span>
                  </div>
                </div>
                <div className="legend">
                  {severity.map(([label, count, percent, color]) => (
                    <div key={label}>
                      <i style={{ background: color }} />
                      <span>{label}</span>
                      <b>{count} ({percent})</b>
                    </div>
                  ))}
                </div>
              </div>
            </article>

            <article className="panel category-panel">
              <PanelTitle title="Top Risk Categories" />
              <div className="bar-chart">
                {riskCategories.map(([label, value, color]) => (
                  <div className="bar-col" key={label}>
                    <span>{value}</span>
                    <i style={{ height: `${value * 1.45}px`, background: color }} />
                    <small>{label}</small>
                  </div>
                ))}
              </div>
            </article>

            <ComplianceScoreCard summary={summary} />

            <article className="panel trend-panel">
              <PanelTitle title="Compliance Score Trend" action="View Report" onAction={() => setActiveView('compliance_report')} />
              <div className="trend-summary">
                <strong>{formatPercent(summary.compliance_score_count)}</strong>
                <span>Overall Score</span>
                <small>Current repository coverage</small>
              </div>
              <div className="line-chart">
                <svg viewBox="0 0 480 190" role="img" aria-label="Compliance score trend from historical scans">
                  <path className="grid-line" d="M50 22H460M50 62H460M50 102H460M50 142H460" />
                  {(() => {
                    const trend = summary.compliance_trend || [0,0,0,0,0,0,0];
                    const xCoords = [50, 105, 170, 235, 300, 365, 445];
                    const trendPoints = trend.map((score, index) => {
                      const y = 166 - (score / 100) * (166 - 22);
                      return `${xCoords[index]},${y}`;
                    });
                    const pointsStr = trendPoints.join(' ');
                    const areaPath = `M${trendPoints[0].replace(',', ' ')} ` + trendPoints.slice(1).map(p => `L${p.replace(',', ' ')}`).join(' ') + ` L445 166 L50 166 Z`;
                    return (
                      <>
                        <path className="trend-area" d={areaPath} />
                        <polyline className="trend-line" points={pointsStr} />
                        {trendPoints.map((p, i) => {
                          const [cx, cy] = p.split(',');
                          return <circle key={i} cx={cx} cy={cy} r="4" />;
                        })}
                      </>
                    );
                  })()}
                </svg>
                <div className="axis-labels">
                  <span>May 14</span><span>May 15</span><span>May 16</span><span>May 17</span><span>May 18</span><span>May 19</span><span>May 20</span>
                </div>
              </div>
            </article>

            <FinopsPanel finops={finops} error={finopsError} loading={finopsLoading} />

            <article className="panel findings-table-panel">
              <PanelTitle title="Top Findings" action="View All Findings" />
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>Repository / File</th>
                    <th>Line</th>
                    <th>AI Analysis</th>
                    <th>Patch</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {topFindings.map((row) => (
                    <tr key={`${row[1]}-${row[3]}`}>
                      <td><span className={`severity-pill ${row[0].toLowerCase()}`}>{row[0]}</span></td>
                      <td>{row[1]}</td>
                      <td>{row[2]}</td>
                      <td>{row[3]}</td>
                      <td><span className={row[4] === 'Yes' ? 'yes-pill' : ''}>{row[4]}</span></td>
                      <td><span className={row[5] === 'Available' ? 'patch-pill' : ''}>{row[5]}</span></td>
                      <td>{row[6]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </article>

            <article className="panel report-panel">
              <div className="report-copy">
                <h2>Generate Report</h2>
                <p>Download comprehensive security audit reports with red-team exploit paths, compliance evidence, and remediation patches.</p>
                <div className="report-buttons">
                  <button><FileDown size={17} /> PDF Report</button>
                  <button><FileJson size={17} /> JSON Report</button>
                  <button><FileArchive size={17} /> CSV Report</button>
                  <button><FileCode2 size={17} /> SARIF Report</button>
                </div>
              </div>
              <div className="report-art">
                <div className="document">
                  <span />
                  <span />
                  <span />
                </div>
                <div className="shield-check"><ShieldCheck size={54} /></div>
                <Cloud className="cloud-a" size={22} />
                <Cloud className="cloud-b" size={20} />
              </div>
            </article>
              </section>
            </>
          )}
        </section>
      </section>

      {isScanModalOpen ? (
        <div className="modal-backdrop" role="presentation">
          <section className="scan-modal" role="dialog" aria-modal="true" aria-labelledby="new-scan-title">
            <div className="modal-heading">
              <div>
                <h2 id="new-scan-title">New Repository Scan</h2>
                <p>Enter a GitHub repository URL or upload source code to start a secure red-team code audit.</p>
              </div>
              <button className="modal-close" aria-label="Close modal" onClick={() => setIsScanModalOpen(false)}>
                <X size={20} />
              </button>
            </div>

            <form onSubmit={startScan}>
              <label htmlFor="repo-url">GitHub repository link</label>
              <div className="repo-input-wrap">
                <GithubIcon />
                <input
                  id="repo-url"
                  type="url"
                  value={repoUrl}
                  onChange={(event) => setRepoUrl(event.target.value)}
                  placeholder="https://github.com/org/repository"
                  disabled={Boolean(scanFile)}
                />
              </div>
              <label htmlFor="repo-file">Or upload a .zip file</label>
              <input
                id="repo-file"
                type="file"
                accept=".zip,application/zip,application/x-zip-compressed"
                onChange={(event) => {
                  const selectedFile = event.target.files?.[0] || null;
                  if (selectedFile && !selectedFile.name.toLowerCase().endsWith('.zip')) {
                    setScanFile(null);
                    setScanError('Only .zip files are permitted for uploads.');
                    event.target.value = '';
                    return;
                  }
                  setScanFile(selectedFile);
                  setScanError('');
                }}
              />
              <div className="modal-note">
                <ShieldCheck size={16} />
                Repository contents will be sent to the ingestion API through the enterprise analysis gateway.
              </div>
              {scanError ? <div className="modal-error"><AlertTriangle size={16} /> {scanError}</div> : null}
              <div className="modal-actions">
                <button type="button" className="cancel-action" onClick={() => setIsScanModalOpen(false)}>Cancel</button>
                <button type="submit" className="submit-action" disabled={isSubmitting || (!repoUrl.trim() && !scanFile)}>
                  {isSubmitting ? 'Submitting...' : 'Start Scan'}
                </button>
              </div>
            </form>
          </section>
        </div>
      ) : null}
    </main>
  );
}

const scanStepIcons = {
  'Repository Intake': Code2,
  'Configuration Analysis': Settings,
  'Static Analysis': SearchCode,
  'Compliance Check': FileText,
  'Dependency Analysis': Database,
  'Risk Correlation': Network,
  'AI Reasoning': Bot,
  'Merging Results': GitPullRequestArrow,
  'Compliance Scoring': ShieldCheck,
  'Report Generation': FileDown
};
const TOTAL_SCAN_STEPS = Object.keys(scanStepIcons).length;

function FinopsPanel({ finops, error, loading }) {
  const promptTokens = Number(finops.prompt_tokens || 0);
  const completionTokens = Number(finops.completion_tokens || 0);
  const totalTokens = Number(finops.total_tokens || promptTokens + completionTokens);
  const promptWidth = totalTokens ? Math.max(4, Math.round((promptTokens / totalTokens) * 100)) : 0;
  const completionWidth = totalTokens ? Math.max(4, Math.round((completionTokens / totalTokens) * 100)) : 0;
  
  let status = finops.status === 'ok' ? 'Live' : finops.status === 'unconfigured' ? 'Setup' : 'Check';
  if (loading) status = 'Loading...';

  return (
    <article className="panel finops-panel">
      <PanelTitle title="FinOps" action={status} />
      <div className="finops-summary">
        <span className="finops-icon"><Coins size={25} /></span>
        <div>
          <span>Total Spend</span>
          <strong className={loading ? 'skeleton-text' : ''}>
            {loading ? '$0.00' : formatCurrency(finops.total_cost)}
          </strong>
          <small>{formatCompactNumber(totalTokens)} tokens in {Number(finops.window_days || 30)} days</small>
        </div>
      </div>
      <div className="finops-meter" aria-label="Token split">
        <span className="prompt" style={{ width: `${promptWidth}%` }} />
        <span className="completion" style={{ width: `${completionWidth}%` }} />
      </div>
      <div className="finops-grid">
        <div>
          <span>Prompt</span>
          <strong className={loading ? 'skeleton-text' : ''}>
            {loading ? '0' : formatCompactNumber(promptTokens)}
          </strong>
        </div>
        <div>
          <span>Completion</span>
          <strong className={loading ? 'skeleton-text' : ''}>
            {loading ? '0' : formatCompactNumber(completionTokens)}
          </strong>
        </div>
        <div>
          <span>LLM Calls</span>
          <strong className={loading ? 'skeleton-text' : ''}>
            {loading ? '0' : formatNumber(finops.llm_calls)}
          </strong>
        </div>
        <div>
          <span>Latency (P50)</span>
          <strong className={loading ? 'skeleton-text' : ''}>
            {loading ? '0.00s' : (finops.latency_p50 ? `${finops.latency_p50.toFixed(2)}s` : 'N/A')}
          </strong>
        </div>
      </div>
      <div className="finops-foot">
        <small>{error || finops.message || 'Cost reflects LangSmith usage metadata and pricing map.'}</small>
      </div>
    </article>
  );
}

function ScanProgressCard({ steps, status }) {
  const progressPercent = status === 'completed'
    ? 100
    : Math.min(96, Math.round((steps.length / TOTAL_SCAN_STEPS) * 100));

  return (
    <article className="panel scan-overview">
      <PanelTitle title="Scan Overview" />
      <div className="scan-timeline">
        {steps.length ? steps.map((step, index) => {
          const Icon = scanStepIcons[step.agent] || Gauge;
          const isLast = index === steps.length - 1;
          return (
            <div className="scan-step" key={`${step.agent}-${index}`}>
              <div className={`scan-node ${isLast && status === 'active' ? 'active' : ''}`}>
                <Icon size={27} />
              </div>
              <strong>{step.agent}</strong>
              <span className="completed"><Check size={13} /> {step.status}</span>
            </div>
          );
        }) : (
          <div className="scan-step">
            <div className="scan-node active"><Gauge size={27} /></div>
            <strong>Starting...</strong>
            <span className="running"><Gauge size={13} /> queued</span>
          </div>
        )}
      </div>
      <div className="progress-row">
        <div>
          <strong>Overall Progress</strong>
          <span>
            {status === 'completed' ? 'Scan complete.' : status === 'failed' ? 'Scan failed - check backend logs.' : 'Scan in progress...'}
          </span>
        </div>
        <div className="progress-track"><span style={{ width: `${progressPercent}%` }} /></div>
        <b>{progressPercent}%</b>
      </div>
    </article>
  );
}

function FindingDetail({ finding, applying, error, onAccept }) {
  return (
    <div className="finding-detail">
      <div className="finding-detail-section">
        <h4>Why this is an issue</h4>
        <p>{finding.description}</p>
        {finding.exploit_explanation ? (
          <>
            <h4>How it could be exploited</h4>
            <p>{finding.exploit_explanation}</p>
          </>
        ) : null}
      </div>

      {finding.code_snippet ? (
        <div className="finding-detail-section">
          <h4>Code area ({finding.file}{finding.line ? `:${finding.line}` : ''})</h4>
          <pre className="code-block">{finding.code_snippet}</pre>
        </div>
      ) : null}

      <div className="finding-detail-section">
        <h4>How to fix</h4>
        <p>{finding.remediation_patch || 'No specific remediation guidance available for this finding.'}</p>
      </div>

      {finding.suggested_fix ? (
        <div className="finding-detail-section">
          <h4>AI-suggested code fix</h4>
          <div className="diff-block">
            <div className="diff-removed">
              <span>- original</span>
              <pre>{finding.suggested_fix.original_snippet}</pre>
            </div>
            <div className="diff-added">
              <span>+ replacement</span>
              <pre>{finding.suggested_fix.replacement_snippet}</pre>
            </div>
          </div>
          {error ? <div className="modal-error"><AlertTriangle size={16} /> {error}</div> : null}
          {finding.fix_status === 'applied' ? (
            <div className="auth-success"><Check size={16} /> Fix applied to the codebase.</div>
          ) : (
            <button className="submit-action" onClick={onAccept} disabled={applying}>
              {applying ? 'Applying...' : 'Accept & Apply Fix'}
            </button>
          )}
        </div>
      ) : null}
    </div>
  );
}

function ScanFindingsTable({ scanId, findings, authToken, onFixApplied }) {
  const [expandedId, setExpandedId] = useState(null);
  const [applyingId, setApplyingId] = useState(null);
  const [applyError, setApplyError] = useState('');

  const toggleExpand = (id) => {
    setExpandedId((current) => (current === id ? null : id));
    setApplyError('');
  };

  const acceptFix = async (finding) => {
    setApplyingId(finding.id);
    setApplyError('');

    try {
      const response = await fetch(`${API_BASE}/scans/${scanId}/findings/${finding.id}/apply-fix`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${authToken}` }
      });
      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(formatApiError(data, 'Unable to apply this fix.'));
      }

      onFixApplied(data);
    } catch (error) {
      setApplyError(error.message);
    } finally {
      setApplyingId(null);
    }
  };

  return (
    <article className="panel findings-table-panel">
      <PanelTitle title="Findings" action={`${findings.length} total`} />
      {findings.length ? (
        <table className="scan-findings-table">
          <thead>
            <tr>
              <th />
              <th>Severity</th>
              <th>Title</th>
              <th>File</th>
              <th>Line</th>
              <th>Category</th>
              <th>AI Analysis</th>
              <th>Fix</th>
            </tr>
          </thead>
          <tbody>
            {findings.slice(0, 50).map((finding) => {
              const isExpanded = expandedId === finding.id;
              return (
                <React.Fragment key={finding.id}>
                  <tr className="finding-row" onClick={() => toggleExpand(finding.id)}>
                    <td>{isExpanded ? <ChevronDown size={15} /> : <ChevronRight size={15} />}</td>
                    <td><span className={`severity-pill ${finding.severity}`}>{finding.severity}</span></td>
                    <td>{finding.title}</td>
                    <td>{finding.file}</td>
                    <td>{finding.line ?? '--'}</td>
                    <td>{finding.category}</td>
                    <td><span className={finding.needs_llm ? 'yes-pill' : ''}>{finding.needs_llm ? 'Yes' : 'No'}</span></td>
                    <td>
                      {finding.fix_status === 'applied' ? (
                        <span className="patch-pill">Applied</span>
                      ) : finding.suggested_fix ? (
                        <span className="patch-pill">Available</span>
                      ) : '--'}
                    </td>
                  </tr>
                  {isExpanded ? (
                    <tr className="finding-detail-row">
                      <td colSpan={8}>
                        <FindingDetail
                          finding={finding}
                          applying={applyingId === finding.id}
                          error={applyingId === finding.id ? applyError : ''}
                          onAccept={() => acceptFix(finding)}
                        />
                      </td>
                    </tr>
                  ) : null}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      ) : (
        <div className="empty-repo-state">
          <ShieldCheck size={34} />
          <strong>No findings</strong>
          <span>This scan did not identify any issues.</span>
        </div>
      )}
    </article>
  );
}

function ScanOverviewPage({ scanPage, onBack, authToken }) {
  const [scanDetail, setScanDetail] = useState(null);
  const [pollError, setPollError] = useState('');
  const [downloadError, setDownloadError] = useState('');
  const [downloading, setDownloading] = useState(false);
  const [reportError, setReportError] = useState('');
  const [downloadingReport, setDownloadingReport] = useState(false);

  useEffect(() => {
    let isMounted = true;
    let timer;

    async function poll() {
      try {
        const response = await fetch(`${API_BASE}/scans/${scanPage.scanId}`, {
          headers: { Authorization: `Bearer ${authToken}` }
        });
        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
          throw new Error(formatApiError(data, 'Unable to load scan status.'));
        }

        if (!isMounted) return;
        setScanDetail(data);
        setPollError('');

        if (data.status === 'pending' || data.status === 'active') {
          timer = setTimeout(poll, 2500);
        }
      } catch (error) {
        if (isMounted) setPollError(error.message);
      }
    }

    poll();

    return () => {
      isMounted = false;
      clearTimeout(timer);
    };
  }, [scanPage.scanId, authToken]);

  const steps = scanDetail?.progress || [];
  const report = scanDetail?.report;
  const status = scanDetail?.status || 'pending';

  const handleFixApplied = ({ finding: updatedFinding, fix_branch: fixBranch, pr_url: prUrl, pr_error: prError }) => {
    setScanDetail((current) => {
      if (!current?.report) return current;
      return {
        ...current,
        ...(fixBranch ? { fix_branch: fixBranch } : {}),
        ...(prUrl ? { pr_url: prUrl } : {}),
        pr_error: prError || null,
        report: {
          ...current.report,
          findings: current.report.findings.map((f) => (f.id === updatedFinding.id ? updatedFinding : f))
        }
      };
    });
  };

  const downloadCode = async () => {
    setDownloadError('');
    setDownloading(true);

    try {
      const response = await fetch(`${API_BASE}/scans/${scanPage.scanId}/download`, {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(formatApiError(data, 'Unable to download the code.'));
      }

      const blob = await response.blob();
      const disposition = response.headers.get('Content-Disposition') || '';
      const match = disposition.match(/filename="?([^"]+)"?/);
      const filename = match ? match[1] : 'codebase.zip';

      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      setDownloadError(error.message);
    } finally {
      setDownloading(false);
    }
  };

  const downloadReport = async () => {
    setReportError('');
    setDownloadingReport(true);

    try {
      const response = await fetch(`${API_BASE}/scans/${scanPage.scanId}/report.pdf`, {
        headers: { Authorization: `Bearer ${authToken}` }
      });

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(formatApiError(data, 'Unable to download the report.'));
      }

      const blob = await response.blob();
      const disposition = response.headers.get('Content-Disposition') || '';
      const match = disposition.match(/filename="?([^"]+)"?/);
      const filename = match ? match[1] : 'scan-report.pdf';

      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      setReportError(error.message);
    } finally {
      setDownloadingReport(false);
    }
  };

  return (
    <section className="scan-page-grid">
      <article className="panel scan-detail-hero">
        <div>
          <p>Active scan</p>
          <h2>{scanPage.repoName}</h2>
          <span>{scanPage.repoUrl || scanPage.scanId}</span>
        </div>
        <div className="scan-hero-actions">
          {status === 'completed' ? (
            <button className="secondary-action" onClick={downloadReport} disabled={downloadingReport}>
              <FileText size={17} /> {downloadingReport ? 'Preparing...' : 'Download Report'}
            </button>
          ) : null}
          {status === 'completed' ? (
            <button className="secondary-action" onClick={downloadCode} disabled={downloading}>
              <FileDown size={17} /> {downloading ? 'Preparing...' : 'Download Code'}
            </button>
          ) : null}
          <button className="secondary-action" onClick={onBack}>Back to Dashboard</button>
        </div>
      </article>
      {downloadError ? <div className="summary-error"><AlertTriangle size={16} /> {downloadError}</div> : null}
      {reportError ? <div className="summary-error"><AlertTriangle size={16} /> {reportError}</div> : null}
      {scanDetail?.pr_url ? (
        <div className="auth-success">
          <GitPullRequestArrow size={16} /> Fixes pushed to branch <code>{scanDetail.fix_branch}</code> —{' '}
          <a href={scanDetail.pr_url} target="_blank" rel="noreferrer">View Pull Request</a>
        </div>
      ) : scanDetail?.pr_error ? (
        <div className="summary-error"><AlertTriangle size={16} /> Fix applied locally, but pushing to GitHub failed: {scanDetail.pr_error}</div>
      ) : null}

      <ScanProgressCard steps={steps} status={status} />

      <article className="panel scan-context-panel">
        <PanelTitle title="Repository Intake" />
        <div className="context-list">
          <div><span>Source</span><strong className="capitalize">{scanPage.sourceType || 'repository'}</strong></div>
          <div><span>Scan ID</span><strong>{scanPage.scanId}</strong></div>
          <div><span>Status</span><strong className="capitalize">{status}</strong></div>
          <div><span>Started</span><strong>{scanPage.startedAt}</strong></div>
        </div>
      </article>

      <article className="panel scan-context-panel">
        <PanelTitle title="Results" />
        {pollError ? <div className="summary-error"><AlertTriangle size={16} /> {pollError}</div> : null}
        <div className="context-list">
          <div><span>Findings</span><strong>{report ? report.findings.length : 'Pending'}</strong></div>
          <div>
            <span>Critical</span>
            <strong>{report ? report.findings.filter((f) => f.severity === 'critical').length : '--'}</strong>
          </div>
          <div><span>AI Reasoning</span><strong>{report ? (report.used_llm ? 'Ran' : 'Not needed') : 'Pending'}</strong></div>
        </div>
      </article>

      {report ? (
        <ScanFindingsTable
          scanId={scanPage.scanId}
          findings={report.findings}
          authToken={authToken}
          onFixApplied={handleFixApplied}
        />
      ) : null}
    </section>
  );
}

function RepositoriesPage({ repositories, summaryError, canTriggerBuild, onTriggerBuild }) {
  return (
    <section className="repositories-view">
      {summaryError ? <div className="summary-error"><AlertTriangle size={16} /> {summaryError}</div> : null}

      <article className="panel repositories-panel">
        <PanelTitle title="Tracked Repositories" action={`${repositories.length} total`} />
        {repositories.length ? (
          <div className="repo-list">
            {repositories.map((repo) => {
              const repoName = getRepoName(repo.source, repo.repo_path);
              const repoId = repo.id || repo.repo_id || repo.scan_id || 'Not assigned';
              const githubUrl = repo.source || repo.github_url || repo.repo_url || 'Not available';
              const status = repo.scan_status || {};
              const normalizedState = normalizeScanState(status.state);

              return (
                <article className={`repo-row ${canTriggerBuild ? 'with-action' : ''}`} key={repo.id || repo.source}>
                  <div className="repo-source-icon">
                    <GitPullRequestArrow size={22} />
                  </div>
                  <div className="repo-main">
                    <span>Name</span>
                    <strong>{repoName}</strong>
                  </div>
                  <div className="repo-meta">
                    <span>GitHub URL</span>
                    <strong className="repo-url">{githubUrl}</strong>
                  </div>
                  <div className="repo-meta">
                    <span>ID</span>
                    <strong>{repoId}</strong>
                  </div>
                  <div className="repo-meta repo-ingested">
                    <span>Ingested</span>
                    <strong>{formatDate(repo.created_at)}</strong>
                  </div>
                  <div className="repo-status">
                    <mark className={normalizedState}>{normalizedState}</mark>
                    <span>{status.message || 'Waiting for scan status.'}</span>
                  </div>
                  {canTriggerBuild ? (
                    <button className="row-action" onClick={() => onTriggerBuild(repo)}>Trigger Build</button>
                  ) : null}
                </article>
              );
            })}
          </div>
        ) : (
          <div className="empty-repo-state">
            <BookOpen size={34} />
            <strong>No repositories ingested yet</strong>
            <span>Use New Scan to add a GitHub repository or upload source code.</span>
          </div>
        )}
      </article>
    </section>
  );
}

function ScansPage({ repositories, summaryError, canTriggerBuild, onTriggerBuild }) {
  const buckets = ['pending', 'active', 'completed', 'failed'];

  return (
    <section className="scans-view">
      {summaryError ? <div className="summary-error"><AlertTriangle size={16} /> {summaryError}</div> : null}
      <div className="scan-status-grid">
        {buckets.map((bucket) => (
          <article className="panel scan-status-card" key={bucket}>
            <span>{bucket}</span>
            <strong>{repositories.filter((repo) => normalizeScanState(repo.scan_status?.state) === bucket).length}</strong>
          </article>
        ))}
      </div>

      <article className="panel scans-panel">
        <PanelTitle title="Repository Scan Overview" action={`${repositories.length} repositories`} />
        {repositories.length ? (
          <div className="scan-card-list">
            {repositories.map((repo) => {
              const status = repo.scan_status || {};
              const normalizedState = normalizeScanState(status.state);
              const progress = getScanProgress(normalizedState);

              return (
                <article className="scan-repo-card" key={repo.id || repo.source}>
                  <div className="scan-repo-heading">
                    <div>
                      <strong>{getRepoName(repo.source, repo.repo_path)}</strong>
                      <span>{repo.source}</span>
                    </div>
                    <mark className={normalizedState}>{normalizedState}</mark>
                  </div>

                  <div className="mini-progress">
                    <span style={{ width: `${progress}%` }} />
                  </div>

                  <div className="scan-mini-steps">
                    {['Intake', 'Static Analysis', 'Compliance', 'AI Review'].map((step, index) => (
                      <div className={index < Math.ceil(progress / 25) ? 'done' : ''} key={step}>
                        <Check size={13} />
                        <span>{step}</span>
                      </div>
                    ))}
                  </div>

                  <p>{status.message || 'Scan has not started for this repository.'}</p>
                  <div className="scan-card-footer">
                    <span>Created {formatDate(repo.created_at)}</span>
                    {canTriggerBuild && normalizedState !== 'active' ? (
                      <button className="row-action" onClick={() => onTriggerBuild(repo)}>Trigger Build</button>
                    ) : null}
                  </div>
                </article>
              );
            })}
          </div>
        ) : (
          <div className="empty-repo-state">
            <SearchCode size={34} />
            <strong>No scans available</strong>
            <span>Ingest a repository to see scan status here.</span>
          </div>
        )}
      </article>
    </section>
  );
}

function UsersPage({ users }) {
  return (
    <section className="users-view">
      <article className="panel users-panel">
        <PanelTitle title="All Users" action={`${users.length} users`} />
        <div className="users-table">
          <div className="users-head users-head-readonly">
            <span>User</span>
            <span>Role</span>
            <span>Main</span>
            <span>Config</span>
            <span>Admin</span>
            <span>Add Repo</span>
            <span>Trigger Build</span>
            <span>Manage Users</span>
          </div>
          {users.map((user) => (
            <div className="user-access-row users-row-readonly" key={user.id}>
              <div className="access-user">
                <strong>{user.name}</strong>
                <span>{user.email}</span>
              </div>
              <span className="role-pill">{formatRole(user.role)}</span>
              {['main', 'configuration', 'admin', 'canAddRepository', 'canTriggerBuild', 'canManageUsers'].map((field) => (
                <span className={`access-indicator ${user.access[field] ? 'allowed' : ''}`} key={field}>
                  {user.access[field] ? 'Yes' : 'No'}
                </span>
              ))}
            </div>
          ))}
        </div>
      </article>
    </section>
  );
}

function RolesPage({ users, currentUserId, onUpdateRole }) {
  return (
    <section className="users-view">
      <article className="panel users-panel">
        <PanelTitle title="Roles & Permissions" action="API backed" />
        <div className="role-editor-list">
          {users.map((user) => (
            <article className="role-editor-row" key={user.id}>
              <div className="access-user">
                <strong>{user.name}</strong>
                <span>{user.username || user.email}</span>
              </div>
              <select
                value={user.role}
                disabled={user.id === currentUserId}
                onChange={(event) => onUpdateRole(user.id, event.target.value)}
              >
                <option value="super_admin">Super Admin</option>
                <option value="developer">Developer</option>
                <option value="manager">Manager</option>
              </select>
              <div className="role-permission-summary">
                <span>{user.access.configuration ? 'Configuration access' : 'Main access only'}</span>
                <span>{user.access.canAddRepository ? 'Can add repositories' : 'View-only repositories'}</span>
                <span>{user.access.canTriggerBuild ? 'Can trigger builds' : 'Cannot trigger builds'}</span>
              </div>
            </article>
          ))}
        </div>
      </article>
    </section>
  );
}

function AdminResourcePage({ title, authToken, endpoint, idField, emptyMessage, fields, renderRow, buildPayload }) {
  const emptyForm = () => Object.fromEntries(fields.map((field) => [field.name, field.default ?? '']));

  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [formValues, setFormValues] = useState(emptyForm);
  const [submitting, setSubmitting] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}${endpoint}`, {
        headers: { Authorization: `Bearer ${authToken}` }
      });
      const data = await response.json().catch(() => []);

      if (!response.ok) {
        throw new Error(formatApiError(data, `Unable to load ${title.toLowerCase()}s.`));
      }

      setItems(Array.isArray(data) ? data : []);
      setError('');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [endpoint, authToken]);

  const submit = async (event) => {
    event.preventDefault();
    setSubmitting(true);

    try {
      const response = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
        body: JSON.stringify(buildPayload(formValues))
      });
      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(formatApiError(data, `Unable to save this ${title.toLowerCase()}.`));
      }

      setFormValues(emptyForm());
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const remove = async (id) => {
    try {
      const response = await fetch(`${API_BASE}${endpoint}/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${authToken}` }
      });

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(formatApiError(data, 'Unable to delete.'));
      }

      await load();
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <section className="admin-view">
      {error ? <div className="summary-error"><AlertTriangle size={16} /> {error}</div> : null}

      <article className="panel admin-form-panel">
        <PanelTitle title={`New ${title}`} />
        <form className="admin-form" onSubmit={submit}>
          {fields.map((field) => (
            <div className="admin-field" key={field.name}>
              <label htmlFor={`af-${endpoint}-${field.name}`}>{field.label}</label>
              {field.type === 'textarea' ? (
                <textarea
                  id={`af-${endpoint}-${field.name}`}
                  value={formValues[field.name]}
                  onChange={(event) => setFormValues((v) => ({ ...v, [field.name]: event.target.value }))}
                  placeholder={field.placeholder}
                />
              ) : field.type === 'select' ? (
                <select
                  id={`af-${endpoint}-${field.name}`}
                  value={formValues[field.name]}
                  onChange={(event) => setFormValues((v) => ({ ...v, [field.name]: event.target.value }))}
                >
                  {field.options.map((option) => <option value={option} key={option}>{option}</option>)}
                </select>
              ) : (
                <input
                  id={`af-${endpoint}-${field.name}`}
                  value={formValues[field.name]}
                  onChange={(event) => setFormValues((v) => ({ ...v, [field.name]: event.target.value }))}
                  placeholder={field.placeholder}
                  required={field.required}
                />
              )}
            </div>
          ))}
          <button type="submit" className="submit-action" disabled={submitting}>
            {submitting ? 'Saving...' : `Add ${title}`}
          </button>
        </form>
      </article>

      <article className="panel admin-list-panel">
        <PanelTitle title={`${title}s`} action={`${items.length} total`} />
        {loading ? (
          <p className="admin-loading">Loading...</p>
        ) : items.length ? (
          <div className="admin-rule-list">
            {items.map((item) => (
              <article className="admin-rule-row" key={item[idField]}>
                {renderRow(item)}
                <button className="row-action" onClick={() => remove(item[idField])}>Delete</button>
              </article>
            ))}
          </div>
        ) : (
          <div className="empty-repo-state">
            <ShieldCheck size={34} />
            <strong>No {title.toLowerCase()}s yet</strong>
            <span>{emptyMessage}</span>
          </div>
        )}
      </article>
    </section>
  );
}

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'info'];

function CompliancePage({ authToken }) {
  return (
    <AdminResourcePage
      title="Compliance Rule"
      authToken={authToken}
      endpoint="/admin/compliance-rules"
      idField="rule_id"
      emptyMessage="Add organizational compliance rules to evaluate ingested code against."
      fields={[
        { name: 'title', label: 'Title', required: true, placeholder: 'e.g. Use structured logging' },
        { name: 'category', label: 'Category', required: true, placeholder: 'e.g. Logging Standard' },
        { name: 'severity', label: 'Severity', type: 'select', options: SEVERITY_OPTIONS, default: 'medium' },
        { name: 'pattern', label: 'Detection pattern (regex)', required: true, placeholder: 'e.g. \\bprint\\(' },
        { name: 'description', label: 'Description', type: 'textarea', placeholder: 'What this rule detects and why it matters.' },
        { name: 'remediation', label: 'Remediation guidance', type: 'textarea' }
      ]}
      buildPayload={(values) => ({
        rule_id: '',
        title: values.title,
        category: values.category,
        severity: values.severity || 'medium',
        languages: [],
        description: values.description,
        detection: { type: 'regex', pattern: values.pattern },
        remediation: values.remediation,
        tags: []
      })}
      renderRow={(rule) => (
        <div className="admin-rule-body">
          <strong>{rule.title}</strong>
          <span className="role-pill">{rule.severity}</span>
          <p>{rule.description}</p>
          <code>{rule.detection?.pattern}</code>
        </div>
      )}
    />
  );
}

function StandardsPage({ authToken }) {
  return (
    <AdminResourcePage
      title="Coding Standard"
      authToken={authToken}
      endpoint="/admin/coding-standards"
      idField="rule_id"
      emptyMessage="Add naming/style rules to evaluate ingested code against."
      fields={[
        { name: 'title', label: 'Title', required: true, placeholder: 'e.g. Functions must be snake_case' },
        { name: 'category', label: 'Category', required: true, placeholder: 'e.g. Naming Standard' },
        { name: 'severity', label: 'Severity', type: 'select', options: SEVERITY_OPTIONS, default: 'low' },
        { name: 'pattern', label: 'Detection pattern (regex)', required: true, placeholder: 'e.g. def [a-z]+[A-Z]\\w*\\(' },
        { name: 'description', label: 'Description', type: 'textarea' },
        { name: 'remediation', label: 'Remediation guidance', type: 'textarea' }
      ]}
      buildPayload={(values) => ({
        rule_id: '',
        title: values.title,
        category: values.category,
        severity: values.severity || 'low',
        languages: [],
        description: values.description,
        detection: { type: 'regex', pattern: values.pattern },
        remediation: values.remediation,
        tags: []
      })}
      renderRow={(rule) => (
        <div className="admin-rule-body">
          <strong>{rule.title}</strong>
          <span className="role-pill">{rule.severity}</span>
          <p>{rule.description}</p>
          <code>{rule.detection?.pattern}</code>
        </div>
      )}
    />
  );
}

function OwaspRulesPage({ authToken }) {
  return (
    <AdminResourcePage
      title="OWASP Top 10 Rule"
      authToken={authToken}
      endpoint="/admin/owasp-rules"
      idField="rule_id"
      emptyMessage="Add OWASP Top 10 detection rules to evaluate ingested code against."
      fields={[
        { name: 'title', label: 'Title', required: true, placeholder: 'e.g. String-Built SQL Query' },
        { name: 'owasp', label: 'OWASP Category', required: true, placeholder: 'e.g. A03:2021' },
        { name: 'severity', label: 'Severity', type: 'select', options: SEVERITY_OPTIONS, default: 'high' },
        { name: 'pattern', label: 'Detection pattern (regex)', required: true, placeholder: 'e.g. \\beval\\(' },
        { name: 'description', label: 'Description', type: 'textarea', placeholder: 'What this rule detects and why it matters.' },
        { name: 'remediation', label: 'Remediation guidance', type: 'textarea' }
      ]}
      buildPayload={(values) => ({
        rule_id: '',
        title: values.title,
        category: 'OWASP Top 10',
        severity: values.severity || 'high',
        languages: [],
        owasp: values.owasp,
        description: values.description,
        detection: { type: 'regex', pattern: values.pattern },
        remediation: values.remediation,
        tags: []
      })}
      renderRow={(rule) => (
        <div className="admin-rule-body">
          <strong>{rule.title}</strong>
          <span className="role-pill">{rule.owasp || rule.severity}</span>
          <span className="role-pill">{rule.severity}</span>
          <p>{rule.description}</p>
          <code>{rule.detection?.pattern}</code>
        </div>
      )}
    />
  );
}

function PlaybooksPage({ authToken }) {
  return (
    <AdminResourcePage
      title="Playbook"
      authToken={authToken}
      endpoint="/admin/playbooks"
      idField="id"
      emptyMessage="Add internal security playbooks to guide the AI Reasoning Agent."
      fields={[
        { name: 'title', label: 'Title', required: true },
        { name: 'category', label: 'Category', default: 'General', placeholder: 'e.g. Logging' },
        { name: 'body', label: 'Guidance', type: 'textarea', required: true },
        { name: 'tags', label: 'Tags (comma-separated)', placeholder: 'logging, secrets, auth' }
      ]}
      buildPayload={(values) => ({
        id: '',
        title: values.title,
        category: values.category || 'General',
        body: values.body,
        tags: (values.tags || '').split(',').map((tag) => tag.trim()).filter(Boolean)
      })}
      renderRow={(playbook) => (
        <div className="admin-rule-body">
          <strong>{playbook.title}</strong>
          <span className="role-pill">{playbook.category}</span>
          <p>{playbook.body}</p>
        </div>
      )}
    />
  );
}

function ConfigurationsPage({ authToken }) {
  return (
    <AdminResourcePage
      title="Configuration Rule"
      authToken={authToken}
      endpoint="/admin/configurations"
      idField="id"
      emptyMessage="Add extra regex patterns for the Configuration Agent (e.g. disabled security flags)."
      fields={[
        { name: 'title', label: 'Title', required: true, placeholder: 'e.g. Admin Panel Enabled Flag' },
        { name: 'severity', label: 'Severity', type: 'select', options: SEVERITY_OPTIONS, default: 'medium' },
        { name: 'pattern', label: 'Detection pattern (regex)', required: true, placeholder: 'e.g. ADMIN_ENABLED\\s*=\\s*True' },
        { name: 'description', label: 'Description', type: 'textarea' }
      ]}
      buildPayload={(values) => ({
        id: '',
        title: values.title,
        description: values.description,
        pattern: values.pattern,
        severity: values.severity || 'medium'
      })}
      renderRow={(rule) => (
        <div className="admin-rule-body">
          <strong>{rule.title}</strong>
          <span className="role-pill">{rule.severity}</span>
          <p>{rule.description}</p>
          <code>{rule.pattern}</code>
        </div>
      )}
    />
  );
}

function AuditLogPage({ authToken }) {
  const [entries, setEntries] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    let isMounted = true;

    (async () => {
      try {
        const response = await fetch(`${API_BASE}/admin/audit-log`, {
          headers: { Authorization: `Bearer ${authToken}` }
        });
        const data = await response.json().catch(() => []);

        if (!response.ok) {
          throw new Error(formatApiError(data, 'Unable to load audit log.'));
        }

        if (isMounted) setEntries(Array.isArray(data) ? data : []);
      } catch (err) {
        if (isMounted) setError(err.message);
      }
    })();

    return () => {
      isMounted = false;
    };
  }, [authToken]);

  return (
    <section className="admin-view">
      {error ? <div className="summary-error"><AlertTriangle size={16} /> {error}</div> : null}
      <article className="panel admin-list-panel">
        <PanelTitle title="Audit Log" action={`${entries.length} entries`} />
        {entries.length ? (
          <table>
            <thead>
              <tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th></tr>
            </thead>
            <tbody>
              {entries.slice(0, 100).map((entry) => (
                <tr key={entry.id}>
                  <td>{formatDate(entry.timestamp)}</td>
                  <td>{entry.actor_user_id}</td>
                  <td>{entry.action}</td>
                  <td>{entry.target}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="empty-repo-state">
            <Database size={34} />
            <strong>No audit entries yet</strong>
            <span>Admin actions will appear here.</span>
          </div>
        )}
      </article>
    </section>
  );
}

function AuthScreen({ mode, setMode, error, loading, onLogin, onRegister }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const isRegister = mode === 'register';

  const submit = (event) => {
    event.preventDefault();
    const payload = { username, password };
    if (isRegister) {
      onRegister(payload);
    } else {
      onLogin(payload);
    }
  };

  return (
    <main className="auth-shell">
      <section className="auth-card">
        <div className="auth-brand">
          <span className="brand-shield"><img src={codeSheildLogo} alt="" /></span>
          <div>
            <strong>CodeSheild AI</strong>
            <span>Red-Team Code Auditor</span>
          </div>
        </div>
        <h1>{isRegister ? 'Register User' : 'Sign In'}</h1>
        <p>{isRegister ? 'New users are registered as managers by default.' : 'Sign in to access your role-based security dashboard.'}</p>

        <form onSubmit={submit} className="auth-form">
          <label htmlFor="auth-username">Username</label>
          <input
            id="auth-username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            placeholder="admin"
            required
          />
          <label htmlFor="auth-password">Password</label>
          <input
            id="auth-password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="Password"
            required
          />
          {error ? <div className={error.includes('complete') ? 'auth-success' : 'modal-error'}><AlertTriangle size={16} /> {error}</div> : null}
          <button className="submit-action" disabled={loading}>{loading ? 'Please wait...' : isRegister ? 'Register as Manager' : 'Sign In'}</button>
        </form>

        <button className="auth-switch" onClick={() => setMode(isRegister ? 'login' : 'register')}>
          {isRegister ? 'Back to login' : 'Create manager account'}
        </button>
      </section>
    </main>
  );
}

function PlaceholderPage({ title }) {
  return (
    <article className="panel placeholder-panel">
      <Settings size={34} />
      <strong>{title}</strong>
      <span>This area is available to users with the required RBAC access.</span>
    </article>
  );
}

function normalizeScanState(state) {
  const value = String(state || 'pending').toLowerCase();
  if (['active', 'running', 'in_progress', 'scanning'].includes(value)) return 'active';
  if (['complete', 'completed', 'success'].includes(value)) return 'completed';
  if (['failed', 'error'].includes(value)) return 'failed';
  return 'pending';
}

function getScanProgress(state) {
  return {
    pending: 18,
    active: 58,
    completed: 100,
    failed: 76
  }[state] || 18;
}

function getRepoName(source, repoPath) {
  if (source) {
    return source.replace(/\/$/, '').split('/').slice(-2).join(' / ');
  }

  if (repoPath) {
    return repoPath.split(/[\\/]/).pop();
  }

  return 'Repository';
}

function formatDate(value) {
  if (!value) return 'Unknown';

  return new Date(value).toLocaleString();
}

function GithubIcon() {
  return <GitPullRequestArrow size={19} />;
}

function PanelTitle({ title, action, onAction }) {
  return (
    <div className="panel-title">
      <h2>{title}</h2>
      {action ? <button onClick={onAction}>{action}</button> : null}
    </div>
  );
}

function ComplianceScoreCard({ summary }) {
  const breakdown = summary.compliance_breakdown || [];
  const score = summary.compliance_score_count || 0;
  const circumference = 377; // 2 * pi * 60
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <article className="panel compliance-panel">
      <PanelTitle title="Compliance Frameworks" />
      <div className="compliance-layout">
        <div className="compliance-gauge-wrapper">
          <svg className="compliance-gauge" viewBox="0 0 150 150">
            <circle cx="75" cy="75" r="60" className="gauge-bg" />
            <circle 
              cx="75" 
              cy="75" 
              r="60" 
              className="gauge-fill" 
              style={{ strokeDashoffset, strokeDasharray: circumference }} 
            />
          </svg>
          <div className="gauge-text">
            <strong>{score}%</strong>
          </div>
        </div>
        <div className="compliance-breakdown-list">
          {breakdown.map((fw) => (
            <div key={fw.framework} className="breakdown-item">
              <span className="fw-name">{fw.framework}</span>
              <span className={`fw-status fw-${fw.status}`}>
                {fw.status.toUpperCase()}
              </span>
            </div>
          ))}
          {breakdown.length === 0 && <span className="text-muted">No framework data.</span>}
        </div>
      </div>
    </article>
  );
}

function ComplianceReportPage({ summary }) {
  const riskDistribution = summary?.risk_distribution || [];

  return (
    <div className="page-content">
      <header className="page-header">
        <div>
          <h1>Compliance Report</h1>
          <p>Detailed analysis of compliance posture and risk distribution.</p>
        </div>
      </header>

      <div className="dashboard-grid">
        <article className="panel scatter-panel">
          <PanelTitle title="Risk vs. Confidence Matrix" />
          <div className="scatter-plot-container">
            <div className="scatter-plot">
              <div className="scatter-grid">
                <div className="quadrant q-tl">High Risk / Low Conf</div>
                <div className="quadrant q-tr">High Risk / High Conf</div>
                <div className="quadrant q-bl">Low Risk / Low Conf</div>
                <div className="quadrant q-br">Low Risk / High Conf</div>
              </div>
              <div className="scatter-axes">
                <div className="y-axis-label">Risk Score</div>
                <div className="x-axis-label">Confidence</div>
              </div>
              {riskDistribution.map((finding) => (
                <div 
                  key={finding.id} 
                  className={`scatter-dot ${finding.severity}`}
                  style={{ 
                    left: `${Math.min(Math.max(finding.confidence * 100, 0), 100)}%`, 
                    bottom: `${Math.min(Math.max(finding.risk_score * 100, 0), 100)}%` 
                  }}
                  data-tooltip={`[${finding.severity.toUpperCase()}] ${finding.category}\nRisk: ${finding.risk_score}\nConf: ${finding.confidence}`}
                />
              ))}
            </div>
          </div>
        </article>

        <article className="panel findings-table-panel">
          <PanelTitle title="Compliance Findings Breakdown" />
          <div style={{ overflowX: 'auto', marginTop: '1rem' }}>
            <table>
              <thead>
                <tr>
                  <th style={{ padding: '0.75rem', borderBottom: '1px solid rgba(255,255,255,0.1)' }}>Category</th>
                  <th style={{ padding: '0.75rem', borderBottom: '1px solid rgba(255,255,255,0.1)' }}>Severity</th>
                  <th style={{ padding: '0.75rem', borderBottom: '1px solid rgba(255,255,255,0.1)' }}>Confidence</th>
                  <th style={{ padding: '0.75rem', borderBottom: '1px solid rgba(255,255,255,0.1)' }}>Risk Score</th>
                </tr>
              </thead>
              <tbody>
                {riskDistribution.map((finding) => (
                  <tr key={finding.id}>
                    <td style={{ padding: '0.75rem', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>{finding.category}</td>
                    <td style={{ padding: '0.75rem', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                      <span className={`severity-pill ${finding.severity}`} style={{ textTransform: 'capitalize' }}>
                        {finding.severity}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>{Math.round(finding.confidence * 100)}%</td>
                    <td style={{ padding: '0.75rem', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>{Math.round(finding.risk_score * 100)}%</td>
                  </tr>
                ))}
                {riskDistribution.length === 0 && (
                  <tr>
                    <td colSpan="4" style={{ padding: '1rem', textAlign: 'center', opacity: 0.5 }}>No recent findings to display.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </article>
      </div>
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />);
