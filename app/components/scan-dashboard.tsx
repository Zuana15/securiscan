"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { signIn, signOut } from "next-auth/react";

import { useSiteTheme } from "./site-shell";

import {
  SCANNERS,
  type ScanAnalytics,
  type ScanAnalyticsResponse,
  type ScanHistoryItem,
  type ScanHistoryResponse,
  type Finding,
  type ScanReport,
  type ScannerId,
  type Severity,
} from "@/src/lib/scan-types";

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

const scannerIdsByResultType: Record<string, ScannerId> = {
  security_headers: "headers",
  ssl_tls: "ssl",
  tech_fingerprint: "tech",
  sensitive_files: "files",
  http_misconfiguration: "misconfig",
  port_scan: "port",
  sql_injection: "sql",
  xss: "xss",
  csrf: "csrf",
};

interface CurrentUser {
  id: string;
  name: string | null;
  email: string | null;
  role: "owner" | "analyst" | "viewer";
}

interface DashboardProps {
  initialUser: CurrentUser | null;
  registrationEnabled: boolean;
  view: "scans" | "history" | "analytics";
  initialAuthMode?: "sign-in" | "sign-up";
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function formatDay(value: string) {
  return new Intl.DateTimeFormat("en", { month: "short", day: "numeric" }).format(
    new Date(`${value}T00:00:00`),
  );
}

function scannerName(id?: string) {
  const scannerId = id && (scannerIdsByResultType[id] ?? id);
  return SCANNERS.find((scanner) => scanner.id === scannerId)?.name ?? "Assessment";
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article className="finding-card">
      <div className="finding-heading">
        <div>
          <p className="eyebrow">{scannerName(finding.scan_type)}</p>
          <h3>{finding.title}</h3>
        </div>
        <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
      </div>
      <p className="finding-description">{finding.description}</p>
      {(finding.owasp || finding.cwe) && (
        <p className="finding-tags">{[finding.owasp, finding.cwe].filter(Boolean).join(" · ")}</p>
      )}
      {finding.location && <p className="finding-location">Location: {finding.location}</p>}
      {finding.evidence && <p className="finding-evidence">Evidence: {finding.evidence}</p>}
      {finding.recommendation && (
        <p className="finding-recommendation">
          <strong>Recommended action:</strong> {finding.recommendation}
        </p>
      )}
    </article>
  );
}

function AccountPanel({
  user,
  registrationEnabled,
  initialAuthMode = "sign-in",
}: {
  user: CurrentUser | null;
  registrationEnabled: boolean;
  initialAuthMode?: "sign-in" | "sign-up";
}) {
  const [isCreatingAccount, setIsCreatingAccount] = useState(initialAuthMode === "sign-up");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  function changeMode(creatingAccount: boolean) {
    setIsCreatingAccount(creatingAccount);
    setMessage("");
    setPassword("");
  }

  async function submitAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("");
    setIsSubmitting(true);

    try {
      if (isCreatingAccount) {
        const response = await fetch("/api/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name, email, password }),
        });
        const payload = (await response.json()) as { error?: string };
        if (!response.ok) {
          throw new Error(payload.error ?? "The account could not be created.");
        }
      }

      const result = await signIn("credentials", {
        redirect: false,
        email,
        password,
      });
      if (!result?.ok) {
        throw new Error(
          isCreatingAccount
            ? "Account was created, but sign-in failed. Check your configuration and try again."
            : "The email address or password is not correct.",
        );
      }

      window.location.assign("/");
    } catch (accountError) {
      setMessage(accountError instanceof Error ? accountError.message : "Unable to continue.");
    } finally {
      setIsSubmitting(false);
    }
  }

  async function endSession() {
    await signOut({ redirect: false });
    window.location.assign("/");
  }

  return (
    <section className="account-panel" aria-labelledby="account-title">
      <div className="account-copy">
        <p className="eyebrow">Workspace access</p>
        <h2 id="account-title">
          {user
            ? `Signed in as ${user.name ?? user.email ?? "user"}`
            : isCreatingAccount
              ? "Create your SecuriScan account"
              : "Sign in to your workspace"}
        </h2>
        <p>
          {user
            ? "Your assessments, scan history, and analytics are private to this account."
            : isCreatingAccount
              ? "Create an account to keep assessments, scan history, and analytics private to your workspace."
              : "Sign in before running an assessment. Saved scans and analytics are private to the account that created them."}
        </p>
      </div>

      {user ? (
        <div className="account-session">
          <div className="account-identity">
            <span className="account-avatar" aria-hidden="true">
              {(user.name ?? user.email ?? "S").charAt(0).toUpperCase()}
            </span>
            <div>
              <strong>{user.name ?? "SecuriScan user"}</strong>
              <span>{user.email}</span>
            </div>
          </div>
          <div className="signed-in-actions">
            <span className="account-role">{user.role}</span>
            <button className="secondary-button" type="button" onClick={() => void endSession()}>
              Sign out
            </button>
          </div>
        </div>
      ) : (
        <form className="account-form" onSubmit={submitAccount}>
          {isCreatingAccount && (
            <label className="account-name">
              Name
              <input
                type="text"
                autoComplete="name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                minLength={2}
                maxLength={80}
                required
              />
            </label>
          )}
          <label>
            Email address
            <input
              type="email"
              autoComplete="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              required
            />
          </label>
          <label>
            Password
            <input
              type="password"
              autoComplete={isCreatingAccount ? "new-password" : "current-password"}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              minLength={isCreatingAccount ? 8 : 1}
              required
            />
          </label>
          {isCreatingAccount && (
            <p className="password-hint">Use at least 8 characters, including a letter and a number.</p>
          )}
          {message && <p className="form-error" role="alert">{message}</p>}
          <div className="account-actions">
            <button className="scan-button" type="submit" disabled={isSubmitting}>
              {isSubmitting ? "Working…" : isCreatingAccount ? "Create account" : "Sign in"}
            </button>
            {registrationEnabled && (
              <button
                className="account-mode-button"
                type="button"
                onClick={() => changeMode(!isCreatingAccount)}
                disabled={isSubmitting}
              >
                {isCreatingAccount ? "I already have an account" : "Create a local account"}
              </button>
            )}
          </div>
          {!registrationEnabled && (
            <p className="account-note">Account creation is managed by an administrator.</p>
          )}
        </form>
      )}
    </section>
  );
}

function AnalyticsPanel({
  analytics,
  available,
  message,
  signedIn,
}: {
  analytics: ScanAnalytics | null;
  available: boolean;
  message: string;
  signedIn: boolean;
}) {
  const highestTrendValue = Math.max(...(analytics?.trend.map((point) => point.findings) ?? [1]), 1);

  return (
    <section className="data-panel" aria-labelledby="analytics-title">
      <div className="data-panel-heading">
        <div>
          <p className="eyebrow">Stored results</p>
          <h2 id="analytics-title">Basic scan analytics</h2>
        </div>
        <span className={`data-status ${available ? "data-status-ready" : ""}`}>
          {available ? "Connected" : signedIn ? "Setup needed" : "Sign in required"}
        </span>
      </div>

      {!available ? (
        <p className="data-empty">{message}</p>
      ) : !analytics || analytics.totalScans === 0 ? (
        <p className="data-empty">Run an assessment to start building your scan history and analytics.</p>
      ) : (
        <>
          <div className="analytics-metrics">
            <div><span>Total scans</span><strong>{analytics.totalScans}</strong></div>
            <div><span>Targets assessed</span><strong>{analytics.uniqueTargets}</strong></div>
            <div><span>Findings recorded</span><strong>{analytics.totalFindings}</strong></div>
          </div>

          <div className="analytics-grid">
            <div>
              <h3>Severity distribution</h3>
              <div className="analytics-severity-list">
                {severityOrder.map((severity) => (
                  <div key={severity}>
                    <span className={`severity severity-${severity}`}>{severity}</span>
                    <strong>{analytics.severity[severity]}</strong>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <h3>Findings over time</h3>
              {analytics.trend.length ? (
                <div className="trend-list">
                  {analytics.trend.map((point) => (
                    <div className="trend-row" key={point.date}>
                      <span>{formatDay(point.date)}</span>
                      <div><i style={{ width: `${Math.max((point.findings / highestTrendValue) * 100, 7)}%` }} /></div>
                      <strong>{point.findings}</strong>
                    </div>
                  ))}
                </div>
              ) : <p className="compact-empty">No trend data yet.</p>}
            </div>
          </div>
        </>
      )}
    </section>
  );
}

function HistoryPanel({
  history,
  available,
  message,
  isLoading,
  onRefresh,
  signedIn,
}: {
  history: ScanHistoryItem[];
  available: boolean;
  message: string;
  isLoading: boolean;
  onRefresh: () => void;
  signedIn: boolean;
}) {
  return (
    <section className="data-panel scan-history" aria-labelledby="history-title">
      <div className="data-panel-heading">
        <div>
          <p className="eyebrow">Audit trail</p>
          <h2 id="history-title">Recent assessments</h2>
        </div>
        <button
          className="refresh-button"
          type="button"
          onClick={onRefresh}
          disabled={isLoading || !signedIn}
        >
          {isLoading ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      {!available ? (
        <p className="data-empty">{message}</p>
      ) : history.length === 0 ? (
        <p className="data-empty">No completed assessments have been saved yet.</p>
      ) : (
        <div className="history-list">
          {history.map((scan) => (
            <article className="history-item" key={scan.id}>
              <div>
                <strong>{scan.target}</strong>
                <span>{formatDate(scan.completedAt)} · {scan.selectedScanners.length} modules</span>
              </div>
              <div className="history-summary">
                <strong>{scan.summary.total_findings}</strong>
                <span>findings</span>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

export default function ScanDashboard({ initialUser, registrationEnabled, view, initialAuthMode }: DashboardProps) {
  const { darkTheme } = useSiteTheme();
  const [professionalUi, setProfessionalUi] = useState(true);
  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [selected, setSelected] = useState<ScannerId[]>(() =>
    SCANNERS.map((scanner) => scanner.id),
  );
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [analytics, setAnalytics] = useState<ScanAnalytics | null>(null);
  const [storedDataAvailable, setStoredDataAvailable] = useState(false);
  const [storedDataMessage, setStoredDataMessage] = useState(
    initialUser
      ? "Run an assessment to build history, then refresh this section to load stored results."
      : "Sign in to save scans and view only your own scan history and analytics.",
  );
  const [isLoadingStoredData, setIsLoadingStoredData] = useState(false);

  const activeScanners = useMemo(
    () => SCANNERS.filter((scanner) => selected.includes(scanner.id)),
    [selected],
  );

  const refreshStoredData = useCallback(async () => {
    if (!initialUser) {
      setStoredDataAvailable(false);
      setStoredDataMessage("Sign in to save scans and view only your own scan history and analytics.");
      setHistory([]);
      setAnalytics(null);
      return;
    }

    setIsLoadingStoredData(true);
    try {
      const [historyResponse, analyticsResponse] = await Promise.all([
        fetch("/api/scan-history", { cache: "no-store" }),
        fetch("/api/analytics", { cache: "no-store" }),
      ]);
      const historyPayload = (await historyResponse.json()) as ScanHistoryResponse;
      const analyticsPayload = (await analyticsResponse.json()) as ScanAnalyticsResponse;
      const available = historyResponse.ok && analyticsResponse.ok && historyPayload.available && analyticsPayload.available;

      setStoredDataAvailable(available);
      setStoredDataMessage(historyPayload.message ?? analyticsPayload.message ?? "Stored results are unavailable.");
      setHistory(historyPayload.items ?? []);
      setAnalytics(analyticsPayload.analytics ?? null);
    } catch {
      setStoredDataAvailable(false);
      setStoredDataMessage("Stored results could not be loaded. Check the database configuration.");
      setHistory([]);
      setAnalytics(null);
    } finally {
      setIsLoadingStoredData(false);
    }
  }, [initialUser]);

  useEffect(() => {
    if (view === "scans") return;
    const refreshTimer = window.setTimeout(() => void refreshStoredData(), 0);
    return () => window.clearTimeout(refreshTimer);
  }, [refreshStoredData, view]);

  function toggleScanner(id: ScannerId) {
    setSelected((current) =>
      current.includes(id) ? current.filter((scanner) => scanner !== id) : [...current, id],
    );
  }

  function selectAllScanners() {
    setSelected(SCANNERS.map((scanner) => scanner.id));
  }

  function clearScanners() {
    setSelected([]);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setReport(null);
    setIsScanning(true);

    try {
      const response = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, scanners: selected, authorized }),
      });
      const payload = (await response.json()) as ScanReport | { error?: string };

      if (!response.ok || !("findings" in payload)) {
        throw new Error("error" in payload ? payload.error : "The scan could not be completed.");
      }

      setReport(payload);
      void refreshStoredData();
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : "The scan could not be completed.");
    } finally {
      setIsScanning(false);
    }
  }

  const viewCopy = {
    scans: {
      eyebrow: "Assessment workspace",
      title: "Run a focused security assessment.",
      copy: "Choose the target and modules in scope, then review evidence-backed findings and recommended actions.",
    },
    history: {
      eyebrow: "Private audit trail",
      title: "Review your scan history.",
      copy: "See the completed assessments stored for this account, including targets, dates, modules, and finding totals.",
    },
    analytics: {
      eyebrow: "Security overview",
      title: "Track what your scans are finding.",
      copy: "Use account-scoped metrics and severity trends to understand assessment coverage and changing exposure.",
    },
  }[view];

  return (
    <main className={`app-shell workspace-${view} ${professionalUi ? "professional-ui" : ""} ${darkTheme ? "theme-dark" : "theme-light"}`}>
      <section className="workspace-intro" aria-labelledby="workspace-page-title">
        <div className="workspace-intro-copy professional-only">
          <p className="eyebrow">{viewCopy.eyebrow}</p>
          <h1 id="workspace-page-title">{viewCopy.title}</h1>
          <p>{viewCopy.copy}</p>
          <div className="workspace-intro-status"><i /> Scanner runner ready · 9 modules available</div>
        </div>
        <button
          className="view-toggle workspace-view-toggle"
          type="button"
          onClick={() => setProfessionalUi((current) => !current)}
        >
          {professionalUi ? "Classic UI" : "Professional UI"}
        </button>
      </section>

      {!professionalUi && view === "scans" && (
        <section className="hero" aria-labelledby="page-title">
          <div className="brand-row">
            <span className="brand-mark" aria-hidden="true">S</span>
            <span>SecuriScan</span>
            <span className="environment-label">Assessment workspace</span>
          </div>
          <p className="eyebrow">Web application security</p>
          <h1 id="page-title">Find the gaps before they become incidents.</h1>
          <p className="hero-copy">Run a focused, authorized assessment and turn the scanner output into a clear list of remediation actions.</p>
        </section>
      )}

      <AccountPanel
        key={initialAuthMode ?? "sign-in"}
        user={initialUser}
        registrationEnabled={registrationEnabled}
        initialAuthMode={initialAuthMode}
      />

      {view === "scans" && (
      <section className="scan-panel" aria-labelledby="new-scan-title">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">New assessment</p>
            <h2 id="new-scan-title">Configure your scan</h2>
          </div>
          <div className="panel-heading-actions">
            <div className="module-tools professional-only" aria-label="Module selection controls">
              <button type="button" onClick={selectAllScanners}>Select all</button>
              <button type="button" onClick={clearScanners}>Clear</button>
            </div>
            <span className="module-count">{activeScanners.length} modules selected</span>
          </div>
        </div>

        <form onSubmit={submit}>
          <label className="target-label" htmlFor="target">
            Target URL
            <input
              id="target"
              name="target"
              type="text"
              inputMode="url"
              autoComplete="url"
              placeholder="https://app.your-company.com"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              required
            />
          </label>
          <p className="input-hint">
            Public HTTP(S) targets only. Local targets are permitted solely in an explicitly enabled
            development demo session.
          </p>

          <fieldset className="scanner-fieldset">
            <legend>Assessment modules</legend>
            <div className="scanner-grid">
              {SCANNERS.map((scanner, index) => (
                <label
                  className={`scanner-option ${selected.includes(scanner.id) ? "scanner-option-selected" : ""}`}
                  data-module-number={String(index + 1).padStart(2, "0")}
                  key={scanner.id}
                >
                  <input
                    type="checkbox"
                    checked={selected.includes(scanner.id)}
                    onChange={() => toggleScanner(scanner.id)}
                  />
                  <span>
                    <strong>{scanner.name}</strong>
                    <small>{scanner.description}</small>
                  </span>
                  {scanner.active && <em>Active test</em>}
                </label>
              ))}
            </div>
          </fieldset>

          <label className="authorization">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(event) => setAuthorized(event.target.checked)}
            />
            <span>I own this target or have explicit written authorization to assess it.</span>
          </label>

          {error && <p className="form-error" role="alert">{error}</p>}

          {isScanning && (
            <div className="scan-progress" role="status">
              <span className="scan-spinner" aria-hidden="true" />
              <div>
                <strong>Assessment in progress</strong>
                <span>Running {activeScanners.length} selected modules against the authorized target.</span>
              </div>
            </div>
          )}

          <button
            className="scan-button scan-submit-button"
            type="submit"
            disabled={isScanning || selected.length === 0 || !initialUser}
          >
            {isScanning
              ? "Assessment in progress…"
              : initialUser
                ? "Run assessment"
                : "Sign in to run assessments"}
          </button>
        </form>
      </section>
      )}

      {view === "analytics" && <AnalyticsPanel
        analytics={analytics}
        available={storedDataAvailable}
        message={storedDataMessage}
        signedIn={Boolean(initialUser)}
      />}

      {view === "history" && <HistoryPanel
        history={history}
        available={storedDataAvailable}
        message={storedDataMessage}
        isLoading={isLoadingStoredData}
        onRefresh={() => void refreshStoredData()}
        signedIn={Boolean(initialUser)}
      />}

      {view === "scans" && report && (
        <section className="results" aria-labelledby="results-title">
          <div className="results-heading">
            <div>
              <p className="eyebrow">Assessment complete</p>
              <h2 id="results-title">Findings for {report.target}</h2>
              <p>{formatDate(report.timestamp)}</p>
            </div>
            <span className="total-findings">{report.summary.total_findings} findings</span>
          </div>

          {report.persistence && (
            <p className={`persistence-message persistence-${report.persistence.state}`}>
              {report.persistence.state === "saved"
                ? "Assessment saved to scan history."
                : report.persistence.message}
            </p>
          )}

          <div className="summary-grid" aria-label="Finding counts by severity">
            {severityOrder.map((severity) => (
              <div className={`summary-card summary-${severity}`} key={severity}>
                <span>{severity}</span>
                <strong>{report.summary[severity]}</strong>
              </div>
            ))}
          </div>

          <section className="scan-coverage" aria-labelledby="coverage-title">
            <div>
              <p className="eyebrow">Coverage</p>
              <h3 id="coverage-title">Module status</h3>
            </div>
            <div className="coverage-grid">
              {Object.values(report.scans).map((scan) => (
                <article className={`coverage-card coverage-${scan.status}`} key={scan.scan_type}>
                  <div>
                    <strong>{scannerName(scan.scan_type)}</strong>
                    <span>{scan.status === "completed" ? "Completed" : "Could not complete"}</span>
                  </div>
                  <p>
                    {scan.status === "failed"
                      ? scan.metadata?.error ?? "The target could not be reached."
                      : `${scan.summary.total_findings} finding${scan.summary.total_findings === 1 ? "" : "s"}`}
                  </p>
                </article>
              ))}
            </div>
          </section>

          <div className="findings-list">
            {report.findings.map((finding, index) => (
              <FindingCard finding={finding} key={`${finding.title}-${index}`} />
            ))}
          </div>
        </section>
      )}
    </main>
  );
}
