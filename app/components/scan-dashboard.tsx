"use client";

import { FormEvent, useMemo, useState } from "react";

import {
  SCANNERS,
  type Finding,
  type ScanReport,
  type ScannerId,
  type Severity,
} from "@/src/lib/scan-types";

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

function formatDate(value: string) {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function scannerName(id?: string) {
  return SCANNERS.find((scanner) => scanner.id === id)?.name ?? "Assessment";
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

export default function ScanDashboard() {
  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [selected, setSelected] = useState<ScannerId[]>(() =>
    SCANNERS.map((scanner) => scanner.id),
  );
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState("");
  const [isScanning, setIsScanning] = useState(false);

  const activeScanners = useMemo(
    () => SCANNERS.filter((scanner) => selected.includes(scanner.id)),
    [selected],
  );

  function toggleScanner(id: ScannerId) {
    setSelected((current) =>
      current.includes(id) ? current.filter((scanner) => scanner !== id) : [...current, id],
    );
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
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : "The scan could not be completed.");
    } finally {
      setIsScanning(false);
    }
  }

  return (
    <main className="app-shell">
      <section className="hero" aria-labelledby="page-title">
        <div className="brand-row">
          <span className="brand-mark" aria-hidden="true">S</span>
          <span>SecuriScan</span>
          <span className="environment-label">Assessment workspace</span>
        </div>
        <p className="eyebrow">Web application security</p>
        <h1 id="page-title">Find the gaps before they become incidents.</h1>
        <p className="hero-copy">
          Run a focused, authorized assessment and turn the scanner output into a clear list of
          remediation actions.
        </p>
      </section>

      <section className="scan-panel" aria-labelledby="new-scan-title">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">New assessment</p>
            <h2 id="new-scan-title">Configure your scan</h2>
          </div>
          <span className="module-count">{activeScanners.length} modules selected</span>
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
            Public HTTP(S) targets only. Private and local network addresses are blocked.
          </p>

          <fieldset className="scanner-fieldset">
            <legend>Assessment modules</legend>
            <div className="scanner-grid">
              {SCANNERS.map((scanner) => (
                <label className="scanner-option" key={scanner.id}>
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

          <button className="scan-button" type="submit" disabled={isScanning || selected.length === 0}>
            {isScanning ? "Assessment in progress…" : "Run assessment"}
          </button>
        </form>
      </section>

      {report && (
        <section className="results" aria-labelledby="results-title">
          <div className="results-heading">
            <div>
              <p className="eyebrow">Assessment complete</p>
              <h2 id="results-title">Findings for {report.target}</h2>
              <p>{formatDate(report.timestamp)}</p>
            </div>
            <span className="total-findings">{report.summary.total_findings} findings</span>
          </div>

          <div className="summary-grid" aria-label="Finding counts by severity">
            {severityOrder.map((severity) => (
              <div className={`summary-card summary-${severity}`} key={severity}>
                <span>{severity}</span>
                <strong>{report.summary[severity]}</strong>
              </div>
            ))}
          </div>

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
