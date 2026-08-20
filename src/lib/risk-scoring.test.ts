import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_RISK_CONTEXT,
  parseRiskContext,
  scoreFinding,
  scoreScanReport,
} from "./risk-scoring";
import type { Finding, RiskContext, ScanReport } from "./scan-types";

const highRiskContext: RiskContext = {
  assetCriticality: "critical",
  exposure: "public",
  threatIntel: "active",
  businessImpact: "severe",
  compensatingControls: "none",
};

const controlledContext: RiskContext = {
  assetCriticality: "low",
  exposure: "internal",
  threatIntel: "none",
  businessImpact: "low",
  compensatingControls: "strong",
};

const sqlFinding: Finding = {
  severity: "high",
  title: "SQL injection indicator detected",
  description: "A database error signature was returned for a tested parameter.",
  scan_type: "sql_injection",
};

test("uses documented defaults when context is omitted", () => {
  assert.deepEqual(parseRiskContext(undefined), DEFAULT_RISK_CONTEXT);
});

test("rejects unrecognized context values", () => {
  assert.throws(
    () => parseRiskContext({ ...DEFAULT_RISK_CONTEXT, exposure: "global" }),
    /not valid/,
  );
});

test("scores all seven explainable factors within the 0-100 boundary", () => {
  const risk = scoreFinding(sqlFinding, highRiskContext);

  assert.equal(risk.modelVersion, "risk-v1");
  assert.equal(risk.factors.length, 7);
  assert.equal(risk.cvssEquivalent, 8);
  assert.ok(risk.score >= 80 && risk.score <= 100);
  assert.equal(risk.priority, "critical");
});

test("strong controls and lower business context reduce remediation priority", () => {
  const exposedRisk = scoreFinding(sqlFinding, highRiskContext);
  const controlledRisk = scoreFinding(sqlFinding, controlledContext);

  assert.ok(controlledRisk.score < exposedRisk.score);
  assert.ok(
    controlledRisk.factors.find((factor) => factor.key === "compensatingControls")!.contribution < 0,
  );
});

test("clean informational results cannot become high priority from context alone", () => {
  const risk = scoreFinding(
    {
      severity: "info",
      title: "No SQL injection indicators detected",
      description: "No database error signatures were observed.",
      scan_type: "sql_injection",
    },
    highRiskContext,
  );

  assert.ok(risk.score <= 10);
  assert.equal(risk.priority, "low");
});

test("scores, sorts, and summarizes a complete report", () => {
  const report: ScanReport = {
    target: "https://example.test/",
    scan_type: "full_assessment",
    timestamp: new Date().toISOString(),
    status: "completed",
    summary: { critical: 0, high: 1, medium: 0, low: 0, info: 1, total_findings: 2 },
    findings: [
      {
        severity: "info",
        title: "Technology detected: React",
        description: "A public framework signature was observed.",
        scan_type: "tech_fingerprint",
      },
      sqlFinding,
    ],
    scans: {},
  };

  const scored = scoreScanReport(report, DEFAULT_RISK_CONTEXT);

  assert.equal(scored.riskSummary?.scoredFindings, 2);
  assert.ok((scored.findings[0].risk?.score ?? 0) >= (scored.findings[1].risk?.score ?? 0));
  assert.deepEqual(scored.riskContext, DEFAULT_RISK_CONTEXT);
});
