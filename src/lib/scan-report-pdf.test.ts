import assert from "node:assert/strict";
import test from "node:test";

import { PDFDocument } from "pdf-lib";

import { generateScanReportPdf } from "./scan-report-pdf";
import type { ScanReport } from "./scan-types";

const sampleReport: ScanReport = {
  target: "https://demo.example.test/",
  scan_type: "full_assessment",
  timestamp: "2026-08-21T10:30:00.000Z",
  status: "completed",
  summary: { critical: 1, high: 1, medium: 0, low: 0, info: 0, total_findings: 2 },
  findings: [
    {
      severity: "critical",
      title: "Potentially exposed resource: /.env",
      description: "The environment configuration file was publicly reachable.",
      evidence: "HTTP 200 — configuration content returned",
      location: "https://demo.example.test/.env",
      owasp: "A01:2021-Broken Access Control",
      cwe: "CWE-538",
      recommendation: "Block public access and rotate any exposed credentials.",
      scan_type: "sensitive_files",
      risk: {
        score: 94,
        priority: "critical",
        cvssEquivalent: 9.1,
        modelVersion: "risk-v1",
        factors: [],
      },
    },
    {
      severity: "high",
      title: "Reflected Cross-Site Scripting (XSS)",
      description: "User-controlled input was reflected without contextual encoding.",
      evidence: "Payload reflected: <img src=x onerror=alert(1)>",
      location: "GET /search?q=...",
      owasp: "A03:2021-Injection",
      cwe: "CWE-79",
      recommendation: "Contextually encode output and apply a restrictive Content-Security-Policy.",
      scan_type: "xss",
      risk: {
        score: 82,
        priority: "critical",
        cvssEquivalent: 8.2,
        modelVersion: "risk-v1",
        factors: [],
      },
    },
  ],
  scans: {
    sensitive_files: {
      scan_type: "sensitive_files",
      status: "completed",
      summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0, total_findings: 1 },
    },
    xss: {
      scan_type: "xss",
      status: "completed",
      summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total_findings: 1 },
    },
  },
  riskContext: {
    assetCriticality: "critical",
    exposure: "public",
    threatIntel: "active",
    businessImpact: "severe",
    compensatingControls: "none",
  },
  riskSummary: {
    averageScore: 88,
    highestScore: 94,
    scoredFindings: 2,
    priorities: { critical: 2, high: 0, medium: 0, low: 0 },
  },
};

test("generates a readable multi-page SecuriScan PDF", async () => {
  const bytes = await generateScanReportPdf(sampleReport, {
    reportId: "66c7fce10ad47f0012345678",
    generatedAt: new Date("2026-08-21T11:00:00.000Z"),
  });

  assert.equal(Buffer.from(bytes.subarray(0, 4)).toString("ascii"), "%PDF");
  const document = await PDFDocument.load(bytes);
  assert.ok(document.getPageCount() >= 3);
  assert.match(document.getTitle() ?? "", /SecuriScan assessment/);
});
