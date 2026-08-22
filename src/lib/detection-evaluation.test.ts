import assert from "node:assert/strict";
import test from "node:test";

import { evaluateScannerDetection, type DetectionManifest } from "./detection-evaluation";
import type { ScanReport } from "./scan-types";

const report: ScanReport = {
  target: "http://demo.test/",
  scan_type: "full_assessment",
  timestamp: "2026-08-21T10:00:00.000Z",
  status: "completed",
  summary: { critical: 0, high: 1, medium: 0, low: 0, info: 1, total_findings: 2 },
  findings: [
    { severity: "high", title: "Reflected Cross-Site Scripting (XSS)", description: "Reflected input", scan_type: "xss", location: "/search" },
    { severity: "info", title: "Technology detected: PHP", description: "Passive fingerprint", scan_type: "tech_fingerprint" },
  ],
  scans: {
    xss: { scan_type: "xss", status: "completed", summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0, total_findings: 1 } },
    tech_fingerprint: { scan_type: "tech_fingerprint", status: "completed", summary: { critical: 0, high: 0, medium: 0, low: 0, info: 1, total_findings: 1 } },
  },
};

const manifest: DetectionManifest = {
  datasetName: "Evaluation fixture",
  target: "http://demo.test/",
  targetDetectionRate: 85,
  groundTruthSource: "Unit-test labels",
  evidenceBoundary: "Synthetic evaluator test only.",
  cases: [
    { id: "xss-reflected", module: "xss", label: "Reflected XSS", expected: "positive", match: { title: "cross-site scripting", location: "/search" } },
    { id: "sql-error", module: "sql", label: "Error-based SQL injection", expected: "positive", match: { title: "sql injection" } },
    { id: "no-laravel", module: "tech", label: "No false Laravel fingerprint", expected: "negative", match: { title: "technology detected: laravel" } },
  ],
};

test("calculates labelled detection and false-positive metrics", () => {
  const result = evaluateScannerDetection(manifest, report, new Date("2026-08-21T11:00:00.000Z"));

  assert.deepEqual(result.metrics, {
    truePositives: 1,
    falseNegatives: 1,
    falsePositives: 0,
    trueNegatives: 1,
    detectionRate: 50,
    precision: 100,
    specificity: 100,
    accuracy: 66.67,
  });
  assert.equal(result.targetMet, false);
  assert.equal(result.moduleCompletion.rate, 100);
  assert.equal(result.unmatchedFindings, 1);
});

test("rejects duplicate case identifiers", () => {
  assert.throws(
    () => evaluateScannerDetection({ ...manifest, cases: [...manifest.cases, manifest.cases[0]] }, report),
    /Duplicate detection case id/,
  );
});
