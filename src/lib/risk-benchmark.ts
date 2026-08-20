import {
  RISK_V1_WEIGHTS,
  scoreFinding,
  scoreFindingWithWeights,
  type RiskModelWeights,
} from "./risk-scoring";
import type {
  Finding,
  RiskBenchmarkMetrics,
  RiskBenchmarkResult,
  RiskContext,
  Severity,
} from "./scan-types";

export type RiskBenchmarkSplit = "calibration" | "validation";

export interface RiskBenchmarkCase {
  id: string;
  split: RiskBenchmarkSplit;
  finding: Finding;
  context: RiskContext;
  expectedUrgency: number;
  rationale: string;
}

interface BenchmarkSpec {
  id: string;
  split: RiskBenchmarkSplit;
  title: string;
  severity: Severity;
  scanType: string;
  context: RiskContext;
  expectedUrgency: number;
  rationale: string;
}

interface WeightCandidate {
  id: string;
  name: string;
  weights: RiskModelWeights;
}

const contexts = {
  extreme: {
    assetCriticality: "critical",
    exposure: "public",
    threatIntel: "active",
    businessImpact: "severe",
    compensatingControls: "none",
  },
  protected: {
    assetCriticality: "low",
    exposure: "internal",
    threatIntel: "none",
    businessImpact: "low",
    compensatingControls: "strong",
  },
  exposedHigh: {
    assetCriticality: "high",
    exposure: "public",
    threatIntel: "emerging",
    businessImpact: "high",
    compensatingControls: "partial",
  },
  importantAuthenticated: {
    assetCriticality: "high",
    exposure: "authenticated",
    threatIntel: "emerging",
    businessImpact: "severe",
    compensatingControls: "partial",
  },
  ordinaryPublic: {
    assetCriticality: "moderate",
    exposure: "public",
    threatIntel: "none",
    businessImpact: "moderate",
    compensatingControls: "none",
  },
  controlledInternal: {
    assetCriticality: "moderate",
    exposure: "internal",
    threatIntel: "none",
    businessImpact: "moderate",
    compensatingControls: "strong",
  },
} satisfies Record<string, RiskContext>;

function makeCase(spec: BenchmarkSpec): RiskBenchmarkCase {
  return {
    id: spec.id,
    split: spec.split,
    finding: {
      severity: spec.severity,
      title: spec.title,
      description: `Benchmark scenario: ${spec.title}.`,
      scan_type: spec.scanType,
    },
    context: spec.context,
    expectedUrgency: spec.expectedUrgency,
    rationale: spec.rationale,
  };
}

export const RISK_BENCHMARK_CASES: readonly RiskBenchmarkCase[] = [
  makeCase({ id: "cal-01", split: "calibration", title: "Actively exploited SQL injection on payment service", severity: "high", scanType: "sql_injection", context: contexts.extreme, expectedUrgency: 95, rationale: "Direct exploitation and severe payment impact require immediate action." }),
  makeCase({ id: "cal-02", split: "calibration", title: "Critical header finding on isolated lab", severity: "critical", scanType: "security_headers", context: contexts.protected, expectedUrgency: 34, rationale: "Isolation and strong controls substantially reduce immediate urgency." }),
  makeCase({ id: "cal-03", split: "calibration", title: "Exposed backup on critical public service", severity: "medium", scanType: "sensitive_files", context: contexts.extreme, expectedUrgency: 84, rationale: "Directly retrievable data on a critical service outweighs the scanner severity." }),
  makeCase({ id: "cal-04", split: "calibration", title: "Stored XSS indicator in protected test tool", severity: "high", scanType: "xss", context: contexts.protected, expectedUrgency: 33, rationale: "The test tool is isolated and protected by verified controls." }),
  makeCase({ id: "cal-05", split: "calibration", title: "Public port exposure with emerging threat activity", severity: "low", scanType: "port_scan", context: contexts.exposedHigh, expectedUrgency: 52, rationale: "Reachability and emerging activity raise a nominally low finding." }),
  makeCase({ id: "cal-06", split: "calibration", title: "TLS weakness on controlled internal service", severity: "medium", scanType: "ssl_tls", context: contexts.controlledInternal, expectedUrgency: 23, rationale: "Internal reachability and strong controls reduce near-term likelihood." }),
  makeCase({ id: "cal-07", split: "calibration", title: "Technology disclosure during active targeting", severity: "info", scanType: "tech_fingerprint", context: contexts.extreme, expectedUrgency: 27, rationale: "Reconnaissance value matters, but disclosure alone remains bounded." }),
  makeCase({ id: "cal-08", split: "calibration", title: "CSRF on mission-critical public workflow", severity: "low", scanType: "csrf", context: contexts.extreme, expectedUrgency: 72, rationale: "Severe workflow impact and active exploitation make remediation urgent." }),
  makeCase({ id: "cal-09", split: "calibration", title: "Sensitive file exposure behind authentication", severity: "critical", scanType: "sensitive_files", context: contexts.importantAuthenticated, expectedUrgency: 76, rationale: "The impact is severe, while authentication and partial controls reduce exposure." }),
  makeCase({ id: "cal-10", split: "calibration", title: "Dangerous HTTP method on targeted public platform", severity: "high", scanType: "http_misconfiguration", context: contexts.extreme, expectedUrgency: 90, rationale: "Public exploitability and severe business impact demand rapid remediation." }),
  makeCase({ id: "cal-11", split: "calibration", title: "Missing CSP on ordinary public website", severity: "medium", scanType: "security_headers", context: contexts.ordinaryPublic, expectedUrgency: 54, rationale: "Public exposure matters, but exploitation usually needs another weakness." }),
  makeCase({ id: "cal-12", split: "calibration", title: "Reflected XSS on actively targeted portal", severity: "low", scanType: "xss", context: contexts.extreme, expectedUrgency: 71, rationale: "Active targeting and direct browser exploitability override the low label." }),

  makeCase({ id: "val-01", split: "validation", title: "Critical network service finding in isolated lab", severity: "critical", scanType: "port_scan", context: contexts.protected, expectedUrgency: 35, rationale: "The issue is real, but isolation and strong controls lower remediation urgency." }),
  makeCase({ id: "val-02", split: "validation", title: "Public SQL injection affecting regulated data", severity: "high", scanType: "sql_injection", context: contexts.extreme, expectedUrgency: 94, rationale: "Active exploitation could directly compromise regulated data." }),
  makeCase({ id: "val-03", split: "validation", title: "CSRF on critical transfer workflow", severity: "medium", scanType: "csrf", context: contexts.extreme, expectedUrgency: 82, rationale: "A public, actively targeted transfer workflow has severe business impact." }),
  makeCase({ id: "val-04", split: "validation", title: "High header severity on protected sandbox", severity: "high", scanType: "security_headers", context: contexts.protected, expectedUrgency: 29, rationale: "The sandbox has low value, internal reachability, and strong controls." }),
  makeCase({ id: "val-05", split: "validation", title: "Low-severity exposed configuration on public asset", severity: "low", scanType: "sensitive_files", context: contexts.extreme, expectedUrgency: 73, rationale: "The resource can be retrieved directly from a critical targeted system." }),
  makeCase({ id: "val-06", split: "validation", title: "Certificate weakness on controlled intranet", severity: "medium", scanType: "ssl_tls", context: contexts.controlledInternal, expectedUrgency: 25, rationale: "Restricted reachability and verified controls reduce exploitation likelihood." }),
  makeCase({ id: "val-07", split: "validation", title: "Minor port exposure on protected internal utility", severity: "low", scanType: "port_scan", context: contexts.protected, expectedUrgency: 17, rationale: "A low-value internal utility with strong controls has limited urgency." }),
  makeCase({ id: "val-08", split: "validation", title: "Reflected XSS on important public application", severity: "medium", scanType: "xss", context: contexts.exposedHigh, expectedUrgency: 65, rationale: "Public browser exploitability and high impact justify accelerated remediation." }),
  makeCase({ id: "val-09", split: "validation", title: "Critical technology disclosure in isolated environment", severity: "critical", scanType: "tech_fingerprint", context: contexts.protected, expectedUrgency: 38, rationale: "Reconnaissance value is limited by isolation and compensating controls." }),
  makeCase({ id: "val-10", split: "validation", title: "No SQL injection indicators detected", severity: "info", scanType: "sql_injection", context: contexts.extreme, expectedUrgency: 5, rationale: "A negative scanner result must not become urgent because of context alone." }),
  makeCase({ id: "val-11", split: "validation", title: "HTTP misconfiguration behind authentication", severity: "high", scanType: "http_misconfiguration", context: contexts.importantAuthenticated, expectedUrgency: 56, rationale: "Severe impact is moderated by authentication and partial controls." }),
  makeCase({ id: "val-12", split: "validation", title: "Missing browser defense on targeted critical portal", severity: "low", scanType: "security_headers", context: contexts.extreme, expectedUrgency: 69, rationale: "Context raises remediation urgency even though another weakness is usually required." }),
] as const;

const WEIGHT_CANDIDATES: readonly WeightCandidate[] = [
  { id: "risk-v1-balanced", name: "Risk v1 balanced", weights: RISK_V1_WEIGHTS },
  { id: "cvss-heavy", name: "CVSS-heavy", weights: { severity: 50, assetCriticality: 10, exposure: 10, threatIntel: 5, businessImpact: 15, exploitability: 10, compensatingControls: 10 } },
  { id: "context-heavy", name: "Context-heavy", weights: { severity: 25, assetCriticality: 20, exposure: 20, threatIntel: 15, businessImpact: 15, exploitability: 5, compensatingControls: 15 } },
  { id: "business-heavy", name: "Business-impact heavy", weights: { severity: 30, assetCriticality: 20, exposure: 10, threatIntel: 10, businessImpact: 20, exploitability: 10, compensatingControls: 15 } },
  { id: "threat-heavy", name: "Threat-activity heavy", weights: { severity: 30, assetCriticality: 10, exposure: 15, threatIntel: 20, businessImpact: 15, exploitability: 10, compensatingControls: 15 } },
] as const;

function round(value: number): number {
  return Math.round(value * 100) / 100;
}

function evaluateScores(cases: readonly RiskBenchmarkCase[], scores: readonly number[]): RiskBenchmarkMetrics {
  let evaluatedPairs = 0;
  let concordantPairs = 0;

  for (let left = 0; left < cases.length; left += 1) {
    for (let right = left + 1; right < cases.length; right += 1) {
      const expectedDirection = Math.sign(cases[left].expectedUrgency - cases[right].expectedUrgency);
      if (expectedDirection === 0) continue;
      const predictedDirection = Math.sign(scores[left] - scores[right]);
      evaluatedPairs += 1;
      if (predictedDirection === expectedDirection) concordantPairs += 1;
      else if (predictedDirection === 0) concordantPairs += 0.5;
    }
  }

  const meanAbsoluteError = cases.length
    ? scores.reduce((total, score, index) => total + Math.abs(score - cases[index].expectedUrgency), 0) / cases.length
    : 0;

  return {
    pairwiseAccuracy: evaluatedPairs ? round((concordantPairs / evaluatedPairs) * 100) : 0,
    meanAbsoluteError: round(meanAbsoluteError),
    evaluatedPairs,
  };
}

function scoreWithWeights(cases: readonly RiskBenchmarkCase[], weights: RiskModelWeights): number[] {
  return cases.map((item) => scoreFindingWithWeights(item.finding, item.context, weights).score);
}

export function evaluateRiskBenchmark(): RiskBenchmarkResult {
  const calibration = RISK_BENCHMARK_CASES.filter((item) => item.split === "calibration");
  const validation = RISK_BENCHMARK_CASES.filter((item) => item.split === "validation");
  const candidateResults = WEIGHT_CANDIDATES.map((candidate) => ({
    ...candidate,
    metrics: evaluateScores(calibration, scoreWithWeights(calibration, candidate.weights)),
  })).sort((left, right) =>
    right.metrics.pairwiseAccuracy - left.metrics.pairwiseAccuracy ||
    left.metrics.meanAbsoluteError - right.metrics.meanAbsoluteError ||
    left.id.localeCompare(right.id),
  );
  const selectedCandidate = candidateResults[0];

  const cvssScores = validation.map((item) => scoreFinding(item.finding, item.context).cvssEquivalent * 10);
  const riskScores = scoreWithWeights(validation, RISK_V1_WEIGHTS);
  const cvssOnly = evaluateScores(validation, cvssScores);
  const riskV1 = evaluateScores(validation, riskScores);
  const percentagePointGain = round(riskV1.pairwiseAccuracy - cvssOnly.pairwiseAccuracy);
  const relativeImprovement = cvssOnly.pairwiseAccuracy
    ? round((percentagePointGain / cvssOnly.pairwiseAccuracy) * 100)
    : 0;

  return {
    datasetName: "SecuriScan prototype ranking benchmark v1",
    labelSource: "24 developer-authored scenarios with manually assigned remediation urgency",
    calibrationCases: calibration.length,
    validationCases: validation.length,
    cvssOnly,
    riskV1,
    percentagePointGain,
    relativeImprovement,
    targetImprovement: 30,
    targetMet: relativeImprovement >= 30,
    selectedCandidate: selectedCandidate.id,
    candidates: candidateResults.map((candidate) => ({
      id: candidate.id,
      name: candidate.name,
      pairwiseAccuracy: candidate.metrics.pairwiseAccuracy,
      meanAbsoluteError: candidate.metrics.meanAbsoluteError,
      selected: candidate.id === selectedCandidate.id,
    })),
    limitation: "This is an internal prototype benchmark, not independent proof. Replace or supplement it with blinded expert labels before making a research claim.",
  };
}
