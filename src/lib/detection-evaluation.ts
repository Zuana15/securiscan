import type { Finding, ScanReport } from "./scan-types";

export type DetectionExpectation = "positive" | "negative";
export type DetectionClassification = "true_positive" | "false_negative" | "false_positive" | "true_negative";
export type MatchableFindingField = "title" | "description" | "evidence" | "location" | "owasp" | "cwe";

export interface DetectionCase {
  id: string;
  module: string;
  label: string;
  expected: DetectionExpectation;
  match: Partial<Record<MatchableFindingField, string>>;
  reference?: string;
}

export interface DetectionManifest {
  datasetName: string;
  target: string;
  targetDetectionRate: number;
  groundTruthSource: string;
  evidenceBoundary: string;
  cases: DetectionCase[];
}

export interface DetectionCaseResult extends DetectionCase {
  detected: boolean;
  classification: DetectionClassification;
  matchedFinding?: Pick<Finding, "title" | "severity" | "location" | "cwe" | "owasp" | "scan_type">;
}

export interface DetectionMetricSummary {
  truePositives: number;
  falseNegatives: number;
  falsePositives: number;
  trueNegatives: number;
  detectionRate: number;
  precision: number;
  specificity: number;
  accuracy: number;
}

export interface ModuleDetectionSummary extends DetectionMetricSummary {
  module: string;
  cases: number;
}

export interface DetectionEvaluationResult {
  datasetName: string;
  target: string;
  evaluatedAt: string;
  groundTruthSource: string;
  evidenceBoundary: string;
  targetDetectionRate: number;
  targetMet: boolean;
  moduleCompletion: {
    completed: number;
    total: number;
    rate: number;
    failedModules: string[];
  };
  metrics: DetectionMetricSummary;
  modules: ModuleDetectionSummary[];
  unmatchedFindings: number;
  cases: DetectionCaseResult[];
}

const moduleAliases: Record<string, string> = {
  headers: "security_headers",
  ssl: "ssl_tls",
  tech: "tech_fingerprint",
  files: "sensitive_files",
  misconfig: "http_misconfiguration",
  port: "port_scan",
  sql: "sql_injection",
};

function round(value: number) {
  return Math.round(value * 100) / 100;
}

function percentage(numerator: number, denominator: number, emptyValue = 0) {
  return denominator ? round((numerator / denominator) * 100) : emptyValue;
}

function normalize(value: unknown) {
  return String(value ?? "").trim().toLowerCase();
}

function normalizeModule(value: string) {
  return moduleAliases[value] ?? value;
}

function matchesCase(finding: Finding, testCase: DetectionCase) {
  if (normalizeModule(finding.scan_type ?? "") !== normalizeModule(testCase.module)) return false;
  const matchEntries = Object.entries(testCase.match) as [MatchableFindingField, string][];
  if (!matchEntries.length) return false;
  return matchEntries.every(([field, expected]) => normalize(finding[field]).includes(normalize(expected)));
}

function summarize(cases: DetectionCaseResult[]): DetectionMetricSummary {
  const truePositives = cases.filter((item) => item.classification === "true_positive").length;
  const falseNegatives = cases.filter((item) => item.classification === "false_negative").length;
  const falsePositives = cases.filter((item) => item.classification === "false_positive").length;
  const trueNegatives = cases.filter((item) => item.classification === "true_negative").length;
  return {
    truePositives,
    falseNegatives,
    falsePositives,
    trueNegatives,
    detectionRate: percentage(truePositives, truePositives + falseNegatives),
    precision: percentage(truePositives, truePositives + falsePositives, 100),
    specificity: percentage(trueNegatives, trueNegatives + falsePositives, 100),
    accuracy: percentage(truePositives + trueNegatives, cases.length),
  };
}

function validateManifest(manifest: DetectionManifest) {
  if (!manifest.datasetName.trim()) throw new Error("The detection manifest requires a datasetName.");
  if (!manifest.cases.length) throw new Error("The detection manifest requires at least one labelled case.");
  if (manifest.targetDetectionRate < 0 || manifest.targetDetectionRate > 100) {
    throw new Error("targetDetectionRate must be between 0 and 100.");
  }
  const ids = new Set<string>();
  for (const testCase of manifest.cases) {
    if (ids.has(testCase.id)) throw new Error(`Duplicate detection case id: ${testCase.id}`);
    ids.add(testCase.id);
    if (!Object.keys(testCase.match).length) throw new Error(`Detection case ${testCase.id} has no matching rule.`);
  }
}

export function evaluateScannerDetection(
  manifest: DetectionManifest,
  report: ScanReport,
  evaluatedAt = new Date(),
): DetectionEvaluationResult {
  validateManifest(manifest);
  const matchedFindingIndexes = new Set<number>();
  const cases: DetectionCaseResult[] = manifest.cases.map((testCase) => {
    const findingIndex = report.findings.findIndex((finding) => matchesCase(finding, testCase));
    const detected = findingIndex >= 0;
    if (detected) matchedFindingIndexes.add(findingIndex);
    const classification: DetectionClassification = testCase.expected === "positive"
      ? detected ? "true_positive" : "false_negative"
      : detected ? "false_positive" : "true_negative";
    const finding = detected ? report.findings[findingIndex] : undefined;
    return {
      ...testCase,
      detected,
      classification,
      matchedFinding: finding ? {
        title: finding.title,
        severity: finding.severity,
        location: finding.location,
        cwe: finding.cwe,
        owasp: finding.owasp,
        scan_type: finding.scan_type,
      } : undefined,
    };
  });

  const moduleNames = [...new Set(cases.map((item) => normalizeModule(item.module)))].sort();
  const modules = moduleNames.map((module) => {
    const moduleCases = cases.filter((item) => normalizeModule(item.module) === module);
    return { module, cases: moduleCases.length, ...summarize(moduleCases) };
  });
  const scans = Object.values(report.scans);
  const failedModules = scans.filter((scan) => scan.status !== "completed").map((scan) => scan.scan_type);
  const metrics = summarize(cases);

  return {
    datasetName: manifest.datasetName,
    target: report.target,
    evaluatedAt: evaluatedAt.toISOString(),
    groundTruthSource: manifest.groundTruthSource,
    evidenceBoundary: manifest.evidenceBoundary,
    targetDetectionRate: manifest.targetDetectionRate,
    targetMet: metrics.detectionRate >= manifest.targetDetectionRate,
    moduleCompletion: {
      completed: scans.length - failedModules.length,
      total: scans.length,
      rate: percentage(scans.length - failedModules.length, scans.length),
      failedModules,
    },
    metrics,
    modules,
    unmatchedFindings: Math.max(0, report.findings.length - matchedFindingIndexes.size),
    cases,
  };
}
