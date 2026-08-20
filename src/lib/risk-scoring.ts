import {
  ASSET_CRITICALITIES,
  BUSINESS_IMPACTS,
  COMPENSATING_CONTROL_LEVELS,
  EXPOSURE_LEVELS,
  THREAT_INTEL_LEVELS,
  type Finding,
  type FindingRisk,
  type RiskContext,
  type RiskPriority,
  type RiskSummary,
  type ScanReport,
  type Severity,
} from "@/src/lib/scan-types";

export const DEFAULT_RISK_CONTEXT: RiskContext = {
  assetCriticality: "moderate",
  exposure: "public",
  threatIntel: "none",
  businessImpact: "moderate",
  compensatingControls: "none",
};

export interface RiskModelWeights {
  severity: number;
  assetCriticality: number;
  exposure: number;
  threatIntel: number;
  businessImpact: number;
  exploitability: number;
  compensatingControls: number;
}

export const RISK_V1_WEIGHTS: RiskModelWeights = {
  severity: 35,
  assetCriticality: 15,
  exposure: 15,
  threatIntel: 10,
  businessImpact: 15,
  exploitability: 10,
  compensatingControls: 15,
};

const severityCvss: Record<Severity, number> = {
  critical: 9.5,
  high: 8,
  medium: 5.5,
  low: 3,
  info: 0,
};

const contextWeights = {
  assetCriticality: { low: 0.25, moderate: 0.5, high: 0.75, critical: 1 },
  exposure: { internal: 0.2, authenticated: 0.55, public: 1 },
  threatIntel: { none: 0, emerging: 0.55, active: 1 },
  businessImpact: { low: 0.25, moderate: 0.5, high: 0.75, severe: 1 },
  compensatingControls: { none: 0, partial: 0.5, strong: 1 },
} as const;

const contextLabels = {
  low: "Low",
  moderate: "Moderate",
  high: "High",
  critical: "Critical",
  internal: "Internal",
  authenticated: "Authenticated",
  public: "Public internet",
  none: "None",
  emerging: "Emerging reports",
  active: "Active exploitation",
  severe: "Severe",
  partial: "Partial",
  strong: "Strong",
} as const;

const exploitabilityByScanType: Record<string, number> = {
  sql_injection: 1,
  xss: 0.9,
  sensitive_files: 0.9,
  http_misconfiguration: 0.7,
  csrf: 0.65,
  port_scan: 0.55,
  security_headers: 0.45,
  ssl_tls: 0.4,
  tech_fingerprint: 0.15,
};

function includesValue<T extends string>(values: readonly T[], value: unknown): value is T {
  return typeof value === "string" && values.includes(value as T);
}

export function parseRiskContext(value: unknown): RiskContext {
  if (value === undefined) return DEFAULT_RISK_CONTEXT;
  if (!value || typeof value !== "object") {
    throw new Error("Provide valid risk context for this assessment.");
  }

  const input = value as Record<string, unknown>;
  if (
    !includesValue(ASSET_CRITICALITIES, input.assetCriticality) ||
    !includesValue(EXPOSURE_LEVELS, input.exposure) ||
    !includesValue(THREAT_INTEL_LEVELS, input.threatIntel) ||
    !includesValue(BUSINESS_IMPACTS, input.businessImpact) ||
    !includesValue(COMPENSATING_CONTROL_LEVELS, input.compensatingControls)
  ) {
    throw new Error("The selected risk-context values are not valid.");
  }

  return {
    assetCriticality: input.assetCriticality,
    exposure: input.exposure,
    threatIntel: input.threatIntel,
    businessImpact: input.businessImpact,
    compensatingControls: input.compensatingControls,
  };
}

function round(value: number): number {
  return Math.round(value * 10) / 10;
}

function priorityForScore(score: number): RiskPriority {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 35) return "medium";
  return "low";
}

function isNegativeFinding(finding: Finding): boolean {
  const text = `${finding.title} ${finding.description}`.toLowerCase();
  return finding.severity === "info" && /\b(no |not detected|not observed|none found|completed successfully)\b/.test(text);
}

function exploitabilityForFinding(finding: Finding): { value: number; reason: string } {
  if (isNegativeFinding(finding)) {
    return { value: 0, reason: "The scanner reported a negative or clean-check result." };
  }

  const value = exploitabilityByScanType[finding.scan_type ?? ""] ?? 0.35;
  const reasons: Record<string, string> = {
    sql_injection: "Injection evidence can provide a direct path to backend data.",
    xss: "Reflected input may be exploitable through a crafted browser request.",
    sensitive_files: "The exposed resource can be requested directly without authentication.",
    http_misconfiguration: "The observed server behavior may be invoked remotely.",
    csrf: "A victim browser can potentially submit the unprotected state-changing request.",
    port_scan: "The responding network service increases the remotely reachable attack surface.",
    security_headers: "Missing defensive headers usually require another weakness to exploit.",
    ssl_tls: "Transport weaknesses depend on network position and client behavior.",
    tech_fingerprint: "Technology disclosure primarily supports reconnaissance.",
  };

  return {
    value,
    reason: reasons[finding.scan_type ?? ""] ?? "Exploitability is estimated from the scanner category.",
  };
}

export function scoreFindingWithWeights(
  finding: Finding,
  context: RiskContext,
  weights: RiskModelWeights,
): FindingRisk {
  const cvssEquivalent = severityCvss[finding.severity];
  const exploitability = exploitabilityForFinding(finding);
  const severityContribution = round((cvssEquivalent / 10) * weights.severity);
  const assetContribution = round(contextWeights.assetCriticality[context.assetCriticality] * weights.assetCriticality);
  const exposureContribution = round(contextWeights.exposure[context.exposure] * weights.exposure);
  const threatContribution = round(contextWeights.threatIntel[context.threatIntel] * weights.threatIntel);
  const businessContribution = round(contextWeights.businessImpact[context.businessImpact] * weights.businessImpact);
  const exploitabilityContribution = round(exploitability.value * weights.exploitability);
  const controlsReduction = round(
    contextWeights.compensatingControls[context.compensatingControls] * -weights.compensatingControls,
  );

  const rawScore =
    severityContribution +
    assetContribution +
    exposureContribution +
    threatContribution +
    businessContribution +
    exploitabilityContribution +
    controlsReduction;
  const score = Math.round(
    Math.max(0, Math.min(isNegativeFinding(finding) ? 10 : finding.severity === "info" ? 29 : 100, rawScore)),
  );

  return {
    score,
    priority: priorityForScore(score),
    cvssEquivalent,
    modelVersion: "risk-v1",
    factors: [
      {
        key: "severity",
        label: "Severity / CVSS baseline",
        value: `${finding.severity} (${cvssEquivalent.toFixed(1)})`,
        contribution: severityContribution,
        maxContribution: weights.severity,
        reason: "Scanner severity is converted to a CVSS-like baseline for comparison.",
      },
      {
        key: "assetCriticality",
        label: "Asset criticality",
        value: contextLabels[context.assetCriticality],
        contribution: assetContribution,
        maxContribution: weights.assetCriticality,
        reason: "More critical assets increase the consequence of exploitation.",
      },
      {
        key: "exposure",
        label: "Exposure",
        value: contextLabels[context.exposure],
        contribution: exposureContribution,
        maxContribution: weights.exposure,
        reason: "More reachable attack surfaces receive higher priority.",
      },
      {
        key: "threatIntel",
        label: "Threat context",
        value: contextLabels[context.threatIntel],
        contribution: threatContribution,
        maxContribution: weights.threatIntel,
        reason: "Analyst-supplied exploitation activity raises urgency; no external feed is used in v1.",
      },
      {
        key: "businessImpact",
        label: "Business impact",
        value: contextLabels[context.businessImpact],
        contribution: businessContribution,
        maxContribution: weights.businessImpact,
        reason: "Potential operational or data impact affects remediation order.",
      },
      {
        key: "exploitability",
        label: "Exploitability",
        value: `${Math.round(exploitability.value * 100)}%`,
        contribution: exploitabilityContribution,
        maxContribution: weights.exploitability,
        reason: exploitability.reason,
      },
      {
        key: "compensatingControls",
        label: "Compensating controls",
        value: contextLabels[context.compensatingControls],
        contribution: controlsReduction,
        maxContribution: -weights.compensatingControls,
        reason: "Verified controls reduce urgency but never remove the underlying finding.",
      },
    ],
  };
}

export function scoreFinding(finding: Finding, context: RiskContext): FindingRisk {
  return scoreFindingWithWeights(finding, context, RISK_V1_WEIGHTS);
}

export function summarizeRisk(findings: Finding[]): RiskSummary {
  const scores = findings.flatMap((finding) => finding.risk ? [finding.risk.score] : []);
  const priorities: Record<RiskPriority, number> = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const finding of findings) {
    if (finding.risk) priorities[finding.risk.priority] += 1;
  }

  return {
    averageScore: scores.length ? Math.round(scores.reduce((total, score) => total + score, 0) / scores.length) : 0,
    highestScore: scores.length ? Math.max(...scores) : 0,
    scoredFindings: scores.length,
    priorities,
  };
}

export function scoreScanReport(report: ScanReport, context: RiskContext): ScanReport {
  const findings = report.findings
    .map((finding) => ({ ...finding, risk: scoreFinding(finding, context) }))
    .sort((left, right) => (right.risk?.score ?? 0) - (left.risk?.score ?? 0));

  return {
    ...report,
    findings,
    riskContext: context,
    riskSummary: summarizeRisk(findings),
  };
}
