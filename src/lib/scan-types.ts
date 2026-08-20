export const SCANNER_IDS = [
  "headers",
  "ssl",
  "tech",
  "files",
  "misconfig",
  "port",
  "sql",
  "xss",
  "csrf",
] as const;

export type ScannerId = (typeof SCANNER_IDS)[number];

export const SCANNERS: ReadonlyArray<{
  id: ScannerId;
  name: string;
  description: string;
  active: boolean;
}> = [
  { id: "headers", name: "Security headers", description: "Checks browser and transport security headers.", active: false },
  { id: "ssl", name: "TLS certificate", description: "Reviews certificate validity, protocols, and ciphers.", active: false },
  { id: "tech", name: "Technology discovery", description: "Identifies public technology fingerprints and metadata.", active: false },
  { id: "files", name: "Sensitive files", description: "Looks for publicly exposed configuration and backup files.", active: false },
  { id: "misconfig", name: "HTTP configuration", description: "Reviews methods, cookies, CORS, and related settings.", active: false },
  { id: "port", name: "Common ports", description: "Tests a focused set of common TCP services.", active: true },
  { id: "sql", name: "SQL injection", description: "Tests detected inputs for database error signatures.", active: true },
  { id: "xss", name: "Reflected XSS", description: "Tests detected inputs for unsafe reflection.", active: true },
  { id: "csrf", name: "CSRF controls", description: "Checks state-changing forms for anti-CSRF tokens.", active: false },
];

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const ASSET_CRITICALITIES = ["low", "moderate", "high", "critical"] as const;
export const EXPOSURE_LEVELS = ["internal", "authenticated", "public"] as const;
export const THREAT_INTEL_LEVELS = ["none", "emerging", "active"] as const;
export const BUSINESS_IMPACTS = ["low", "moderate", "high", "severe"] as const;
export const COMPENSATING_CONTROL_LEVELS = ["none", "partial", "strong"] as const;

export type AssetCriticality = (typeof ASSET_CRITICALITIES)[number];
export type ExposureLevel = (typeof EXPOSURE_LEVELS)[number];
export type ThreatIntelLevel = (typeof THREAT_INTEL_LEVELS)[number];
export type BusinessImpact = (typeof BUSINESS_IMPACTS)[number];
export type CompensatingControlLevel = (typeof COMPENSATING_CONTROL_LEVELS)[number];
export type RiskPriority = "critical" | "high" | "medium" | "low";

export interface RiskContext {
  assetCriticality: AssetCriticality;
  exposure: ExposureLevel;
  threatIntel: ThreatIntelLevel;
  businessImpact: BusinessImpact;
  compensatingControls: CompensatingControlLevel;
}

export interface RiskFactor {
  key:
    | "severity"
    | "assetCriticality"
    | "exposure"
    | "threatIntel"
    | "businessImpact"
    | "exploitability"
    | "compensatingControls";
  label: string;
  value: string;
  contribution: number;
  maxContribution: number;
  reason: string;
}

export interface FindingRisk {
  score: number;
  priority: RiskPriority;
  cvssEquivalent: number;
  modelVersion: "risk-v1";
  factors: RiskFactor[];
}

export interface RiskSummary {
  averageScore: number;
  highestScore: number;
  scoredFindings: number;
  priorities: Record<RiskPriority, number>;
}

export interface RiskBenchmarkMetrics {
  pairwiseAccuracy: number;
  meanAbsoluteError: number;
  evaluatedPairs: number;
}

export interface RiskCalibrationCandidate {
  id: string;
  name: string;
  pairwiseAccuracy: number;
  meanAbsoluteError: number;
  selected: boolean;
}

export interface RiskBenchmarkResult {
  datasetName: string;
  labelSource: string;
  calibrationCases: number;
  validationCases: number;
  cvssOnly: RiskBenchmarkMetrics;
  riskV1: RiskBenchmarkMetrics;
  percentagePointGain: number;
  relativeImprovement: number;
  targetImprovement: number;
  targetMet: boolean;
  selectedCandidate: string;
  candidates: RiskCalibrationCandidate[];
  limitation: string;
}

export interface Finding {
  severity: Severity;
  title: string;
  description: string;
  evidence?: string;
  location?: string;
  owasp?: string;
  cwe?: string;
  recommendation?: string;
  scan_type?: string;
  risk?: FindingRisk;
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total_findings: number;
}

export interface ModuleScanResult {
  scan_type: string;
  status: "completed" | "failed";
  summary: ScanSummary;
  metadata?: {
    error?: string;
  };
}

export interface ScanReport {
  target: string;
  scan_type: "full_assessment";
  timestamp: string;
  status: string;
  summary: ScanSummary;
  findings: Finding[];
  scans: Record<string, ModuleScanResult>;
  riskContext?: RiskContext;
  riskSummary?: RiskSummary;
  persistence?: ScanPersistence;
}

export interface ScanPersistence {
  state: "saved" | "unavailable" | "disabled" | "failed";
  recordId?: string;
  message?: string;
}

export interface ScanHistoryItem {
  id: string;
  target: string;
  selectedScanners: ScannerId[];
  status: string;
  completedAt: string;
  summary: ScanSummary;
  riskSummary?: RiskSummary;
}

export interface ScanHistoryResponse {
  available: boolean;
  message?: string;
  items: ScanHistoryItem[];
}

export interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanTrendPoint {
  date: string;
  scans: number;
  findings: number;
}

export interface ScannerFindingCount {
  scanType: string;
  findings: number;
}

export interface ScanAnalytics {
  totalScans: number;
  uniqueTargets: number;
  totalFindings: number;
  severity: SeverityBreakdown;
  trend: ScanTrendPoint[];
  scannerFindings: ScannerFindingCount[];
  risk: RiskSummary;
  benchmark: RiskBenchmarkResult;
}

export interface ScanAnalyticsResponse {
  available: boolean;
  message?: string;
  analytics?: ScanAnalytics;
}
