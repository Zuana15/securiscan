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
}

export interface ScanAnalyticsResponse {
  available: boolean;
  message?: string;
  analytics?: ScanAnalytics;
}
