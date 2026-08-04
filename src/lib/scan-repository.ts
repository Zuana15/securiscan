import dbConnect, { isMongoConfigured } from "@/src/lib/mongodb";
import type {
  ScanAnalytics,
  ScanHistoryItem,
  ScanPersistence,
  ScanReport,
  ScannerFindingCount,
  ScannerId,
  SeverityBreakdown,
} from "@/src/lib/scan-types";
import ScanRecord from "@/src/models/scan-record";

const HISTORY_LIMIT = 12;
const ANALYTICS_LIMIT = 250;

export async function persistScanReport(
  report: ScanReport,
  selectedScanners: ScannerId[],
  ownerId: string,
): Promise<ScanPersistence> {
  if (!isMongoConfigured()) {
    return {
      state: "unavailable",
      message: "Scan completed, but it was not saved because MONGODB_URI is not configured.",
    };
  }

  try {
    await dbConnect();
    const record = await ScanRecord.create({
      ownerId,
      target: report.target,
      selectedScanners,
      status: report.status,
      completedAt: new Date(report.timestamp),
      summary: report.summary,
      findings: report.findings,
      scans: report.scans,
    });

    return { state: "saved", recordId: record.id };
  } catch (error) {
    console.error("Unable to persist the completed scan", error);
    return {
      state: "failed",
      message: "Scan completed, but the result could not be saved. Check the MongoDB connection.",
    };
  }
}

export async function listScanHistory(ownerId: string, limit = HISTORY_LIMIT): Promise<ScanHistoryItem[]> {
  await dbConnect();
  const records = await ScanRecord.find({ ownerId }).sort({ completedAt: -1 }).limit(limit).lean();

  return records.map((record) => ({
    id: record._id.toString(),
    target: record.target,
    selectedScanners: record.selectedScanners,
    status: record.status,
    completedAt: record.completedAt.toISOString(),
    summary: record.summary,
  }));
}

export async function getScanAnalytics(ownerId: string): Promise<ScanAnalytics> {
  await dbConnect();
  const records = await ScanRecord.find({ ownerId })
    .sort({ completedAt: -1 })
    .limit(ANALYTICS_LIMIT)
    .lean();
  const severity: SeverityBreakdown = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const targets = new Set<string>();
  const trendByDate = new Map<string, { scans: number; findings: number }>();
  const findingsByScanner = new Map<string, number>();
  let totalFindings = 0;

  for (const record of records) {
    targets.add(record.target);
    totalFindings += record.summary.total_findings;
    severity.critical += record.summary.critical;
    severity.high += record.summary.high;
    severity.medium += record.summary.medium;
    severity.low += record.summary.low;
    severity.info += record.summary.info;

    const date = record.completedAt.toISOString().slice(0, 10);
    const trend = trendByDate.get(date) ?? { scans: 0, findings: 0 };
    trend.scans += 1;
    trend.findings += record.summary.total_findings;
    trendByDate.set(date, trend);

    for (const finding of record.findings) {
      const scanType = finding.scan_type ?? "other";
      findingsByScanner.set(scanType, (findingsByScanner.get(scanType) ?? 0) + 1);
    }
  }

  const scannerFindings: ScannerFindingCount[] = [...findingsByScanner.entries()]
    .map(([scanType, findings]) => ({ scanType, findings }))
    .sort((left, right) => right.findings - left.findings)
    .slice(0, 5);

  return {
    totalScans: records.length,
    uniqueTargets: targets.size,
    totalFindings,
    severity,
    trend: [...trendByDate.entries()]
      .map(([date, value]) => ({ date, ...value }))
      .sort((left, right) => left.date.localeCompare(right.date))
      .slice(-7),
    scannerFindings,
  };
}
