import { Schema, model, models, type Model } from "mongoose";

import type { Finding, ScanSummary, ScannerId } from "@/src/lib/scan-types";

export interface StoredScanRecord {
  ownerId: string;
  target: string;
  selectedScanners: ScannerId[];
  status: string;
  completedAt: Date;
  summary: ScanSummary;
  findings: Finding[];
  scans: Record<string, unknown>;
}

const summarySchema = new Schema<ScanSummary>(
  {
    critical: { type: Number, required: true, min: 0 },
    high: { type: Number, required: true, min: 0 },
    medium: { type: Number, required: true, min: 0 },
    low: { type: Number, required: true, min: 0 },
    info: { type: Number, required: true, min: 0 },
    total_findings: { type: Number, required: true, min: 0 },
  },
  { _id: false },
);

const findingSchema = new Schema<Finding>(
  {
    severity: { type: String, required: true, enum: ["critical", "high", "medium", "low", "info"] },
    title: { type: String, required: true, trim: true },
    description: { type: String, required: true },
    evidence: { type: String },
    location: { type: String },
    owasp: { type: String },
    cwe: { type: String },
    recommendation: { type: String },
    scan_type: { type: String },
  },
  { _id: false },
);

const scanRecordSchema = new Schema<StoredScanRecord>(
  {
    ownerId: { type: String, required: true, index: true },
    target: { type: String, required: true, trim: true, index: true },
    selectedScanners: { type: [String], required: true },
    status: { type: String, required: true },
    completedAt: { type: Date, required: true, index: true },
    summary: { type: summarySchema, required: true },
    findings: { type: [findingSchema], default: [] },
    scans: { type: Schema.Types.Mixed, default: {} },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

scanRecordSchema.index({ ownerId: 1, completedAt: -1 });

const ScanRecord: Model<StoredScanRecord> =
  (models.ScanRecord as Model<StoredScanRecord> | undefined) ??
  model<StoredScanRecord>("ScanRecord", scanRecordSchema);

export default ScanRecord;
