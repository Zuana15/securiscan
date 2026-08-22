import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import {
  evaluateScannerDetection,
  type DetectionManifest,
} from "../src/lib/detection-evaluation";
import type { ScanReport } from "../src/lib/scan-types";

function option(name: string) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

async function readJson<T>(filePath: string): Promise<T> {
  return JSON.parse(await readFile(filePath, "utf8")) as T;
}

async function main() {
  const manifestPath = option("--manifest");
  const reportPath = option("--report");
  const outputPath = option("--output");
  if (!manifestPath || !reportPath) {
    throw new Error(
      "Usage: npm run scanner:evaluate -- --manifest <ground-truth.json> --report <scan-report.json> [--output <result.json>] [--require-target]",
    );
  }

  const [manifest, report] = await Promise.all([
    readJson<DetectionManifest>(manifestPath),
    readJson<ScanReport>(reportPath),
  ]);
  const result = evaluateScannerDetection(manifest, report);

  if (outputPath) {
    await mkdir(path.dirname(path.resolve(outputPath)), { recursive: true });
    await writeFile(outputPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
  }

  console.log(`Dataset: ${result.datasetName}`);
  console.log(`Module completion: ${result.moduleCompletion.completed}/${result.moduleCompletion.total} (${result.moduleCompletion.rate}%)`);
  console.log(`True-positive detection rate: ${result.metrics.detectionRate}% (${result.metrics.truePositives}/${result.metrics.truePositives + result.metrics.falseNegatives})`);
  console.log(`Precision: ${result.metrics.precision}% | Specificity: ${result.metrics.specificity}% | Accuracy: ${result.metrics.accuracy}%`);
  console.log(`Unmatched findings requiring review: ${result.unmatchedFindings}`);
  console.log(`Target: >=${result.targetDetectionRate}% | ${result.targetMet ? "MET" : "NOT MET"}`);
  console.log(`Evidence boundary: ${result.evidenceBoundary}`);
  if (outputPath) console.log(`Result written to ${outputPath}`);

  if (process.argv.includes("--require-target") && !result.targetMet) process.exitCode = 2;
}

void main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
