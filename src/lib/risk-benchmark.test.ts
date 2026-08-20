import assert from "node:assert/strict";
import test from "node:test";

import { evaluateRiskBenchmark, RISK_BENCHMARK_CASES } from "./risk-benchmark";

test("uses separate calibration and validation scenarios", () => {
  const calibrationIds = new Set(
    RISK_BENCHMARK_CASES.filter((item) => item.split === "calibration").map((item) => item.id),
  );
  const validationIds = RISK_BENCHMARK_CASES
    .filter((item) => item.split === "validation")
    .map((item) => item.id);

  assert.equal(calibrationIds.size, 12);
  assert.equal(validationIds.length, 12);
  assert.ok(validationIds.every((id) => !calibrationIds.has(id)));
});

test("keeps benchmark labels valid and identifiers unique", () => {
  const ids = new Set(RISK_BENCHMARK_CASES.map((item) => item.id));

  assert.equal(ids.size, RISK_BENCHMARK_CASES.length);
  assert.ok(RISK_BENCHMARK_CASES.every((item) => item.expectedUrgency >= 0 && item.expectedUrgency <= 100));
});

test("reports bounded comparison metrics and a calibration recommendation", () => {
  const result = evaluateRiskBenchmark();

  assert.ok(result.cvssOnly.pairwiseAccuracy >= 0 && result.cvssOnly.pairwiseAccuracy <= 100);
  assert.ok(result.riskV1.pairwiseAccuracy >= 0 && result.riskV1.pairwiseAccuracy <= 100);
  assert.ok(result.riskV1.pairwiseAccuracy > result.cvssOnly.pairwiseAccuracy);
  assert.ok(result.candidates.some((candidate) => candidate.id === result.selectedCandidate && candidate.selected));
});
