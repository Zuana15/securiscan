import { evaluateRiskBenchmark } from "../src/lib/risk-benchmark";

const result = evaluateRiskBenchmark();

console.log("SecuriScan risk-model benchmark");
console.log(`Dataset: ${result.datasetName}`);
console.log(`Labels: ${result.labelSource}`);
console.log(`Calibration cases: ${result.calibrationCases}`);
console.log(`Validation cases: ${result.validationCases}`);
console.log("");
console.log(`CVSS-only pairwise accuracy: ${result.cvssOnly.pairwiseAccuracy}%`);
console.log(`Risk v1 pairwise accuracy: ${result.riskV1.pairwiseAccuracy}%`);
console.log(`Percentage-point gain: ${result.percentagePointGain}`);
console.log(`Relative improvement: ${result.relativeImprovement}%`);
console.log(`30% target met on prototype benchmark: ${result.targetMet ? "yes" : "no"}`);
console.log(`Calibration recommendation: ${result.selectedCandidate}`);
console.log("");
console.log(`Limitation: ${result.limitation}`);
