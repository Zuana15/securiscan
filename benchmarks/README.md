# Risk ranking benchmark v1

The executable dataset is defined in `src/lib/risk-benchmark.ts`. It contains
24 developer-authored vulnerability scenarios with manually assigned 0-100
remediation-urgency labels:

- 12 calibration cases used to compare five candidate weight profiles.
- 12 separate validation cases used to compare Risk v1 with CVSS-only ranking.

The primary metric is pairwise ranking accuracy: for every validation pair with
different expected urgency, the evaluator checks whether the model puts the more
urgent finding first. Tied model scores receive half credit. Mean absolute error
is included as a secondary calibration metric.

Run the repeatable evaluation with:

```bash
npm run risk:benchmark
```

## Evidence boundary

This dataset verifies the evaluation pipeline and provides prototype evidence;
it is not an independent validation study. The scenario authors also developed
the model, so the labels may encode model assumptions. Before reporting the 30%
improvement as a research result, replace or supplement the validation split with:

1. Findings captured from authorized WebGoat and DVWA assessments.
2. Blinded urgency labels from multiple independent security practitioners.
3. Inter-rater agreement and a documented method for resolving disagreements.
4. A frozen model and untouched holdout set evaluated only once.
5. Confidence intervals and sensitivity analysis across asset contexts.

# Scanner detection evaluation

The `detection/` directory contains the labelled-case evaluator for Objective 1.
It compares a frozen SecuriScan JSON report with an explicit ground-truth manifest
and reports:

- true positives, false negatives, false positives, and true negatives;
- true-positive detection rate (recall), precision, specificity, and accuracy;
- completion rate for the selected scanner modules;
- per-module metrics and unmatched findings requiring manual review.

The local demonstration manifest traces every label to a route, response, header,
form, or method in `scanners/demo_target.py`. Reproduce it with:

```powershell
Start-Process -FilePath .venv\Scripts\python.exe -ArgumentList scanners/demo_target.py
.venv\Scripts\python.exe scanners/run_scan.py http://127.0.0.1:8080 --output reports/demo-scan.json
npm run scanner:evaluate -- --manifest benchmarks/detection/securiscan-demo-ground-truth.json --report reports/demo-scan.json --output reports/demo-evaluation.json --require-target
```

The result recorded on 21 August 2026 completed 9/9 modules and detected 34/34
labelled positive cases. This is a developer-authored integration benchmark, not
independent proof of the proposal's WebGoat/DVWA target. Two additional open-port
findings from services running on the evaluation computer were left unmatched for
manual review rather than being incorrectly counted as labelled true positives.

`webgoat-dvwa-ground-truth.template.json` defines the required format for the
formal study. Replace its placeholder only after fixing exact application versions
and configurations, selecting scanner-reachable lessons, and obtaining blinded
labels. Keep the resulting scan report unchanged, document every excluded lesson,
and run the evaluator once against the frozen manifest. Never copy the local demo's
100% figure into the formal WebGoat/DVWA claim.
