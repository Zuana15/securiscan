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
