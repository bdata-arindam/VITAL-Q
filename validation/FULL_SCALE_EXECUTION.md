# Full-scale execution report

Completed successfully on 12 October 2026. This is a new execution of the primary synthetic latency workflow in the recorded Linux environment. The manuscript and published measurements remain unchanged. It is not independent external replication.

## Execution and completeness

| Check | Result |
| --- | --- |
| Development sizes | 1,000 and 10,000 records |
| Development histories / measurements | 72 / 864 |
| Evaluation size | 100,000 records |
| Evaluation histories / measurements | 90 / 1,080 |
| Total histories / measurements | 162 / 1,944 |
| Qualification checks | 233 / 233 passed |
| Newly retained selective proofs reverified | 486 / 486 |
| Complete checksummed history journals | 162 / 162 |
| Model-cell CSV rows reconciled to analysis | 252 / 252 |
| Original reference-file hashes unchanged | 1,015 / 1,015 |
| Final checkpoint member hashes verified | 1,013 / 1,013 |
| Training input hashes and pre-evaluation model freeze | Passed |
| Full-scale elapsed time through final checkpoint | 121.21 minutes |

Start: 2026-10-12T18:56:27.941328+00:00. Final checkpoint: 2026-10-12T20:57:40.268087+00:00. Elapsed time includes qualification, calibration, archive generation, measurements, checkpoints, fitting, analysis, verification and figures. It is not model-fitting time or primitive-calibration cost alone. It excludes the preceding failed attempt, environment setup and subsequent packaging.

## Prediction results

Median absolute relative error is calculated across the 18 evaluation cells, using the original analysis and frozen development fit.

| Mode | Published model error | Fresh model error | Fresh bytes-only error | Fresh point passes | Fresh interval passes | Support rule |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Balanced | 1.6316% | 2.1202% | 38.1448% | 18/18 | 17/18 | Passed |
| Isolated | 2.5545% | 2.2087% | 37.0715% | 18/18 | 16/18 | Passed |

Point passes require absolute relative error at most 15%. Interval passes require the entire pointwise 95% bootstrap interval to fall within ±15%. All point estimates passed; some intervals crossed the tolerance boundary. The original support rule requires at least 15 point passes, at least one point pass in each arm/query stratum, and a lower median absolute relative error than the bytes-only baseline. Both modes passed that rule. Intervals are conditional on the frozen fit and use 10,000 matched-block bootstrap resamples.

## Executed code and retained outputs

`executions/full_scale_20261012/` contains the actual run. Its `revision/release/` is the exact working scientific release used; `revision/measured/` holds calibration, raw observations, histories, barriers and per-history journals; `revision/retained/` holds all retained selective proofs and public enrollment policies. `revision/results/` contains the numerical analysis and model-cell CSV. `revision/figures/` contains PNG and SVG figures. Logs, environment, model coefficients, freeze receipts, validation reports, the pre-evaluation snapshot and final checkpoint are included.

The original scientific source remains under `src/`. The executed portable driver and checkpoint/journal adapters are under `scripts/`. No missing observations were estimated or fabricated. Complete full archives and full-query proof files were verified during collection and deliberately discarded by the original storage protocol; the included code regenerates them. Newly generated signatures and timing values will differ.

## Reproduce and audit

From the extracted `vital-q` folder, run:

```bash
bash setup.sh
bash run.sh all
```

This replays published numerical results, verifies original retained proofs, then runs a new full-scale campaign. To audit the included executed run without recollecting measurements:

```bash
.venv/bin/python scripts/audit_execution.py
```

For the equivalent full-scale execution used here, with disposable files on a standard local temporary filesystem:

```bash
bash run.sh fresh --output /tmp/vital-q-fresh-001
```

Choose a new output path; existing paths are refused. Keep the completed output folder if you need it after temporary-directory cleanup. Historical absolute paths in logs and receipts document the execution location; the supplied working code resolves data relative to its own location.

## Disclosed incomplete attempt and limits

An initial attempt in the managed workspace stopped after 53 successful histories. History 54 completed its measurements but failed during untimed `shutil.rmtree` cleanup with `OSError: Directory not empty`. Its failure record and last-checkpoint receipt are in `validation/FULL_SCALE_INCOMPLETE_ATTEMPT.json`. No observations from that attempt were reused. The full workflow was restarted from qualification in a new standard temporary directory using the same runner and scientific code, and completed with all 162 histories successful. The filesystem cause was not established; no cleanup code change is claimed.

All measurements remain warm-cache local verification. No cold-cache, network-storage, different-hardware or production-trust experiments were added. Local checkpoints and clock records are not trusted timestamps or independent hosted backups. Docker and the historical secondary MHEALTH example were not executed. Public GitHub publication remains a separate step; this ZIP is a ready-to-upload repository, not a claim that a public URL exists.
