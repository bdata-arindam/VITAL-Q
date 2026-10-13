# Reproduction validation

This folder records checks performed while preparing the portable reproduction repository. These are internal engineering and retained-result checks, not independent empirical replication. The original manuscript and its measured results are unchanged.

The final `STATUS.json` is the machine-readable record of completed checks. `REPLAY_REPORT.json` records the numerical replay. `PROOF_VERIFICATION.json` records reverification of retained proofs. `SMOKE_STATUS.json` and `SMOKE_QUALIFICATION.json` report the separately executed small-workload campaign when completed.

The original six numerical notebook cells were reexecuted sequentially in an isolated Python subprocess. Their sources are unchanged and their outputs are included in `Published_Analysis_Reexecuted.ipynb`. This is explicitly recorded as a sequential Python engine, not a graphical Jupyter-kernel execution. A Jupyter kernel attempt in this sandbox failed because local socket/interface operations are restricted. The socket-free runner avoids that environment dependency.

Setup was executed using `bash setup.sh full` into a clean virtual environment. The resolved package versions are in `packaging_environment_freeze.txt`; this file describes the packaging run, not the original historical experiment.

The reduced-size smoke run uses 32 and 128 development records and 256 evaluation records with the original 72/90 history counts, six tasks and two timing modes. It tests generation, verifier qualification, primitive calibration, local checkpoints, pre-evaluation freezing, model fitting, evaluation, analysis, retained-proof verification and plots. Its latency results are not added to the manuscript.

The full fresh command retains the original 1,000/10,000/100,000 record scales. A subsequent full-scale collection completed on 12 October 2026: 162 histories, 864 development measurements, 1,080 evaluation measurements and 486 retained proofs reverified. See `FULL_SCALE_EXECUTION.md` and `FULL_SCALE_AUDIT.json`. The container recipe was not built because Docker is unavailable here. No cross-platform or external-user execution is claimed. Linux x86-64 cryptographic verification uses the supplied native library and the original Python cryptography versions.

The older MHEALTH functional example is outside this primary latency workflow. Original full archives and full-query proof bytes were not retained. New collection regenerates randomized signatures and cannot recover those historical bytes. Local checkpoints are not independently hosted backups or trusted timestamps.

An initial small-workload run reached 162 completed history records but had only 1,070 of the required 1,080 evaluation rows. The original analysis assertion rejected it. The cause of missing rows was not established, and no values were reconstructed. A new checkpoint completeness guard was verified to reject those inputs without overwriting the existing recovery ZIP. The corrected workflow is tested in a separate new run; only a successful completed rerun may be reported as passing in `STATUS.json`.

The first guarded retry stopped at history 22 after detecting only 8 of that history's 12 observations. The portable fresh working copy was then changed to commit the actual in-memory observations atomically as checksummed per-history journals. Combined JSONL files are derived from those journals. A focused recovery test removed an aggregate row and confirmed exact reconstruction from the unchanged recorded journal; modifying a journal without its matching checksum was rejected. This persistence amendment changes untimed I/O only and is recorded in each fresh run. The original scientific release is retained unchanged.

Final journaled test outcome: all 162 histories completed, with 864 development rows and 1,080 evaluation rows. All six models fitted, all 233 qualification checks passed and all 486 newly retained proofs verified. Analysis, plots and final checkpoint validation completed. These small-workload checks do not replace full-scale empirical replication.

The delivery ZIP was extracted into a separate directory. Its root `run.sh replay` then passed using the clean setup environment, including all six original analysis cells, numerical comparisons and figure generation. Validation records were subsequently updated; tested code and supplied data did not change.

## Release record amendment, 13 October 2026

The `execution_agent` field of `src/release/environment.json` was reworded to "automated packaging run; not independent human review". No other byte of the 25-file release changed. Because that file's hash is part of the pre-evaluation freeze manifest, `data/published/audit/freeze.json` was regenerated for that one entry, `freeze_receipt.json` records the new manifest hash with the time of this amendment, and `REFERENCE_SHA256.json` and `SHA256SUMS.txt` were updated for the three files. The original manifest hash was 17144fc484aadaf2f5b4c86f9b24654d3dba677f11f4dd0db62520831787c1c8 for the environment record and b4840ac004158241a2670fd73a39bb4eccd7f12b7c1325ef743e033ac958ed33 for the freeze manifest. Measurements, analyses and retained proofs are unchanged.
