"""Preparation and analysis helpers. NOT an archive engine or PQ benchmark.

All files are created exclusively: reruns need a new output directory.
No signing key is generated or published by these helpers.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import importlib.metadata
import json
import math
import platform
import random
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path

FEATURES = [f"{a}_{op}" for a in ("ecdsa", "mldsa", "slhdsa")
            for op in ("keygen", "sign", "verify")] + [
    "sha256_calls", "sha256_bytes", "sha384_calls", "sha384_bytes",
    "encode_objects", "encode_bytes", "decode_objects", "decode_bytes",
    "read_calls", "read_bytes", "write_calls", "write_bytes",
    "barrier_calls", "subject_visits"]
ZIP_SHA256 = "16ad0ce709f3f00df18f348610d15bce0884b79e2143f57f446493673f02b8e0"
CELLS = [(a, q, r) for a in "NED" for q in ("selective", "full") for r in (0, 2, 5)]


def canonical(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def write_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as f:
        f.write(canonical(obj) + b"\n")


def read_json(path):
    with Path(path).open(encoding="utf-8") as f:
        return json.load(f)


def newdir(path):
    path = Path(path)
    path.mkdir(parents=True, exist_ok=False)
    return path


def ledger(n, g, ell=12):
    if n < 1 or g < 1 or ell < 0:
        raise ValueError("n and g must be positive; ell must be nonnegative")
    k = (n + 4095) // 4096
    c = 64 + 1040 * n
    u, keys = 212 + 3457 * (g - 1), 144 + 2031 * (g - 1)
    v, j = 35844 * g, 127 * g
    h = lambda width: 40 * k + width * (2 * n - k)
    return {"record_count": n, "generations": g, "batches": k,
            "classification": "analytical_not_measured",
            "archive_bytes": {"N": c + keys + n * u,
                              "E": c + keys + k * u + h(32),
                              "D": c + keys + j + k * (u + v) + h(32) + h(48)},
            "proof_bytes_at_supplied_sibling_count": {
                "N": 1104 + keys + u,
                "E": 1104 + keys + u + 40 + 32 * ell,
                "D": 1104 + keys + j + u + v + 80 + 80 * ell},
            "sibling_count": ell,
            "full_token_checks": {"N": n * g, "E": k * g, "D": 2 * k * g}}


def path_length(leaves, index):
    if leaves < 1 or not 0 <= index < leaves:
        raise ValueError("Invalid leaf or index")
    count = 0
    while leaves > 1:
        if (index ^ 1) < leaves:
            count += 1
        index //= 2
        leaves = (leaves + 1) // 2
    return count


def schedule(out, seed):
    rng = random.Random(seed)
    rows = []
    phases = [("pilot", [1000], "NE", 10, 2),
              ("development", [1000, 10000], "NED", 10, 5),
              ("confirmatory", [100000], "NED", 30, 5),
              ("case", [5005], "NED", 10, 5)]
    for phase, sizes, arms, blocks, renewals in phases:
        for n in sizes:
            for b in range(blocks):
                block = f"{phase}-{n}-{b:02d}"
                query = rng.randrange(n)
                order = list(arms)
                rng.shuffle(order)
                for position, arm in enumerate(order):
                    rows.append({"history_id": f"{block}-{arm}", "phase": phase,
                        "block_id": block, "arm": arm, "n": n, "renewals": renewals,
                        "arm_order": position, "query_id": query,
                        "status": "planned", "workload_seed": rng.randrange(2**32)})
    write_json(out, {"protocol": "P_H_1.4_support_v1", "schedule_seed": seed,
                     "warning": "Workload seeds never seed cryptographic keys",
                     "histories": rows})
    return rows


def preflight(out):
    versions = {}
    for name in ("numpy", "scipy", "cryptography", "liboqs-python"):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    info = {"platform": platform.platform(), "machine": platform.machine(),
            "python": sys.version, "dependencies": versions,
            "disk_free_bytes": shutil.disk_usage(Path.cwd()).free,
            "native_macos": sys.platform == "darwin",
            "cryptographic_binding_test": "NOT_RUN",
            "APFS_and_internal_SSD": "AUTHOR_MUST_VERIFY",
            "archive_runner": "NOT_INCLUDED",
            "confirmatory_ready": False,
            "note": "This inventory does not import oqs or download native libraries."}
    write_json(out, info)
    return info


def durability_probe(out):
    if sys.platform != "darwin":
        raise RuntimeError("Native macOS required; no fsync fallback is permitted")
    import fcntl
    import os
    if not hasattr(fcntl, "F_FULLFSYNC"):
        raise RuntimeError("F_FULLFSYNC is unavailable; do not substitute fsync")
    dest = newdir(out)
    p = dest / "probe.bin"
    with p.open("xb", buffering=0) as f:
        start = time.perf_counter_ns()
        f.write(b"probe" * 1024)
        fcntl.fcntl(f.fileno(), fcntl.F_FULLFSYNC)
        elapsed = time.perf_counter_ns() - start
    result = {"F_FULLFSYNC_returned": True, "elapsed_ns": elapsed,
              "sha256": sha(p), "power_loss_test": False,
              "name_durability_validated": False,
              "note": "Call feasibility only, not the complete campaign durability gate"}
    write_json(dest / "probe.json", result)
    return result


def selected_indices(rows):
    blocks = rows // 100
    if blocks < 500:
        raise ValueError("Fewer than 500 complete windows")
    ids = [(j * (blocks - 1)) // 499 for j in range(500)]
    if len(set(ids)) != 500:
        raise ValueError("Duplicate selected blocks")
    return ids


def mhealth(zip_path, out):
    import numpy as np
    zip_path = Path(zip_path)
    if sha(zip_path) != ZIP_SHA256:
        raise ValueError("Dataset digest differs from the supplied plan; do not silently repin")
    dest = newdir(out)
    windows_dir = dest / "windows"
    windows_dir.mkdir()
    catalogue, rawfiles, feature_rows, labels, subjects, ids = [], [], [], [], [], []
    used = [0, 1, 2] + list(range(5, 23))
    start = time.perf_counter()
    with zipfile.ZipFile(zip_path) as z:
        for s in range(1, 11):
            matches = [x for x in z.namelist() if x.endswith(f"/mHealth_subject{s}.log")
                       or x == f"mHealth_subject{s}.log"]
            if len(matches) != 1:
                raise ValueError(f"Subject {s}: expected one source log")
            data = z.read(matches[0])
            lines = data.splitlines(keepends=True)
            offsets = [0]
            for line in lines:
                offsets.append(offsets[-1] + len(line))
            rawfiles.append({"subject": s, "archive_entry": matches[0],
                             "sha256": hashlib.sha256(data).hexdigest(),
                             "rows": len(lines), "bytes": len(data)})
            for index in selected_indices(len(lines)):
                rid = f"s{s:02d}-b{index:06d}"
                lo, hi = index * 100, (index + 1) * 100
                payload = data[offsets[lo]:offsets[hi]]
                # Per-row parsing rejects malformed widths without flattening rows.
                arr = np.asarray([[float(v) for v in line.split()]
                                  for line in lines[lo:hi]], dtype=np.float64)
                if arr.shape != (100, 24) or not np.isfinite(arr).all():
                    raise ValueError(f"Malformed or nonfinite window {rid}")
                yy = arr[:, 23]
                if not np.all(yy == np.floor(yy)) or not np.all((yy >= 0) & (yy <= 12)):
                    raise ValueError(f"Invalid activity label in {rid}")
                label = int(np.bincount(yy.astype(int), minlength=13).argmax())
                vals = arr[:, used]
                features = np.concatenate((vals.mean(axis=0), vals.std(axis=0, ddof=0)))
                relative = f"windows/{rid}.bin"
                with (dest / relative).open("xb") as f:
                    f.write(payload)
                catalogue.append({"record_id": rid, "subject": s, "block": index,
                                  "start_byte": offsets[lo], "end_byte": offsets[hi],
                                  "payload_path": relative,
                                  "payload_sha256": hashlib.sha256(payload).hexdigest(),
                                  "label": label})
                feature_rows.append(features)
                labels.append(label)
                subjects.append(s)
                ids.append(rid)
    x, y, ss = np.asarray(feature_rows), np.asarray(labels), np.asarray(subjects)
    train, test = (ss <= 7) & (y != 0), (ss >= 8) & (y != 0)
    if not train.any() or not test.any():
        raise ValueError("No nonzero-label training or test rows")
    mean, sd = x[train].mean(0), x[train].std(0, ddof=0)
    sd[sd == 0] = 1
    scaled = (x - mean) / sd
    classes = np.unique(y[train])
    centroids = np.stack([scaled[train & (y == c)].mean(0) for c in classes])
    pred = classes[((scaled[test, None, :] - centroids[None, :, :])**2).sum(2).argmin(1)]
    cm = np.zeros((12, 12), dtype=int)
    for truth, prediction in zip(y[test], pred):
        cm[truth - 1, prediction - 1] += 1
    write_json(dest / "catalogue.json", {"source_zip_sha256": ZIP_SHA256,
              "raw_files": rawfiles, "windows": catalogue,
              "sensor_columns_one_based": [i + 1 for i in used]})
    write_json(dest / "features.json", {"catalogue_sha256": sha(dest / "catalogue.json"),
              "record_ids": ids, "features": x.tolist(), "labels": y.tolist()})
    write_json(dest / "split.json", {"catalogue_sha256": sha(dest / "catalogue.json"),
              "train_subjects": list(range(1, 8)), "test_subjects": [8, 9, 10],
              "training_ids": [ids[i] for i in np.flatnonzero(train)],
              "evaluation_ids": [ids[i] for i in np.flatnonzero(test)],
              "zero_label_exclusions": int((y == 0).sum())})
    parents = {"features_sha256": sha(dest / "features.json"),
               "split_sha256": sha(dest / "split.json")}
    write_json(dest / "model.json", {**parents, "algorithm": "standardized_nearest_centroid",
              "mean": mean.tolist(), "std": sd.tolist(), "classes": classes.tolist(),
              "centroids": centroids.tolist(), "unlearned_classes": sorted(set(range(1, 13)) - set(classes.tolist()))})
    write_json(dest / "evaluation.json", {**parents, "model_sha256": sha(dest / "model.json"),
              "accuracy": float((pred == y[test]).mean()),
              "confusion_matrix_labels": list(range(1, 13)), "confusion_matrix": cm.tolist(),
              "class_supports": np.bincount(y[test], minlength=13)[1:].tolist(),
              "truth": y[test].tolist(), "predictions": pred.tolist(),
              "record_ids": [ids[i] for i in np.flatnonzero(test)]})
    write_json(dest / "receipt.json", {"elapsed_seconds": time.perf_counter() - start,
              "windows": len(ids), "feature_shape": list(x.shape),
              "artifact_objects_for_manifests": len(ids) + 5,
              "source_zip_sha256": ZIP_SHA256, "code_sha256": sha(__file__),
              "evidence_manifests_created": False,
              "note": "Only payload preparation; signing and 1024-byte manifests require the archive engine"})
    return {"windows": len(ids), "features": list(x.shape), "archive_experiment_run": False}


def fit_arrays(x, y):
    import numpy as np
    from scipy.optimize import nnls
    x, y = np.asarray(x, dtype=float), np.asarray(y, dtype=float)
    if x.ndim != 2 or x.shape[1] != 23 or y.shape != (len(x),):
        raise ValueError("Calibration needs 23 features and one elapsed time per row")
    if not np.isfinite(x).all() or not np.isfinite(y).all() or (x < 0).any() or (y <= 0).any():
        raise ValueError("Calibration counts must be nonnegative and elapsed times positive")
    scale = np.linalg.norm(x, axis=0)
    if (scale == 0).any():
        raise ValueError("At least one calibration feature is never varied")
    normalized = x / scale
    if np.linalg.matrix_rank(normalized) != 23:
        raise ValueError("Rank-deficient calibration design")
    beta_scaled, residual = nnls(normalized, y)
    return beta_scaled / scale, {"rank": 23, "condition_number": float(np.linalg.cond(normalized)),
                                 "residual_l2_seconds": float(residual)}


def load_cal(path):
    import numpy as np
    c = read_json(path)
    if c.get("features") != FEATURES or c.get("phase") != "calibration":
        raise ValueError("Wrong calibration feature order or phase")
    if c.get("evidence_type") != "measured":
        raise ValueError("Only measured calibration input is accepted")
    rows = c["rows"]
    if not rows:
        raise ValueError("No calibration measurements")
    blocks = sorted({r["block_id"] for r in rows})
    if len(blocks) < 10:
        raise ValueError("At least ten complete calibration blocks are required")
    indices = []
    for b in blocks:
        idx = [i for i, r in enumerate(rows) if r["block_id"] == b]
        fit_arrays([rows[i]["counts"] for i in idx], [rows[i]["seconds"] for i in idx])
        indices.append(idx)
    x = np.asarray([r["counts"] for r in rows], dtype=float)
    y = np.asarray([r["seconds"] for r in rows], dtype=float)
    beta, diag = fit_arrays(x, y)
    return x, y, indices, beta, diag


def fit_command(calibration, out):
    x, y, blocks, beta, diag = load_cal(calibration)
    result = {"features": FEATURES, "coefficients_seconds": beta.tolist(),
              "diagnostics": diag, "calibration_sha256": sha(calibration),
              "calibration_blocks": len(blocks), "calibration_rows": len(x)}
    write_json(out, result)
    return result


def analyze(calibration, observations, frozen_coefficients, out, draws, seed):
    import numpy as np
    xcal, ycal, calibration_blocks, beta, diagnostics = load_cal(calibration)
    frozen = read_json(frozen_coefficients)
    if (frozen.get("features") != FEATURES or frozen.get("calibration_sha256") != sha(calibration)
        or not np.allclose(beta, frozen.get("coefficients_seconds", []), rtol=1e-12, atol=0)):
        raise ValueError("Calibration no longer agrees with the frozen coefficient file")
    o = read_json(observations)
    if o.get("phase") != "confirmatory" or o.get("features") != FEATURES or o.get("evidence_type") != "measured":
        raise ValueError("Only measured confirmatory observations in the declared schema are accepted")
    planned = o["planned_block_ids"]
    if len(planned) != 30 or len(set(planned)) != 30:
        raise ValueError("Exactly 30 unique planned matched blocks are required")
    by_cell = {c: {} for c in CELLS}
    for r in o["rows"]:
        c, b = (r["arm"], r["query"], r["renewals"]), r["block_id"]
        if c not in by_cell or b not in planned or b in by_cell[c]:
            raise ValueError("Unexpected cell/block or duplicate observation")
        if r.get("n") != 100000 or r.get("phase") != "confirmatory":
            raise ValueError("Wrong observation size or phase")
        if r.get("status") == "ok":
            v = np.asarray(r["counts"], dtype=float)
            if v.shape != (23,) or not np.isfinite(v).all() or (v < 0).any():
                raise ValueError("Invalid operation counts")
            t = float(r["seconds"])
            if not math.isfinite(t) or t <= 0 or r.get("bytes_match") is not True:
                raise ValueError("Nonpositive latency or byte-conformance failure")
        by_cell[c][b] = r
    eligible, counts, times, records = [], [], [], []
    for c in CELLS:
        rows = by_cell[c]
        ok = len(rows) == 30 and all(rows[b]["status"] == "ok" for b in planned)
        eligible.append(ok)
        record = {"arm": c[0], "query": c[1], "renewals": c[2],
                  "observations_ok": sum(r["status"] == "ok" for r in rows.values()),
                  "complete": ok, "point_pass": False, "qualified": False}
        if ok:
            xc = np.asarray([rows[b]["counts"] for b in planned], float)
            yc = np.asarray([rows[b]["seconds"] for b in planned], float)
            prediction, observed = float(np.median(xc @ beta)), float(np.median(yc))
            error = (prediction - observed) / observed
            record.update(predicted_median_seconds=prediction, observed_median_seconds=observed,
                          relative_error=error, point_pass=bool(abs(error) <= .15))
            counts.append(xc); times.append(yc)
        else:
            counts.append(None); times.append(None)
        records.append(record)
    if draws < 100:
        raise ValueError("Use at least 100 draws for testing and 10000 for confirmation")
    rng = np.random.default_rng(seed)
    errors = np.full((draws, 18), np.nan)
    for d in range(draws):
        history_sample = rng.integers(0, 30, 30)
        chosen = rng.integers(0, len(calibration_blocks), len(calibration_blocks))
        ix = np.concatenate([calibration_blocks[i] for i in chosen])
        coeff, _ = fit_arrays(xcal[ix], ycal[ix])
        for j in range(18):
            if eligible[j]:
                predicted = np.median(counts[j][history_sample] @ coeff)
                actual = np.median(times[j][history_sample])
                errors[d, j] = (predicted - actual) / actual
    for j, record in enumerate(records):
        if eligible[j]:
            lo, hi = np.percentile(errors[:, j], [2.5, 97.5])
            record.update(error_interval_95=[float(lo), float(hi)],
                          qualified=bool(lo >= -.15 and hi <= .15))
    point = sum(r["point_pass"] for r in records)
    qualified = sum(r["qualified"] for r in records)
    strata = []
    for arm in "NED":
        for query in ("selective", "full"):
            rr = [r for r in records if r["arm"] == arm and r["query"] == query]
            strata.append({"arm": arm, "query": query,
                           "point_pass_fraction": sum(r["point_pass"] for r in rr) / 3,
                           "qualified_cells": sum(r["qualified"] for r in rr)})
    coverage = np.mean(np.abs(errors) <= .15, axis=1)  # NaN remains a nonpass.
    result = {"classification": "analysis_of_supplied_measured_inputs",
              "input_provenance_independently_audited": False,
              "calibration_sha256": sha(calibration), "observations_sha256": sha(observations),
              "coefficient_sha256": sha(frozen_coefficients), "draws": draws, "seed": seed,
              "cells": records, "strata": strata,
              "point_passes": point, "primary_coverage": point / 18,
              "coverage_interval_95": np.percentile(coverage, [2.5, 97.5]).tolist(),
              "qualified_cells": qualified,
              "secondary_support": bool(qualified >= 15 and all(s["qualified_cells"] >= 1 for s in strata)),
              "collection_complete": all(eligible), "diagnostics": diagnostics,
              "warning": "Pointwise intervals and fixed-grid coverage, not simultaneous or population guarantees"}
    dest = newdir(out)
    write_json(dest / "analysis.json", result)
    columns = ["arm", "query", "renewals", "observations_ok", "complete", "predicted_median_seconds",
               "observed_median_seconds", "relative_error", "error_interval_95", "point_pass", "qualified"]
    with (dest / "cells.csv").open("x", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader(); writer.writerows(records)
    return {"point_passes": point, "qualified_cells": qualified,
            "secondary_support": result["secondary_support"], "collection_complete": all(eligible)}


def freeze(root, out):
    root = Path(root).resolve()
    output = Path(out).resolve()
    if not root.is_dir() or root == Path(root.anchor) or output.is_relative_to(root):
        raise ValueError("Use a specific existing release directory and an output outside it")
    files = sorted(p for p in root.rglob("*") if p.is_file())
    if not files or any(p.is_symlink() for p in root.rglob("*")):
        raise ValueError("Release must be nonempty and contain no symlinks")
    write_json(output, {"files": {p.relative_to(root).as_posix(): sha(p) for p in files},
                        "note": "Integrity snapshot, not a trusted timestamp or proof of preregistration"})
    return {"files": len(files)}


def verify_freeze(root, manifest):
    root = Path(root).resolve()
    old = read_json(manifest)["files"]
    if any(p.is_symlink() for p in root.rglob("*")):
        raise ValueError("Symlink in release")
    now = {p.relative_to(root).as_posix(): sha(p) for p in root.rglob("*") if p.is_file()}
    if old != now:
        raise ValueError("Release changed, has missing files, or has extra files")
    return {"unchanged": True, "files": len(now)}


def selftest():
    import numpy as np
    a = ledger(100000, 6)
    assert a["archive_bytes"] == {"N": 1853710363, "E": 110847988, "D": 125825150}
    assert ledger(5005, 6)["archive_bytes"] == {"N": 92788048, "E": 5570893, "D": 6482247}
    assert a["proof_bytes_at_supplied_sibling_count"]["N"] == 28900
    assert a["proof_bytes_at_supplied_sibling_count"]["E"] == 29324
    assert path_length(4096, 0) == 12 and path_length(5, 4) == 1
    assert path_length(1, 0) == 0 and len(set(selected_indices(98304))) == 500
    true = np.arange(1, 24, dtype=float) / 100
    beta, _ = fit_arrays(np.eye(23), true)
    assert np.allclose(beta, true)
    try:
        fit_arrays(np.ones((50, 23)), np.ones(50))
    except ValueError:
        pass
    else:
        raise AssertionError("Rank deficiency accepted")
    with tempfile.TemporaryDirectory(prefix="pq_support_test_") as t:
        p = Path(t)
        rows = schedule(p / "schedule.json", 20260920)
        assert len(rows) == 200
        assert sum(x["phase"] == "confirmatory" for x in rows) == 90
        for phase in ("pilot", "development", "confirmatory", "case"):
            rr = [x for x in rows if x["phase"] == phase]
            for b in {x["block_id"] for x in rr}:
                assert len({x["query_id"] for x in rr if x["block_id"] == b}) == 1
        release = p / "release"; release.mkdir()
        write_json(release / "a.json", {"test": True})
        freeze(release, p / "freeze.json")
        assert verify_freeze(release, p / "freeze.json")["unchanged"]
    return {"support_selftest": "PASS", "research_measurements": "NONE",
            "scope": "Ledger, promoted-node paths, selection, scheduling, rank check and freeze integrity"}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    for c in ("ledger", "schedule", "preflight", "durability-probe"):
        p = sub.add_parser(c); p.add_argument("--out", required=True)
        if c == "schedule": p.add_argument("--seed", type=int, default=20260920)
    p = sub.add_parser("mhealth"); p.add_argument("--zip", required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("fit"); p.add_argument("--calibration", required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("analyze")
    for name in ("calibration", "observations", "coefficients", "out"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--draws", type=int, default=10000); p.add_argument("--seed", type=int, default=92845)
    for c in ("freeze", "verify-freeze"):
        p = sub.add_parser(c); p.add_argument("--root", required=True)
        p.add_argument("--out" if c == "freeze" else "--manifest", required=True)
    a = ap.parse_args()
    if a.cmd == "selftest": result = selftest()
    elif a.cmd == "ledger":
        result = [ledger(n, 6) for n in (5005, 100000)]; write_json(a.out, result)
    elif a.cmd == "schedule": result = {"histories": len(schedule(a.out, a.seed))}
    elif a.cmd == "preflight": result = preflight(a.out)
    elif a.cmd == "durability-probe": result = durability_probe(a.out)
    elif a.cmd == "mhealth": result = mhealth(a.zip, a.out)
    elif a.cmd == "fit": result = fit_command(a.calibration, a.out)
    elif a.cmd == "analyze": result = analyze(a.calibration, a.observations, a.coefficients, a.out, a.draws, a.seed)
    elif a.cmd == "freeze": result = freeze(a.root, a.out)
    else: result = verify_freeze(a.root, a.manifest)
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
