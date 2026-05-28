"""Tests for the bench loop: stats shape, regression vs baseline."""
from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

import pytest

from pqc_v2x_bench import algorithms as alg_mod
from pqc_v2x_bench import bench as bench_mod
from pqc_v2x_bench import report as report_mod


# Quick algorithms only — keep the test suite under ~30s.
# ECDSA sigs are DER-encoded with variable r/s padding, so we exclude them
# from byte-exact determinism assertions.
FAST_NAMES = ["ECDSA-P256", "ML-DSA-44", "ML-KEM-512", "HQC-128"]
FIXED_SIZE_NAMES = ["ML-DSA-44", "ML-KEM-512", "HQC-128"]


def _fast_algs():
    by_name = {a.name: a for a in alg_mod.list_algorithms()}
    return [by_name[n] for n in FAST_NAMES]


def test_bench_one_sign_shape():
    alg = next(a for a in alg_mod.list_algorithms() if a.name == "ML-DSA-44")
    res = bench_mod.bench_one(alg, iters=5, warmup=1, msg_size=128)
    assert res.algorithm == "ML-DSA-44"
    assert res.kind == "sign"
    assert res.iters == 5
    assert res.sig_size == 2420
    assert res.op1_ms_p50 > 0
    assert res.op2_ms_p50 >= 0  # verify can be sub-microsecond
    # mean and std consistency
    assert res.op1_ms_std >= 0


def test_bench_one_kem_shape():
    alg = next(a for a in alg_mod.list_algorithms() if a.name == "ML-KEM-768")
    res = bench_mod.bench_one(alg, iters=5, warmup=1)
    assert res.kind == "kem"
    assert res.sig_size == 1088  # ciphertext
    assert res.shared_secret_size == 32
    assert res.pubkey_size == 1184


def test_bench_many_writes_full_report():
    rep = bench_mod.bench_many(_fast_algs(), iters=3, warmup=1, msg_size=128)
    assert rep.schema_version == "1"
    assert rep.params["iters"] == 3
    assert rep.params["msg_size"] == 128
    assert len(rep.results) == len(FAST_NAMES)
    assert "machine" in rep.host


def test_bench_determinism_sig_sizes(tmp_path):
    """Fixed-size algorithms produce byte-identical sizes across runs."""
    by_name = {a.name: a for a in alg_mod.list_algorithms()}
    fixed = [by_name[n] for n in FIXED_SIZE_NAMES]
    a = bench_mod.bench_many(fixed, iters=3, warmup=1, msg_size=128)
    b = bench_mod.bench_many(fixed, iters=3, warmup=1, msg_size=128)
    sizes_a = {r.algorithm: (r.sig_size, r.pubkey_size, r.privkey_size) for r in a.results}
    sizes_b = {r.algorithm: (r.sig_size, r.pubkey_size, r.privkey_size) for r in b.results}
    assert sizes_a == sizes_b


def test_report_roundtrip(tmp_path):
    rep = bench_mod.bench_many(_fast_algs(), iters=2, warmup=0, msg_size=128)
    p = tmp_path / "results.json"
    bench_mod.write_report(rep, str(p))
    loaded = bench_mod.load_report(str(p))
    assert loaded.schema_version == rep.schema_version
    assert len(loaded.results) == len(rep.results)
    assert loaded.results[0].algorithm == rep.results[0].algorithm


def test_load_legacy_baseline():
    """The shipped baseline (flat list-of-dicts) must load via from_dict."""
    base_path = Path(__file__).resolve().parent.parent / "src" / "pqc_v2x_bench" / "baselines" / "baseline_i7_13620h.json"
    rep = bench_mod.load_report(str(base_path))
    assert rep.schema_version == "0-legacy"
    names = {r.algorithm for r in rep.results}
    assert "ML-DSA-44" in names
    assert "Falcon-512" in names


# ---------------------------------------------------------------------------
# Regression vs shipped baseline (CI safety belt)
# ---------------------------------------------------------------------------

def test_regression_sig_sizes_match_baseline():
    """Sig sizes must match the bundled baseline byte-exact (no Falcon noise:
    Falcon sigs vary, so we tolerate it via 'le' bound)."""
    base_path = Path(__file__).resolve().parent.parent / "src" / "pqc_v2x_bench" / "baselines" / "baseline_i7_13620h.json"
    baseline = bench_mod.load_report(str(base_path))
    base_by_name = {r.algorithm: r for r in baseline.results}

    # Re-measure overlapping sign algorithms in a fast pass.
    by_name = {a.name: a for a in alg_mod.list_algorithms()}
    overlap = [by_name[n] for n in base_by_name if n in by_name and by_name[n].kind == "sign"]
    rep = bench_mod.bench_many(overlap, iters=2, warmup=0, msg_size=256)
    new_by_name = {r.algorithm: r for r in rep.results}

    for name, base in base_by_name.items():
        if name not in new_by_name:
            continue
        new = new_by_name[name]
        # ECDSA DER-encoded sigs are variable (70-72B for P-256) because r/s
        # integer encoding may pad a leading zero. Falcon sigs are inherently
        # variable due to rejection sampling. Both are checked against the
        # spec upper bound rather than baseline byte-exactness.
        if name.startswith("ECDSA"):
            assert abs(new.sig_size - base.sig_size) <= 4, (
                f"{name}: sig size {new.sig_size} vs baseline {base.sig_size}"
            )
            continue
        if name == "Falcon-512":
            assert new.sig_size <= 666, f"{name}: sig {new.sig_size} > FIPS-206 bound 666"
            continue
        if name == "Falcon-1024":
            assert new.sig_size <= 1280, f"{name}: sig {new.sig_size} > FIPS-206 bound 1280"
            continue
        assert new.sig_size == base.sig_size, f"{name}: sig size drift {new.sig_size} vs baseline {base.sig_size}"


def test_compare_threshold_flags_regression():
    """compare() must flag >=50% deltas by default."""
    base = bench_mod.BenchReport(
        host={}, params={},
        results=[bench_mod.AlgorithmResult(
            algorithm="X", kind="sign", family="X", nist_level="L1",
            sig_size=100, op1_ms_p50=1.0, op2_ms_p50=1.0, keygen_ms_p50=1.0,
        )],
    )
    curr = bench_mod.BenchReport(
        host={}, params={},
        results=[bench_mod.AlgorithmResult(
            algorithm="X", kind="sign", family="X", nist_level="L1",
            sig_size=100, op1_ms_p50=2.0, op2_ms_p50=1.0, keygen_ms_p50=1.0,
        )],
    )
    diff = report_mod.compare(base, curr, threshold_pct=50.0)
    assert len(diff["flagged"]) == 1
    assert "op1_p50_pct" in diff["flagged"][0]["breached_metrics"]


def test_compare_within_threshold_no_flag():
    base = bench_mod.BenchReport(
        host={}, params={},
        results=[bench_mod.AlgorithmResult(
            algorithm="X", kind="sign", family="X", nist_level="L1",
            sig_size=100, op1_ms_p50=1.0, op2_ms_p50=1.0, keygen_ms_p50=1.0,
        )],
    )
    curr = bench_mod.BenchReport(
        host={}, params={},
        results=[bench_mod.AlgorithmResult(
            algorithm="X", kind="sign", family="X", nist_level="L1",
            sig_size=100, op1_ms_p50=1.2, op2_ms_p50=1.0, keygen_ms_p50=1.0,
        )],
    )
    diff = report_mod.compare(base, curr, threshold_pct=50.0)
    assert diff["flagged"] == []


def test_bench_one_rejects_bad_iters():
    alg = next(a for a in alg_mod.list_algorithms() if a.name == "ECDSA-P256")
    with pytest.raises(ValueError):
        bench_mod.bench_one(alg, iters=0)
