"""Tests for report formatters and CLI smoke."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from pqc_v2x_bench import bench as bench_mod
from pqc_v2x_bench import report as report_mod


def _toy_report() -> bench_mod.BenchReport:
    return bench_mod.BenchReport(
        host={"machine": "x86_64", "cpu_model": "Test CPU", "python": "3.12", "system": "Linux"},
        params={"iters": 10, "warmup": 1, "msg_size": 256},
        results=[
            bench_mod.AlgorithmResult(
                algorithm="ECDSA-P256", kind="sign", family="ECDSA", nist_level="~L1",
                sig_size=72, pubkey_size=65, privkey_size=138,
                op1_ms_p50=0.030, op1_ms_p95=0.035,
                op2_ms_p50=0.072, op2_ms_p95=0.082,
                keygen_ms_p50=0.013, keygen_ms_p95=0.016, iters=10,
            ),
            bench_mod.AlgorithmResult(
                algorithm="ML-KEM-512", kind="kem", family="ML-KEM", nist_level="NIST L1",
                sig_size=768, pubkey_size=800, privkey_size=1632, shared_secret_size=32,
                op1_ms_p50=0.040, op1_ms_p95=0.050,
                op2_ms_p50=0.030, op2_ms_p95=0.040,
                keygen_ms_p50=0.020, keygen_ms_p95=0.025, iters=10,
            ),
        ],
    )


def test_format_markdown_contains_table_pipes():
    text = report_mod.to_markdown(_toy_report())
    # tabulate github format uses pipe separators.
    assert "| Algorithm" in text
    assert "| ECDSA-P256" in text
    assert "| ML-KEM-512" in text
    assert "768" in text  # KEM ciphertext size
    assert "32" in text   # shared secret size


def test_format_json_is_parseable():
    text = report_mod.to_json(_toy_report())
    data = json.loads(text)
    assert data["schema_version"] == "1"
    assert data["params"]["msg_size"] == 256
    assert len(data["results"]) == 2


def test_format_csv_has_header_and_rows():
    text = report_mod.to_csv(_toy_report())
    lines = [l for l in text.splitlines() if l]
    assert lines[0].startswith("algorithm,kind,family")
    assert any(l.startswith("ECDSA-P256,") for l in lines)


def test_format_report_unknown_raises():
    with pytest.raises(ValueError):
        report_mod.format_report(_toy_report(), "xml")


def test_compare_markdown_renders_only_in_sets():
    base = _toy_report()
    curr = _toy_report()
    # Drop one result from current; add a fake one.
    curr.results = curr.results[:1] + [bench_mod.AlgorithmResult(
        algorithm="NEW-ALG", kind="sign", family="X", nist_level="L1",
        sig_size=10, op1_ms_p50=1.0, op2_ms_p50=1.0, keygen_ms_p50=1.0,
    )]
    diff = report_mod.compare(base, curr, threshold_pct=50.0)
    md = report_mod.compare_to_markdown(diff)
    assert "Only in baseline" in md or "ML-KEM-512" in diff["only_in_baseline"]
    assert "NEW-ALG" in diff["only_in_current"]


def test_cli_help_lists_subcommands():
    """CLI --help must mention run/report/compare/list (acceptance criterion 2)."""
    out = subprocess.run(
        [sys.executable, "-m", "pqc_v2x_bench.cli", "--help"],
        capture_output=True, text=True, check=True,
    )
    text = out.stdout + out.stderr
    for sub in ("run", "report", "compare", "list"):
        assert sub in text, f"--help missing subcommand {sub!r}"


def test_cli_list_lists_kem_and_sign():
    out = subprocess.run(
        [sys.executable, "-m", "pqc_v2x_bench.cli", "list"],
        capture_output=True, text=True, check=True,
    )
    text = out.stdout
    assert "ML-DSA-44" in text
    assert "ML-KEM-512" in text
    assert "HQC-128" in text


def test_cli_run_outputs_valid_json(tmp_path: Path):
    out = subprocess.run(
        [
            sys.executable, "-m", "pqc_v2x_bench.cli", "run",
            "--iters", "2", "--warmup", "0",
            "--algorithms", "ECDSA-P256,ML-KEM-512",
            "--output", "json",
            "--out", str(tmp_path / "r.json"),
            "--quiet",
        ],
        capture_output=True, text=True, check=True,
    )
    payload = json.loads(out.stdout)
    assert payload["schema_version"] == "1"
    assert len(payload["results"]) == 2
    assert (tmp_path / "r.json").exists()
