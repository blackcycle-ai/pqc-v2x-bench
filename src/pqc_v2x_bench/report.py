"""Report formatters and comparison utilities."""
from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict
from typing import Iterable

from tabulate import tabulate

from .bench import AlgorithmResult, BenchReport


# Columns common to both sign and KEM tables. Naming follows the brief:
# Sig (B) doubles as ciphertext size for KEM rows for visual compactness.
_HEADERS = [
    "Algorithm", "Kind", "Level", "Sig/CT (B)", "Pub (B)", "Priv (B)", "SS (B)",
    "KG p50", "KG p95",
    "Op1 p50", "Op1 p95",
    "Op2 p50", "Op2 p95",
]


def _row(r: AlgorithmResult) -> list[object]:
    return [
        r.algorithm,
        r.kind,
        r.nist_level,
        r.sig_size,
        r.pubkey_size,
        r.privkey_size,
        r.shared_secret_size if r.kind == "kem" else "-",
        f"{r.keygen_ms_p50:.3f}", f"{r.keygen_ms_p95:.3f}",
        f"{r.op1_ms_p50:.3f}", f"{r.op1_ms_p95:.3f}",
        f"{r.op2_ms_p50:.3f}", f"{r.op2_ms_p95:.3f}",
    ]


def to_markdown(report: BenchReport, *, include_host: bool = True) -> str:
    lines: list[str] = []
    if include_host:
        host = report.host
        cpu = host.get("cpu_model", host.get("processor", "unknown"))
        lines.append(f"# pqc-v2x-bench report")
        lines.append("")
        lines.append(f"- Tool version: `{report.tool_version}` (schema `{report.schema_version}`)")
        lines.append(f"- Host: `{cpu}` ({host.get('machine', '?')}, {host.get('system', '?')})")
        lines.append(f"- Python: `{host.get('python', '?')}`")
        params = report.params
        lines.append(
            f"- Params: iters={params.get('iters', '?')}, warmup={params.get('warmup', '?')}, "
            f"msg_size={params.get('msg_size', '?')}B"
        )
        lines.append("")
        lines.append("Latency columns in milliseconds. `Op1` is `sign` for sig algs, "
                     "`encapsulate` for KEM. `Op2` is `verify`/`decapsulate`.")
        lines.append("")
    rows = [_row(r) for r in report.results]
    lines.append(tabulate(rows, headers=_HEADERS, tablefmt="github"))
    return "\n".join(lines) + "\n"


def to_json(report: BenchReport) -> str:
    return json.dumps(report.to_dict(), indent=2) + "\n"


def to_csv(report: BenchReport) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "algorithm", "kind", "family", "nist_level",
        "sig_size", "pubkey_size", "privkey_size", "shared_secret_size",
        "keygen_ms_p50", "keygen_ms_p95", "keygen_ms_mean", "keygen_ms_std",
        "op1_ms_p50", "op1_ms_p95", "op1_ms_mean", "op1_ms_std",
        "op2_ms_p50", "op2_ms_p95", "op2_ms_mean", "op2_ms_std",
        "iters",
    ])
    for r in report.results:
        d = asdict(r)
        w.writerow([d[col] for col in [
            "algorithm", "kind", "family", "nist_level",
            "sig_size", "pubkey_size", "privkey_size", "shared_secret_size",
            "keygen_ms_p50", "keygen_ms_p95", "keygen_ms_mean", "keygen_ms_std",
            "op1_ms_p50", "op1_ms_p95", "op1_ms_mean", "op1_ms_std",
            "op2_ms_p50", "op2_ms_p95", "op2_ms_mean", "op2_ms_std",
            "iters",
        ]])
    return buf.getvalue()


def format_report(report: BenchReport, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return to_json(report)
    if fmt == "markdown" or fmt == "md":
        return to_markdown(report)
    if fmt == "csv":
        return to_csv(report)
    raise ValueError(f"unknown format: {fmt!r} (expected json|markdown|csv)")


# ---------------------------------------------------------------------------
# Compare
# ---------------------------------------------------------------------------

def _pct_delta(new: float, old: float) -> float:
    """Symmetric-safe percent delta. Returns 0 when both ~0."""
    if old == 0 and new == 0:
        return 0.0
    if old == 0:
        return float("inf")
    return (new - old) / old * 100.0


def compare(baseline: BenchReport, current: BenchReport, *, threshold_pct: float = 50.0) -> dict:
    """Diff two reports by algorithm name. Returns a structured dict.

    threshold_pct flags any |delta| >= threshold on any of:
    sig_size, keygen_ms_p50, op1_ms_p50, op2_ms_p50.
    """
    by_name_old = {r.algorithm: r for r in baseline.results}
    by_name_new = {r.algorithm: r for r in current.results}
    rows: list[dict] = []
    flagged: list[dict] = []
    only_baseline = sorted(set(by_name_old) - set(by_name_new))
    only_current = sorted(set(by_name_new) - set(by_name_old))
    for name in sorted(set(by_name_old) & set(by_name_new)):
        b = by_name_old[name]
        c = by_name_new[name]
        size_delta = c.sig_size - b.sig_size  # absolute bytes
        deltas = {
            "sig_size_bytes_delta": size_delta,
            "sig_size_pct": _pct_delta(c.sig_size, b.sig_size),
            "keygen_p50_pct": _pct_delta(c.keygen_ms_p50, b.keygen_ms_p50),
            "op1_p50_pct": _pct_delta(c.op1_ms_p50, b.op1_ms_p50),
            "op2_p50_pct": _pct_delta(c.op2_ms_p50, b.op2_ms_p50),
        }
        row = {
            "algorithm": name,
            "baseline": {
                "sig_size": b.sig_size,
                "keygen_p50": b.keygen_ms_p50,
                "op1_p50": b.op1_ms_p50,
                "op2_p50": b.op2_ms_p50,
            },
            "current": {
                "sig_size": c.sig_size,
                "keygen_p50": c.keygen_ms_p50,
                "op1_p50": c.op1_ms_p50,
                "op2_p50": c.op2_ms_p50,
            },
            "delta": deltas,
        }
        rows.append(row)
        breaches = [
            k for k, v in deltas.items()
            if k != "sig_size_bytes_delta" and abs(v) >= threshold_pct and v != float("inf")
        ]
        if size_delta != 0:
            breaches.append("sig_size_bytes_delta")
        if breaches:
            row_flag = dict(row)
            row_flag["breached_metrics"] = breaches
            flagged.append(row_flag)
    return {
        "threshold_pct": threshold_pct,
        "only_in_baseline": only_baseline,
        "only_in_current": only_current,
        "rows": rows,
        "flagged": flagged,
    }


def compare_to_markdown(diff: dict) -> str:
    headers = [
        "Algorithm", "Sig Δ (B)",
        "KG p50 base→now (ms)", "KG Δ%",
        "Op1 p50 base→now (ms)", "Op1 Δ%",
        "Op2 p50 base→now (ms)", "Op2 Δ%",
        "Flagged",
    ]
    rows = []
    flagged_names = {r["algorithm"] for r in diff.get("flagged", [])}
    for r in diff["rows"]:
        b, c, d = r["baseline"], r["current"], r["delta"]
        rows.append([
            r["algorithm"],
            d["sig_size_bytes_delta"],
            f"{b['keygen_p50']:.3f}→{c['keygen_p50']:.3f}",
            _fmt_pct(d["keygen_p50_pct"]),
            f"{b['op1_p50']:.3f}→{c['op1_p50']:.3f}",
            _fmt_pct(d["op1_p50_pct"]),
            f"{b['op2_p50']:.3f}→{c['op2_p50']:.3f}",
            _fmt_pct(d["op2_p50_pct"]),
            "yes" if r["algorithm"] in flagged_names else "",
        ])
    lines = [
        f"# Compare report (threshold ±{diff['threshold_pct']:.0f}%)",
        "",
        tabulate(rows, headers=headers, tablefmt="github"),
        "",
    ]
    if diff["only_in_baseline"]:
        lines.append(f"Only in baseline: {', '.join(diff['only_in_baseline'])}")
    if diff["only_in_current"]:
        lines.append(f"Only in current: {', '.join(diff['only_in_current'])}")
    return "\n".join(lines) + "\n"


def _fmt_pct(v: float) -> str:
    if v == float("inf"):
        return "n/a"
    return f"{v:+.1f}%"
