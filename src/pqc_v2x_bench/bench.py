"""Core measurement loop.

Each Algorithm is timed over N iterations after a warmup phase using
time.perf_counter_ns. Stats reported: p50, p95, mean, std (ms). Sizes
(sig/pubkey/privkey or ct/pubkey/privkey/sharedsecret) are captured
once on the first non-warmup iteration; the loop asserts they remain
stable to catch backend non-determinism.
"""
from __future__ import annotations

import json
import os
import platform
import statistics
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from . import __version__
from .algorithms import Algorithm


@dataclass
class AlgorithmResult:
    algorithm: str
    kind: str  # "sign" | "kem"
    family: str
    nist_level: str
    # Sizes (bytes)
    sig_size: int = 0          # sign kind: signature length; KEM: ciphertext length
    pubkey_size: int = 0
    privkey_size: int = 0
    shared_secret_size: int = 0  # KEM only, 0 for sign
    # Latencies (ms)
    keygen_ms_p50: float = 0.0
    keygen_ms_p95: float = 0.0
    keygen_ms_mean: float = 0.0
    keygen_ms_std: float = 0.0
    op1_ms_p50: float = 0.0    # sign latency or encaps latency
    op1_ms_p95: float = 0.0
    op1_ms_mean: float = 0.0
    op1_ms_std: float = 0.0
    op2_ms_p50: float = 0.0    # verify latency or decaps latency
    op2_ms_p95: float = 0.0
    op2_ms_mean: float = 0.0
    op2_ms_std: float = 0.0
    iters: int = 0
    # Optional raw samples (populated when bench is run with collect_raw=True).
    # Empty lists in the default case keep the JSON schema stable but small.
    raw_keygen_ms: list[float] = field(default_factory=list)
    raw_op1_ms: list[float] = field(default_factory=list)
    raw_op2_ms: list[float] = field(default_factory=list)


@dataclass
class BenchReport:
    schema_version: str = "1"
    tool_version: str = __version__
    host: dict[str, Any] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)
    results: list[AlgorithmResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool_version": self.tool_version,
            "host": self.host,
            "params": self.params,
            "results": [asdict(r) for r in self.results],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BenchReport":
        # Tolerate the original flat list-of-results format used by the
        # legacy bench/results.json file shipped in context/.
        if isinstance(data, list):
            return cls(
                schema_version="0-legacy",
                tool_version="unknown",
                host={},
                params={},
                results=[_legacy_result(r) for r in data],
            )
        results = [
            AlgorithmResult(**_compatible_fields(r, AlgorithmResult))
            for r in data.get("results", [])
        ]
        return cls(
            schema_version=data.get("schema_version", "unknown"),
            tool_version=data.get("tool_version", "unknown"),
            host=data.get("host", {}),
            params=data.get("params", {}),
            results=results,
        )


def _compatible_fields(d: dict[str, Any], cls) -> dict[str, Any]:
    names = {f for f in cls.__dataclass_fields__}
    return {k: v for k, v in d.items() if k in names}


def _legacy_result(d: dict[str, Any]) -> AlgorithmResult:
    """Map old bench_pqc_sigs.py shape (sign_ms_*/verify_ms_*) to AlgorithmResult."""
    return AlgorithmResult(
        algorithm=d.get("algorithm", "?"),
        kind="sign",
        family=_infer_family(d.get("algorithm", "")),
        nist_level=d.get("nist_level", ""),
        sig_size=d.get("sig_size", 0),
        pubkey_size=d.get("pubkey_size", 0),
        privkey_size=d.get("privkey_size", 0),
        keygen_ms_p50=d.get("keygen_ms_p50", 0.0),
        keygen_ms_p95=d.get("keygen_ms_p95", 0.0),
        op1_ms_p50=d.get("sign_ms_p50", 0.0),
        op1_ms_p95=d.get("sign_ms_p95", 0.0),
        op2_ms_p50=d.get("verify_ms_p50", 0.0),
        op2_ms_p95=d.get("verify_ms_p95", 0.0),
    )


def _infer_family(name: str) -> str:
    n = name.upper()
    for tag in ("ECDSA", "ML-DSA", "FALCON", "SLH-DSA", "SPHINCS", "ML-KEM", "HQC"):
        if tag in n:
            return tag
    return "?"


# ---------------------------------------------------------------------------
# Host detection
# ---------------------------------------------------------------------------

def detect_host() -> dict[str, Any]:
    info: dict[str, Any] = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "python": sys.version.split()[0],
        "system": platform.system(),
    }
    # /proc/cpuinfo is the cheapest reliable CPU model source on Linux.
    cpuinfo = "/proc/cpuinfo"
    if os.path.exists(cpuinfo):
        try:
            with open(cpuinfo, "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.lower().startswith("model name"):
                        info["cpu_model"] = line.split(":", 1)[1].strip()
                        break
        except OSError:
            pass
    return info


# ---------------------------------------------------------------------------
# Stats helpers
# ---------------------------------------------------------------------------

def _percentile(values_us: list[float], pct: float) -> float:
    """pct in [0,100]. Returns microseconds."""
    if not values_us:
        return 0.0
    if len(values_us) == 1:
        return values_us[0]
    qs = statistics.quantiles(values_us, n=100, method="inclusive")
    idx = int(pct) - 1
    idx = max(0, min(idx, len(qs) - 1))
    return qs[idx]


def _summarize(values_us: list[float]) -> tuple[float, float, float, float]:
    """(p50_ms, p95_ms, mean_ms, std_ms) from a list of microseconds."""
    if not values_us:
        return 0.0, 0.0, 0.0, 0.0
    p50 = statistics.median(values_us) / 1000.0
    p95 = _percentile(values_us, 95) / 1000.0
    mean = statistics.fmean(values_us) / 1000.0
    std = (statistics.pstdev(values_us) if len(values_us) > 1 else 0.0) / 1000.0
    return p50, p95, mean, std


# ---------------------------------------------------------------------------
# Bench loop
# ---------------------------------------------------------------------------

def _bench_sign(alg: Algorithm, iters: int, warmup: int, msg: bytes,
                collect_raw: bool = False) -> AlgorithmResult:
    """Bench a signature algorithm in two phases:

    Phase 1 — keygen latency: N+warmup independent generations.
    Phase 2 — sign/verify latency: one fixed keypair, N+warmup operations
              (production-realistic: keys loaded once, reused).

    This separation avoids ECDSA's DER parse cost being charged to every
    sign/verify call when the underlying adapter caches parsed objects.
    """
    kg: list[float] = []
    op1: list[float] = []
    op2: list[float] = []
    sig_size = pub_size = priv_size = 0

    # Phase 1: keygen latency
    for i in range(iters + warmup):
        t0 = time.perf_counter_ns()
        pk, sk = alg.keygen()
        t1 = time.perf_counter_ns()
        if i < warmup:
            continue
        kg.append((t1 - t0) / 1000.0)
        if pub_size == 0:
            pub_size, priv_size = len(pk), len(sk)
        else:
            if len(pk) != pub_size or len(sk) != priv_size:
                raise RuntimeError(f"{alg.name}: key size drift mid-run")

    # Phase 2: sign/verify on one fixed keypair
    pk_fixed, sk_fixed = alg.keygen()
    for i in range(iters + warmup):
        t2a = time.perf_counter_ns()
        sig = alg.op1(pk_fixed, sk_fixed, msg)
        t2b = time.perf_counter_ns()
        ok = alg.op2(pk_fixed, sk_fixed, (msg, sig))
        t2c = time.perf_counter_ns()
        if not ok:
            raise RuntimeError(f"{alg.name}: verify returned False (corrupted backend?)")
        if i < warmup:
            continue
        op1.append((t2b - t2a) / 1000.0)
        op2.append((t2c - t2b) / 1000.0)
        if sig_size == 0:
            sig_size = len(sig)

    p_kg = _summarize(kg)
    p_o1 = _summarize(op1)
    p_o2 = _summarize(op2)
    result = AlgorithmResult(
        algorithm=alg.name, kind="sign", family=alg.family, nist_level=alg.nist_level,
        sig_size=sig_size, pubkey_size=pub_size, privkey_size=priv_size,
        keygen_ms_p50=p_kg[0], keygen_ms_p95=p_kg[1], keygen_ms_mean=p_kg[2], keygen_ms_std=p_kg[3],
        op1_ms_p50=p_o1[0], op1_ms_p95=p_o1[1], op1_ms_mean=p_o1[2], op1_ms_std=p_o1[3],
        op2_ms_p50=p_o2[0], op2_ms_p95=p_o2[1], op2_ms_mean=p_o2[2], op2_ms_std=p_o2[3],
        iters=iters,
    )
    if collect_raw:
        result.raw_keygen_ms = kg
        result.raw_op1_ms = op1
        result.raw_op2_ms = op2
    return result


def _bench_kem(alg: Algorithm, iters: int, warmup: int, _msg: bytes,
               collect_raw: bool = False) -> AlgorithmResult:
    """Bench a KEM in two phases (keygen alone, then encaps/decaps on fixed key)."""
    kg: list[float] = []
    op1: list[float] = []
    op2: list[float] = []
    ct_size = pub_size = priv_size = ss_size = 0

    # Phase 1: keygen
    for i in range(iters + warmup):
        t0 = time.perf_counter_ns()
        pk, sk = alg.keygen()
        t1 = time.perf_counter_ns()
        if i < warmup:
            continue
        kg.append((t1 - t0) / 1000.0)
        if pub_size == 0:
            pub_size, priv_size = len(pk), len(sk)

    # Phase 2: encaps/decaps on fixed keypair
    pk_fixed, sk_fixed = alg.keygen()
    for i in range(iters + warmup):
        t2a = time.perf_counter_ns()
        ct, ss = alg.op1(pk_fixed, sk_fixed, b"")
        t2b = time.perf_counter_ns()
        ss2 = alg.op2(pk_fixed, sk_fixed, (ct, ss))
        t2c = time.perf_counter_ns()
        if ss != ss2:
            raise RuntimeError(f"{alg.name}: KEM shared secret mismatch")
        if i < warmup:
            continue
        op1.append((t2b - t2a) / 1000.0)
        op2.append((t2c - t2b) / 1000.0)
        if ct_size == 0:
            ct_size, ss_size = len(ct), len(ss)

    p_kg = _summarize(kg)
    p_o1 = _summarize(op1)
    p_o2 = _summarize(op2)
    result = AlgorithmResult(
        algorithm=alg.name, kind="kem", family=alg.family, nist_level=alg.nist_level,
        sig_size=ct_size, pubkey_size=pub_size, privkey_size=priv_size,
        shared_secret_size=ss_size,
        keygen_ms_p50=p_kg[0], keygen_ms_p95=p_kg[1], keygen_ms_mean=p_kg[2], keygen_ms_std=p_kg[3],
        op1_ms_p50=p_o1[0], op1_ms_p95=p_o1[1], op1_ms_mean=p_o1[2], op1_ms_std=p_o1[3],
        op2_ms_p50=p_o2[0], op2_ms_p95=p_o2[1], op2_ms_mean=p_o2[2], op2_ms_std=p_o2[3],
        iters=iters,
    )
    if collect_raw:
        result.raw_keygen_ms = kg
        result.raw_op1_ms = op1
        result.raw_op2_ms = op2
    return result


def bench_one(alg: Algorithm, iters: int = 100, warmup: int = 5,
              msg_size: int = 256, msg: bytes | None = None,
              collect_raw: bool = False) -> AlgorithmResult:
    """Bench a single algorithm. msg overrides msg_size when provided."""
    if iters <= 0:
        raise ValueError("iters must be >= 1")
    if warmup < 0:
        raise ValueError("warmup must be >= 0")
    payload = msg if msg is not None else os.urandom(msg_size)
    if alg.kind == "sign":
        return _bench_sign(alg, iters, warmup, payload, collect_raw=collect_raw)
    if alg.kind == "kem":
        return _bench_kem(alg, iters, warmup, payload, collect_raw=collect_raw)
    raise ValueError(f"unknown algorithm kind: {alg.kind}")


def bench_many(algs: Iterable[Algorithm], *, iters: int = 100, warmup: int = 5,
               msg_size: int = 256, progress=None,
               collect_raw: bool = False) -> BenchReport:
    """Bench a list of algorithms and assemble a BenchReport."""
    algs = list(algs)
    # Shared payload across all sign algorithms keeps comparisons fair.
    msg = os.urandom(msg_size)
    out = BenchReport(
        host=detect_host(),
        params={"iters": iters, "warmup": warmup, "msg_size": msg_size,
                "collect_raw": collect_raw},
        results=[],
    )
    for alg in algs:
        if progress is not None:
            progress(alg.name)
        out.results.append(bench_one(alg, iters=iters, warmup=warmup, msg=msg,
                                     collect_raw=collect_raw))
    return out


def write_report(report: BenchReport, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report.to_dict(), fh, indent=2)


def load_report(path: str) -> BenchReport:
    with open(path, "r", encoding="utf-8") as fh:
        return BenchReport.from_dict(json.load(fh))
