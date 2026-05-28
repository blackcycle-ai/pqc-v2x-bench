# pqc-v2x-bench

A reproducible benchmark suite for **post-quantum cryptography** primitives
relevant to **V2X PKI** (IEEE 1609.2 / ETSI TS 103 097 / SCMS).

It measures the FIPS-published PQC standards alongside the classical ECDSA
baselines that V2X PKIs use today, with one consistent harness, one
versioned JSON schema, and one CI matrix that runs the same numbers on
x86_64 and ARM64.

| | |
|---|---|
| License | Apache-2.0 |
| Python | 3.10+ |
| Status | 0.1.0 — early release |
| Citation | see [Citation](#citation) |

> **Why does this exist?** Several published V2X-PQC performance papers
> (notably Chen 2023 / IACR 2022/1619) report credible numbers but do not
> ship reproducible code. This repo lets any researcher run the same
> measurements on their own hardware and obtain a comparable table.

---

## Quickstart

```bash
pip install pqc-v2x-bench    # PyPI
# ...or, from source
git clone https://github.com/blackcycle-ai/pqc-v2x-bench
cd pqc-v2x-bench
pip install -e .

pqc-v2x-bench --help
pqc-v2x-bench list
pqc-v2x-bench run --iters 100 --output markdown
```

### CLI overview

| Command | Purpose |
|---|---|
| `pqc-v2x-bench list` | Show every registered algorithm + NIST level. |
| `pqc-v2x-bench run` | Measure latencies and sizes, emit JSON/Markdown/CSV. |
| `pqc-v2x-bench report <results.json>` | Re-render a results file in another format. |
| `pqc-v2x-bench compare <baseline.json> <current.json>` | Diff two results with a ±% threshold (default 50). |

Common flags for `run`:

| Flag | Default | Notes |
|---|---|---|
| `--iters / -n` | `100` | Measurement iterations per algorithm. |
| `--warmup / -w` | `5` | Warmup iterations discarded from stats. |
| `--msg-size / -m` | `256` | Payload size (B). Try `700` or `1400` for CAM-like loads. |
| `--algorithms / -a` | (all) | Comma-separated glob, e.g. `ml-dsa-*,falcon-*`. |
| `--output / -o` | `json` | `json` \| `markdown` \| `csv`. |
| `--out` | `results.{ext}` | Output file. |

Example:

```bash
pqc-v2x-bench run \
  --iters 100 \
  --msg-size 700 \
  --algorithms 'ml-dsa-*,falcon-*,ml-kem-*' \
  --output markdown \
  --out cam-bench.md
```

---

## Algorithms

Eighteen primitives across two operation families:

- **Signatures** (`kind=sign`): ECDSA P-256 / Brainpool P-256r1 / Brainpool
  P-384r1 (classical baselines); FIPS-204 ML-DSA-44/65/87; Falcon-512/1024
  (pending FIPS-206); FIPS-205 SLH-DSA-128s/128f.
- **Key Encapsulation** (`kind=kem`): FIPS-203 ML-KEM-512/768/1024;
  NIST round-4 alternative HQC-128/192/256.

All PQC implementations come from [`pqcrypto`](https://pypi.org/project/pqcrypto/)
which wraps PQClean. The registry is intentionally one-line-per-algorithm so a
second backend (e.g. `oqs-python`, Cloudflare CIRCL) can be added without
touching the bench loop.

---

## Sample results

Reference run on `Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz` (Linux, Python
3.12.13), `--iters 30 --warmup 3 --msg-size 256`:

| Algorithm     | Kind | Level         | Sig/CT (B) | Pub (B) | Priv (B) | SS (B) | KG p50 | KG p95 | Op1 p50 | Op1 p95 | Op2 p50 | Op2 p95 |
|---------------|------|---------------|-----------:|--------:|---------:|-------:|-------:|-------:|--------:|--------:|--------:|--------:|
| ECDSA-P256    | sign | ~L1 (128-bit) |         71 |      65 |      138 |   –    |  0.028 |  0.029 |   0.054 |   0.056 |   0.073 |   0.075 |
| ECDSA-BP256r1 | sign | ~L1 (128-bit) |         70 |      65 |      139 |   –    |  0.300 |  0.305 |   0.600 |   0.604 |   0.315 |   0.319 |
| ECDSA-BP384r1 | sign | ~L3 (192-bit) |        102 |      97 |      189 |   –    |  0.674 |  0.695 |   1.362 |   1.442 |   0.621 |   0.675 |
| ML-DSA-44     | sign | NIST L2       |       2420 |    1312 |     2560 |   –    |  0.092 |  0.094 |   0.301 |   0.803 |   0.099 |   0.099 |
| ML-DSA-65     | sign | NIST L3       |       3309 |    1952 |     4032 |   –    |  0.164 |  0.187 |   0.589 |   1.932 |   0.161 |   0.181 |
| ML-DSA-87     | sign | NIST L5       |       4627 |    2592 |     4896 |   –    |  0.253 |  0.288 |   0.550 |   1.357 |   0.263 |   0.295 |
| Falcon-512    | sign | NIST L1       |       ≤666 |     897 |     1281 |   –    | 10.393 | 21.420 |   3.403 |   3.645 |   0.042 |   0.055 |
| Falcon-1024   | sign | NIST L5       |      ≤1280 |    1793 |     2305 |   –    | 31.000 | 65.710 |   7.483 |   7.692 |   0.081 |   0.083 |
| SLH-DSA-128s  | sign | NIST L1       |       7856 |      32 |       64 |   –    | 76.372 | 77.197 | 582.644 | 586.734 |   0.581 |   0.615 |
| SLH-DSA-128f  | sign | NIST L1       |      17088 |      32 |       64 |   –    |  1.194 |  1.290 |  28.137 |  28.513 |   1.687 |   1.758 |
| ML-KEM-512    | kem  | NIST L1       |        768 |     800 |     1632 |   32   |  0.032 |  0.033 |   0.040 |   0.041 |   0.050 |   0.051 |
| ML-KEM-768    | kem  | NIST L3       |       1088 |    1184 |     2400 |   32   |  0.054 |  0.074 |   0.064 |   0.072 |   0.076 |   0.080 |
| ML-KEM-1024   | kem  | NIST L5       |       1568 |    1568 |     3168 |   32   |  0.082 |  0.084 |   0.093 |   0.095 |   0.108 |   0.110 |
| HQC-128       | kem  | NIST L1       |       4433 |    2249 |     2305 |   64   |  1.358 |  1.426 |   2.755 |   2.854 |   4.470 |   4.734 |
| HQC-192       | kem  | NIST L3       |       8978 |    4522 |     4586 |   64   |  4.150 |  4.307 |   8.359 |   8.688 |  13.125 |  13.547 |
| HQC-256       | kem  | NIST L5       |      14421 |    7245 |     7317 |   64   |  7.588 |  7.829 |  15.389 |  15.683 |  24.257 |  24.657 |

Times in milliseconds. `Op1` is `sign` for signature algorithms or `encapsulate`
for KEMs; `Op2` is `verify` / `decapsulate`. Falcon signature sizes are
variable (rejection sampling) — column shows the FIPS-206 upper bound.

Nightly results for both `x86_64` and `arm64` are published to the
[`nightly`](https://github.com/blackcycle-ai/pqc-v2x-bench/tree/nightly) branch by
the CI workflow.

### Reading the table for V2X PKI

- **Signature size dominates** for V2X CAM/DENM broadcasts (1400B air-interface
  cap). Only Falcon-512 fits a single CAM packet today; ML-DSA-44 needs 2420B
  just for the signature.
- **ECDSA verify is ~70× slower than ML-DSA verify** — counter-intuitive but
  consistent with Chen 2023 + IACR 2022/1619.
- **Brainpool ECDSA** is the EU classical baseline; it is ~8× slower than NIST
  P-256 on OpenSSL software paths, which narrows the EU PQC-migration gap.
- **HQC is the NIST round-4 KEM alternative**: bigger ciphertexts than ML-KEM,
  similar shared-secret size.

---

## Output formats

### JSON (schema v1)

```json
{
  "schema_version": "1",
  "tool_version": "0.1.0",
  "host": {
    "platform": "...",
    "machine": "x86_64",
    "cpu_model": "...",
    "python": "3.12.13",
    "system": "Linux"
  },
  "params": { "iters": 100, "warmup": 5, "msg_size": 256 },
  "results": [
    {
      "algorithm": "ML-DSA-44",
      "kind": "sign",
      "family": "ML-DSA",
      "nist_level": "NIST L2",
      "sig_size": 2420,
      "pubkey_size": 1312,
      "privkey_size": 2560,
      "shared_secret_size": 0,
      "keygen_ms_p50": 0.092, "keygen_ms_p95": 0.094,
      "keygen_ms_mean": 0.093, "keygen_ms_std": 0.005,
      "op1_ms_p50": 0.301, "op1_ms_p95": 0.803,
      "op1_ms_mean": 0.420, "op1_ms_std": 0.180,
      "op2_ms_p50": 0.099, "op2_ms_p95": 0.099,
      "op2_ms_mean": 0.099, "op2_ms_std": 0.001,
      "iters": 30
    }
  ]
}
```

- `op1` / `op2` semantics depend on `kind`:
  - `sign`: `op1=sign`, `op2=verify` (`sig_size` = signature bytes)
  - `kem`: `op1=encapsulate`, `op2=decapsulate` (`sig_size` = ciphertext bytes,
    `shared_secret_size` = SS bytes)

### Markdown

GitHub-flavored table via [`tabulate`](https://pypi.org/project/tabulate/),
suitable for embedding in PRs or research notes.

### CSV

Wide format with every percentile + mean/std for downstream analysis in
notebooks.

---

## Comparing two runs

`compare` flags algorithms whose key metrics (sig size, keygen p50, op1 p50,
op2 p50) drift more than `--threshold %` against a baseline:

```bash
pqc-v2x-bench compare baseline.json results.json --threshold 50 \
  --output markdown --fail-on-flag
```

`--fail-on-flag` exits non-zero — useful as a CI guardrail to catch backend
regressions (e.g. a `pqcrypto` upgrade that silently regresses a sign path).

A baseline measured on `i7-13620H` is shipped under
`src/pqc_v2x_bench/baselines/baseline_i7_13620h.json` for convenience.

---

## Testing

```bash
pip install -e ".[test]"
pytest -v
```

The suite includes smoke tests for every registered algorithm, byte-exact
sig/key-size oracles against FIPS-203/204/205, KEM round-trip determinism,
a regression check against the shipped baseline, and CLI subprocess tests.

---

## Continuous Integration

`.github/workflows/bench.yml` runs:

- **Matrix**: `ubuntu-latest` (x86_64) and `ubuntu-24.04-arm` (ARM64), Python 3.11.
- **Steps**: install, `pytest`, `pqc-v2x-bench run --iters 30`, render markdown,
  compare to the shipped baseline.
- **Nightly job** pushes the JSON + markdown artifacts to the `nightly` branch.

---

## Citation

```bibtex
@misc{pqc-v2x-bench-2026,
  title  = {pqc-v2x-bench: a reproducible benchmark suite for post-quantum
            cryptography in V2X PKI},
  author = {Fornell, Miguel},
  year   = {2026},
  url    = {https://github.com/blackcycle-ai/pqc-v2x-bench},
  note   = {Apache-2.0}
}
```

If you find a measurement on your hardware diverges materially from the
shipped baseline, please open a PR with a `results-<arch>.json` attached.

---

## Roadmap

- Optional `oqs-python` backend behind `--backend liboqs`.
- Composite (hybrid) signature schemes once the IETF PQUIP composite drafts
  stabilise.
- Memory footprint metrics (heap snapshot per operation) for embedded RSU
  scenarios.
- COER envelope overhead measurement (V2X-specific) — Fase B of the research
  line (internal research notes; companion paper forthcoming on arXiv).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

<sub>**BlackCycle Lab** · companion to the Castell C-ITS PKI testbed at [pki.skyv2x.com](https://pki.skyv2x.com)</sub>
