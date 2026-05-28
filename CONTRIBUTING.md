# Contributing to pqc-v2x-bench

Thank you for considering a contribution! This project is small and
opinionated. The sections below describe what kinds of contributions are
likely to be merged and how to land them.

## Scope

- ✅ Adding new PQC algorithms (sign or KEM) to the registry — provided
  they come from a maintained, FIPS-aligned implementation.
- ✅ Adding a second backend (e.g. `oqs-python`, Cloudflare CIRCL) behind a
  feature flag — keep the registry vendor-neutral.
- ✅ Reporting hardware on which the suite was run (open a PR adding the
  JSON results under a clearly labelled platform).
- ✅ Bugfixes, clearer error messages, additional output formats.

- ❌ Code that depends on private V2X PKI deployments (this repo must
  remain Apache-2.0 standalone).
- ❌ Heavy dependencies (no `scipy`/`numpy`/`pandas` etc. without a
  documented reason — keep the dep surface small).
- ❌ Benchmarks that take more than ~10 minutes for a full `--iters 100`
  pass; if a new algorithm is intrinsically slow, add it but skip in CI
  by default.

## Local development

```bash
git clone https://github.com/blackcycle-ai/pqc-v2x-bench
cd pqc-v2x-bench
python -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"
pytest -v
```

The CLI is installed as `pqc-v2x-bench`; the source lives under
`src/pqc_v2x_bench/`.

## Adding an algorithm

1. Import the implementation in `src/pqc_v2x_bench/algorithms.py`.
2. Wrap it in `_make_pq_sign(...)` or `_make_pq_kem(...)`.
3. Append the entry to `REGISTRY` with the canonical name (e.g. `ML-DSA-44`)
   and the NIST level.
4. Add a row to the FIPS-size oracles in `tests/test_algorithms.py` if the
   spec publishes byte-exact sizes; otherwise add a bounded check.
5. Run `pytest -v` — every entry in the registry is exercised by the
   parametrized smoke test.

## Code style

- Type hints on every public function. The codebase targets Python 3.10+.
- No new dependencies unless discussed in an issue first.
- Comments explain *why*, not *what* — the names of identifiers cover *what*.

## Commit + PR conventions

- Open a draft PR early. Small, focused commits land faster than mega-PRs.
- The Apache-2.0 licence implicitly covers all contributions.
- If your change alters numbers, regenerate `results.json` on your machine
  and include it in the PR description so reviewers can sanity-check
  against the baseline.

## Reporting an issue

Useful issues include:

- `pqc-v2x-bench --version` output
- `python --version` and `uname -a`
- Exact command that triggered the problem
- The full traceback (sanitise any internal hostnames if needed)

## Security

If you discover a security-relevant bug (e.g. a memory-safety issue in a
wrapped backend), please email `security@skyv2x.com` rather than opening a
public issue.

---

<sub>**BlackCycle Lab** · companion to the Castell C-ITS PKI testbed at [pki.skyv2x.com](https://pki.skyv2x.com)</sub>
