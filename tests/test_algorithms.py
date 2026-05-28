"""Smoke + determinism tests for each registered algorithm."""
from __future__ import annotations

import os

import pytest

from pqc_v2x_bench import algorithms as alg_mod


ALL = alg_mod.list_algorithms()
SIGN_ALGS = [a for a in ALL if a.kind == "sign"]
KEM_ALGS = [a for a in ALL if a.kind == "kem"]


# ---------------------------------------------------------------------------
# Sign smoke + sig sizes
# ---------------------------------------------------------------------------

# FIPS-published / spec sig-size oracle. For variable-length schemes (Falcon)
# the bound is upper bound; we assert <= bound (and > 0).
FIPS_SIGN_ORACLE: dict[str, tuple[str, int]] = {
    "ML-DSA-44": ("eq", 2420),
    "ML-DSA-65": ("eq", 3309),
    "ML-DSA-87": ("eq", 4627),
    "Falcon-512": ("le", 666),
    "Falcon-1024": ("le", 1280),
    "SLH-DSA-128s": ("eq", 7856),
    "SLH-DSA-128f": ("eq", 17088),
}

FIPS_KEY_ORACLE: dict[str, dict[str, int]] = {
    "ML-DSA-44": {"pk": 1312, "sk": 2560},
    "ML-DSA-65": {"pk": 1952, "sk": 4032},
    "ML-DSA-87": {"pk": 2592, "sk": 4896},
    "Falcon-512": {"pk": 897, "sk": 1281},
    "Falcon-1024": {"pk": 1793, "sk": 2305},
    "SLH-DSA-128s": {"pk": 32, "sk": 64},
    "SLH-DSA-128f": {"pk": 32, "sk": 64},
}

# FIPS-203 ML-KEM ciphertext / shared-secret sizes
FIPS_KEM_ORACLE: dict[str, dict[str, int]] = {
    "ML-KEM-512": {"pk": 800, "sk": 1632, "ct": 768, "ss": 32},
    "ML-KEM-768": {"pk": 1184, "sk": 2400, "ct": 1088, "ss": 32},
    "ML-KEM-1024": {"pk": 1568, "sk": 3168, "ct": 1568, "ss": 32},
}


@pytest.mark.parametrize("alg", SIGN_ALGS, ids=lambda a: a.name)
def test_sign_smoke(alg):
    pk, sk = alg.keygen()
    assert len(pk) > 0 and len(sk) > 0
    msg = os.urandom(128)
    sig = alg.op1(pk, sk, msg)
    assert len(sig) > 0
    assert alg.op2(pk, sk, (msg, sig)) is True


@pytest.mark.parametrize("alg", SIGN_ALGS, ids=lambda a: a.name)
def test_sign_rejects_tampered(alg):
    pk, sk = alg.keygen()
    msg = os.urandom(64)
    sig = alg.op1(pk, sk, msg)
    bad_msg = bytes([msg[0] ^ 0xFF]) + msg[1:]
    # Verify must return False (or raise — both acceptable; we coerce to bool).
    try:
        ok = alg.op2(pk, sk, (bad_msg, sig))
    except Exception:
        ok = False
    assert ok is False


@pytest.mark.parametrize("alg", KEM_ALGS, ids=lambda a: a.name)
def test_kem_smoke(alg):
    pk, sk = alg.keygen()
    ct, ss = alg.op1(pk, sk, b"")
    assert len(ct) > 0 and len(ss) > 0
    ss2 = alg.op2(pk, sk, (ct, ss))
    assert ss == ss2


@pytest.mark.parametrize("name,kind_size", list(FIPS_SIGN_ORACLE.items()))
def test_sig_sizes_match_fips(name, kind_size):
    kind, expected = kind_size
    alg = next(a for a in SIGN_ALGS if a.name == name)
    pk, sk = alg.keygen()
    msg = os.urandom(64)
    sig = alg.op1(pk, sk, msg)
    if kind == "eq":
        assert len(sig) == expected, f"{name}: sig {len(sig)} != FIPS {expected}"
    elif kind == "le":
        assert 0 < len(sig) <= expected, f"{name}: sig {len(sig)} > FIPS upper bound {expected}"


@pytest.mark.parametrize("name,sizes", list(FIPS_KEY_ORACLE.items()))
def test_key_sizes_match_fips(name, sizes):
    alg = next(a for a in SIGN_ALGS if a.name == name)
    pk, sk = alg.keygen()
    assert len(pk) == sizes["pk"], f"{name}: pk {len(pk)} != FIPS {sizes['pk']}"
    assert len(sk) == sizes["sk"], f"{name}: sk {len(sk)} != FIPS {sizes['sk']}"


@pytest.mark.parametrize("name,sizes", list(FIPS_KEM_ORACLE.items()))
def test_mlkem_sizes_match_fips(name, sizes):
    alg = next(a for a in KEM_ALGS if a.name == name)
    pk, sk = alg.keygen()
    ct, ss = alg.op1(pk, sk, b"")
    assert len(pk) == sizes["pk"]
    assert len(sk) == sizes["sk"]
    assert len(ct) == sizes["ct"]
    assert len(ss) == sizes["ss"]


def test_select_filter_glob():
    sel = alg_mod.select(["ml-dsa-*", "falcon-*"])
    names = {a.name for a in sel}
    assert "ML-DSA-44" in names
    assert "ML-DSA-65" in names
    assert "Falcon-512" in names
    assert "ECDSA-P256" not in names


def test_select_unknown_returns_empty():
    assert alg_mod.select(["nonsense-*"]) == []


def test_select_empty_returns_all():
    assert len(alg_mod.select(None)) == len(ALL)
    assert len(alg_mod.select([])) == len(ALL)


def test_registry_has_required_families():
    families = {a.family for a in ALL}
    assert {"ECDSA", "ML-DSA", "Falcon", "SLH-DSA", "ML-KEM", "HQC"} <= families
