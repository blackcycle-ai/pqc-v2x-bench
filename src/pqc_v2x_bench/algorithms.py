"""Algorithm registry — homogeneous-libcrypto port.

Branch: `homogeneous-libcrypto`. Compared to `main`, the PQC adapters
no longer go through `pqcrypto` (PQClean reference C). They go through
`liboqs-python` 0.12.0, which dispatches to liboqs 0.15.0 — built with
AArch64 NEON + ARMv8 crypto extensions on Cortex-A78AE and verified-
formally `mlkem-native` / `mldsa-native` paths.

ECDSA adapters keep `cryptography` (pyca), which is recompiled from
source against the same OpenSSL 3.5.6 install used by liboqs. The two
backends share a libcrypto root and ISA-level optimizations, closing
the implementation-asymmetry confound flagged by reviewers of the
HNDL CCMS preprint.

Residual caveat (must stay in paper Limitations): `cryptography` goes
through EVP_PKEY → libcrypto, while `liboqs-python` calls the liboqs
C API directly. Both backends are compiled with the same optimization
flags and target ISA, but they do not share dispatch paths. The
implementation-asymmetry is minimized, not eliminated.

Two operation families, uniform interface:
  - signatures: op1=sign, op2=verify
  - KEMs: op1=encapsulate, op2=decapsulate
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# liboqs-python (oqs) — single PQ backend for all post-quantum families.
# Fail loudly at import time: silent skips would produce a bench table
# where algorithms vanish without warning.
import oqs


Kind = str  # "sign" | "kem"


@dataclass(frozen=True)
class Algorithm:
    name: str
    kind: Kind
    nist_level: str
    family: str
    keygen: Callable[[], tuple[bytes, bytes]]
    op1: Callable[[bytes, bytes, bytes], bytes]  # sign(sk,msg)->sig OR encaps(pk)->(ct,ss); see invoke_op1
    op2: Callable[[bytes, bytes, bytes], object]  # verify(pk,msg,sig)->bool OR decaps(sk,ct)->ss

    def matches(self, pattern: str) -> bool:
        """Glob-like match used by --algorithms filter."""
        import fnmatch
        return fnmatch.fnmatch(self.name.lower(), pattern.lower())


# ---------------------------------------------------------------------------
# ECDSA adapters (sign family) — IDENTICAL to main branch
# ---------------------------------------------------------------------------

def _ecdsa_factory(curve_ctor: Callable[[], ec.EllipticCurve]) -> dict[str, Callable]:
    """Build keygen/sign/verify closures over a cryptography EC curve.

    Parsed key objects are cached per raw-bytes representation so that
    sign/verify do not pay the DER deserialization cost on every call —
    a production CCMS endpoint loads the key once at boot and reuses it
    for thousands of operations.
    """
    from cryptography.hazmat.primitives.serialization import load_der_private_key

    _sk_cache: dict[bytes, ec.EllipticCurvePrivateKey] = {}
    _pk_cache: dict[bytes, ec.EllipticCurvePublicKey] = {}

    def keygen() -> tuple[bytes, bytes]:
        sk = ec.generate_private_key(curve_ctor())
        pk = sk.public_key()
        pk_bytes = pk.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        sk_bytes = sk.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        _sk_cache[sk_bytes] = sk
        _pk_cache[pk_bytes] = pk
        return pk_bytes, sk_bytes

    def _hash_for(curve: ec.EllipticCurve) -> hashes.HashAlgorithm:
        return hashes.SHA256() if curve.key_size <= 256 else hashes.SHA384()

    def sign(_pk: bytes, sk_bytes: bytes, msg: bytes) -> bytes:
        sk = _sk_cache.get(sk_bytes)
        if sk is None:
            sk = load_der_private_key(sk_bytes, password=None)
            _sk_cache[sk_bytes] = sk
        return sk.sign(msg, ec.ECDSA(_hash_for(sk.curve)))

    def verify(pk_bytes: bytes, _sk: bytes, msg: bytes, sig: bytes) -> bool:
        pk = _pk_cache.get(pk_bytes)
        if pk is None:
            pk = ec.EllipticCurvePublicKey.from_encoded_point(curve_ctor(), pk_bytes)
            _pk_cache[pk_bytes] = pk
        try:
            pk.verify(sig, msg, ec.ECDSA(_hash_for(pk.curve)))
            return True
        except InvalidSignature:
            return False

    return {"keygen": keygen, "sign": sign, "verify": verify}


def _make_ecdsa(name: str, curve_ctor: Callable[[], ec.EllipticCurve], level: str) -> Algorithm:
    f = _ecdsa_factory(curve_ctor)

    def op1(pk: bytes, sk: bytes, msg: bytes) -> bytes:
        return f["sign"](pk, sk, msg)

    def op2(pk: bytes, sk: bytes, msg_sig: tuple[bytes, bytes]) -> bool:
        msg, sig = msg_sig
        return f["verify"](pk, sk, msg, sig)

    return Algorithm(
        name=name,
        kind="sign",
        nist_level=level,
        family="ECDSA",
        keygen=f["keygen"],
        op1=op1,
        op2=op2,
    )


# ---------------------------------------------------------------------------
# PQ sign adapters via liboqs-python
# ---------------------------------------------------------------------------
#
# liboqs-python `Signature` is stateful: each `sign()` call needs a
# Signature object holding the secret key. We cache one signer object
# per sk_bytes (analogous to the ECDSA _sk_cache pattern) so sign latency
# does not include the cost of re-loading the key into liboqs internal
# state on every iteration. Verifier objects are stateless (no key in
# constructor), but caching them anyway saves Python-side allocation.
#
# Caveat: `oqs.Signature(name, sk)` keeps the secret key as a Python-side
# bytearray that liboqs reads via ctypes. The cache holds Python objects,
# not raw C pointers — no use-after-free risk.

def _make_oqs_sign(display_name: str, oqs_name: str, level: str, family: str) -> Algorithm:
    _signer_cache: dict[bytes, "oqs.Signature"] = {}
    _verifier: "oqs.Signature | None" = None

    def _get_verifier() -> "oqs.Signature":
        nonlocal _verifier
        if _verifier is None:
            _verifier = oqs.Signature(oqs_name)
        return _verifier

    def keygen() -> tuple[bytes, bytes]:
        signer = oqs.Signature(oqs_name)
        pk = signer.generate_keypair()
        sk = signer.export_secret_key()
        # Pre-populate cache so first sign() does not pay re-instantiation.
        _signer_cache[sk] = oqs.Signature(oqs_name, sk)
        return pk, sk

    def op1(_pk: bytes, sk: bytes, msg: bytes) -> bytes:
        signer = _signer_cache.get(sk)
        if signer is None:
            signer = oqs.Signature(oqs_name, sk)
            _signer_cache[sk] = signer
        return signer.sign(msg)

    def op2(pk: bytes, _sk: bytes, msg_sig: tuple[bytes, bytes]) -> bool:
        msg, sig = msg_sig
        verifier = _get_verifier()
        return bool(verifier.verify(msg, sig, pk))

    return Algorithm(
        name=display_name,
        kind="sign",
        nist_level=level,
        family=family,
        keygen=keygen,
        op1=op1,
        op2=op2,
    )


# ---------------------------------------------------------------------------
# PQ KEM adapters via liboqs-python
# ---------------------------------------------------------------------------

def _make_oqs_kem(display_name: str, oqs_name: str, level: str, family: str) -> Algorithm:
    _decapsulator_cache: dict[bytes, "oqs.KeyEncapsulation"] = {}
    _encapsulator: "oqs.KeyEncapsulation | None" = None

    def _get_encapsulator() -> "oqs.KeyEncapsulation":
        nonlocal _encapsulator
        if _encapsulator is None:
            _encapsulator = oqs.KeyEncapsulation(oqs_name)
        return _encapsulator

    def keygen() -> tuple[bytes, bytes]:
        kem = oqs.KeyEncapsulation(oqs_name)
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        _decapsulator_cache[sk] = oqs.KeyEncapsulation(oqs_name, sk)
        return pk, sk

    def op1(pk: bytes, _sk: bytes, _msg: bytes) -> tuple[bytes, bytes]:
        # encapsulate -> (ciphertext, shared_secret)
        encap = _get_encapsulator()
        ct, ss = encap.encap_secret(pk)
        return ct, ss

    def op2(_pk: bytes, sk: bytes, ct_ss: tuple[bytes, bytes]) -> bytes:
        ct, _ss = ct_ss
        decap = _decapsulator_cache.get(sk)
        if decap is None:
            decap = oqs.KeyEncapsulation(oqs_name, sk)
            _decapsulator_cache[sk] = decap
        return decap.decap_secret(ct)

    return Algorithm(
        name=display_name,
        kind="kem",
        nist_level=level,
        family=family,
        keygen=keygen,
        op1=op1,
        op2=op2,
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
#
# Display names kept identical to main branch for tooling/figures
# compatibility. The `oqs_name` second column is the liboqs canonical
# mechanism name — verify with `oqs.get_enabled_sig_mechanisms()` and
# `oqs.get_enabled_kem_mechanisms()` on the target host.

REGISTRY: tuple[Algorithm, ...] = (
    # Classical baselines via pyca/cryptography → OpenSSL 3.5.6 libcrypto
    _make_ecdsa("ECDSA-P256", ec.SECP256R1, "~L1 (128-bit)"),
    _make_ecdsa("ECDSA-BP256r1", ec.BrainpoolP256R1, "~L1 (128-bit)"),
    _make_ecdsa("ECDSA-BP384r1", ec.BrainpoolP384R1, "~L3 (192-bit)"),
    # FIPS-204 ML-DSA (lattice, sign) via liboqs 0.15 mldsa-native AArch64
    _make_oqs_sign("ML-DSA-44", "ML-DSA-44", "NIST L2", "ML-DSA"),
    _make_oqs_sign("ML-DSA-65", "ML-DSA-65", "NIST L3", "ML-DSA"),
    _make_oqs_sign("ML-DSA-87", "ML-DSA-87", "NIST L5", "ML-DSA"),
    # Falcon (lattice, sign — pending FIPS-206 ratification)
    _make_oqs_sign("Falcon-512", "Falcon-512", "NIST L1", "Falcon"),
    _make_oqs_sign("Falcon-1024", "Falcon-1024", "NIST L5", "Falcon"),
    # FIPS-205 SLH-DSA (hash-based, sign)
    _make_oqs_sign("SLH-DSA-128s", "SPHINCS+-SHA2-128s-simple", "NIST L1", "SLH-DSA"),
    _make_oqs_sign("SLH-DSA-128f", "SPHINCS+-SHA2-128f-simple", "NIST L1", "SLH-DSA"),
    # FIPS-203 ML-KEM (lattice, KEM) via liboqs 0.15 mlkem-native AArch64
    _make_oqs_kem("ML-KEM-512", "ML-KEM-512", "NIST L1", "ML-KEM"),
    _make_oqs_kem("ML-KEM-768", "ML-KEM-768", "NIST L3", "ML-KEM"),
    _make_oqs_kem("ML-KEM-1024", "ML-KEM-1024", "NIST L5", "ML-KEM"),
    # NIST round-4 alternative KEM (code-based) — DISABLED in liboqs 0.15
    # default build pending security audit re-validation of timing
    # side-channel disclosed in 2024. The paper retains the original
    # `pqcrypto` HQC numbers (from main branch run) for context; this
    # branch's runs report 13/16 algorithms.
    # _make_oqs_kem("HQC-128", "HQC-128", "NIST L1", "HQC"),
    # _make_oqs_kem("HQC-192", "HQC-192", "NIST L3", "HQC"),
    # _make_oqs_kem("HQC-256", "HQC-256", "NIST L5", "HQC"),
)


def list_algorithms() -> tuple[Algorithm, ...]:
    return REGISTRY


def select(patterns: Iterable[str] | None) -> list[Algorithm]:
    """Filter the registry by comma/list of glob patterns. None or empty -> all."""
    pats = [p.strip() for p in (patterns or []) if p and p.strip()]
    if not pats:
        return list(REGISTRY)
    out: list[Algorithm] = []
    seen: set[str] = set()
    for alg in REGISTRY:
        for p in pats:
            if alg.matches(p) and alg.name not in seen:
                out.append(alg)
                seen.add(alg.name)
                break
    return out
