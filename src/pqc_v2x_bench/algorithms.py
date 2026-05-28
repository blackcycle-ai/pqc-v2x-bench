"""Algorithm registry.

Each algorithm is wrapped in a small adapter that exposes a uniform
keygen/op1/op2 interface to the bench loop. Two operation families
are supported: signatures (op1=sign, op2=verify) and KEMs
(op1=encapsulate, op2=decapsulate).

The registry is intentionally thin so new backends (e.g. oqs-python)
can be added by appending entries — no inheritance hierarchies.
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

# PQC sign modules. Fail loudly if any are missing — silent skips would
# produce a bench table where algorithms vanish without warning.
from pqcrypto.sign import (
    falcon_512,
    falcon_1024,
    ml_dsa_44,
    ml_dsa_65,
    ml_dsa_87,
    sphincs_sha2_128f_simple,
    sphincs_sha2_128s_simple,
)
from pqcrypto.kem import (
    hqc_128,
    hqc_192,
    hqc_256,
    ml_kem_512,
    ml_kem_768,
    ml_kem_1024,
)


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
# ECDSA adapters (sign family)
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
        # Pre-populate caches with the freshly-built objects so the first
        # sign/verify call on these bytes is already cold-free.
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
# PQ sign adapters (pqcrypto modules)
# ---------------------------------------------------------------------------

def _make_pq_sign(name: str, module, level: str, family: str) -> Algorithm:
    def keygen() -> tuple[bytes, bytes]:
        return module.generate_keypair()

    def op1(pk: bytes, sk: bytes, msg: bytes) -> bytes:
        return module.sign(sk, msg)

    def op2(pk: bytes, sk: bytes, msg_sig: tuple[bytes, bytes]) -> bool:
        msg, sig = msg_sig
        return bool(module.verify(pk, msg, sig))

    return Algorithm(name=name, kind="sign", nist_level=level, family=family,
                     keygen=keygen, op1=op1, op2=op2)


# ---------------------------------------------------------------------------
# PQ KEM adapters
# ---------------------------------------------------------------------------

def _make_pq_kem(name: str, module, level: str, family: str) -> Algorithm:
    def keygen() -> tuple[bytes, bytes]:
        return module.generate_keypair()

    def op1(pk: bytes, sk: bytes, _msg: bytes) -> tuple[bytes, bytes]:
        # encapsulate -> (ciphertext, shared_secret)
        return module.encrypt(pk)

    def op2(pk: bytes, sk: bytes, ct_ss: tuple[bytes, bytes]) -> bytes:
        ct, _ss = ct_ss
        return module.decrypt(sk, ct)

    return Algorithm(name=name, kind="kem", nist_level=level, family=family,
                     keygen=keygen, op1=op1, op2=op2)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

REGISTRY: tuple[Algorithm, ...] = (
    # Classical baselines
    _make_ecdsa("ECDSA-P256", ec.SECP256R1, "~L1 (128-bit)"),
    _make_ecdsa("ECDSA-BP256r1", ec.BrainpoolP256R1, "~L1 (128-bit)"),
    _make_ecdsa("ECDSA-BP384r1", ec.BrainpoolP384R1, "~L3 (192-bit)"),
    # FIPS-204 ML-DSA (lattice, sign)
    _make_pq_sign("ML-DSA-44", ml_dsa_44, "NIST L2", "ML-DSA"),
    _make_pq_sign("ML-DSA-65", ml_dsa_65, "NIST L3", "ML-DSA"),
    _make_pq_sign("ML-DSA-87", ml_dsa_87, "NIST L5", "ML-DSA"),
    # Falcon (lattice, sign — pending FIPS-206 ratification)
    _make_pq_sign("Falcon-512", falcon_512, "NIST L1", "Falcon"),
    _make_pq_sign("Falcon-1024", falcon_1024, "NIST L5", "Falcon"),
    # FIPS-205 SLH-DSA (hash-based, sign)
    _make_pq_sign("SLH-DSA-128s", sphincs_sha2_128s_simple, "NIST L1", "SLH-DSA"),
    _make_pq_sign("SLH-DSA-128f", sphincs_sha2_128f_simple, "NIST L1", "SLH-DSA"),
    # FIPS-203 ML-KEM (lattice, KEM)
    _make_pq_kem("ML-KEM-512", ml_kem_512, "NIST L1", "ML-KEM"),
    _make_pq_kem("ML-KEM-768", ml_kem_768, "NIST L3", "ML-KEM"),
    _make_pq_kem("ML-KEM-1024", ml_kem_1024, "NIST L5", "ML-KEM"),
    # NIST round-4 alternative KEM (code-based)
    _make_pq_kem("HQC-128", hqc_128, "NIST L1", "HQC"),
    _make_pq_kem("HQC-192", hqc_192, "NIST L3", "HQC"),
    _make_pq_kem("HQC-256", hqc_256, "NIST L5", "HQC"),
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
