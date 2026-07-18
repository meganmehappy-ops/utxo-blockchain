"""
ecc.py - secp256k1 elliptic curve + Schnorr signatures (pure Python, stdlib only).

EDUCATIONAL / REFERENCE IMPLEMENTATION - see README security disclaimer.
- All field/scalar arithmetic uses Python's built-in big integers and pow().
- This is NOT constant-time: point additions, the modular inverse and the
  double-and-add ladder all leak timing/branch information. Do NOT use it to
  protect real keys or real funds.
- Every secret (private key, nonce) is derived from a CSPRNG (`secrets`) or a
  keyed hash of the secret - never from the `random` module.
"""

from __future__ import annotations
import hashlib
import secrets

# --- secp256k1 domain parameters (the exact curve Bitcoin uses) ---
# Curve: y^2 = x^3 + 7  (a = 0, b = 7)  over the prime field F_P.
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # field prime
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # group order
A  = 0
B  = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (Gx, Gy)  # the standard generator / base point

# A point is a tuple (x, y). The point at infinity (identity) is None.
Point = "tuple[int, int] | None"


def inv(x: int, m: int = P) -> int:
    """Modular inverse via Fermat/Euclid (Python's built-in extended pow)."""
    return pow(x, -1, m)


def is_on_curve(pt) -> bool:
    if pt is None:
        return True
    x, y = pt
    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_add(p1, p2):
    """Add two points on secp256k1 using the affine group law."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None  # P + (-P) = identity
    if p1 == p2:
        # tangent slope: (3x^2 + a) / (2y)
        m = (3 * x1 * x1 + A) * inv(2 * y1) % P
    else:
        # chord slope: (y2 - y1) / (x2 - x1)
        m = (y2 - y1) * inv(x2 - x1) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mul(k: int, pt):
    """Compute k*pt with the double-and-add ladder (NOT constant-time)."""
    k %= N
    result = None
    addend = pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


# --------------------------- keys ---------------------------

def gen_privkey() -> int:
    """A private key is a random scalar in [1, N-1], drawn from the CSPRNG."""
    return secrets.randbelow(N - 1) + 1


def privkey_to_pubkey(d: int):
    """Public key = d * G (a curve point)."""
    return scalar_mul(d, G)


def compress(pt) -> bytes:
    """SEC1 compressed encoding: 0x02/0x03 (y parity) || x (32 bytes)."""
    x, y = pt
    prefix = b"\x03" if (y & 1) else b"\x02"
    return prefix + x.to_bytes(32, "big")


def decompress(data: bytes):
    """Recover a point from its compressed encoding.

    secp256k1's prime satisfies P % 4 == 3, so the square root of a residue r
    is r^((P+1)/4) mod P.
    """
    prefix = data[0]
    x = int.from_bytes(data[1:33], "big")
    y2 = (pow(x, 3, P) + A * x + B) % P
    y = pow(y2, (P + 1) // 4, P)
    if (y * y) % P != y2:
        raise ValueError("point not on curve")
    if (y & 1) != (prefix & 1):
        y = P - y
    return (x, y)


def pubkey_to_address(pub_compressed: bytes) -> str:
    """Bitcoin-style address = hash of the pubkey.

    Real Bitcoin uses RIPEMD160(SHA256(pubkey)) (a.k.a. HASH160). RIPEMD160 is
    not guaranteed to be present in every hashlib build, so here we use
    double-SHA256 truncated to 20 bytes. Documented simplification.
    """
    h = hashlib.sha256(hashlib.sha256(pub_compressed).digest()).digest()
    return "1x" + h[:20].hex()


# --------------------------- Schnorr signatures ---------------------------
# Sign(d, m):  R = k*G,  e = H(R || P || m),  s = k + e*d   -> sig = (R, s)
# Verify:      s*G == R + e*P
# This is the classic Schnorr identification/signature scheme over secp256k1.

def _hash_scalar(*chunks: bytes) -> int:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return int.from_bytes(h.digest(), "big") % N


def sign(d: int, msg: bytes) -> bytes:
    """Schnorr-sign a message with private key d. Returns 65 bytes: R(33)||s(32).

    The nonce k is derived deterministically from (d, msg) - RFC6979 in spirit.
    Because k depends on the secret AND the message, every distinct message gets
    a fresh, unpredictable nonce; a reused nonce across two messages would leak
    the private key, so we never let that happen.
    """
    pub = privkey_to_pubkey(d)
    seed = hashlib.sha256(d.to_bytes(32, "big") + msg).digest()
    k = (int.from_bytes(seed, "big") % (N - 1)) + 1
    R = scalar_mul(k, G)
    e = _hash_scalar(compress(R), compress(pub), msg)
    s = (k + e * d) % N
    return compress(R) + s.to_bytes(32, "big")


def verify(pub_compressed: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify a Schnorr signature. Returns True only for a valid signature."""
    try:
        if len(sig) != 65:
            return False
        R = decompress(sig[:33])
        s = int.from_bytes(sig[33:65], "big")
        pub = decompress(pub_compressed)
        if not (is_on_curve(R) and is_on_curve(pub)):
            return False
        e = _hash_scalar(sig[:33], pub_compressed, msg)
        left = scalar_mul(s, G)            # s*G
        right = point_add(R, scalar_mul(e, pub))  # R + e*P
        return left == right
    except Exception:
        return False
