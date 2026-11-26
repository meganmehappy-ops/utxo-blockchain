"""
taproot.py - real-Bitcoin taproot (BIP340 / BIP341 / BIP350) for this ledger.

EDUCATIONAL / REFERENCE IMPLEMENTATION - see README security disclaimer.
Everything here is the actual mainnet wire format:

* BIP350 bech32m addresses (hrp "bc", witness version 1, 32-byte program),
* BIP340 Schnorr signatures over secp256k1 (x-only keys, tagged hashes),
* BIP341 key-path-only outputs: Q = P + H_TapTweak(P) * G, and the BIP341
  key-path sighash (SIGHASH_DEFAULT, no annex, no script path),
* BIP341 scriptPubKey: OP_1 <32-byte x-only output key>.

The curve arithmetic is reused from ecc.py (affine, not constant-time).
Signing helpers take 32-byte secrets so the same code path as Bitcoin applies.
"""

from __future__ import annotations
import hashlib

from ecc import P, N, G, point_add, scalar_mul, is_on_curve

# --------------------------- tagged hashes (BIP340) ---------------------------


def tagged_hash(tag: str, msg: bytes) -> bytes:
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + msg).digest()


# --------------------------- bech32m (BIP173 + BIP350) ---------------------------

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


def _polymod(values) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits: int, tobits: int, pad: bool):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or value >> frombits:
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def segwit_encode(hrp: str, witver: int, program: bytes) -> str:
    """bech32m (BIP350) encoding, which is what witness v1+ uses on mainnet."""
    data = [witver] + _convertbits(program, 8, 5, True)
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)


def segwit_decode(addr: str):
    """Decode a bech32m segwit address -> (hrp, witver, program). Raises ValueError."""
    if not addr or any(ord(c) < 33 or ord(c) > 126 for c in addr):
        raise ValueError("invalid character")
    if addr.lower() != addr and addr.upper() != addr:
        raise ValueError("mixed case")
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        raise ValueError("invalid separator position")
    hrp, rest = addr[:pos], addr[pos + 1:]
    try:
        data = [CHARSET.index(c) for c in rest]
    except ValueError:
        raise ValueError("invalid data character")
    if _polymod(_hrp_expand(hrp) + data) != BECH32M_CONST:
        raise ValueError("invalid bech32m checksum")
    data = data[:-6]
    if not data:
        raise ValueError("empty data")
    witver = data[0]
    program = _convertbits(data[1:], 5, 8, False)
    if program is None:
        raise ValueError("invalid padding")
    program = bytes(program)
    if witver > 16:
        raise ValueError("invalid witness version")
    if witver == 0 and len(program) not in (20, 32):
        raise ValueError("invalid v0 program length")
    if witver != 0 and not (2 <= len(program) <= 40):
        raise ValueError("invalid program length")
    return hrp, witver, program


# --------------------------- x-only keys, tweaks, addresses ---------------------------

XONLY_G = G


def lift_x(x32: bytes):
    """BIP340 lift_x: the curve point with this x and an even y (None if none)."""
    if len(x32) != 32:
        return None
    x = int.from_bytes(x32, "big")
    if x >= P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if (y * y) % P != y2:
        return None
    return (x, y if (y & 1) == 0 else P - y)


def xonly(pt) -> bytes:
    """x-only encoding of a point (None -> ValueError)."""
    if pt is None:
        raise ValueError("point at infinity has no x-only encoding")
    return pt[0].to_bytes(32, "big")


def has_even_y(pt) -> bool:
    return pt[1] % 2 == 0


def point_neg(pt):
    return None if pt is None else (pt[0], P - pt[1])


def tap_tweak(internal_x: bytes, merkle_root: bytes | None = None) -> int:
    """BIP341 tweak t = H_TapTweak(internal_x || merkle_root) mod n."""
    return int.from_bytes(
        tagged_hash("TapTweak", internal_x + (merkle_root or b"")), "big") % N


def output_key(internal_x: bytes, merkle_root: bytes | None = None):
    """BIP341 key-path-only output key: returns (xonly 32 bytes, output_is_odd)."""
    P_int = lift_x(internal_x)
    if P_int is None:
        raise ValueError("internal key is not a valid x-only pubkey")
    Q = point_add(P_int, scalar_mul(tap_tweak(internal_x, merkle_root), G))
    if Q is None:
        raise ValueError("degenerate taproot output key")
    return xonly(Q), has_even_y(Q)


def taproot_address(internal_x: bytes, hrp: str = "bc", merkle_root: bytes | None = None) -> str:
    """The mainnet-style P2TR address (bc1p...) committing to this internal key."""
    q, _ = output_key(internal_x, merkle_root)
    return segwit_encode(hrp, 1, q)


def address_to_output_key(addr: str, hrp: str | None = None) -> bytes:
    """Decode a P2TR address and return its 32-byte x-only output key."""
    got_hrp, witver, program = segwit_decode(addr)
    if hrp is not None and got_hrp != hrp:
        raise ValueError(f"wrong network prefix {got_hrp!r}, expected {hrp!r}")
    if witver != 1 or len(program) != 32:
        raise ValueError("not a P2TR address (needs witness v1, 32 bytes)")
    return program


def is_taproot_address(addr: str, hrp: str | None = None) -> bool:
    try:
        address_to_output_key(addr, hrp)
        return True
    except ValueError:
        return False


def script_pubkey(output_x: bytes) -> bytes:
    """BIP341 scriptPubKey: OP_1 (0x51) PUSH32 <32-byte output key>."""
    if len(output_x) != 32:
        raise ValueError("output key must be 32 bytes")
    return b"\x51\x20" + output_x


# --------------------------- BIP340 Schnorr ---------------------------


def bip340_sign(seckey: bytes, msg: bytes, aux: bytes | None = None) -> bytes:
    """Sign a message with a 32-byte secret key -> 64-byte BIP340 sig.

    BIP340 allows any message length; Bitcoin itself always signs a 32-byte
    sighash. `aux` is 32 bytes of auxiliary randomness; default is 32 zero
    bytes, which is what the BIP340 test vectors use.
    """
    if len(seckey) != 32:
        raise ValueError("secret key must be 32 bytes")
    aux = b"\x00" * 32 if aux is None else aux
    if len(aux) != 32:
        raise ValueError("aux_rand must be 32 bytes")
    d0 = int.from_bytes(seckey, "big")
    if not 1 <= d0 <= N - 1:
        raise ValueError("secret key out of range")
    P_pt = scalar_mul(d0, G)
    d = d0 if has_even_y(P_pt) else N - d0
    px = xonly(P_pt)
    t = (d ^ int.from_bytes(tagged_hash("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(tagged_hash("BIP0340/nonce", t + px + msg), "big") % N
    if k0 == 0:
        raise ValueError("bad nonce")
    R = scalar_mul(k0, G)
    k = k0 if has_even_y(R) else N - k0
    rx = xonly(R)
    e = int.from_bytes(tagged_hash("BIP0340/challenge", rx + px + msg), "big") % N
    sig = rx + ((k + e * d) % N).to_bytes(32, "big")
    if not bip340_verify(px, msg, sig):
        raise RuntimeError("produced an invalid signature")
    return sig


def bip340_verify(pub_x: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify a BIP340 signature against an x-only public key."""
    try:
        if len(pub_x) != 32 or len(sig) != 64:
            return False
        Pt = lift_x(pub_x)
        if Pt is None:
            return False
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        if r >= P or s >= N:
            return False
        e = int.from_bytes(
            tagged_hash("BIP0340/challenge", sig[:32] + pub_x + msg), "big") % N
        R = point_add(scalar_mul(s, G), point_neg(scalar_mul(e, Pt)))
        if R is None or not has_even_y(R) or R[0] != r:
            return False
        return True
    except Exception:
        return False


# --------------------------- taproot key-path signing ---------------------------


def taproot_sign(seckey: bytes, msg: bytes, merkle_root: bytes | None = None,
                 aux: bytes | None = None) -> bytes:
    """BIP341 key-path signature: tweak the secret key, then BIP340-sign.

    If the internal key P has odd y the effective secret is n-d, and the tweak is
    added mod n - exactly what a Bitcoin wallet does for a key-path spend.
    """
    d0 = int.from_bytes(seckey, "big")
    if not 1 <= d0 <= N - 1:
        raise ValueError("secret key out of range")
    P_pt = scalar_mul(d0, G)
    d = d0 if has_even_y(P_pt) else N - d0
    t = tap_tweak(xonly(P_pt), merkle_root)
    d_tweaked = (d + t) % N
    if d_tweaked == 0:
        raise ValueError("invalid tweaked key")
    return bip340_sign(d_tweaked.to_bytes(32, "big"), msg, aux)


def taproot_verify(address: str, msg: bytes, sig: bytes, hrp: str | None = None) -> bool:
    """Verify a key-path signature for a P2TR address over a 32-byte sighash."""
    try:
        return bip340_verify(address_to_output_key(address, hrp), msg, sig)
    except ValueError:
        return False


# --------------------------- BIP341 sighash (key path) ---------------------------

SIGHASH_DEFAULT = 0x00
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80
_VALID_HASHTYPES = {0, 1, 2, 3, 0x81, 0x82, 0x83}


def _sha256(*chunks: bytes) -> bytes:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()


def _ser_string(b: bytes) -> bytes:
    return _varint(len(b)) + b


def _varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def bip341_sighash(prevouts, amounts, script_pubkeys, sequences, outputs,
                   input_index: int, hash_type: int = SIGHASH_DEFAULT,
                   annex: bytes | None = None, ext_flag: int = 0,
                   version: int = 2, locktime: int = 0) -> bytes:
    """BIP341 TapSighash for a key-path spend (ext_flag 0 by default).

    prevouts:  list of (txid_bytes_internal_order, vout)
    amounts:   list[int] in sats
    script_pubkeys: list[bytes] of the spent outputs
    sequences: list[int]
    outputs:   list[(amount, script_pubkey_bytes)]
    """
    if hash_type not in _VALID_HASHTYPES:
        raise ValueError("invalid hash type")
    n_in = len(prevouts)
    if not (len(amounts) == len(script_pubkeys) == len(sequences) == n_in):
        raise ValueError("prevout arrays must be the same length")
    if not 0 <= input_index < n_in:
        raise ValueError("input_index out of range")

    out_type = hash_type & 3
    anyonecanpay = bool(hash_type & SIGHASH_ANYONECANPAY)

    msg = bytearray([hash_type])
    msg += int(version).to_bytes(4, "little")
    msg += int(locktime).to_bytes(4, "little")

    if not anyonecanpay:
        msg += _sha256(b"".join(
            (bytes.fromhex(p[0]) if isinstance(p[0], str) else p[0])
            + int(p[1]).to_bytes(4, "little") for p in prevouts))
        msg += _sha256(b"".join(int(a).to_bytes(8, "little") for a in amounts))
        msg += _sha256(b"".join(_ser_string(spk) for spk in script_pubkeys))
        msg += _sha256(b"".join(int(s).to_bytes(4, "little") for s in sequences))

    if out_type in (SIGHASH_DEFAULT, SIGHASH_ALL):
        msg += _sha256(*(int(a).to_bytes(8, "little") + _ser_string(spk)
                         for a, spk in outputs))

    msg += bytes([ext_flag * 2 + (1 if annex is not None else 0)])

    if anyonecanpay:
        prev_txid = prevouts[input_index][0]
        if isinstance(prev_txid, str):
            prev_txid = bytes.fromhex(prev_txid)
        msg += prev_txid + int(prevouts[input_index][1]).to_bytes(4, "little")
        msg += int(amounts[input_index]).to_bytes(8, "little")
        msg += _ser_string(script_pubkeys[input_index])
        msg += int(sequences[input_index]).to_bytes(4, "little")
    else:
        msg += input_index.to_bytes(4, "little")

    if annex is not None:
        msg += _sha256(_ser_string(annex))

    if out_type == SIGHASH_SINGLE:
        if input_index >= len(outputs):
            raise ValueError("SIGHASH_SINGLE input has no matching output")
        amt, spk = outputs[input_index]
        msg += _sha256(int(amt).to_bytes(8, "little") + _ser_string(spk))

    if ext_flag != 0:
        raise NotImplementedError("tapscript extension (script-path) is not implemented")

    return tagged_hash("TapSighash", b"\x00" + bytes(msg))
