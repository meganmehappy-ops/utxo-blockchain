"""
test_taproot.py - taproot layer checked against the official Bitcoin test vectors.

Covers:
  * BIP350 bech32m address encode/decode (round-trip + checksum rejection)
  * BIP341 scriptPubKey / address vectors (internal key -> tweak -> output key)
  * BIP341 key-path sighash + signature vectors (real unsigned mainnet tx)
  * BIP340 Schnorr verify/sign vectors
  * the ledger's taproot spend path end to end

Run: python test_taproot.py
"""

from __future__ import annotations
import csv
import json
import os
import sys

from taproot import (
    CHARSET, address_to_output_key, bip340_sign, bip340_verify,
    bip341_sighash, is_taproot_address, output_key, script_pubkey,
    segwit_decode, segwit_encode, tap_tweak, taproot_address,
    taproot_sign, taproot_verify, tagged_hash, xonly, lift_x,
)
from ecc import N, G, scalar_mul, compress
import utxo
from utxo import Blockchain, TaprootWallet, Wallet, build_taproot_spend, build_spend
from taproot import BECH32M_CONST, _convertbits, _hrp_expand, _polymod

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, "vectors")

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"[PASS] {name}")
    else:
        failed += 1
        print(f"[FAIL] {name}" + (f"  ({detail})" if detail else ""))


def raises(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except Exception:
        return True
    return False


# --------------------------- BIP350 bech32m ---------------------------

check("bech32m encode of a known v1 program",
      segwit_encode("bc", 1, bytes.fromhex(
          "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")).startswith("bc1p"))
for addr in ["bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5",
             "bc1pz37fc4cn9ah8anwm4xqqhvxygjf9rjf2resrw8h8w4tmvcs0863sa2e586"]:
    hrp, ver, prog = segwit_decode(addr)
    check(f"decode {addr[:14]}... -> v{ver}, 32-byte program", ver == 1 and len(prog) == 32)
    check("  re-encodes to the same string", segwit_encode(hrp, ver, prog) == addr)
check("a flipped character breaks the bech32m checksum",
      raises(segwit_decode, "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z6"))
def bech32_encode_checksum_const(hrp: str, data5, const: int) -> str:
    """Encode with an arbitrary checksum constant (1 = bech32, 0x2bc830a3 = bech32m)."""
    vals = _hrp_expand(hrp) + list(data5)
    polymod = _polymod(vals + [0] * 6) ^ const
    return hrp + "1" + "".join(CHARSET[d] for d in list(data5) +
                                [(polymod >> 5 * (5 - i)) & 31 for i in range(6)])


_prog32 = bytes(range(32))
_data5 = [1] + _convertbits(_prog32, 8, 5, True)
_good = bech32_encode_checksum_const("bc", _data5, BECH32M_CONST)
_old = bech32_encode_checksum_const("bc", _data5, 1)
check("a v1 address with bech32m checksum decodes", segwit_decode(_good)[2] == _prog32)
check("the same v1 program with an old bech32 checksum is rejected", raises(segwit_decode, _old))

# --------------------------- BIP341 scriptPubKey vectors ---------------------------

with open(os.path.join(VEC, "bip341-wallet-test-vectors.json")) as f:
    vec = json.load(f)

spk_vectors = [v for v in vec["scriptPubKey"] if v["given"]["scriptTree"] is None
               and v["intermediary"]["merkleRoot"] is None]
check("found the key-path-only scriptPubKey vectors", len(spk_vectors) >= 1)

for v in spk_vectors:
    internal = bytes.fromhex(v["given"]["internalPubkey"])
    tweak = v["intermediary"]["tweak"]
    q = v["intermediary"]["tweakedPubkey"]
    check(f"tweak matches BIP341 for internal key {internal.hex()[:12]}...",
          tap_tweak(internal).to_bytes(32, "big").hex() == tweak)
    check("  output key matches", output_key(internal)[0].hex() == q)
    check("  scriptPubKey matches 51 20 <key>",
          script_pubkey(bytes.fromhex(q)).hex() == v["expected"]["scriptPubKey"])
    check("  bc1p address matches the vector",
          taproot_address(internal) == v["expected"]["bip350Address"],
          taproot_address(internal))
    check("  address decodes back to the output key",
          address_to_output_key(v["expected"]["bip350Address"]).hex() == q)

# script-tree vectors: merkle root is committed too (address level only)
tree_vectors = [v for v in vec["scriptPubKey"] if v["intermediary"]["merkleRoot"]]
check("found script-tree scriptPubKey vectors", len(tree_vectors) >= 1)
for v in tree_vectors:
    internal = bytes.fromhex(v["given"]["internalPubkey"])
    root = bytes.fromhex(v["intermediary"]["merkleRoot"])
    check(f"tap-tweak with merkle root {root.hex()[:10]}... matches",
          tap_tweak(internal, root).to_bytes(32, "big").hex() == v["intermediary"]["tweak"])
    check("  committed address matches the vector",
          taproot_address(internal, merkle_root=root) == v["expected"]["bip350Address"])

# --------------------------- BIP340 Schnorr vectors ---------------------------

sign_ok = verify_ok = 0
rows = 0
with open(os.path.join(VEC, "bip340-test-vectors.csv")) as f:
    for row in csv.DictReader(f):
        rows += 1
        pub = bytes.fromhex(row["public key"])
        msg = bytes.fromhex(row["message"])
        sig = bytes.fromhex(row["signature"])
        want = row["verification result"].strip() == "TRUE"
        got = bip340_verify(pub, msg, sig)
        verify_ok += (want == got)
        if want and row["secret key"].strip():
            sec = bytes.fromhex(row["secret key"])
            aux = bytes.fromhex(row["aux_rand"] or "00" * 32)
            sign_ok += (bip340_sign(sec, msg, aux) == sig)
check(f"BIP340 verify: all {rows} vectors agree", verify_ok == rows, f"{verify_ok}/{rows}")
check("BIP340 sign: every signing vector reproduced byte for byte (incl. its aux_rand)",
      sign_ok == 8, f"{sign_ok}/8")

# --------------------------- BIP341 key-path sighash + signature vectors ---------

_raw = vec["keyPathSpending"][0]["given"]["rawUnsignedTx"]


def parse_tx(raw_hex: str):
    """Minimal Bitcoin tx parser -> (version, [(txid_le, vout, seq)], [(amount, spk)], locktime)."""
    b = bytes.fromhex(raw_hex)
    i = 0

    def rd(n):
        nonlocal i
        v = b[i:i + n]
        i += n
        return v

    def varint():
        nonlocal i
        n = b[i]
        i += 1
        if n < 0xFD:
            return n
        size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[n]
        v = int.from_bytes(rd(size), "little")
        return v

    version = int.from_bytes(rd(4), "little", signed=True)
    n_in = varint()
    inputs = []
    for _ in range(n_in):
        prev = rd(32)
        vout = int.from_bytes(rd(4), "little")
        script = rd(varint())
        seq = int.from_bytes(rd(4), "little")
        inputs.append((prev, vout, seq, script))
    n_out = varint()
    outputs = []
    for _ in range(n_out):
        amt = int.from_bytes(rd(8), "little")
        spk = rd(varint())
        outputs.append((amt, spk))
    locktime = int.from_bytes(rd(4), "little")
    return version, inputs, outputs, locktime


version, txins, txouts, locktime = parse_tx(_raw)
spend = vec["keyPathSpending"][0]
utxos = spend["given"]["utxosSpent"]
check("parsed the real unsigned tx (9 inputs, 2 outputs)",
      len(txins) == 9 and len(txouts) == 2 and version == 2)

prevouts = [(t[0], t[1]) for t in txins]
amounts = [u["amountSats"] for u in utxos]
spks = [bytes.fromhex(u["scriptPubKey"]) for u in utxos]
seqs = [t[2] for t in txins]

cases = spend["inputSpending"]
check(f"found {len(cases)} key-path spending cases", len(cases) >= 5)

for c in cases:
    idx = c["given"]["txinIndex"]
    ht = c["given"]["hashType"]
    root = bytes.fromhex(c["given"]["merkleRoot"]) if c["given"]["merkleRoot"] else None
    want = c["intermediary"]["sigHash"]
    got = bip341_sighash(prevouts, amounts, spks, seqs, txouts, idx,
                         hash_type=ht, version=version, locktime=locktime)
    check(f"BIP341 sighash matches (input {idx}, hashType {ht:#04x})",
          got.hex() == want, got.hex())
    # the signature in the fixture is made with aux = 32 zero bytes
    sig = taproot_sign(bytes.fromhex(c["given"]["internalPrivkey"]),
                       bytes.fromhex(want), merkle_root=root, aux=b"\x00" * 32)
    witness = c["expected"]["witness"][0]
    expect_hex = sig.hex() + ("" if ht == 0 else f"{ht:02x}")
    check("  key-path signature reproduced byte for byte", expect_hex == witness,
          expect_hex)
    q = output_key(xonly(scalar_mul(int.from_bytes(
        bytes.fromhex(c["given"]["internalPrivkey"]), "big"), G)), root)[0]
    check("  signature verifies against the output key", bip340_verify(q, bytes.fromhex(want), sig))

# --------------------------- ledger: real taproot spend ---------------------------

bc = Blockchain(difficulty=2, subsidy=50)
alice = TaprootWallet("alice")
bob = TaprootWallet("bob")
miner = Wallet("miner")

check("wallet address is a mainnet-style bc1p... P2TR", is_taproot_address(alice.address)
      and alice.address.startswith("bc1p") and len(alice.address) == 62)
check("the address commits to Q = P + H_TapTweak(P)*G",
      address_to_output_key(alice.address) == alice.output_key)

bc.add_block([], alice.address)          # coinbase 50 -> alice, paid to a P2TR output
check("alice holds the P2TR coinbase output", bc.balance(alice.address) == 50)

tx = build_taproot_spend(bc, alice, [(bob.address, 20)], fee=2)
check("taproot spend has no pubkey in the input (key path)", tx.inputs[0].pubkey == "")
msg0 = utxo.bip341_sighash_for(tx, bc.utxo, 0)
check("its signature is a valid BIP340 key-path sig for alice's P2TR output",
      taproot_verify(alice.address, msg0, bytes.fromhex(tx.inputs[0].signature)))
bc.add_block([tx], miner.address)
check("bob credited 20", bc.balance(bob.address) == 20)
check("alice kept 28 change", bc.balance(alice.address) == 28)
check("miner collected 50 + 2 fee", bc.balance(miner.address) == 52)
ok, reason = bc.validate_chain()
check("chain re-validates with a real BIP341 spend in it", ok, reason)

# bob pays alice back, changing the sighash -> a new valid signature
tx2 = build_taproot_spend(bc, bob, [(alice.address, 5)], fee=1)
bc.add_block([tx2], miner.address)
check("second taproot spend accepted", bc.balance(alice.address) == 33)

# replaying an already-spent coinbase output is rejected
old_outpoint = (tx2.inputs[0].prev_txid, tx2.inputs[0].prev_index)
dangling = utxo.Transaction([utxo.TxInput(*old_outpoint)],
                            [utxo.TxOutput(1, bob.address)])
dangling.inputs[0].signature = tx2.inputs[0].signature
ok2, fee2, why = bc.validate_tx(dangling, bc.utxo)
check("replaying an already-spent P2TR outpoint is rejected", not ok2, why)

# tampering: change an output after signing -> BIP341 sighash binds the outputs
tampered = utxo.Transaction([utxo.TxInput("0" * 64, 0)], [utxo.TxOutput(1, bob.address)])
tx3 = build_taproot_spend(bc, alice, [(bob.address, 5)], fee=1)
tx3.outputs[0].amount = 6
ok3, _, why3 = bc.validate_tx(tx3, bc.utxo)
check("editing an output after signing breaks the key-path signature", not ok3, why3)

# and a signature made for one address cannot spend another's coins
thief = TaprootWallet("thief")
tx4 = build_taproot_spend(bc, alice, [(bob.address, 1)], fee=1)
tx4.inputs[0].signature = taproot_sign(thief.seckey, utxo.bip341_sighash_for(tx4, bc.utxo, 0)).hex()
ok4, _, why4 = bc.validate_tx(tx4, bc.utxo)
check("a signature from the wrong key is rejected", not ok4, why4)

# the old ECDSA-ish ledger still works alongside taproot outputs
legacy = Wallet("legacy")
bc.add_block([], legacy.address)
check("legacy 1x... wallet coins a block too", bc.balance(legacy.address) == 50)
ltx = build_spend(bc, legacy, [(alice.address, 10)], fee=1)
bc.add_block([ltx], miner.address)
check("legacy wallet can pay a taproot address", bc.balance(alice.address) == 43)
ok5, reason5 = bc.validate_chain()
check("mixed chain (legacy + taproot outputs) validates", ok5, reason5)

print("=" * 60)
print(f"{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
