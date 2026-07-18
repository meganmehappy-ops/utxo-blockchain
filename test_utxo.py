"""
test_utxo.py - correctness tests for the crypto primitives and the UTXO ledger.

Run:  python test_utxo.py
Exit code 0 and all [PASS] lines mean the whole pipeline verified.
"""

from __future__ import annotations
import os

from ecc import (
    N, G, scalar_mul, gen_privkey, privkey_to_pubkey, compress, decompress,
    pubkey_to_address, sign, verify, is_on_curve,
)
from utxo import (
    Blockchain, Wallet, build_spend, sign_input,
    Transaction, TxInput, TxOutput,
)

_passed = 0


def check(name, cond):
    global _passed
    if cond:
        _passed += 1
        print(f"[PASS] {name}")
    else:
        print(f"[FAIL] {name}")
        raise AssertionError(name)


# --------------------------- curve / signature tests ---------------------------

def test_curve_order():
    # A hard correctness check on the group: N * G must be the identity.
    check("N*G == point at infinity (correct group order)", scalar_mul(N, G) is None)
    check("generator G is on the curve", is_on_curve(G))


def test_point_roundtrip():
    d = gen_privkey()
    pub = privkey_to_pubkey(d)
    check("pubkey is on the curve", is_on_curve(pub))
    check("compress/decompress round-trips", decompress(compress(pub)) == pub)


def test_signature_roundtrip():
    d = gen_privkey()
    pub = compress(privkey_to_pubkey(d))
    msg = os.urandom(32)
    sig = sign(d, msg)
    check("valid Schnorr signature verifies", verify(pub, msg, sig))


def test_forgery_rejected():
    d = gen_privkey()
    pub = compress(privkey_to_pubkey(d))
    msg = b"pay Bob 10 coins"
    sig = sign(d, msg)
    # tampered message
    check("signature over a different message is rejected",
          not verify(pub, b"pay Bob 99 coins", sig))
    # tampered signature bytes
    bad = bytearray(sig); bad[-1] ^= 0x01
    check("tampered signature bytes are rejected", not verify(pub, msg, bytes(bad)))
    # wrong key
    other = compress(privkey_to_pubkey(gen_privkey()))
    check("signature verified against wrong pubkey is rejected",
          not verify(other, msg, sig))


def test_address_binds_pubkey():
    d = gen_privkey()
    pub = compress(privkey_to_pubkey(d))
    other = compress(privkey_to_pubkey(gen_privkey()))
    check("address is deterministic from pubkey",
          pubkey_to_address(pub) == pubkey_to_address(pub))
    check("different pubkeys give different addresses",
          pubkey_to_address(pub) != pubkey_to_address(other))


# --------------------------- transaction tests ---------------------------

def test_sighash_and_txid():
    tx = Transaction([TxInput("ab" * 32, 0)], [TxOutput(10, "1xdead")])
    tx2 = Transaction([TxInput("ab" * 32, 0)], [TxOutput(11, "1xdead")])
    check("changing an output changes the sighash", tx.sighash() != tx2.sighash())
    check("txid is stable for identical tx", tx.txid() == Transaction(
        [TxInput("ab" * 32, 0)], [TxOutput(10, "1xdead")]).txid())


# --------------------------- ledger tests ---------------------------

def fresh_chain():
    alice, bob, charlie, miner = (Wallet(n) for n in ("Alice", "Bob", "Charlie", "Miner"))
    bc = Blockchain(difficulty=2, subsidy=50)  # difficulty 2 keeps tests fast
    bc.add_block([], alice.address)            # genesis coinbase -> Alice 50
    return bc, alice, bob, charlie, miner


def test_genesis_and_spend():
    bc, alice, bob, charlie, miner = fresh_chain()
    check("genesis credits Alice 50", bc.balance(alice.address) == 50)

    spend = build_spend(bc, alice, [(bob.address, 30), (charlie.address, 15)], fee=5)
    bc.add_block([spend], miner.address)
    check("Bob received 30", bc.balance(bob.address) == 30)
    check("Charlie received 15", bc.balance(charlie.address) == 15)
    check("Alice has 0 left (spent whole 50)", bc.balance(alice.address) == 0)
    check("Miner earned subsidy 50 + fee 5 = 55", bc.balance(miner.address) == 55)
    ok, _ = bc.validate_chain()
    check("chain validates after honest spend", ok)


def test_change_output():
    bc, alice, bob, charlie, miner = fresh_chain()
    spend = build_spend(bc, alice, [(bob.address, 20)], fee=0)  # 50 -> 20 + 30 change
    bc.add_block([spend], miner.address)
    check("Bob got 20", bc.balance(bob.address) == 20)
    check("Alice kept 30 change", bc.balance(alice.address) == 30)


def test_double_spend_rejected():
    bc, alice, bob, charlie, miner = fresh_chain()
    spend = build_spend(bc, alice, [(bob.address, 50)], fee=0)
    bc.add_block([spend], miner.address)  # genesis UTXO now spent

    genesis_cb = bc.chain[0].transactions[0]
    evil = Transaction([TxInput(genesis_cb.txid(), 0)], [TxOutput(50, charlie.address)])
    sign_input(evil, 0, alice.priv)
    rejected = False
    try:
        bc.add_block([evil], miner.address)
    except ValueError:
        rejected = True
    check("double-spend of an already-spent UTXO is rejected", rejected)


def test_value_creation_rejected():
    bc, alice, bob, charlie, miner = fresh_chain()
    # try to spend 50 into 80 (out of thin air)
    spend = Transaction([TxInput(bc.chain[0].transactions[0].txid(), 0)],
                        [TxOutput(80, bob.address)])
    sign_input(spend, 0, alice.priv)
    rejected = False
    try:
        bc.add_block([spend], miner.address)
    except ValueError:
        rejected = True
    check("outputs exceeding inputs are rejected", rejected)


def test_tampered_amount_rejected():
    bc, alice, bob, charlie, miner = fresh_chain()
    spend = build_spend(bc, alice, [(bob.address, 10)], fee=0)  # signs 10 + 40 change
    # attacker rewrites the recipient amount AFTER signing -> sighash changes
    spend.outputs[0].amount = 45
    ok, _, reason = bc.validate_tx(spend, dict(bc.utxo))
    check("editing an output after signing invalidates the signature",
          (not ok) and reason == "invalid signature")


def test_wrong_signer_rejected():
    bc, alice, bob, charlie, miner = fresh_chain()
    # Bob tries to spend Alice's genesis UTXO by signing with his own key
    theft = Transaction([TxInput(bc.chain[0].transactions[0].txid(), 0)],
                        [TxOutput(50, bob.address)])
    sign_input(theft, 0, bob.priv)  # wrong key -> pubkey won't match address
    ok, _, reason = bc.validate_tx(theft, dict(bc.utxo))
    check("spending someone else's UTXO is rejected",
          (not ok) and reason == "pubkey does not hash to the output's address")


def test_insufficient_funds():
    bc, alice, bob, charlie, miner = fresh_chain()
    raised = False
    try:
        build_spend(bc, bob, [(alice.address, 10)])  # Bob has nothing
    except ValueError:
        raised = True
    check("build_spend raises on insufficient funds", raised)


def test_tampered_chain_detected():
    bc, alice, bob, charlie, miner = fresh_chain()
    bc.add_block([build_spend(bc, alice, [(bob.address, 50)])], miner.address)
    check("honest chain is valid", bc.validate_chain()[0])
    # forge a stored output amount without re-mining
    bc.chain[1].transactions[1].outputs[0].amount = 999
    ok, _ = bc.validate_chain()
    check("tampering with a stored block is detected", not ok)


def main():
    tests = [
        test_curve_order, test_point_roundtrip, test_signature_roundtrip,
        test_forgery_rejected, test_address_binds_pubkey, test_sighash_and_txid,
        test_genesis_and_spend, test_change_output, test_double_spend_rejected,
        test_value_creation_rejected, test_tampered_amount_rejected,
        test_wrong_signer_rejected, test_insufficient_funds,
        test_tampered_chain_detected,
    ]
    print("=" * 60)
    for t in tests:
        t()
    print("=" * 60)
    print(f"ALL {_passed} CHECKS PASSED")


if __name__ == "__main__":
    main()
