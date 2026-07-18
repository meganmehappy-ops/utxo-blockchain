"""
demo.py - end-to-end walkthrough of the UTXO ledger.

Run:  python demo.py        (or:  python demo.py --demo)

Story:
  1. Genesis block mints a 50-coin coinbase to Alice.
  2. Alice pays Bob 30 and Charlie 15 (fee 5), with change back to herself.
  3. A miner seals that block; balances update.
  4. Alice tries to double-spend a UTXO she already spent -> REJECTED.
  5. The whole chain is re-validated from genesis.

Note: private keys, addresses and block hashes are random per run, so the exact
hex strings below will differ each time you execute it.
"""

from __future__ import annotations
import argparse

from utxo import Blockchain, Wallet, build_spend, TxInput, TxOutput, Transaction, sign_input


def line(c="-", n=64):
    print(c * n)


def show_balances(bc, wallets):
    for w in wallets:
        print(f"    {w.name:<8} {w.address}  balance = {bc.balance(w.address):>4}")


def main():
    argparse.ArgumentParser(description="UTXO blockchain demo").parse_args()

    alice = Wallet("Alice")
    bob = Wallet("Bob")
    charlie = Wallet("Charlie")
    miner = Wallet("Miner")

    bc = Blockchain(difficulty=3, subsidy=50)

    line("=")
    print(" UTXO BLOCKCHAIN DEMO")
    line("=")

    # --- 1. genesis coinbase to Alice ---
    print("\n[1] Mining GENESIS block (coinbase 50 -> Alice)")
    g = bc.add_block([], alice.address)
    print(f"    block #{g.index}  hash {g.hash()[:20]}...  nonce {g.nonce}")
    show_balances(bc, [alice, bob, charlie, miner])

    # --- 2. Alice pays Bob 30 and Charlie 15, fee 5 ---
    print("\n[2] Alice -> Bob 30, Charlie 15  (fee 5, change 0)")
    spend = build_spend(bc, alice, [(bob.address, 30), (charlie.address, 15)], fee=5)
    print(f"    tx {spend.txid()[:20]}...  {len(spend.inputs)} in / {len(spend.outputs)} out")

    print("\n[3] Miner seals block #1 (fee 5 -> coinbase, so miner gets 55)")
    b1 = bc.add_block([spend], miner.address)
    print(f"    block #{b1.index}  hash {b1.hash()[:20]}...  nonce {b1.nonce}")
    show_balances(bc, [alice, bob, charlie, miner])

    # --- 4. double-spend attempt ---
    print("\n[4] Alice tries to DOUBLE-SPEND the genesis coin she already spent")
    spent_txid, spent_idx = g.transactions[0].txid(), 0  # the genesis coinbase output
    evil_in = TxInput(spent_txid, spent_idx)
    evil = Transaction([evil_in], [TxOutput(50, charlie.address)])
    sign_input(evil, 0, alice.priv)
    try:
        bc.add_block([evil], miner.address)
        print("    !! ERROR: double-spend was accepted (should never happen)")
    except ValueError as e:
        print(f"    REJECTED as expected -> {e}")

    # --- 5. validate the whole chain ---
    print("\n[5] Re-validating the entire chain from genesis")
    ok, reason = bc.validate_chain()
    print(f"    validate_chain() -> {ok}  ({reason})")
    print(f"    chain length = {len(bc.chain)} blocks, UTXO set = {len(bc.utxo)} outputs")

    line("=")
    total = sum(o.amount for o in bc.utxo.values())
    print(f" Total coins in existence: {total}  (2 coinbases x 50 + fees)")
    line("=")


if __name__ == "__main__":
    main()
