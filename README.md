# utxo-blockchain

**A from-scratch, Bitcoin-style UTXO ledger in pure Python: real Schnorr signatures over secp256k1, real taproot (BIP340/341/350) addresses and key-path spends, a live UTXO set, double-spend rejection, blocks and proof-of-work.**

## What this is

This is a minimal but faithful model of how Bitcoin actually tracks money. Instead of account balances, value lives in **Unspent Transaction Outputs (UTXOs)** - each a `(amount, address)` coin. A transaction *consumes* existing UTXOs (its inputs) and *creates* new ones (its outputs), and each input is authorised by a digital signature from the owner of the coin being spent. It sits squarely in the "ledger design" layer of blockchain/DLT: the UTXO model is what distinguishes Bitcoin (and Cardano) from account-based chains like Ethereum. I built it to understand every step end-to-end - the elliptic-curve keys, the signature that binds a spend, the validation rules that stop double-spends and value creation, and the proof-of-work that seals blocks.

Everything is implemented on Python's standard library only - the secp256k1 curve math is done with big-integer `pow()`, and signatures use a classic Schnorr scheme I wrote by hand.

## How it works

**1. Keys & addresses (`ecc.py`).** A private key `d` is a random scalar in `[1, N-1]` from a CSPRNG. The public key is the curve point `P = d*G` on secp256k1 (`y^2 = x^3 + 7`). Points are compressed to `0x02/0x03 || x`. An address is a hash of the compressed pubkey (double-SHA256 truncated to 20 bytes - see the simplification note below).

**2. Schnorr signatures.** To spend, the owner signs the transaction's *sighash* `m`:

```
nonce   k = H(d || m)          # secret- and message-dependent -> unique per message
         R = k*G
commit   e = H(R || P || m)  (mod N)
respond  s = k + e*d          (mod N)
sig = (R, s)
```

Verification checks `s*G == R + e*P`. Expanding the left side: `s*G = (k + e*d)*G = k*G + e*(d*G) = R + e*P`, so a valid signature always passes and forging one requires the private key. The nonce is derived deterministically from the secret and the message (RFC 6979 in spirit) so it is never reused - reuse across two messages would leak `d`.

**3. Transactions & the sighash (`utxo.py`).** Each input references a prior output by *outpoint* `(prev_txid, index)`. The sighash commits to every outpoint and every output (amount + address) but **not** to the signatures themselves - a simplified analogue of Bitcoin's `SIGHASH_ALL`. So a signer commits to exactly which coins are spent and where they go.

**4. Validation.** A transaction is accepted only if: every input exists in the current UTXO set (no unknown/already-spent outpoints - this is what blocks double-spends), no input is used twice within the same tx, each signature verifies **and** its pubkey hashes to the referenced output's address, all outputs are positive, and `sum(inputs) >= sum(outputs)`. The difference is the fee.

**5. Blocks & proof-of-work.** A block bundles a *coinbase* transaction (which mints `subsidy + total fees`) plus ordinary transactions, committed via a Merkle root. Mining grinds a nonce until the double-SHA256 block hash has `difficulty` leading zero hex digits. `validate_chain()` replays every block from genesis onto a fresh UTXO set, re-checking links, PoW, all signatures, and that no coinbase over-issues.

**6. Taproot (`taproot.py`).** The real Bitcoin wire format for P2TR: BIP350 bech32m `bc1p...` addresses, BIP340 x-only Schnorr signatures with tagged hashes, BIP341 key-path-only output keys `Q = P + H_TapTweak(P)*G`, the BIP341 `scriptPubKey` (`OP_1 PUSH32 <key>`), and the BIP341 key-path sighash (all hash types, version, locktime, annex, ext_flag). `TaprootWallet` is a wallet, `build_taproot_spend` signs every input, and `validate_tx` verifies a P2TR output from its committed output key alone - no pubkey in the input, the way mainnet spends work.

## Taproot: against the Bitcoin test vectors

`taproot.py` is checked against the official BIP data downloaded into `vectors/`:

- **BIP341** - every key-path-only and script-tree `scriptPubKey` vector (tweak, output key, `scriptPubKey`, `bc1p` address) matches. For the real 9-input unsigned mainnet transaction in the wallet vectors, all 7 key-path sighashes match for hash types `0x00/0x01/0x02/0x03/0x81/0x82/0x83`, and every signature reproduces byte for byte.
- **BIP340** - all 19 verify vectors agree (invalid signatures and non-curve points included); all 8 signing vectors reproduce exactly, aux_rand included.
- **BIP350** - addresses round-trip; a flipped character and an old bech32 (not bech32m) checksum on a v1 program are both rejected.
- In the ledger itself: real taproot spends are accepted, double-spends, wrong-key signatures and any output edited after signing are rejected.

## Features

- **Real taproot (BIP340/341/350)**: bech32m `bc1p` addresses, x-only keys, tap tweaks, key-path sighashes and signatures matching the official Bitcoin test vectors byte for byte.
- **Real secp256k1** elliptic-curve arithmetic (point add/double, scalar mul) from big integers - the same curve Bitcoin uses.
- **Hand-rolled Schnorr signatures** with deterministic nonces; forgeries, tampered messages, tampered signatures and wrong-key spends are all rejected.
- **Full UTXO set** with outpoint-based inputs and change outputs.
- **Complete validation**: double-spend rejection (within a tx, within a block, and across blocks), no value creation, signature-to-address binding.
- **Coinbase issuance** with block subsidy + fee collection.
- **Proof-of-work** blocks with a Merkle root and double-SHA256 header hash.
- **Whole-chain re-validation** that detects any tampering with stored blocks.
- `--demo` walkthrough, a **27-check ledger suite** and a **68-check taproot suite** verified against the BIP340/341/350 vectors; zero third-party dependencies.

## Tech stack

- **Python 3.8+** (developed on 3.13), standard library only: `hashlib`, `secrets`, `os.urandom`, big-integer `pow()`, `dataclasses`.
- No `pip install` required - no third-party packages.

## Installation

```bash
git clone https://github.com/arpitgupta369/utxo-blockchain.git
cd utxo-blockchain
python --version   # 3.8 or newer
```

That's it - there are no dependencies to install.

## Usage

Run the end-to-end demo:

```bash
python demo.py
```

Expected output (key hashes and addresses are randomised per run):

```
================================================================
 UTXO BLOCKCHAIN DEMO
================================================================

[1] Mining GENESIS block (coinbase 50 -> Alice)
    block #0  hash 000552892b8a465c8330...  nonce 3720
    Alice    1xfeaa821e17646c97d30a2085a8e2bd47f5d5d7bf  balance =   50
    Bob      1x20f976195e92285b2bb1b9d6fa4158f6d7aee3ae  balance =    0
    Charlie  1xa8520eb2539e702cf367175bfb10420cdd5be22c  balance =    0
    Miner    1x8b11e955b8a49267a1eaa0a4ac86c41d274a5978  balance =    0

[2] Alice -> Bob 30, Charlie 15  (fee 5, change 0)
    tx c1b40ac6c72bfe707379...  1 in / 2 out

[3] Miner seals block #1 (fee 5 -> coinbase, so miner gets 55)
    block #1  hash 0002e296bf364c0fcf19...  nonce 2507
    Alice    1xfeaa821e17646c97d30a2085a8e2bd47f5d5d7bf  balance =    0
    Bob      1x20f976195e92285b2bb1b9d6fa4158f6d7aee3ae  balance =   30
    Charlie  1xa8520eb2539e702cf367175bfb10420cdd5be22c  balance =   15
    Miner    1x8b11e955b8a49267a1eaa0a4ac86c41d274a5978  balance =   55

[4] Alice tries to DOUBLE-SPEND the genesis coin she already spent
    REJECTED as expected -> rejected tx 41faa173870f..: input already spent or unknown (double-spend)

[5] Re-validating the entire chain from genesis
    validate_chain() -> True  (chain valid)
    chain length = 2 blocks, UTXO set = 3 outputs

[6] Taproot: Dave gets a bc1p... coinbase and spends it key-path only
    Dave     bc1pgzm77cd0zrt09kdhrxk4e6tgukdmwpnn7a65v624dptx3l23d09sdhv4fy  (P2TR, BIP350 bech32m)
    block #2  hash 000fab42f211e544c4e4...  nonce 1464
    Dave -> Erin 10 (fee 1); input carries no pubkey, only a BIP340 sig
    Dave balance = 39, Erin balance = 10
    validate_chain() -> True
================================================================
 Total coins in existence: 200  (coinbases + fees)
================================================================
```

Run the test suite:

```bash
python test_utxo.py
```

```
[PASS] N*G == point at infinity (correct group order)
...
[PASS] tampering with a stored block is detected
============================================================
ALL 27 CHECKS PASSED
```

Run the taproot suite (verified against the official BIP vectors):

```bash
python test_taproot.py
```

```
[PASS] tweak matches BIP341 for internal key d6889cb08103...
[PASS] BIP341 sighash matches (input 8, hashType 0x81)
...
68 passed, 0 failed
```

## Project structure

```
utxo-blockchain/
|-- ecc.py          # secp256k1 curve math + Schnorr sign/verify + addresses
|-- taproot.py      # BIP340 Schnorr, BIP341 taproot + sighash, BIP350 bech32m
|-- utxo.py         # transactions, UTXO set, validation, blocks, PoW, chain
|-- demo.py         # end-to-end walkthrough (genesis, spend, double-spend, validate)
|-- test_utxo.py    # 27 correctness checks (crypto + ledger)
|-- test_taproot.py # 68 checks incl. the official BIP340/341/350 vectors
|-- vectors/        # downloaded BIP340 + BIP341 test vectors
|-- README.md
|-- LICENSE
`-- .gitignore
```

## Security / Educational disclaimer

**This is an educational / reference implementation. It is NOT audited, NOT constant-time, and NOT safe for production or real funds.** The elliptic-curve point operations, modular inverse, and double-and-add ladder all leak timing and branch information, so this code must never guard real private keys. Documented simplifications made for clarity:

- **Addresses** for the legacy `1x...` wallets use double-SHA256 truncated to 20 bytes instead of Bitcoin's `RIPEMD160(SHA256(pubkey))`, because RIPEMD160 is not present in every `hashlib` build.
- **Sighash** for taproot outputs is the real BIP341 key-path sighash, but script-path spends (script trees) are not implemented - only key-path spends. The legacy `1x...` outputs still use a single whole-transaction hash (an analogue of `SIGHASH_ALL`), and there is no Script system.
- **Proof-of-work** targets leading zero *hex digits* (default difficulty 3) rather than a full 256-bit difficulty target, and there is no difficulty retargeting, mempool, or peer-to-peer networking.
- Parameters like the block subsidy are toy values chosen so the demo reads clearly.

The cryptographic *pipeline* demonstrated here (key generation, Schnorr signing/verification, and UTXO validation) is correct - the tests prove valid signatures verify, forgeries are rejected, double-spends fail, and tampered chains are detected. The simplifications are about production-hardening and parameters, not about the algorithm being modelled.

---

Built by **Arpit Gupta** - [GitHub](https://github.com/arpitgupta369) . [LinkedIn](https://linkedin.com/in/arpit-gupta-060b302a7/)
