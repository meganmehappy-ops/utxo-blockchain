"""
utxo.py - a Bitcoin-style UTXO ledger: transactions, the UTXO set, validation,
blocks, proof-of-work and full-chain verification.

EDUCATIONAL / REFERENCE IMPLEMENTATION - see README security disclaimer.

Model overview
--------------
* Value lives in "unspent transaction outputs" (UTXOs), each a (amount, address).
* A transaction consumes existing UTXOs (its inputs, referenced by outpoint =
  (prev_txid, index)) and creates new ones (its outputs).
* An input is authorised by a Schnorr signature over the transaction's sighash;
  the signer's public key must hash to the address of the output being spent.
* A block bundles a coinbase (which mints the subsidy + collected fees) plus
  ordinary transactions, and is sealed by proof-of-work.
"""

from __future__ import annotations
import time
import secrets
from dataclasses import dataclass, field
import hashlib

from ecc import (
    gen_privkey, privkey_to_pubkey, compress, decompress,
    pubkey_to_address, sign, verify, scalar_mul, G, N,
)
from taproot import (
    SIGHASH_DEFAULT, address_to_output_key, bip341_sighash, is_taproot_address,
    output_key, script_pubkey, taproot_address, taproot_sign, taproot_verify, xonly,
)

COINBASE_TXID = "0" * 64  # sentinel outpoint txid for coinbase inputs
SEQUENCE_FINAL = 0xFFFFFFFD  # what taproot wallets use (RBF-signalling off)


def _ser(*parts) -> bytes:
    """Length-prefixed canonical serialization (no concatenation ambiguity)."""
    out = bytearray()
    for p in parts:
        b = p if isinstance(p, bytes) else str(p).encode()
        out += len(b).to_bytes(4, "big") + b
    return bytes(out)


# --------------------------- transactions ---------------------------

@dataclass
class TxOutput:
    amount: int
    address: str


@dataclass
class TxInput:
    prev_txid: str            # txid of the transaction that created the output
    prev_index: int           # which output of that transaction
    pubkey: str = ""          # hex compressed pubkey of the spender
    signature: str = ""       # hex Schnorr signature over the tx sighash


@dataclass
class Transaction:
    inputs: list
    outputs: list
    is_coinbase: bool = False
    coinbase_tag: str = ""    # arbitrary bytes making each coinbase unique

    def sighash(self) -> bytes:
        """The message every input signs.

        Commits to the coinbase tag, every input's *outpoint*, and every output
        (amount + address) - but NOT to the pubkeys/signatures themselves. So a
        signer commits to exactly which coins are spent and where they go, while
        signatures remain free to be filled in. This is a simplified analogue of
        Bitcoin's SIGHASH_ALL.
        """
        parts = [self.coinbase_tag.encode()]
        for i in self.inputs:
            parts += [i.prev_txid, i.prev_index]
        for o in self.outputs:
            parts += [o.amount, o.address]
        return hashlib.sha256(_ser(*parts)).digest()

    def txid(self) -> str:
        """Transaction id = double-SHA256 of the fully-signed transaction."""
        kind = b"coinbase" if self.is_coinbase else b"normal"
        parts = [self.coinbase_tag.encode(), kind]
        for i in self.inputs:
            parts += [i.prev_txid, i.prev_index, i.pubkey, i.signature]
        for o in self.outputs:
            parts += [o.amount, o.address]
        d = hashlib.sha256(hashlib.sha256(_ser(*parts)).digest()).digest()
        return d.hex()


def sign_input(tx: Transaction, index: int, privkey: int) -> None:
    """Fill input `index` with a Schnorr signature over tx.sighash()."""
    pub = privkey_to_pubkey(privkey)
    tx.inputs[index].pubkey = compress(pub).hex()
    tx.inputs[index].signature = sign(privkey, tx.sighash()).hex()


def script_pubkey_for(address: str) -> bytes:
    """The scriptPubKey that pays `address`.

    P2TR (bc1p...) -> OP_1 PUSH32 <output key>, exactly as on mainnet.
    The ledger's own `1x...` addresses -> a structurally valid P2WPKH script
    (OP_0 PUSH20 <hash>) so both live in one sighash message.
    """
    if is_taproot_address(address):
        return script_pubkey(address_to_output_key(address))
    if address.startswith("1x") and len(address) == 42:
        return b"\x00\x14" + bytes.fromhex(address[2:])
    raise ValueError(f"unrecognised address {address!r}")


def bip341_sighash_for(tx: Transaction, utxo_view: dict, input_index: int) -> bytes:
    """The real BIP341 key-path sighash for input `input_index` of `tx`.

    Unlike the ledger's simplified sighash(), this commits to every spent
    outpoint *with its amount and scriptPubKey* and to every output - the
    BIP341 anti-fee-sniping / value-binding rules.
    """
    prevouts, amounts, spks, seqs = [], [], [], []
    for inp in tx.inputs:
        prev = utxo_view.get((inp.prev_txid, inp.prev_index))
        if prev is None:
            raise ValueError("input already spent or unknown (double-spend)")
        prevouts.append((bytes.fromhex(inp.prev_txid), inp.prev_index))
        amounts.append(prev.amount)
        spks.append(script_pubkey_for(prev.address))
        seqs.append(SEQUENCE_FINAL)
    outs = [(o.amount, script_pubkey_for(o.address)) for o in tx.outputs]
    return bip341_sighash(prevouts, amounts, spks, seqs, outs, input_index,
                          SIGHASH_DEFAULT)


# --------------------------- wallet ---------------------------

class Wallet:
    """A keypair + address. Keys come from the CSPRNG (see ecc.gen_privkey)."""

    def __init__(self, name: str = ""):
        self.name = name
        self.priv = gen_privkey()
        self.pub = privkey_to_pubkey(self.priv)
        self.pubc = compress(self.pub)
        self.address = pubkey_to_address(self.pubc)

    def __repr__(self):
        return f"Wallet({self.name}, {self.address})"


class TaprootWallet:
    """A BIP86-style taproot wallet: x-only key -> bc1p... key-path-only address.

    The secret is the raw 32 bytes a real wallet holds; the address commits to
    Q = P + H_TapTweak(P)*G, so spending needs the tweaked key (see taproot.py).
    """

    def __init__(self, name: str = "", seckey: bytes | None = None):
        self.name = name
        self.seckey = seckey or gen_privkey().to_bytes(32, "big")
        d = int.from_bytes(self.seckey, "big")
        if not 1 <= d <= N - 1:
            raise ValueError("secret key out of range for secp256k1")
        self.internal_key = xonly(scalar_mul(d, G))
        self.output_key, self.output_is_odd = output_key(self.internal_key)
        self.address = taproot_address(self.internal_key)

    def __repr__(self):
        return f"TaprootWallet({self.name}, {self.address})"


# --------------------------- blocks + PoW ---------------------------

@dataclass
class Block:
    index: int
    prev_hash: str
    transactions: list
    timestamp: int = field(default_factory=lambda: int(time.time()))
    nonce: int = 0

    def merkle_root(self) -> bytes:
        ids = [bytes.fromhex(tx.txid()) for tx in self.transactions]
        if not ids:
            return b"\x00" * 32
        while len(ids) > 1:
            if len(ids) % 2:
                ids.append(ids[-1])  # duplicate the last if odd (as Bitcoin does)
            ids = [hashlib.sha256(ids[i] + ids[i + 1]).digest()
                   for i in range(0, len(ids), 2)]
        return ids[0]

    def header(self) -> bytes:
        return _ser(self.index, self.prev_hash, self.timestamp,
                    self.merkle_root(), self.nonce)

    def hash(self) -> str:
        return hashlib.sha256(hashlib.sha256(self.header()).digest()).hexdigest()


def mine(block: Block, difficulty: int) -> str:
    """Proof-of-work: grind the nonce until the block hash has `difficulty`
    leading zero hex digits. (Real Bitcoin targets leading zero *bits*.)"""
    target = "0" * difficulty
    while not block.hash().startswith(target):
        block.nonce += 1
    return block.hash()


# --------------------------- the chain ---------------------------

class Blockchain:
    def __init__(self, difficulty: int = 3, subsidy: int = 50):
        self.difficulty = difficulty
        self.subsidy = subsidy
        self.chain = []            # list[Block]
        self.utxo = {}             # (txid, index) -> TxOutput

    # ---- helpers ----
    def create_coinbase(self, address: str, fees: int, tag: str) -> Transaction:
        out = TxOutput(self.subsidy + fees, address)
        cb_in = TxInput(COINBASE_TXID, 0xFFFFFFFF)
        return Transaction([cb_in], [out], is_coinbase=True, coinbase_tag=tag)

    def balance(self, address: str) -> int:
        return sum(o.amount for o in self.utxo.values() if o.address == address)

    def utxos_for(self, address: str) -> dict:
        return {k: o for k, o in self.utxo.items() if o.address == address}

    # ---- validation ----
    def validate_tx(self, tx: Transaction, utxo_view: dict):
        """Validate a NON-coinbase transaction against a UTXO view.

        Returns (ok: bool, fee: int, reason: str).
        Enforces: inputs exist (no double-spend / no unknown outpoints), no
        duplicate inputs inside the tx, each signature is valid AND its pubkey
        hashes to the referenced output's address, outputs are positive, and
        sum(inputs) >= sum(outputs).
        """
        if tx.is_coinbase:
            return True, 0, "coinbase"

        msg = tx.sighash()
        seen = set()
        in_sum = 0
        for pos, inp in enumerate(tx.inputs):
            key = (inp.prev_txid, inp.prev_index)
            if key in seen:
                return False, 0, "duplicate input (double-spend within tx)"
            seen.add(key)
            if key not in utxo_view:
                return False, 0, "input already spent or unknown (double-spend)"
            prev = utxo_view[key]
            try:
                sig = bytes.fromhex(inp.signature)
            except ValueError:
                return False, 0, "malformed signature"
            if is_taproot_address(prev.address):
                # Real Bitcoin path: BIP341 key-path spend of a P2TR output.
                try:
                    tm = bip341_sighash_for(tx, utxo_view, pos)
                except ValueError as e:
                    return False, 0, str(e)
                if not taproot_verify(prev.address, tm, sig):
                    return False, 0, "invalid taproot key-path signature"
            else:
                try:
                    pub = bytes.fromhex(inp.pubkey)
                except ValueError:
                    return False, 0, "malformed pubkey"
                if pubkey_to_address(pub) != prev.address:
                    return False, 0, "pubkey does not hash to the output's address"
                if not verify(pub, msg, sig):
                    return False, 0, "invalid signature"
            in_sum += prev.amount

        if any(o.amount <= 0 for o in tx.outputs):
            return False, 0, "non-positive output amount"
        out_sum = sum(o.amount for o in tx.outputs)
        if out_sum > in_sum:
            return False, 0, "outputs exceed inputs (value creation)"
        return True, in_sum - out_sum, "ok"

    def add_block(self, transactions: list, miner_address: str, tag: str = ""):
        """Validate ordinary transactions, build+mine a block, apply it.

        `transactions` are the NON-coinbase txs; the coinbase is built here so it
        can claim exactly subsidy + total fees.
        """
        view = dict(self.utxo)   # a scratch copy so intra-block spends chain
        total_fees = 0
        for tx in transactions:
            ok, fee, reason = self.validate_tx(tx, view)
            if not ok:
                raise ValueError(f"rejected tx {tx.txid()[:12]}..: {reason}")
            for inp in tx.inputs:                 # spend
                del view[(inp.prev_txid, inp.prev_index)]
            for idx, out in enumerate(tx.outputs):  # create
                view[(tx.txid(), idx)] = out
            total_fees += fee

        tag = tag or f"height:{len(self.chain)}"
        coinbase = self.create_coinbase(miner_address, total_fees, tag)
        all_txs = [coinbase] + list(transactions)
        prev_hash = self.chain[-1].hash() if self.chain else "0" * 64
        block = Block(len(self.chain), prev_hash, all_txs)
        mine(block, self.difficulty)
        self._apply_block(block)
        return block

    def _apply_block(self, block: Block) -> None:
        for tx in block.transactions:
            if not tx.is_coinbase:
                for inp in tx.inputs:
                    del self.utxo[(inp.prev_txid, inp.prev_index)]
            txid = tx.txid()
            for idx, out in enumerate(tx.outputs):
                self.utxo[(txid, idx)] = out
        self.chain.append(block)

    def validate_chain(self):
        """Re-verify the whole chain from genesis by replaying every block onto
        a fresh UTXO set. Returns (ok: bool, reason: str)."""
        utxo = {}
        prev_hash = "0" * 64
        for h, block in enumerate(self.chain):
            if block.index != h:
                return False, f"block {h}: wrong index"
            if block.prev_hash != prev_hash:
                return False, f"block {h}: broken prev-hash link"
            if not block.hash().startswith("0" * self.difficulty):
                return False, f"block {h}: proof-of-work not satisfied"
            if not block.transactions or not block.transactions[0].is_coinbase:
                return False, f"block {h}: missing/misplaced coinbase"

            total_fees = 0
            for tx in block.transactions[1:]:
                if tx.is_coinbase:
                    return False, f"block {h}: multiple coinbase txs"
                ok, fee, reason = self.validate_tx(tx, utxo)
                if not ok:
                    return False, f"block {h}: {reason}"
                for inp in tx.inputs:
                    del utxo[(inp.prev_txid, inp.prev_index)]
                for idx, out in enumerate(tx.outputs):
                    utxo[(tx.txid(), idx)] = out
                total_fees += fee

            cb = block.transactions[0]
            if sum(o.amount for o in cb.outputs) > self.subsidy + total_fees:
                return False, f"block {h}: coinbase over-issues coins"
            for idx, out in enumerate(cb.outputs):
                utxo[(cb.txid(), idx)] = out

            prev_hash = block.hash()
        return True, "chain valid"


def build_taproot_spend(bc: Blockchain, sender: "TaprootWallet", sends: list, fee: int = 0):
    """Same as build_spend, but signs with BIP341 key-path signatures."""
    need = sum(a for _, a in sends) + fee
    gathered, chosen = 0, []
    for (txid, idx), out in bc.utxo.items():
        if out.address == sender.address:
            chosen.append((txid, idx, out))
            gathered += out.amount
            if gathered >= need:
                break
    if gathered < need:
        raise ValueError(f"insufficient funds: have {gathered}, need {need}")

    inputs = [TxInput(txid, idx) for txid, idx, _ in chosen]
    outputs = [TxOutput(amt, addr) for addr, amt in sends]
    change = gathered - need
    if change > 0:
        outputs.append(TxOutput(change, sender.address))

    tx = Transaction(inputs, outputs)
    for i in range(len(inputs)):            # BIP341 sighash depends on input index
        tm = bip341_sighash_for(tx, bc.utxo, i)
        tx.inputs[i].signature = taproot_sign(sender.seckey, tm).hex()
    return tx


def build_spend(bc: Blockchain, sender: Wallet, sends: list, fee: int = 0):
    """Convenience: build & sign a transaction spending `sender`'s UTXOs.

    `sends` is a list of (recipient_address, amount). Gathers enough of the
    sender's UTXOs to cover sum(amounts) + fee, adds a change output back to the
    sender if needed, and Schnorr-signs every input. Raises on insufficient funds.
    """
    need = sum(a for _, a in sends) + fee
    gathered, chosen = 0, []
    for (txid, idx), out in bc.utxo.items():
        if out.address == sender.address:
            chosen.append((txid, idx, out))
            gathered += out.amount
            if gathered >= need:
                break
    if gathered < need:
        raise ValueError(f"insufficient funds: have {gathered}, need {need}")

    inputs = [TxInput(txid, idx) for txid, idx, _ in chosen]
    outputs = [TxOutput(amt, addr) for addr, amt in sends]
    change = gathered - need
    if change > 0:
        outputs.append(TxOutput(change, sender.address))

    tx = Transaction(inputs, outputs)
    for i in range(len(inputs)):            # sign every input we own
        sign_input(tx, i, sender.priv)
    return tx
