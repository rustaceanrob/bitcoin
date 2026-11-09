#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Demonstrate libbitcoinmempool (attempt 4: pushed tip, batched coin callback outside locks).

The demo plays a small regtest node built from two libraries:

  * libbitcoinkernel validates the blocks the demo mines and stores them.
  * libbitcoinmempool holds unconfirmed transactions. It keeps no chain: the
    tip is pushed with each block, and coins (with the hash and median time
    past of their block) are fetched in batches through one get_coins
    callback that runs without any pool lock held. That callback may block,
    so the demo also drives the pool from asyncio, and it may call back into
    the pool, which the demo does once.

It walks through a plain submission, replace-by-fee, child-pays-for-parent
(both inside the pool and as a zero-fee TRUC package), and compact block
relay (encoding a block, reconstructing it from the pool, fetching the one
missing transaction) followed by confirmation.

Usage: contrib/mempool_demo.py [--build-dir build] [--verbose]
"""

import argparse
import asyncio
import ctypes
import hashlib
import os
import struct
import sys
import tempfile
import time
from ctypes import (CFUNCTYPE, POINTER, Structure, byref, c_char_p, c_int, c_int32, c_int64, c_size_t,
                    c_uint8, c_uint32, c_uint64, c_void_p)

COIN = 100_000_000

# --------------------------------------------------------------------------
# Minimal Bitcoin primitives
# --------------------------------------------------------------------------


def sha256(b):
    return hashlib.sha256(b).digest()


def hash256(b):
    return sha256(sha256(b))


def ser_compact_size(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def ser_bytes(b):
    return ser_compact_size(len(b)) + b


def short(h):
    """Display form of an internal byte order hash."""
    return h[::-1].hex()[:16]


OP_TRUE = b"\x51"
# Pay-to-witness-script-hash of OP_TRUE: anyone can spend it by revealing the script.
ANYONE_CAN_SPEND = b"\x00\x20" + sha256(OP_TRUE)


class Tx:
    def __init__(self, vin, vout, version=2, locktime=0):
        self.vin = vin      # [(txid, n, script_sig, sequence, witness_stack)]
        self.vout = vout    # [(value, script_pubkey)]
        self.version = version
        self.locktime = locktime

    def serialize(self, with_witness=True):
        has_witness = with_witness and any(w for *_, w in self.vin)
        r = struct.pack("<I", self.version)
        if has_witness:
            r += b"\x00\x01"
        r += ser_compact_size(len(self.vin))
        for txid, n, script_sig, sequence, _ in self.vin:
            r += txid + struct.pack("<I", n) + ser_bytes(script_sig) + struct.pack("<I", sequence)
        r += ser_compact_size(len(self.vout))
        for value, spk in self.vout:
            r += struct.pack("<q", value) + ser_bytes(spk)
        if has_witness:
            for *_, witness in self.vin:
                r += ser_compact_size(len(witness)) + b"".join(ser_bytes(item) for item in witness)
        return r + struct.pack("<I", self.locktime)

    @property
    def txid(self):
        return hash256(self.serialize(with_witness=False))

    @property
    def wtxid(self):
        return hash256(self.serialize())

    def is_coinbase(self):
        return len(self.vin) == 1 and self.vin[0][0] == b"\x00" * 32 and self.vin[0][1] == 0xffffffff


def spend(outpoints, outputs, version=2):
    """A transaction spending anyone-can-spend outpoints, signalling replaceability."""
    return Tx([(txid, n, b"", 0xfffffffd, [OP_TRUE]) for txid, n in outpoints], outputs, version=version)


def script_num_push(n):
    if 1 <= n <= 16:
        return bytes([0x50 + n])
    data = n.to_bytes((n.bit_length() + 8) // 8, "little")
    return ser_bytes(data)


def merkle_root(hashes):
    while len(hashes) > 1:
        if len(hashes) % 2:
            hashes.append(hashes[-1])
        hashes = [hash256(hashes[i] + hashes[i + 1]) for i in range(0, len(hashes), 2)]
    return hashes[0]


def build_block(prev_hash, height, ntime, txs, fees):
    reserved = b"\x00" * 32
    witness_root = merkle_root([b"\x00" * 32] + [tx.wtxid for tx in txs])
    commitment = b"\x6a\x24\xaa\x21\xa9\xed" + hash256(witness_root + reserved)
    subsidy = (50 * COIN) >> (height // 150)
    coinbase = Tx([(b"\x00" * 32, 0xffffffff, script_num_push(height) + b"\x00", 0xffffffff, [reserved])],
                  [(subsidy + fees, ANYONE_CAN_SPEND), (0, commitment)])
    all_txs = [coinbase] + txs
    root = merkle_root([tx.txid for tx in all_txs])
    header = struct.pack("<i", 0x20000000) + prev_hash + root + struct.pack("<II", ntime, 0x207fffff)
    target = 0x7fffff << (8 * (0x20 - 3))
    nonce = 0
    while int.from_bytes(hash256(header + struct.pack("<I", nonce)), "little") > target:
        nonce += 1
    header += struct.pack("<I", nonce)
    body = ser_compact_size(len(all_txs)) + b"".join(tx.serialize() for tx in all_txs)
    return header + body, all_txs


# --------------------------------------------------------------------------
# libbitcoinkernel: validates and stores the blocks we mine
# --------------------------------------------------------------------------


class Kernel:
    def __init__(self, lib_path, datadir):
        k = self.lib = ctypes.CDLL(lib_path)
        for name, res, args in [
            ("btck_chain_parameters_create", c_void_p, [c_uint8]),
            ("btck_context_options_create", c_void_p, []),
            ("btck_context_options_set_chainparams", None, [c_void_p, c_void_p]),
            ("btck_context_create", c_void_p, [c_void_p]),
            ("btck_chainstate_manager_options_create", c_void_p, [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t]),
            ("btck_chainstate_manager_options_update_block_tree_db_in_memory", None, [c_void_p, c_int]),
            ("btck_chainstate_manager_options_update_chainstate_db_in_memory", None, [c_void_p, c_int]),
            ("btck_chainstate_manager_create", c_void_p, [c_void_p]),
            ("btck_chainstate_manager_get_best_entry", c_void_p, [c_void_p]),
            ("btck_block_tree_entry_get_height", c_int32, [c_void_p]),
            ("btck_block_create", c_void_p, [c_void_p, c_size_t]),
            ("btck_chainstate_manager_process_block", c_int, [c_void_p, c_void_p, POINTER(c_int)]),
            ("btck_block_destroy", None, [c_void_p]),
            ("btck_chainstate_manager_destroy", None, [c_void_p]),
            ("btck_chainstate_manager_options_destroy", None, [c_void_p]),
            ("btck_context_destroy", None, [c_void_p]),
            ("btck_context_options_destroy", None, [c_void_p]),
            ("btck_chain_parameters_destroy", None, [c_void_p]),
        ]:
            fn = getattr(k, name)
            fn.restype, fn.argtypes = res, args
        params = k.btck_chain_parameters_create(4)  # btck_ChainType_REGTEST
        opts = k.btck_context_options_create()
        k.btck_context_options_set_chainparams(opts, params)
        self.context = k.btck_context_create(opts)
        k.btck_context_options_destroy(opts)
        k.btck_chain_parameters_destroy(params)
        datadir_b, blocksdir_b = datadir.encode(), os.path.join(datadir, "blocks").encode()
        cm_opts = k.btck_chainstate_manager_options_create(self.context, datadir_b, len(datadir_b), blocksdir_b, len(blocksdir_b))
        k.btck_chainstate_manager_options_update_block_tree_db_in_memory(cm_opts, 1)
        k.btck_chainstate_manager_options_update_chainstate_db_in_memory(cm_opts, 1)
        self.chainman = k.btck_chainstate_manager_create(cm_opts)
        k.btck_chainstate_manager_options_destroy(cm_opts)
        assert self.chainman, "failed to create chainstate manager"

    def height(self):
        return self.lib.btck_block_tree_entry_get_height(self.lib.btck_chainstate_manager_get_best_entry(self.chainman))

    def process_block(self, raw, extends_tip=True):
        block = self.lib.btck_block_create(raw, len(raw))
        new = c_int(0)
        before = self.height()
        rc = self.lib.btck_chainstate_manager_process_block(self.chainman, block, byref(new))
        self.lib.btck_block_destroy(block)
        return rc == 0 and (not extends_tip or self.height() == before + 1)

    def close(self):
        self.lib.btck_chainstate_manager_destroy(self.chainman)
        self.lib.btck_context_destroy(self.context)


# --------------------------------------------------------------------------
# libbitcoinmempool bindings
# --------------------------------------------------------------------------

REMOVAL_REASONS = ["EXPIRY", "SIZELIMIT", "REORG", "BLOCK", "CONFLICT", "REPLACED"]
ACCEPT_STATUS = ["VALID", "INVALID", "MEMPOOL_ENTRY", "DIFFERENT_WITNESS", "NOT_EVALUATED"]
READ_STATUS = ["OK", "INVALID", "FAILED"]
TEST_ACCEPT = 1

Hash = c_uint8 * 32


class StringView(Structure):
    _fields_ = [("data", c_void_p), ("size", c_size_t)]

    def __str__(self):
        return ctypes.string_at(self.data, self.size).decode() if self.size else ""


class Config(Structure):
    _fields_ = [("struct_size", c_size_t), ("chain_type", c_uint8), ("max_size_bytes", c_int64),
                ("expiry_seconds", c_int64), ("min_relay_feerate", c_int64), ("incremental_relay_feerate", c_int64),
                ("require_standard", c_int), ("check_ratio", c_int)]


class Tip(Structure):
    _fields_ = [("struct_size", c_size_t), ("height", c_int32), ("hash", Hash), ("median_time_past", c_int64)]


class OutPoint(Structure):
    _fields_ = [("txid", Hash), ("index", c_uint32)]


class Coin(Structure):
    _fields_ = [("struct_size", c_size_t), ("amount", c_int64), ("script_pubkey", c_char_p),
                ("script_pubkey_len", c_size_t), ("height", c_int32), ("is_coinbase", c_int), ("block_hash", Hash),
                ("prev_median_time_past", c_int64)]


class TxOutcome(Structure):
    _fields_ = [("struct_size", c_size_t), ("status", c_uint8), ("txid", Hash), ("wtxid", Hash), ("fee", c_int64),
                ("vsize", c_int64), ("effective_feerate", c_int64), ("other_wtxid", Hash),
                ("reject_reason", StringView), ("debug_message", StringView)]


class EntryInfo(Structure):
    _fields_ = [("struct_size", c_size_t), ("txid", Hash), ("wtxid", Hash), ("fee", c_int64), ("modified_fee", c_int64),
                ("vsize", c_int64), ("weight", c_int64), ("chunk_fee", c_int64), ("chunk_weight", c_int64),
                ("ancestor_count", c_uint32), ("descendant_count", c_uint32), ("cluster_count", c_uint32),
                ("time", c_int64), ("height", c_int32)]


def versioned(cls):
    """A zeroed instance of a versioned struct, sized for this binding."""
    obj = cls()
    obj.struct_size = ctypes.sizeof(cls)
    return obj


DESTROY = CFUNCTYPE(None, c_void_p)
GET_COINS = CFUNCTYPE(None, c_void_p, POINTER(OutPoint), c_size_t, c_void_p)
TX_ADDED = CFUNCTYPE(None, c_void_p, c_void_p, c_int64, c_int64, c_uint64)
TX_REMOVED = CFUNCTYPE(None, c_void_p, c_void_p, c_uint8, c_uint64)
WRITE_BYTES = CFUNCTYPE(c_int, c_void_p, c_size_t, c_void_p)
LOG = CFUNCTYPE(None, c_void_p, StringView)


class Callbacks(Structure):
    _fields_ = [("user_data", c_void_p), ("user_data_destroy", DESTROY), ("get_coins", GET_COINS),
                ("transaction_added", TX_ADDED), ("transaction_removed", TX_REMOVED)]


class MempoolLib:
    def __init__(self, path):
        m = self.lib = ctypes.CDLL(path)
        for name, res, args in [
            ("btcm_set_log_callback", None, [LOG, c_void_p]),
            ("btcm_config_init", None, [POINTER(Config), c_uint8]),
            ("btcm_coin_batch_set", None, [c_void_p, c_size_t, POINTER(Coin)]),
            ("btcm_transaction_create", c_void_p, [c_char_p, c_size_t]),
            ("btcm_transaction_get_txid", None, [c_void_p, c_char_p]),
            ("btcm_transaction_destroy", None, [c_void_p]),
            ("btcm_block_create", c_void_p, [c_char_p, c_size_t]),
            ("btcm_block_to_bytes", c_int, [c_void_p, WRITE_BYTES, c_void_p]),
            ("btcm_block_destroy", None, [c_void_p]),
            ("btcm_mempool_create", c_void_p, [POINTER(Config), POINTER(Tip), POINTER(Callbacks)]),
            ("btcm_mempool_destroy", None, [c_void_p]),
            ("btcm_mempool_block_connected", c_int, [c_void_p, c_void_p, POINTER(Tip)]),
            ("btcm_mempool_block_disconnected", c_int, [c_void_p, c_void_p, POINTER(Tip)]),
            ("btcm_mempool_submit", c_void_p, [c_void_p, POINTER(c_void_p), c_size_t, c_uint32]),
            ("btcm_mempool_check", None, [c_void_p]),
            ("btcm_mempool_size", c_size_t, [c_void_p]),
            ("btcm_mempool_get_transaction", c_void_p, [c_void_p, c_char_p]),
            ("btcm_mempool_get_entry", c_int, [c_void_p, c_char_p, POINTER(EntryInfo)]),
            ("btcm_mempool_snapshot", c_void_p, [c_void_p]),
            ("btcm_submit_result_count", c_size_t, [c_void_p]),
            ("btcm_submit_result_get", None, [c_void_p, c_size_t, POINTER(TxOutcome)]),
            ("btcm_submit_result_get_package_error", StringView, [c_void_p]),
            ("btcm_submit_result_destroy", None, [c_void_p]),
            ("btcm_snapshot_count", c_size_t, [c_void_p]),
            ("btcm_snapshot_get_sequence", c_uint64, [c_void_p]),
            ("btcm_snapshot_get_entry", None, [c_void_p, c_size_t, POINTER(EntryInfo)]),
            ("btcm_snapshot_destroy", None, [c_void_p]),
            ("btcm_compact_block_encode", c_int, [c_void_p, c_uint64, WRITE_BYTES, c_void_p]),
            ("btcm_reconstruction_create", c_void_p, [c_void_p, c_char_p, c_size_t, POINTER(c_uint8)]),
            ("btcm_reconstruction_missing_count", c_size_t, [c_void_p]),
            ("btcm_reconstruction_missing_index", c_uint32, [c_void_p, c_size_t]),
            ("btcm_reconstruction_finish", c_void_p, [c_void_p, POINTER(c_void_p), c_size_t, POINTER(c_uint8)]),
            ("btcm_reconstruction_destroy", None, [c_void_p]),
        ]:
            fn = getattr(m, name)
            fn.restype, fn.argtypes = res, args

    def txid(self, tx_handle):
        out = ctypes.create_string_buffer(32)
        self.lib.btcm_transaction_get_txid(tx_handle, out)
        return out.raw


def collect_bytes(fn, *args):
    out = []
    writer = WRITE_BYTES(lambda data, size, _: out.append(ctypes.string_at(data, size)) or 0)
    rc = fn(*args, writer, None)
    return b"".join(out) if rc == 0 else None


class Result:
    """Python copy of a btcm_TxOutcome, taken while its btcm_SubmitResult is alive."""

    def __init__(self, o):
        self.status = ACCEPT_STATUS[o.status]
        self.reject_reason = str(o.reject_reason)
        self.fee, self.vsize, self.feerate = o.fee, o.vsize, o.effective_feerate

    def __str__(self):
        if self.status == "INVALID":
            return f"INVALID ({self.reject_reason})"
        if self.status == "VALID":
            return f"VALID (fee {self.fee} sat, {self.vsize} vB, effective feerate {self.feerate / 1000:.1f} sat/vB)"
        return self.status


class Mempool:
    """Python face of a btcm_Mempool. get_coins is answered by `node`."""

    def __init__(self, ml, node):
        self.ml, self.m, self.node = ml, ml.lib, node
        self.events = []
        self.fetches = []  # sizes of get_coins batches since the last report
        self.resolver = None  # when set, resolves a list of outpoints (used to bridge into asyncio)
        self.on_fetch = None  # one-shot hook run inside get_coins

        def get_coins(_, outpoints, n, batch):
            ops = [(bytes(outpoints[i].txid), outpoints[i].index) for i in range(n)]
            self.fetches.append(n)
            if self.on_fetch:
                hook, self.on_fetch = self.on_fetch, None
                hook()
            coins = self.resolver(ops) if self.resolver else [node.coin(*op) for op in ops]
            for i, coin in enumerate(coins):
                if coin is not None:
                    self.m.btcm_coin_batch_set(batch, i, byref(coin))

        def added(_, tx, fee, vsize, sequence):
            self.events.append(f"+ added   {short(self.ml.txid(tx))} fee={fee} vsize={vsize} seq={sequence}")

        def removed(_, tx, reason, sequence):
            self.events.append(f"- removed {short(self.ml.txid(tx))} reason={REMOVAL_REASONS[reason]} seq={sequence}")

        # Keep the ctypes trampolines alive as long as the pool.
        self._callbacks = Callbacks(None, DESTROY(), GET_COINS(get_coins), TX_ADDED(added), TX_REMOVED(removed))
        config = Config()
        self.m.btcm_config_init(byref(config), 4)  # REGTEST
        config.check_ratio = 1  # btcm_mempool_check always runs.
        self.pool = self.m.btcm_mempool_create(byref(config), byref(node.tip()), byref(self._callbacks))
        assert self.pool

    def report(self):
        if self.fetches:
            print(f"      (get_coins called {len(self.fetches)}x with {sum(self.fetches)} outpoint(s))")
        for e in self.events:
            print(f"      {e}")
        self.events.clear()
        self.fetches.clear()

    def _handles(self, txs):
        raws = [tx.serialize() for tx in txs]
        return (c_void_p * len(txs))(*[self.m.btcm_transaction_create(raw, len(raw)) for raw in raws])

    def submit(self, txs, test=False):
        handles = self._handles(txs)
        res = self.m.btcm_mempool_submit(self.pool, handles, len(txs), TEST_ACCEPT if test else 0)
        results = []
        for i in range(self.m.btcm_submit_result_count(res)):
            outcome = versioned(TxOutcome)
            self.m.btcm_submit_result_get(res, i, byref(outcome))
            results.append(Result(outcome))
        error = str(self.m.btcm_submit_result_get_package_error(res))
        self.m.btcm_submit_result_destroy(res)
        for h in handles:
            self.m.btcm_transaction_destroy(h)
        return results, error

    def accept(self, tx, test=False):
        return self.submit([tx], test)[0][0]

    def check(self):
        self.m.btcm_mempool_check(self.pool)

    def _with_block(self, fn, raw, tip):
        block = self.m.btcm_block_create(raw, len(raw))
        rc = fn(self.pool, block, byref(tip))
        self.m.btcm_block_destroy(block)
        assert rc == 0, "the pushed tip does not match the notification"

    def block_connected(self, raw, tip):
        self._with_block(self.m.btcm_mempool_block_connected, raw, tip)

    def block_disconnected(self, raw, tip):
        self._with_block(self.m.btcm_mempool_block_disconnected, raw, tip)

    def size(self):
        return self.m.btcm_mempool_size(self.pool)

    def contains(self, txid):
        tx = self.m.btcm_mempool_get_transaction(self.pool, txid)
        self.m.btcm_transaction_destroy(tx)
        return bool(tx)

    def entry(self, txid):
        info = versioned(EntryInfo)
        return info if self.m.btcm_mempool_get_entry(self.pool, txid, byref(info)) == 0 else None

    def mining_order(self):
        snap = self.m.btcm_mempool_snapshot(self.pool)
        order = []
        for i in range(self.m.btcm_snapshot_count(snap)):
            info = versioned(EntryInfo)
            self.m.btcm_snapshot_get_entry(snap, i, byref(info))
            order.append((bytes(info.txid), info.fee, info.vsize, info.chunk_fee, info.chunk_weight))
        sequence = self.m.btcm_snapshot_get_sequence(snap)
        self.m.btcm_snapshot_destroy(snap)
        return order, sequence

    def encode_compact(self, raw_block, nonce):
        block = self.m.btcm_block_create(raw_block, len(raw_block))
        raw = collect_bytes(self.m.btcm_compact_block_encode, block, nonce)
        self.m.btcm_block_destroy(block)
        return raw

    def reconstruct(self, cmpctblock, fetch):
        """Rebuild a block from a cmpctblock payload; fetch(indexes) plays the getblocktxn round trip."""
        status = c_uint8()
        rec = self.m.btcm_reconstruction_create(self.pool, cmpctblock, len(cmpctblock), byref(status))
        if not rec:
            return None, READ_STATUS[status.value]
        indexes = [self.m.btcm_reconstruction_missing_index(rec, i) for i in range(self.m.btcm_reconstruction_missing_count(rec))]
        missing = self._handles(fetch(indexes))
        block = self.m.btcm_reconstruction_finish(rec, missing, len(missing), byref(status))
        self.m.btcm_reconstruction_destroy(rec)
        for h in missing:
            self.m.btcm_transaction_destroy(h)
        raw = collect_bytes(self.m.btcm_block_to_bytes, block) if block else None
        self.m.btcm_block_destroy(block)
        return raw, READ_STATUS[status.value]

    def close(self):
        self.m.btcm_mempool_destroy(self.pool)


# --------------------------------------------------------------------------
# A tiny node tying both libraries together
# --------------------------------------------------------------------------


class Node:
    def __init__(self, kernel, mempool_lib):
        self.kernel = kernel
        self.utxos = {}  # (txid, n) -> (value, script_pubkey, height, is_coinbase)
        genesis = bytes.fromhex("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")[::-1]
        self.chain = [(genesis, 1296688602, None, None, None)]  # (hash, time, raw, txs, undo)
        self.start_time = int(time.time()) - 10_000
        self.mempool = Mempool(mempool_lib, self)

    @property
    def height(self):
        return len(self.chain) - 1

    def median_time_past(self, height):
        times = sorted(entry[1] for entry in self.chain[max(0, height - 10):height + 1])
        return times[len(times) // 2]

    def tip(self):
        tip = versioned(Tip)
        tip.height, tip.hash, tip.median_time_past = self.height, Hash(*self.chain[-1][0]), self.median_time_past(self.height)
        return tip

    def coin(self, txid, n):
        """Answer one outpoint of a get_coins batch: the coin plus the chain context of its block."""
        found = self.utxos.get((txid, n))
        if found is None:
            return None
        value, spk, height, coinbase = found
        coin = versioned(Coin)
        coin.amount, coin.script_pubkey, coin.script_pubkey_len = value, spk, len(spk)
        coin.height, coin.is_coinbase = height, coinbase
        coin.block_hash = Hash(*self.chain[height][0])
        coin.prev_median_time_past = self.median_time_past(max(height - 1, 0))
        return coin

    async def coin_async(self, txid, n):
        """The same lookup, as if the UTXO set lived across the network."""
        await asyncio.sleep(0.001)
        return self.coin(txid, n)

    def fee_of(self, tx, extra=None):
        coins = {**self.utxos, **(extra or {})}
        return sum(coins[(t, n)][0] for t, n, *_ in tx.vin) - sum(v for v, _ in tx.vout)

    def make_block(self, txs=(), parent=None):
        """Build a block with txs on top of parent = (hash, height), by default the tip."""
        prev_hash, prev_height = parent or (self.chain[-1][0], self.height)
        fees, created = 0, {}
        for tx in txs:
            fees += self.fee_of(tx, created)
            created.update({(tx.txid, i): (v, s, 0, False) for i, (v, s) in enumerate(tx.vout)})
        return build_block(prev_hash, prev_height + 1, self.start_time + prev_height + 1, list(txs), fees)

    def connect(self, raw, txs):
        """Apply a block the kernel made our tip: UTXO set first, then the mempool."""
        undo = []
        for tx in txs:
            if not tx.is_coinbase():
                for txid, n, *_ in tx.vin:
                    undo.append(((txid, n), self.utxos.pop((txid, n))))
            for i, (value, spk) in enumerate(tx.vout):
                if not spk.startswith(b"\x6a"):
                    self.utxos[(tx.txid, i)] = (value, spk, self.height + 1, tx.is_coinbase())
        self.chain.append((hash256(raw[:80]), struct.unpack_from("<I", raw, 68)[0], raw, txs, undo))
        self.mempool.block_connected(raw, self.tip())

    def disconnect(self):
        """Undo the tip block: UTXO set first, then the mempool."""
        _, _, raw, txs, undo = self.chain.pop()
        for tx in txs:
            for i in range(len(tx.vout)):
                self.utxos.pop((tx.txid, i), None)
        self.utxos.update(dict(undo))
        self.mempool.block_disconnected(raw, self.tip())

    def mine(self, txs=()):
        raw, block_txs = self.make_block(txs)
        assert self.kernel.process_block(raw), "kernel rejected block"
        self.connect(raw, block_txs)
        return raw, block_txs


def step(title):
    print(f"\n=== {title} ===")


def scenario(node, kernel, mempool_lib):
    pool = node.mempool

    step("Setup: mine 110 regtest blocks through libbitcoinkernel")
    for _ in range(110):
        node.mine()
    # The first 10 coinbases have the 100 confirmations needed to be spent.
    spendable = [((node.chain[h][3][0].txid, 0), node.chain[h][3][0].vout[0][0]) for h in range(1, 11)]
    # One confirmed output that is not a coinbase, for section 3c.
    (op_f, value_f) = spendable.pop()
    fan = spend([op_f], [(value_f - 1_000, ANYONE_CAN_SPEND)])
    node.mine([fan])
    print(f"kernel height {kernel.height()}; the pool only knows the tip it was pushed, height {node.height}")
    created = {}  # txid -> Tx, everything we broadcast

    def remember(*txs):
        created.update({tx.txid: tx for tx in txs})

    def submit(label, tx, **kwargs):
        print(f"   {label}: {pool.accept(tx, **kwargs)}")
        pool.report()

    step("1. Submit a transaction")
    (outpoint, value) = spendable.pop(0)
    a = spend([outpoint], [(value - 1_000, ANYONE_CAN_SPEND)])
    remember(a)
    pool.on_fetch = lambda: print(f"   (inside get_coins, the callback re-enters the pool: size() = {pool.size()})")
    submit(f"tx A {short(a.txid)} pays 1000 sat", a)
    submit("test-accepting A again (no coins needed)", a, test=True)

    step("2. Replace-by-fee")
    a_low = spend([outpoint], [(value - 1_005, ANYONE_CAN_SPEND)])
    submit("A' pays 1005 sat, less than A plus the incremental relay fee", a_low)
    a2 = spend([outpoint], [(value - 5_000, ANYONE_CAN_SPEND)])
    remember(a2)
    submit(f"A'' {short(a2.txid)} pays 5000 sat", a2)
    print(f"   A in pool: {pool.contains(a.txid)}, A'' in pool: {pool.contains(a2.txid)}")

    step("3a. Child pays for parent inside the pool")
    (op_u, value_u) = spendable.pop(0)
    u = spend([op_u], [(value_u - 2_000, ANYONE_CAN_SPEND)])
    submit(f"unrelated tx U {short(u.txid)}", u)
    (op_p, value_p) = spendable.pop(0)
    p = spend([op_p], [(value_p - 200, ANYONE_CAN_SPEND)])
    submit(f"low fee parent P {short(p.txid)}", p)
    c = spend([(p.txid, 0)], [(value_p - 200 - 8_000, ANYONE_CAN_SPEND)])
    remember(u, p, c)
    names = {a2.txid: "A''", u.txid: "U", p.txid: "P", c.txid: "C"}

    def show_order(label):
        order, sequence = pool.mining_order()
        print(f"   mining order {label} (snapshot at sequence {sequence}):")
        for txid, fee, vsize, chunk_fee, chunk_weight in order:
            print(f"     {names.get(txid, '?'):4} {short(txid)} {fee / vsize:6.2f} sat/vB own, "
                  f"{chunk_fee / ((chunk_weight + 3) // 4):6.2f} sat/vB chunk")
    show_order("before the child")
    submit(f"high fee child C {short(c.txid)} (parent in the pool: no coins needed)", c)
    show_order("after the child")
    info = pool.entry(p.txid)
    print(f"   P now has {info.descendant_count - 1} descendant(s) and is mined in a chunk of "
          f"{info.chunk_fee} sat / {(info.chunk_weight + 3) // 4} vB")

    step("3b. Package CPFP: a zero fee TRUC parent sponsored by its child")
    (op_z, value_z) = spendable.pop(0)
    zero = spend([op_z], [(value_z, ANYONE_CAN_SPEND)], version=3)
    submit(f"zero fee parent Z {short(zero.txid)} alone", zero)
    sponsor = spend([(zero.txid, 0)], [(value_z - 10_000, ANYONE_CAN_SPEND)], version=3)
    remember(zero, sponsor)
    results, error = pool.submit([zero, sponsor])
    print(f"   package [Z, child]: {'package error ' + error if error else 'accepted'}")
    for name, r in zip(["Z", "child"], results):
        print(f"     {name}: {r}")
    pool.report()
    print(f"   pool now holds {pool.size()} transactions; running the full consistency check:")
    pool.check()
    pool.report()

    step("3c. The same pool from asyncio, with a remote UTXO set")

    async def remote():
        loop = asyncio.get_running_loop()

        async def lookup_all(ops):
            return await asyncio.gather(*(node.coin_async(*op) for op in ops))

        def resolve(ops):
            # Runs on the worker thread inside get_coins; no pool lock is held, so blocking is fine.
            return asyncio.run_coroutine_threadsafe(lookup_all(ops), loop).result()
        pool.resolver = resolve
        r = spend([(fan.txid, 0)], [(fan.vout[0][0] - 3_000, ANYONE_CAN_SPEND)])
        remember(r)
        names[r.txid] = "R"
        result = await asyncio.to_thread(pool.accept, r)
        pool.resolver = None
        return r, result
    r, result = asyncio.run(remote())
    print(f"   tx R {short(r.txid)} submitted from a worker thread, coins awaited on the event loop: {result}")
    pool.report()

    step("4. Compact block relay")
    # A miner builds a block from the pool in mining order, but it saw A before A'' and never saw R.
    template = [created[txid] for txid, *_ in pool.mining_order()[0]]
    template = [tx for tx in template if tx.txid not in (a2.txid, r.txid)] + [a]
    raw_block, block_txs = node.make_block(template)
    cmpct = pool.encode_compact(raw_block, 0xdeadbeef)
    print(f"   block {short(hash256(raw_block[:80]))} with {len(block_txs)} txs is {len(raw_block)} bytes; "
          f"its cmpctblock is {len(cmpct)} bytes")

    def fetch(indexes):
        print(f"   pool is missing block indexes {indexes}: fetching them from the peer (getblocktxn)")
        return [block_txs[i] for i in indexes]
    rebuilt, status = pool.reconstruct(cmpct, fetch)
    print(f"   reconstruction: {status}, identical to the original: {rebuilt == raw_block}")
    print("   connecting the reconstructed block through the kernel, then the mempool:")
    assert kernel.process_block(rebuilt)
    node.connect(rebuilt, block_txs)
    pool.report()
    print(f"   kernel height {kernel.height()}, pool now holds {pool.size()} transactions")

    step("5. Reorg: a longer competing chain without our transactions")
    f1, f1_txs = node.make_block(parent=(node.chain[-2][0], node.height - 1))
    f2, f2_txs = node.make_block(parent=(hash256(f1[:80]), node.height))
    assert kernel.process_block(f1, extends_tip=False) and kernel.process_block(f2, extends_tip=False)
    print(f"   kernel switched to the fork, height {kernel.height()}")
    node.disconnect()
    print("   connecting the first fork block re-adds the disconnected transactions:")
    node.connect(f1, f1_txs)
    pool.report()
    node.connect(f2, f2_txs)
    print(f"   chain height {node.height}, pool holds {pool.size()} transactions; A is back: {pool.contains(a.txid)}")
    print("   R stayed in the pool throughout, and its coin was not looked up again: it was confirmed below the")
    print("   fork and is not a coinbase, so its lock points and maturity cannot have changed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build-dir", default=os.path.join(os.path.dirname(__file__), "..", "build"))
    parser.add_argument("--verbose", action="store_true", help="print library log lines")
    args = parser.parse_args()
    libdir = os.path.join(args.build_dir, "lib")
    ext = "dylib" if sys.platform == "darwin" else "so"
    mempool_lib = MempoolLib(os.path.join(libdir, f"libbitcoinmempool.{ext}"))
    if args.verbose:
        log_cb = LOG(lambda _, msg: print(f"   [mempool log] {msg}"))
        mempool_lib.lib.btcm_set_log_callback(log_cb, None)

    with tempfile.TemporaryDirectory(prefix="mempool_demo_") as datadir:
        kernel = Kernel(os.path.join(libdir, f"libbitcoinkernel.{ext}"), datadir)
        node = Node(kernel, mempool_lib)
        scenario(node, kernel, mempool_lib)
        node.mempool.close()
        kernel.close()


if __name__ == "__main__":
    main()
