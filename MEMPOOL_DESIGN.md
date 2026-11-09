# libbitcoinmempool — attempt 4: pushed tip, batched coins, no callbacks under locks

Branch: `mempool-lib-4`. This is the final attempt; it keeps what worked in
attempts 1–3 and drops what did not.

## Summary

* **libbitcoinkernel contains no mempool.** It no longer compiles `txmempool`,
  `txgraph`, RBF/package/TRUC/ephemeral policy, `MemPoolAccept`, the
  disconnected-transactions buffer, `MemPoolRemovalReason`, or the mempool
  notification dispatch, and it no longer links Boost. All 124 kernel objects
  were checked against the ninja dependency database: none includes a Boost
  header or any mempool header.
* **libbitcoinmempool** (`-DBUILD_MEMPOOL_LIB=ON`, header
  `src/mempool/bitcoinmempool.h`, 47 functions) does no I/O and keeps no
  chain. The embedder pushes the tip with each block and serves coins through
  one batched callback. Events arrive through callbacks. No callback ever runs
  while the pool holds a lock.
* **`contrib/mempool_demo.py`** drives both libraries from Python. It covers
  RBF, CPFP in the pool, zero-fee TRUC package CPFP, compact block encode and
  reconstruct with a `getblocktxn` round trip, a reorg, a callback that
  re-enters the pool, and an asyncio-backed UTXO source.

## Part 1: removing the mempool from the kernel

Five commits, shared with earlier attempts where noted.

1. **`kernel: decouple the mempool from libbitcoinkernel`** (all attempts)
   * `MemPoolAccept`, ATMP, package acceptance, `LimitMempoolSize` and reorg
     handling move from `validation.cpp` to `src/mempool_accept.{h,cpp}`. They
     are written against a `MempoolChainView` interface instead of `Chainstate`.
   * `Chainstate::m_mempool` becomes a `kernel::MempoolHooks*`, a pure
     interface (`GetMutex`, `MaxSizeBytes`, `DynamicMemoryUsage`, `IsEmpty`,
     `TipChanged`, `BlockDisconnected`, `BlockConnected`, `ReorgFinished`,
     `Check`). The kernel ships no implementation.
   * The node implements the hooks in `node::ChainstateMempoolHooks`
     (`src/node/chainstate_mempool.cpp`), together with the Chainstate-backed
     `ChainstateMempoolView` and the `AcceptToMemoryPool`,
     `ProcessNewPackage` and `ProcessTransaction` wrappers.
     `ChainstateManager::ProcessTransaction` became the free function
     `ProcessTransaction(chainman, pool, tx)`.
   * Script checks, `ValidationCache` and the merkle/witness mutation checks
     move to `src/validation_common.{h,cpp}`, which both libraries compile.
   * `validation.h` no longer includes `txmempool.h`, and with it Boost.MultiIndex.
2. **`mempool: validate against a chain oracle instead of a CChain`** (attempts 2–4)
   * `MempoolChainView` answers `TipHeight`, `BlockHash(h)` and `MedianTimePast(h)`.
   * `LockPoints::maxInputBlock` (a `CBlockIndex*`) becomes
     `max_input_block`, a `(height, hash)` pair.
   * `CTxMemPool::removeForReorg` loses its `CChain&` parameter.
   * Consensus code gains `CalculateSequenceLocks` and `EvaluateSequenceLocks`
     overloads that need no block index. The `CBlockIndex` versions forward to
     them, so block validation is unchanged.
3. **`kernel: move mempool signal dispatch out of libbitcoinkernel`** (attempts 3–4)
   * The mempool members of `ValidationSignals` are now defined in
     `src/validationinterface_mempool.cpp`, which only `bitcoin_node` and the
     mempool library compile.
   * The kernel drops `mempool_removal_reason.cpp`.
4. **`mempool: let chain views answer lock point validity directly`** (attempt 4)
   * Adds `MempoolChainView::IsInActiveChain(height, hash)`, which defaults to
     `BlockHash(height) == hash`.
5. **`mempool: add libbitcoinmempool C library, attempt 4`**
   * The library, the demo and this document.

Node behaviour is unchanged. Verified with:

* `ctest`: 361/361 (unit tests, `test_kernel`, secp256k1).
* Functional tests: `mempool_reorg`, `mempool_accept`, `feature_rbf`,
  `rpc_packages`, `p2p_compactblocks`, `mempool_persist`, `mempool_limit`,
  `mempool_truc`, `feature_bip68_sequence`, `mempool_resurrect`,
  `mempool_package_rbf`, `rpc_invalidateblock`, `feature_assumeutxo` and
  `mempool_updatefromblock` all pass.
* `fuzz` and `bench_bitcoin` build, and `-Wthread-safety` is clean.

## Part 2: the library API

### Data flow

```
                 push: btcm_mempool_block_connected(block, tip)
                       btcm_mempool_block_disconnected(block, tip)
   embedder ──────────────────────────────────────────────────────────▶  btcm_Mempool
   (UTXO set,  ◀── get_coins(outpoints[], batch) ─────────────────────   (CTxMemPool,
    chain)          answered with btcm_coin_batch_set(batch, i, coin)     sigcache,
               ◀── transaction_added / transaction_removed ───────────   reorg buffer)
                   (all callbacks run with no pool lock held)
```

* **The tip is pushed** (`btcm_Tip`: height, hash, median time past) at
  creation and with every block. The pool knows no other block.
  `block_connected` refuses a tip that doesn't extend its own.
* **Coins carry their chain context.** A `btcm_Coin` holds amount, script,
  height, coinbase flag, the hash of its block, and the median time past of
  the block before it. That is everything BIP 68 lock points and coinbase
  maturity need, so the pool never asks a chain question.
* **One batched lookup per round.** `btcm_mempool_submit` works out every
  outpoint the transaction or package needs that neither the pool nor the
  package provides, then asks for all of them in one `get_coins` call. A CPFP
  child of a pool transaction needs no lookup at all.
* **No callback runs under a lock.** The pool releases its locks before
  calling `get_coins` and re-checks afterwards. If the tip moved, the coins are
  discarded and fetched again; if the pool gained a parent, fewer are needed.
  Events are buffered and delivered after the locks are released, so callbacks
  may block, and may call any pool function, including `submit`.
* **Reorgs finish themselves, cheaply.** `block_disconnected` buffers the
  block's transactions, and the next `block_connected` re-adds them. Coins are
  fetched only for:
  * the disconnected transactions,
  * pool entries that spend a coinbase (maturity),
  * pool entries whose lock points reference a block at or above the fork.
  The pool tracks the fork height itself (`IsInActiveChain`), so every other
  entry is provably unaffected and needs nothing.

### Objects and values

Owned objects are opaque handles (libbitcoinkernel style). Plain data crosses
as versioned structs: the first field is `struct_size`, and the library reads
and writes only the fields the caller knows about.

| Kind | Type | Functions |
|---|---|---|
| handle | `btcm_Mempool` | `create(config, tip, callbacks)`, `destroy`, `block_connected`, `block_disconnected`, `submit(txs, n, flags)`, `prioritise_transaction`, `check`, `size`, `dynamic_memory_usage`, `min_feerate`, `get_transaction`, `get_entry`, `snapshot` |
| handle | `btcm_Transaction` | `create(bytes)`, `copy`, `get_txid`, `get_wtxid`, `to_bytes`, `destroy`. It shares the immutable `CTransaction` with the pool. |
| handle | `btcm_Block` | `create(bytes)`, `get_hash`, `count_transactions`, `get_transaction_at` (lent), `to_bytes`, `destroy` |
| handle | `btcm_SubmitResult` | `count`, `get(i, btcm_TxOutcome*)`, `get_package_error`, `destroy` |
| handle | `btcm_Snapshot` | `count`, `get_sequence`, `get_entry(i, btcm_EntryInfo*)`, `get_transaction(i)` (lent), `destroy` |
| handle | `btcm_Reconstruction` | `create(pool, cmpctblock bytes, &status)`, `missing_count`, `missing_index(i)`, `finish(missing txs) → btcm_Block*`, `destroy` |
| value | `btcm_Config`, `btcm_Tip`, `btcm_Coin`, `btcm_TxOutcome`, `btcm_EntryInfo` | `_init` functions |
| callbacks | `btcm_Callbacks` | `get_coins` (required), `transaction_added`, `transaction_removed`, `user_data_destroy` |
| free | — | `btcm_set_log_callback`, `btcm_coin_batch_set`, `btcm_compact_block_encode(block, nonce)` |

* Single transactions and packages go through one entry point:
  `btcm_mempool_submit(pool, txs, n, flags)`, with `btcm_SubmitFlags_TEST_ACCEPT`.
* Strings come back as `btcm_StringView` values lent by the result handle that
  produced them.
* `btcm_Snapshot` returns entries in mining order, with chunk fee and weight
  and ancestor, descendant and cluster counts. Its `sequence` can be matched
  against the `sequence` carried by events.

### No I/O

The library is built from its own source list (`src/mempool/CMakeLists.txt`)
and does not include LevelDB, `dbwrapper`, `blockstorage`, `validation.cpp`,
`streams.cpp` (`AutoFile`) or `randomenv.cpp`. The environment-entropy
collector is replaced by no-ops, so randomness comes from `getrandom()` and
the CPU. The shared object imports no `open`, `read`, `stat`, `socket` or
`getifaddrs`. Only the assertion-failure message in `util/check.cpp` writes
to `stderr`. Logs go to `btcm_set_log_callback`.

## Demo

### Running it

```
git checkout mempool-lib-4
cmake -B build-demo -DBUILD_SHARED_LIBS=ON -DBUILD_KERNEL_LIB=ON -DBUILD_MEMPOOL_LIB=ON
cmake --build build-demo --target bitcoinkernel bitcoinmempool -j$(nproc)
python3 contrib/mempool_demo.py --build-dir build-demo
```

* `-DBUILD_SHARED_LIBS=ON` is required: the demo loads
  `<build-dir>/lib/libbitcoinkernel.so` and `libbitcoinmempool.so` (`.dylib`
  on macOS) through `ctypes`, so static archives won't work.
* `--build-dir` defaults to `build/` at the repository root. Pass it unless
  you built there.
* The demo needs only Python 3 and its standard library.
* `--verbose` also prints the mempool library's log lines.
* It takes a few seconds, mostly mining 113 regtest blocks. The kernel's
  block files go into a temporary directory that is deleted at the end.
* The other attempts work the same way: check out `mempool-lib-1`, `-2` or
  `-3`, rebuild the two targets and run the same command. Each branch has its
  own demo matching its API, so rebuild after every branch switch.

### What it shows

The Python "node" validates every block it mines with **libbitcoinkernel**,
keeps a dict UTXO set, and wires that into **libbitcoinmempool**:

1. **Setup**: 111 regtest blocks; one includes a fan-out transaction.
2. **Submit**: A is accepted with one batched lookup. Inside that `get_coins`
   callback the demo calls `btcm_mempool_size`, which shows the callback holds
   no lock. Test-accepting A again needs no coins (`txn-already-in-mempool`).
3. **RBF**: a replacement paying +5 sat is rejected with `insufficient fee`.
   One paying +4000 sat replaces A, and the callbacks report `REPLACED`, then
   `added`.
4. **CPFP in the pool**: the child of a pool transaction needs no lookup. In
   the snapshot's mining order, the 2 sat/vB parent forms a 43 sat/vB chunk
   with its child and moves ahead of a 21 sat/vB transaction.
5. **Package CPFP**: a zero-fee TRUC parent alone gives `min relay fee not
   met`. As a 1p1c package with its child, both are accepted. A
   `btcm_mempool_check` then fetches the 4 coins it needs and passes.
6. **asyncio**: `asyncio.to_thread` submits a transaction. Its `get_coins`
   callback awaits coroutine lookups on the event loop with
   `run_coroutine_threadsafe`. Blocking inside the callback is safe because
   the pool holds no lock.
7. **Compact blocks**: the miner's block holds the pool's transactions minus
   R, plus the transaction the pool had replaced. `btcm_compact_block_encode`
   shrinks it from 855 to 307 bytes. Reconstruction lacks index 6 only, and
   `finish` returns a byte-identical block. The kernel connects it; the pool
   reports 5 `BLOCK` removals and 1 `CONFLICT`, and R stays.
8. **Reorg**: the kernel switches to a longer fork. The first fork block
   re-adds all six transactions after **one batched lookup of 4 outpoints**.
   R stays in the pool and is not looked up again, because it was confirmed
   below the fork and spends no coinbase.

## How the four attempts compare

| | Attempt 1 | Attempt 2 | Attempt 3 | Attempt 4 |
|---|---|---|---|---|
| Chain knowledge | own `CBlockIndex` chain from replayed headers | pulled by callback per question | pushed tip; coins carry block context | pushed tip; coins carry block context |
| Coin access | `get_coin` callback, one at a time, under lock | `get_coin` callback, one at a time, under lock | embedder answers job requests, no callbacks | batched `get_coins` callback, no lock held |
| Events | callbacks under lock | callbacks under lock | queue drained by embedder | callbacks after locks released |
| Reorg | automatic | automatic | explicit `finish_reorg` job | automatic |
| Coins needed for a reorg | as needed by the filter | as needed by the filter | every pool input | disconnected txs plus entries the fork can affect |
| ABI style | fixed structs, bytes | opaque handles, accessors | versioned structs, bytes | handles for owned objects, versioned structs for values |
| Exported functions | 26 | 74 | 40 | 47 |
| async embedders | no | no | native | via a blocking callback on a worker thread |
| Re-entrant callbacks | no | no | n/a | yes |
| Kernel also free of mempool notification code | no | no | yes | yes |

## Tradeoffs that remain

* **The consensus code is duplicated.** libbitcoinmempool carries its own
  script interpreter, secp256k1 and hashing, because libbitcoinkernel only
  exports its C API. Building both libraries from one tree keeps them in
  lockstep, but a process that loads both holds two copies.
* **The coin record is wide.** Every coin repeats its block's hash and
  previous median time past. That is cheap for an embedder that has them at
  hand (the kernel's block tree does), but redundant over the wire.
* **Lookups are bounded retries, not transactions.** Under a fast-moving tip,
  `submit` re-fetches up to 16 times and then reports `chain-tip-unstable`,
  instead of looping forever.
* **`btcm_mempool_check` needs every pool input.** It is a debugging aid,
  where the node runs its check after every change.
* **No persistence.** `mempool.dat` is not loaded or dumped, because that
  would be I/O. An embedder that wants it can re-submit from its own store, or
  serialize `btcm_Snapshot` transactions.
* **The kernel still knows a mempool may exist.** It keeps the abstract
  `kernel::MempoolHooks` (the node's hook point) and `CValidationInterface`'s
  empty default handlers for mempool events. Both are interfaces only; there
  is no mempool code behind them.
