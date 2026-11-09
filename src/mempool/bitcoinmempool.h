// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MEMPOOL_BITCOINMEMPOOL_H
#define BITCOIN_MEMPOOL_BITCOINMEMPOOL_H

#ifndef __cplusplus
#include <stddef.h>
#include <stdint.h>
#else
#include <cstddef>
#include <cstdint>
#endif // __cplusplus

#ifndef BITCOINMEMPOOL_API
    #ifdef BITCOINMEMPOOL_BUILD
        #if defined(_WIN32)
            #define BITCOINMEMPOOL_API __declspec(dllexport)
        #else
            #define BITCOINMEMPOOL_API __attribute__((visibility("default")))
        #endif
    #else
        #if defined(_WIN32) && !defined(BITCOINMEMPOOL_STATIC)
            #define BITCOINMEMPOOL_API __declspec(dllimport)
        #else
            #define BITCOINMEMPOOL_API
        #endif
    #endif
#endif

#if !defined(BITCOINMEMPOOL_GNUC_PREREQ)
    #if defined(__GNUC__) && defined(__GNUC_MINOR__)
        #define BITCOINMEMPOOL_GNUC_PREREQ(_maj, _min) \
            ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((_maj) << 16) + (_min))
    #else
        #define BITCOINMEMPOOL_GNUC_PREREQ(_maj, _min) 0
    #endif
#endif

#if BITCOINMEMPOOL_GNUC_PREREQ(3, 4)
    #define BITCOINMEMPOOL_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#else
    #define BITCOINMEMPOOL_WARN_UNUSED_RESULT
#endif

#if !defined(BITCOINMEMPOOL_BUILD) && BITCOINMEMPOOL_GNUC_PREREQ(3, 4)
    #define BITCOINMEMPOOL_ARG_NONNULL(...) __attribute__((__nonnull__(__VA_ARGS__)))
#else
    #define BITCOINMEMPOOL_ARG_NONNULL(...)
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @page mempool libbitcoinmempool
 *
 * A transaction memory pool that performs no I/O and keeps no copy of the
 * chain.
 *
 * - The chain tip (height, hash, median time past) is pushed with every block
 *   notification. The pool knows no other block.
 * - Unspent outputs are pulled in batches through the get_coins callback.
 *   Each coin carries the chain context needed to spend it: the hash of its
 *   block and the median time past before it (BIP 68).
 * - Events are delivered through callbacks.
 *
 * Callbacks are never invoked while the pool holds a lock. They may block
 * (for example on a network lookup or an async event loop) and may call back
 * into the pool. If the tip moves while coins are being looked up, the pool
 * fetches again.
 *
 * Conventions:
 * - Owned objects are opaque handles: `_create` returns one, `_destroy` frees
 *   it, and `const` pointers returned by getters are lent by their owner.
 *   btcm_StringView values are lent by the handle that returned them.
 * - Plain data crosses as structs whose first field is struct_size.
 *   Initialize them with their _init function. The library only reads and
 *   writes the fields the caller's struct has, so fields can be appended in
 *   later versions.
 * - Hashes are 32 bytes in internal (little endian) byte order.
 * - All functions are thread safe.
 */

typedef struct btcm_Mempool btcm_Mempool;
typedef struct btcm_Transaction btcm_Transaction;
typedef struct btcm_Block btcm_Block;
typedef struct btcm_CoinBatch btcm_CoinBatch;
typedef struct btcm_SubmitResult btcm_SubmitResult;
typedef struct btcm_Snapshot btcm_Snapshot;
typedef struct btcm_Reconstruction btcm_Reconstruction;

typedef uint8_t btcm_ChainType;
#define btcm_ChainType_MAINNET ((btcm_ChainType)(0))
#define btcm_ChainType_TESTNET ((btcm_ChainType)(1))
#define btcm_ChainType_TESTNET_4 ((btcm_ChainType)(2))
#define btcm_ChainType_SIGNET ((btcm_ChainType)(3))
#define btcm_ChainType_REGTEST ((btcm_ChainType)(4))

typedef uint8_t btcm_AcceptStatus;
#define btcm_AcceptStatus_VALID ((btcm_AcceptStatus)(0))             //!< Validated and, unless testing, added.
#define btcm_AcceptStatus_INVALID ((btcm_AcceptStatus)(1))           //!< Rejected, see reject_reason.
#define btcm_AcceptStatus_MEMPOOL_ENTRY ((btcm_AcceptStatus)(2))     //!< Already in the pool.
#define btcm_AcceptStatus_DIFFERENT_WITNESS ((btcm_AcceptStatus)(3)) //!< The same txid with another witness is in the pool.
#define btcm_AcceptStatus_NOT_EVALUATED ((btcm_AcceptStatus)(4))     //!< Package evaluation stopped before this transaction.

typedef uint8_t btcm_RemovalReason;
#define btcm_RemovalReason_EXPIRY ((btcm_RemovalReason)(0))
#define btcm_RemovalReason_SIZELIMIT ((btcm_RemovalReason)(1))
#define btcm_RemovalReason_REORG ((btcm_RemovalReason)(2))
#define btcm_RemovalReason_BLOCK ((btcm_RemovalReason)(3))
#define btcm_RemovalReason_CONFLICT ((btcm_RemovalReason)(4))
#define btcm_RemovalReason_REPLACED ((btcm_RemovalReason)(5))

typedef uint8_t btcm_ReadStatus;
#define btcm_ReadStatus_OK ((btcm_ReadStatus)(0))
#define btcm_ReadStatus_INVALID ((btcm_ReadStatus)(1)) //!< Malformed or mutated; the sender is misbehaving.
#define btcm_ReadStatus_FAILED ((btcm_ReadStatus)(2))  //!< Reconstruction failed (e.g. a short id collision); fetch the full block.

typedef uint32_t btcm_SubmitFlags;
#define btcm_SubmitFlags_NONE ((btcm_SubmitFlags)(0))
#define btcm_SubmitFlags_TEST_ACCEPT ((btcm_SubmitFlags)(1U << 0)) //!< Validate only, never add.

/** A borrowed string, not NUL terminated. */
typedef struct {
    const char* data;
    size_t size;
} btcm_StringView;

typedef struct {
    uint8_t txid[32];
    uint32_t index;
} btcm_OutPoint;

/** Pool configuration. */
typedef struct {
    size_t struct_size;
    btcm_ChainType chain_type;
    int64_t max_size_bytes;
    int64_t expiry_seconds;
    int64_t min_relay_feerate;         //!< sat/kvB
    int64_t incremental_relay_feerate; //!< sat/kvB
    int require_standard;
    int check_ratio; //!< Let btcm_mempool_check() run 1/check_ratio of the times it is called; 0 disables.
} btcm_Config;

/** The active chain tip. */
typedef struct {
    size_t struct_size;
    int32_t height;
    uint8_t hash[32];
    int64_t median_time_past; //!< BIP 113 median time past of the tip.
} btcm_Tip;

/** An unspent output, with the chain context needed to spend it. */
typedef struct {
    size_t struct_size;
    int64_t amount;
    const uint8_t* script_pubkey; //!< Copied by btcm_coin_batch_set.
    size_t script_pubkey_len;
    int32_t height;                //!< Height of the block that created the output.
    int is_coinbase;
    uint8_t block_hash[32];        //!< Hash of that block.
    int64_t prev_median_time_past; //!< Median time past of the block before it.
} btcm_Coin;

/** Outcome for one submitted transaction. Strings are lent by the btcm_SubmitResult. */
typedef struct {
    size_t struct_size;
    btcm_AcceptStatus status;
    uint8_t txid[32];
    uint8_t wtxid[32];
    int64_t fee;               //!< -1 if unknown.
    int64_t vsize;             //!< -1 if unknown.
    int64_t effective_feerate; //!< sat/kvB the fee checks used, including package members; -1 if unknown.
    uint8_t other_wtxid[32];   //!< DIFFERENT_WITNESS only.
    btcm_StringView reject_reason; //!< Empty unless INVALID.
    btcm_StringView debug_message; //!< Empty unless INVALID.
} btcm_TxOutcome;

/** A snapshot of a pool entry. */
typedef struct {
    size_t struct_size;
    uint8_t txid[32];
    uint8_t wtxid[32];
    int64_t fee;
    int64_t modified_fee; //!< Including prioritisation deltas.
    int64_t vsize;
    int64_t weight;
    int64_t chunk_fee;    //!< Fee of the chunk the transaction is mined in.
    int64_t chunk_weight; //!< Weight of that chunk.
    uint32_t ancestor_count;
    uint32_t descendant_count;
    uint32_t cluster_count;
    int64_t time;
    int32_t height;
} btcm_EntryInfo;

typedef void (*btcm_DestroyCallback)(void* user_data);

/** Receives serialized bytes. Return 0 on success. */
typedef int (*btcm_WriteBytes)(const void* bytes, size_t size, void* user_data);

/** Receives the library's log lines. */
typedef void (*btcm_LogCallback)(void* user_data, btcm_StringView message);

/** How the pool reaches the embedder. Every callback is invoked without any pool lock held. */
typedef struct {
    void* user_data;
    btcm_DestroyCallback user_data_destroy; //!< Called when the pool is destroyed. Nullable.
    /**
     * Look up outpoints in the UTXO set at the tip the pool was last told
     * about. Call btcm_coin_batch_set(batch, i, &coin) for each outpoints[i]
     * that is unspent; leave the others unset. Required.
     */
    void (*get_coins)(void* user_data, const btcm_OutPoint* outpoints, size_t outpoints_len, btcm_CoinBatch* batch);
    /** A transaction entered the pool. The transaction is lent for the call. Nullable. */
    void (*transaction_added)(void* user_data, const btcm_Transaction* tx, int64_t fee, int64_t vsize, uint64_t sequence);
    /**
     * A transaction left the pool. sequence is the pool's event counter at the
     * removal; it is 0 for BLOCK removals. Nullable.
     */
    void (*transaction_removed)(void* user_data, const btcm_Transaction* tx, btcm_RemovalReason reason, uint64_t sequence);
} btcm_Callbacks;

BITCOINMEMPOOL_API void btcm_set_log_callback(btcm_LogCallback callback, void* user_data);

BITCOINMEMPOOL_API void btcm_config_init(btcm_Config* config, btcm_ChainType chain_type) BITCOINMEMPOOL_ARG_NONNULL(1);
BITCOINMEMPOOL_API void btcm_tip_init(btcm_Tip* tip) BITCOINMEMPOOL_ARG_NONNULL(1);
BITCOINMEMPOOL_API void btcm_coin_init(btcm_Coin* coin) BITCOINMEMPOOL_ARG_NONNULL(1);
BITCOINMEMPOOL_API void btcm_tx_outcome_init(btcm_TxOutcome* outcome) BITCOINMEMPOOL_ARG_NONNULL(1);
BITCOINMEMPOOL_API void btcm_entry_info_init(btcm_EntryInfo* info) BITCOINMEMPOOL_ARG_NONNULL(1);

/** Answer outpoints[index] of a get_coins call with an unspent coin. */
BITCOINMEMPOOL_API void btcm_coin_batch_set(btcm_CoinBatch* batch, size_t index, const btcm_Coin* coin) BITCOINMEMPOOL_ARG_NONNULL(1, 3);

/** @name Transactions and blocks */
///@{

/** Parse a serialized transaction. Returns NULL if it is malformed. */
BITCOINMEMPOOL_API btcm_Transaction* BITCOINMEMPOOL_WARN_UNUSED_RESULT btcm_transaction_create(const void* raw, size_t raw_len);
/** Another reference to the same immutable transaction. */
BITCOINMEMPOOL_API btcm_Transaction* BITCOINMEMPOOL_WARN_UNUSED_RESULT btcm_transaction_copy(const btcm_Transaction* tx) BITCOINMEMPOOL_ARG_NONNULL(1);
BITCOINMEMPOOL_API void btcm_transaction_get_txid(const btcm_Transaction* tx, uint8_t txid[32]) BITCOINMEMPOOL_ARG_NONNULL(1, 2);
BITCOINMEMPOOL_API void btcm_transaction_get_wtxid(const btcm_Transaction* tx, uint8_t wtxid[32]) BITCOINMEMPOOL_ARG_NONNULL(1, 2);
BITCOINMEMPOOL_API int btcm_transaction_to_bytes(const btcm_Transaction* tx, btcm_WriteBytes writer, void* user_data) BITCOINMEMPOOL_ARG_NONNULL(1, 2);
BITCOINMEMPOOL_API void btcm_transaction_destroy(btcm_Transaction* tx);

/** Parse a serialized block. Returns NULL if it is malformed. */
BITCOINMEMPOOL_API btcm_Block* BITCOINMEMPOOL_WARN_UNUSED_RESULT btcm_block_create(const void* raw, size_t raw_len);
BITCOINMEMPOOL_API void btcm_block_get_hash(const btcm_Block* block, uint8_t hash[32]) BITCOINMEMPOOL_ARG_NONNULL(1, 2);
BITCOINMEMPOOL_API size_t btcm_block_count_transactions(const btcm_Block* block) BITCOINMEMPOOL_ARG_NONNULL(1);
BITCOINMEMPOOL_API const btcm_Transaction* btcm_block_get_transaction_at(const btcm_Block* block, size_t index) BITCOINMEMPOOL_ARG_NONNULL(1);
BITCOINMEMPOOL_API int btcm_block_to_bytes(const btcm_Block* block, btcm_WriteBytes writer, void* user_data) BITCOINMEMPOOL_ARG_NONNULL(1, 2);
BITCOINMEMPOOL_API void btcm_block_destroy(btcm_Block* block);
///@}

/** @name Pool */
///@{

/** Create an empty pool on top of tip. The callbacks struct is copied. Returns NULL on invalid input. */
BITCOINMEMPOOL_API btcm_Mempool* BITCOINMEMPOOL_WARN_UNUSED_RESULT btcm_mempool_create(
    const btcm_Config* config, const btcm_Tip* tip, const btcm_Callbacks* callbacks) BITCOINMEMPOOL_ARG_NONNULL(1, 2, 3);
BITCOINMEMPOOL_API void btcm_mempool_destroy(btcm_Mempool* mempool);

/**
 * block was connected and new_tip (which is block) is the tip. Confirmed and
 * conflicting transactions are removed. If blocks were disconnected before,
 * their transactions are re-added now. Returns 0, or -1 if new_tip does not
 * extend the pool's tip with block.
 */
BITCOINMEMPOOL_API int btcm_mempool_block_connected(btcm_Mempool* mempool, const btcm_Block* block, const btcm_Tip* new_tip) BITCOINMEMPOOL_ARG_NONNULL(1, 2, 3);

/**
 * block was disconnected and new_tip (its parent) is the tip. Its transactions
 * are re-added with the next connected block. Returns 0, or -1 if block is
 * not the pool's tip.
 */
BITCOINMEMPOOL_API int btcm_mempool_block_disconnected(btcm_Mempool* mempool, const btcm_Block* block, const btcm_Tip* new_tip) BITCOINMEMPOOL_ARG_NONNULL(1, 2, 3);

/**
 * Validate one transaction, or a child with its unconfirmed parents
 * (topologically sorted, child last) letting the child pay for them, and add
 * them unless TEST_ACCEPT. With TEST_ACCEPT, any set of up to 25 transactions
 * can be checked. Returns NULL if txs_len is 0.
 */
BITCOINMEMPOOL_API btcm_SubmitResult* BITCOINMEMPOOL_WARN_UNUSED_RESULT btcm_mempool_submit(
    btcm_Mempool* mempool, const btcm_Transaction* const* txs, size_t txs_len, btcm_SubmitFlags flags) BITCOINMEMPOOL_ARG_NONNULL(1, 2);

/** Add delta satoshis to the fee a transaction is mined and evicted by. It may not be in the pool yet. */
BITCOINMEMPOOL_API void btcm_mempool_prioritise_transaction(btcm_Mempool* mempool, const uint8_t txid[32], int64_t delta) BITCOINMEMPOOL_ARG_NONNULL(1, 2);

/**
 * Run the pool's full consistency check (subject to check_ratio). It needs
 * the coins spent by every pool transaction, so it is a debugging aid.
 */
BITCOINMEMPOOL_API void btcm_mempool_check(btcm_Mempool* mempool) BITCOINMEMPOOL_ARG_NONNULL(1);

BITCOINMEMPOOL_API size_t btcm_mempool_size(const btcm_Mempool* mempool) BITCOINMEMPOOL_ARG_NONNULL(1);
BITCOINMEMPOOL_API size_t btcm_mempool_dynamic_memory_usage(const btcm_Mempool* mempool) BITCOINMEMPOOL_ARG_NONNULL(1);
/** Feerate (sat/kvB) below which transactions are currently rejected. */
BITCOINMEMPOOL_API int64_t btcm_mempool_min_feerate(const btcm_Mempool* mempool) BITCOINMEMPOOL_ARG_NONNULL(1);
/** The transaction with this txid, or NULL. Shares the pool's copy. */
BITCOINMEMPOOL_API btcm_Transaction* BITCOINMEMPOOL_WARN_UNUSED_RESULT btcm_mempool_get_transaction(
    const btcm_Mempool* mempool, const uint8_t txid[32]) BITCOINMEMPOOL_ARG_NONNULL(1, 2);
/** Returns 0 and fills info if the transaction is in the pool. */
BITCOINMEMPOOL_API int btcm_mempool_get_entry(const btcm_Mempool* mempool, const uint8_t txid[32], btcm_EntryInfo* info) BITCOINMEMPOOL_ARG_NONNULL(1, 2, 3);
/** A consistent snapshot of all entries in mining order (best chunk first). */
BITCOINMEMPOOL_API btcm_Snapshot* BITCOINMEMPOOL_WARN_UNUSED_RESULT btcm_mempool_snapshot(const btcm_Mempool* mempool) BITCOINMEMPOOL_ARG_NONNULL(1);
///@}

/** @name Results and snapshots */
///@{

BITCOINMEMPOOL_API size_t btcm_submit_result_count(const btcm_SubmitResult* result) BITCOINMEMPOOL_ARG_NONNULL(1);
/** Outcome for the transaction at index in the submitted order. */
BITCOINMEMPOOL_API void btcm_submit_result_get(const btcm_SubmitResult* result, size_t index, btcm_TxOutcome* outcome) BITCOINMEMPOOL_ARG_NONNULL(1, 3);
/** Package-wide reject reason, empty if none. */
BITCOINMEMPOOL_API btcm_StringView btcm_submit_result_get_package_error(const btcm_SubmitResult* result) BITCOINMEMPOOL_ARG_NONNULL(1);
BITCOINMEMPOOL_API void btcm_submit_result_destroy(btcm_SubmitResult* result);

BITCOINMEMPOOL_API size_t btcm_snapshot_count(const btcm_Snapshot* snapshot) BITCOINMEMPOOL_ARG_NONNULL(1);
/** The pool's event counter when the snapshot was taken; later events have a higher sequence. */
BITCOINMEMPOOL_API uint64_t btcm_snapshot_get_sequence(const btcm_Snapshot* snapshot) BITCOINMEMPOOL_ARG_NONNULL(1);
BITCOINMEMPOOL_API void btcm_snapshot_get_entry(const btcm_Snapshot* snapshot, size_t index, btcm_EntryInfo* info) BITCOINMEMPOOL_ARG_NONNULL(1, 3);
BITCOINMEMPOOL_API const btcm_Transaction* btcm_snapshot_get_transaction(const btcm_Snapshot* snapshot, size_t index) BITCOINMEMPOOL_ARG_NONNULL(1);
BITCOINMEMPOOL_API void btcm_snapshot_destroy(btcm_Snapshot* snapshot);
///@}

/** @name Compact block relay (BIP 152) */
///@{

/** Encode block as a cmpctblock payload with the given short id nonce. Returns 0 on success. */
BITCOINMEMPOOL_API int btcm_compact_block_encode(const btcm_Block* block, uint64_t nonce, btcm_WriteBytes writer, void* user_data) BITCOINMEMPOOL_ARG_NONNULL(1, 3);

/**
 * Start rebuilding a block from a cmpctblock payload and the pool. Must not
 * outlive the pool. Returns NULL and sets status if the payload is unusable.
 */
BITCOINMEMPOOL_API btcm_Reconstruction* BITCOINMEMPOOL_WARN_UNUSED_RESULT btcm_reconstruction_create(
    btcm_Mempool* mempool, const void* cmpctblock, size_t cmpctblock_len, btcm_ReadStatus* status) BITCOINMEMPOOL_ARG_NONNULL(1, 4);
BITCOINMEMPOOL_API size_t btcm_reconstruction_missing_count(const btcm_Reconstruction* reconstruction) BITCOINMEMPOOL_ARG_NONNULL(1);
/** Block index of the i-th missing transaction (to request with getblocktxn), increasing. */
BITCOINMEMPOOL_API uint32_t btcm_reconstruction_missing_index(const btcm_Reconstruction* reconstruction, size_t i) BITCOINMEMPOOL_ARG_NONNULL(1);
/** Complete with the missing transactions (blocktxn) in index order. Returns the block, or NULL and sets status. Only once. */
BITCOINMEMPOOL_API btcm_Block* BITCOINMEMPOOL_WARN_UNUSED_RESULT btcm_reconstruction_finish(
    btcm_Reconstruction* reconstruction, const btcm_Transaction* const* txs, size_t txs_len, btcm_ReadStatus* status) BITCOINMEMPOOL_ARG_NONNULL(1, 4);
BITCOINMEMPOOL_API void btcm_reconstruction_destroy(btcm_Reconstruction* reconstruction);
///@}

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif // BITCOIN_MEMPOOL_BITCOINMEMPOOL_H
