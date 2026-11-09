// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATION_COMMON_H
#define BITCOIN_VALIDATION_COMMON_H

#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <cuckoocache.h>
#include <kernel/cs_main.h>
#include <primitives/transaction.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/verify_flags.h>
#include <sync.h>
#include <uint256.h>

#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

class CBlock;
class CCoinsViewCache;
struct PrecomputedTransactionData;

/**
 * Closure representing one script verification
 * Note that this stores references to the spending transaction
 */
class CScriptCheck
{
private:
    CTxOut m_tx_out;
    const CTransaction *ptxTo;
    unsigned int nIn;
    script_verify_flags m_flags;
    bool cacheStore;
    PrecomputedTransactionData *txdata;
    SignatureCache* m_signature_cache;

public:
    CScriptCheck(const CTxOut& outIn, const CTransaction& txToIn, SignatureCache& signature_cache, unsigned int nInIn, script_verify_flags flags, bool cacheIn, PrecomputedTransactionData* txdataIn) :
        m_tx_out(outIn), ptxTo(&txToIn), nIn(nInIn), m_flags(flags), cacheStore(cacheIn), txdata(txdataIn), m_signature_cache(&signature_cache) { }

    CScriptCheck(const CScriptCheck&) = delete;
    CScriptCheck& operator=(const CScriptCheck&) = delete;
    CScriptCheck(CScriptCheck&&) = default;
    CScriptCheck& operator=(CScriptCheck&&) = default;

    std::optional<std::pair<ScriptError, std::string>> operator()();
};

// CScriptCheck is used a lot in std::vector, make sure that's efficient
static_assert(std::is_nothrow_move_assignable_v<CScriptCheck>);
static_assert(std::is_nothrow_move_constructible_v<CScriptCheck>);
static_assert(std::is_nothrow_destructible_v<CScriptCheck>);

/**
 * Convenience class for initializing and passing the script execution cache
 * and signature cache.
 */
class ValidationCache
{
private:
    //! Pre-initialized hasher to avoid having to recreate it for every hash calculation.
    CSHA256 m_script_execution_cache_hasher;

public:
    CuckooCache::cache<uint256, SignatureCacheHasher> m_script_execution_cache;
    SignatureCache m_signature_cache;

    ValidationCache(size_t script_execution_cache_bytes, size_t signature_cache_bytes);

    ValidationCache(const ValidationCache&) = delete;
    ValidationCache& operator=(const ValidationCache&) = delete;

    //! Return a copy of the pre-initialized hasher.
    CSHA256 ScriptExecutionCacheHasher() const { return m_script_execution_cache_hasher; }
};

/** Check the block's merkle root, including CVE-2012-2459 malleation. */
bool CheckMerkleRoot(const CBlock& block, BlockValidationState& state);

/** CheckWitnessMalleation performs checks for block malleation with regard to
 * its witnesses.
 *
 * Note: If the witness commitment is expected (i.e. `expect_witness_commitment
 * = true`), then the block is required to have at least one transaction and the
 * first transaction needs to have at least one input. */
bool CheckWitnessMalleation(const CBlock& block, bool expect_witness_commitment, BlockValidationState& state);

/** Check if a block has been mutated (with respect to its merkle root and witness commitments). */
bool IsBlockMutated(const CBlock& block, bool check_witness_root);

/** The context CheckInputScripts is called in, which decides how a
 *  script failure is reported: as a consensus failure for blocks,
 *  or as a standardness failure for the mempool. The flags alone can't
 *  determine this, as the mempool may check with consensus flags only
 *  (-acceptnonstdtxn).
 */
enum class CheckInputScriptsFor {
    Block,
    Mempool,
};

bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs,
                       script_verify_flags flags,
                       CheckInputScriptsFor check_for,
                       bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       ValidationCache& validation_cache,
                       std::vector<CScriptCheck>* pvChecks = nullptr)
                       EXCLUSIVE_LOCKS_REQUIRED(cs_main);

#endif // BITCOIN_VALIDATION_COMMON_H
