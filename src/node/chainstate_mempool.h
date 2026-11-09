// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_CHAINSTATE_MEMPOOL_H
#define BITCOIN_NODE_CHAINSTATE_MEMPOOL_H

#include <kernel/cs_main.h>
#include <kernel/disconnected_transactions.h>
#include <kernel/mempool_hooks.h>
#include <mempool_accept.h>
#include <policy/feerate.h>
#include <policy/packages.h>
#include <primitives/transaction.h>
#include <sync.h>

#include <cstdint>
#include <memory>
#include <optional>

class Chainstate;
class ChainstateManager;
class CTxMemPool;

namespace node {

/** MempoolChainView backed by a node's Chainstate. */
class ChainstateMempoolView final : public MempoolChainView
{
    Chainstate& m_chainstate;

public:
    explicit ChainstateMempoolView(Chainstate& chainstate) : m_chainstate{chainstate} {}

    CCoinsViewCache& CoinsTip() override EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    CChain& ActiveChain() override EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    script_verify_flags TipScriptFlags() override EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    script_verify_flags AllConsensusScriptFlags() const override;
    ValidationCache& GetValidationCache() override;
    bool IsCurrentForFeeEstimation() override EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    void CoinsCacheTrimmed() override EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
};

/**
 * Keeps a CTxMemPool consistent with the chainstate it is attached to.
 *
 * The pool is referenced through its owning pointer so that it can be replaced
 * (as tests do) without re-attaching the hooks to the chainstate.
 */
class ChainstateMempoolHooks final : public kernel::MempoolHooks
{
    const std::unique_ptr<CTxMemPool>& m_pool;
    DisconnectedBlockTransactions m_disconnectpool;

    CTxMemPool& Pool() const;

public:
    explicit ChainstateMempoolHooks(const std::unique_ptr<CTxMemPool>& pool);
    ~ChainstateMempoolHooks() override;

    RecursiveMutex& GetMutex() const override;
    size_t MaxSizeBytes() const override;
    size_t DynamicMemoryUsage() const override;
    bool IsEmpty() const override;
    void TipChanged() override;
    void BlockDisconnected(const std::vector<CTransactionRef>& vtx) override;
    void BlockConnected(Chainstate& chainstate, const std::shared_ptr<const CBlock>& block, const CBlockIndex& index) override;
    void ReorgFinished(Chainstate& chainstate, bool resurrect) override;
    void Check(Chainstate& chainstate) override;
};

} // namespace node

/**
 * Try to add a transaction to the mempool, validating it against the given chainstate.
 * This is an internal function and is exposed only for testing.
 * Client code should use ProcessTransaction().
 */
MempoolAcceptResult AcceptToMemoryPool(Chainstate& active_chainstate, CTxMemPool& pool, const CTransactionRef& tx,
                                       int64_t accept_time, bool bypass_limits, bool test_accept)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** Validate (and maybe submit) a package to the mempool against the given chainstate. */
PackageMempoolAcceptResult ProcessNewPackage(Chainstate& active_chainstate, CTxMemPool& pool,
                                             const Package& txns, bool test_accept, const std::optional<CFeeRate>& client_maxfeerate)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Try to add a transaction to the memory pool, validating it against the active chainstate.
 *
 * @param[in]  pool            The mempool. If null, the transaction is rejected with TX_NO_MEMPOOL.
 * @param[in]  tx              The transaction to submit for mempool acceptance.
 * @param[in]  test_accept     When true, run validation checks but don't submit to mempool.
 */
[[nodiscard]] MempoolAcceptResult ProcessTransaction(ChainstateManager& chainman, CTxMemPool* pool,
                                                     const CTransactionRef& tx, bool test_accept = false)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

#endif // BITCOIN_NODE_CHAINSTATE_MEMPOOL_H
