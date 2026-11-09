// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/chainstate_mempool.h>

#include <chain.h>
#include <consensus/validation.h>
#include <kernel/mempool_entry.h>
#include <kernel/mempool_removal_reason.h>
#include <txmempool.h>
#include <util/check.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <chrono>
#include <utility>

/** Maximum age of our tip for us to be considered current for fee estimation */
static constexpr std::chrono::hours MAX_FEE_ESTIMATION_TIP_AGE{3};

namespace node {

CCoinsViewCache& ChainstateMempoolView::CoinsTip() { return m_chainstate.CoinsTip(); }

CChain& ChainstateMempoolView::ActiveChain() { return m_chainstate.m_chain; }

script_verify_flags ChainstateMempoolView::TipScriptFlags()
{
    return GetBlockScriptFlags(*Assert(m_chainstate.m_chain.Tip()), m_chainstate.m_chainman);
}

script_verify_flags ChainstateMempoolView::AllConsensusScriptFlags() const
{
    return m_chainstate.m_chainman.m_all_consensus_script_flags;
}

ValidationCache& ChainstateMempoolView::GetValidationCache() { return m_chainstate.m_chainman.m_validation_cache; }

bool ChainstateMempoolView::IsCurrentForFeeEstimation()
{
    AssertLockHeld(cs_main);
    const ChainstateManager& chainman{m_chainstate.m_chainman};
    if (chainman.IsInitialBlockDownload()) {
        return false;
    }
    if (m_chainstate.m_chain.Tip()->GetBlockTime() < count_seconds(GetTime<std::chrono::seconds>() - MAX_FEE_ESTIMATION_TIP_AGE))
        return false;
    if (m_chainstate.m_chain.Height() < chainman.m_best_header->nHeight - 1) {
        return false;
    }
    return true;
}

void ChainstateMempoolView::CoinsCacheTrimmed()
{
    // After we've (potentially) uncached entries, ensure our coins cache is still within its size limits
    BlockValidationState state_dummy;
    m_chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
}

ChainstateMempoolHooks::ChainstateMempoolHooks(const std::unique_ptr<CTxMemPool>& pool)
    : m_pool{pool}, m_disconnectpool{MAX_DISCONNECTED_TX_POOL_BYTES} {}

ChainstateMempoolHooks::~ChainstateMempoolHooks()
{
    m_disconnectpool.clear();
}

CTxMemPool& ChainstateMempoolHooks::Pool() const { return *Assert(m_pool); }

RecursiveMutex& ChainstateMempoolHooks::GetMutex() const { return Pool().cs; }

size_t ChainstateMempoolHooks::MaxSizeBytes() const { return Pool().m_opts.max_size_bytes; }

size_t ChainstateMempoolHooks::DynamicMemoryUsage() const { return Pool().DynamicMemoryUsage(); }

bool ChainstateMempoolHooks::IsEmpty() const { return Pool().size() == 0; }

void ChainstateMempoolHooks::TipChanged() { Pool().AddTransactionsUpdated(1); }

// The hooks are called with cs_main and the pool mutex held. Both are recursive,
// so they are taken again below to make that visible to the thread safety analysis.

void ChainstateMempoolHooks::BlockDisconnected(const std::vector<CTransactionRef>& vtx)
{
    CTxMemPool& pool{Pool()};
    LOCK(pool.cs);
    // If any entries are evicted for exceeding memory limits, remove them and their descendants from the mempool.
    for (auto&& evicted_tx : m_disconnectpool.AddTransactionsFromBlock(vtx)) {
        pool.removeRecursive(*evicted_tx, MemPoolRemovalReason::REORG);
    }
}

void ChainstateMempoolHooks::BlockConnected(Chainstate& chainstate, const std::shared_ptr<const CBlock>& block, const CBlockIndex& index)
{
    CTxMemPool& pool{Pool()};
    LOCK2(::cs_main, pool.cs);
    auto txs_removed_for_block{pool.removeForBlock(block->vtx)};
    m_disconnectpool.removeForBlock(block->vtx);
    // Not fired while IBD is active. removeForBlock() above still runs.
    if (pool.m_opts.signals && !chainstate.m_chainman.IsInitialBlockDownload()) {
        pool.m_opts.signals->MempoolTransactionsRemovedForBlock(block, std::move(txs_removed_for_block), index.nHeight);
    }
}

void ChainstateMempoolHooks::ReorgFinished(Chainstate& chainstate, bool resurrect)
{
    CTxMemPool& pool{Pool()};
    LOCK2(::cs_main, pool.cs);
    ChainstateMempoolView view{chainstate};
    UpdateMempoolForReorg(pool, view, m_disconnectpool, resurrect);
}

void ChainstateMempoolHooks::Check(Chainstate& chainstate)
{
    LOCK(::cs_main);
    Pool().check(chainstate.CoinsTip(), chainstate.m_chain.Height() + 1);
}

} // namespace node

MempoolAcceptResult AcceptToMemoryPool(Chainstate& active_chainstate, CTxMemPool& pool, const CTransactionRef& tx,
                                       int64_t accept_time, bool bypass_limits, bool test_accept)
{
    node::ChainstateMempoolView view{active_chainstate};
    return AcceptToMemoryPool(pool, view, tx, accept_time, bypass_limits, test_accept);
}

PackageMempoolAcceptResult ProcessNewPackage(Chainstate& active_chainstate, CTxMemPool& pool,
                                             const Package& txns, bool test_accept, const std::optional<CFeeRate>& client_maxfeerate)
{
    node::ChainstateMempoolView view{active_chainstate};
    return ProcessNewPackage(pool, view, txns, test_accept, client_maxfeerate);
}

MempoolAcceptResult ProcessTransaction(ChainstateManager& chainman, CTxMemPool* pool, const CTransactionRef& tx, bool test_accept)
{
    AssertLockHeld(cs_main);
    if (!pool) {
        TxValidationState state;
        state.Invalid(TxValidationResult::TX_NO_MEMPOOL, "no-mempool");
        return MempoolAcceptResult::Failure(state);
    }
    Chainstate& active_chainstate{chainman.ActiveChainstate()};
    auto result = AcceptToMemoryPool(active_chainstate, *pool, tx, GetTime(), /*bypass_limits=*/false, test_accept);
    pool->check(active_chainstate.CoinsTip(), active_chainstate.m_chain.Height() + 1);
    return result;
}
