// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validationinterface.h>

#include <kernel/mempool_removal_reason.h>
#include <kernel/mempool_tx_info.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <util/check.h>
#include <validationinterface_events.h>

#include <memory>
#include <utility>
#include <vector>

void ValidationSignals::TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t mempool_sequence)
{
    auto log_msg = LOG_MSG("%s: txid=%s wtxid=%s", __func__,
                          tx.info.m_tx->GetHash().ToString(),
                          tx.info.m_tx->GetWitnessHash().ToString());
    auto event = [tx, mempool_sequence, this] {
        ForEachSubscriber([&](CValidationInterface& callbacks) { callbacks.TransactionAddedToMempool(tx, mempool_sequence); });
    };
    ENQUEUE_AND_LOG_EVENT(std::move(event), std::move(log_msg));
}

void ValidationSignals::TransactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason, uint64_t mempool_sequence) {
    auto log_msg = LOG_MSG("%s: txid=%s wtxid=%s reason=%s", __func__,
                          tx->GetHash().ToString(),
                          tx->GetWitnessHash().ToString(),
                          RemovalReasonToString(reason));
    auto event = [tx, reason, mempool_sequence, this] {
        ForEachSubscriber([&](CValidationInterface& callbacks) { callbacks.TransactionRemovedFromMempool(tx, reason, mempool_sequence); });
    };
    ENQUEUE_AND_LOG_EVENT(std::move(event), std::move(log_msg));
}

void ValidationSignals::MempoolTransactionsRemovedForBlock(std::shared_ptr<const CBlock> block, std::vector<RemovedMempoolTransactionInfo> txs_removed_for_block, unsigned int block_height)
{
    Assume(block);
    auto log_msg = LOG_MSG("%s: block hash=%s block height=%s txs removed=%s block txs=%s", __func__,
                           block->GetHash().ToString(),
                           block_height,
                           txs_removed_for_block.size(),
                           block->vtx.size());
    auto event = [block = std::move(block), txs_removed_for_block = std::move(txs_removed_for_block), block_height, this] {
        ForEachSubscriber([&](CValidationInterface& callbacks) { callbacks.MempoolTransactionsRemovedForBlock(block, txs_removed_for_block, block_height); });
    };
    ENQUEUE_AND_LOG_EVENT(std::move(event), std::move(log_msg));
}
