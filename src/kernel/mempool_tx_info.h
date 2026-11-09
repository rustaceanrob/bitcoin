// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_MEMPOOL_TX_INFO_H
#define BITCOIN_KERNEL_MEMPOOL_TX_INFO_H

#include <consensus/amount.h>
#include <primitives/transaction.h>

#include <cstdint>

class CTxMemPoolEntry;

struct TransactionInfo {
    const CTransactionRef m_tx;
    /* The fee the transaction paid */
    const CAmount m_fee;
    /**
     * The virtual transaction size.
     *
     * This is a policy field which considers the sigop cost of the
     * transaction as well as its weight, and reinterprets it as bytes.
     *
     * It is the primary metric by which the mining algorithm selects
     * transactions.
     */
    const int64_t m_virtual_transaction_size;
    /* The block height the transaction entered the mempool */
    const unsigned int txHeight;

    TransactionInfo(const CTransactionRef& tx, const CAmount& fee, const int64_t vsize, const unsigned int height)
        : m_tx{tx},
          m_fee{fee},
          m_virtual_transaction_size{vsize},
          txHeight{height} {}
};

struct RemovedMempoolTransactionInfo {
    TransactionInfo info;
    explicit RemovedMempoolTransactionInfo(const CTxMemPoolEntry& entry);
};

struct NewMempoolTransactionInfo {
    TransactionInfo info;
    /*
     * This boolean indicates whether the transaction was added
     * without enforcing mempool fee limits.
     */
    const bool m_mempool_limit_bypassed;
    /* This boolean indicates whether the transaction is part of a package. */
    const bool m_submitted_in_package;
    /*
     * This boolean indicates whether the blockchain is up to date when the
     * transaction is added to the mempool.
     */
    const bool m_chainstate_is_current;
    /* Indicates whether the transaction has unconfirmed parents. */
    const bool m_has_no_mempool_parents;

    explicit NewMempoolTransactionInfo(const CTransactionRef& tx, const CAmount& fee,
                                       const int64_t vsize, const unsigned int height,
                                       const bool mempool_limit_bypassed, const bool submitted_in_package,
                                       const bool chainstate_is_current,
                                       const bool has_no_mempool_parents)
        : info{tx, fee, vsize, height},
          m_mempool_limit_bypassed{mempool_limit_bypassed},
          m_submitted_in_package{submitted_in_package},
          m_chainstate_is_current{chainstate_is_current},
          m_has_no_mempool_parents{has_no_mempool_parents} {}
};

#endif // BITCOIN_KERNEL_MEMPOOL_TX_INFO_H
