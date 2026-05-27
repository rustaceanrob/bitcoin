// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MEMPOOL_VALIDATION_H
#define BITCOIN_MEMPOOL_VALIDATION_H

#include <kernel/cs_main.h>
#include <kernel/mempool_entry.h>
#include <policy/feerate.h>
#include <policy/packages.h>
#include <primitives/transaction.h>
#include <txmempool.h>

#include <list>
#include <map>
#include <optional>
#include <vector>

class CBlockIndex;
class Chainstate;
class ChainstateManager;
class CCoinsView;
class CCoinsViewCache;
class DisconnectedBlockTransactions;

/**
 * Validation result for a transaction evaluated by MemPoolAccept (single or package).
 * Here are the expected fields and properties of a result depending on its ResultType, applicable to
 * results returned from package evaluation:
 *+---------------------------+----------------+-------------------+------------------+----------------+-------------------+
 *| Field or property         |    VALID       |                 INVALID              |  MEMPOOL_ENTRY | DIFFERENT_WITNESS |
 *|                           |                |--------------------------------------|                |                   |
 *|                           |                | TX_RECONSIDERABLE |     Other        |                |                   |
 *+---------------------------+----------------+-------------------+------------------+----------------+-------------------+
 *| txid in mempool?          | yes            | no                | no*              | yes            | yes               |
 *| wtxid in mempool?         | yes            | no                | no*              | yes            | no                |
 *| m_state                   | yes, IsValid() | yes, IsInvalid()  | yes, IsInvalid() | yes, IsValid() | yes, IsValid()    |
 *| m_vsize                   | yes            | no                | no               | yes            | no                |
 *| m_base_fees               | yes            | no                | no               | yes            | no                |
 *| m_effective_feerate       | yes            | yes               | no               | no             | no                |
 *| m_wtxids_fee_calculations | yes            | yes               | no               | no             | no                |
 *| m_other_wtxid             | no             | no                | no               | no             | yes               |
 *+---------------------------+----------------+-------------------+------------------+----------------+-------------------+
 * (*) Individual transaction acceptance doesn't return MEMPOOL_ENTRY and DIFFERENT_WITNESS. It returns
 * INVALID, with the errors txn-already-in-mempool and txn-same-nonwitness-data-in-mempool
 * respectively. In those cases, the txid or wtxid may be in the mempool for a TX_CONFLICT.
 */
struct MempoolAcceptResult {
    /** Used to indicate the results of mempool validation. */
    enum class ResultType {
        VALID,             //!> Fully validated, valid.
        INVALID,           //!> Invalid.
        MEMPOOL_ENTRY,     //!> Valid, transaction was already in the mempool.
        DIFFERENT_WITNESS, //!> Not validated. A same-txid-different-witness tx (see m_other_wtxid) already exists in the mempool and was not replaced.
    };
    /** Result type. Present in all MempoolAcceptResults. */
    const ResultType m_result_type;

    /** Contains information about why the transaction failed. */
    const TxValidationState m_state;

    /** Mempool transactions replaced by the tx. */
    const std::list<CTransactionRef> m_replaced_transactions;
    /** Virtual size as used by the mempool, calculated using serialized size and sigops. */
    const std::optional<int64_t> m_vsize;
    /** Raw base fees in satoshis. */
    const std::optional<CAmount> m_base_fees;
    /** The feerate at which this transaction was considered. This includes any fee delta added
     * using prioritisetransaction (i.e. modified fees). If this transaction was submitted as a
     * package, this is the package feerate, which may also include its descendants and/or
     * ancestors (see m_wtxids_fee_calculations below).
     */
    const std::optional<CFeeRate> m_effective_feerate;
    /** Contains the wtxids of the transactions used for fee-related checks. Includes this
     * transaction's wtxid and may include others if this transaction was validated as part of a
     * package. This is not necessarily equivalent to the list of transactions passed to
     * ProcessNewPackage().
     * Only present when m_result_type = ResultType::VALID. */
    const std::optional<std::vector<Wtxid>> m_wtxids_fee_calculations;

    /** The wtxid of the transaction in the mempool which has the same txid but different witness. */
    const std::optional<Wtxid> m_other_wtxid;

    static MempoolAcceptResult Failure(TxValidationState state)
    {
        return MempoolAcceptResult(state);
    }

    static MempoolAcceptResult FeeFailure(TxValidationState state,
                                          CFeeRate effective_feerate,
                                          const std::vector<Wtxid>& wtxids_fee_calculations)
    {
        return MempoolAcceptResult(state, effective_feerate, wtxids_fee_calculations);
    }

    static MempoolAcceptResult Success(std::list<CTransactionRef>&& replaced_txns,
                                       int64_t vsize,
                                       CAmount fees,
                                       CFeeRate effective_feerate,
                                       const std::vector<Wtxid>& wtxids_fee_calculations)
    {
        return MempoolAcceptResult(std::move(replaced_txns), vsize, fees,
                                   effective_feerate, wtxids_fee_calculations);
    }

    static MempoolAcceptResult MempoolTx(int64_t vsize, CAmount fees)
    {
        return MempoolAcceptResult(vsize, fees);
    }

    static MempoolAcceptResult MempoolTxDifferentWitness(const Wtxid& other_wtxid)
    {
        return MempoolAcceptResult(other_wtxid);
    }

    // Private constructors. Use static methods MempoolAcceptResult::Success, etc. to construct.
private:
    /** Constructor for failure case */
    explicit MempoolAcceptResult(TxValidationState state)
        : m_result_type(ResultType::INVALID), m_state(state)
    {
        Assume(!state.IsValid()); // Can be invalid or error
    }

    /** Constructor for success case */
    explicit MempoolAcceptResult(std::list<CTransactionRef>&& replaced_txns,
                                 int64_t vsize,
                                 CAmount fees,
                                 CFeeRate effective_feerate,
                                 const std::vector<Wtxid>& wtxids_fee_calculations)
        : m_result_type(ResultType::VALID),
          m_replaced_transactions(std::move(replaced_txns)),
          m_vsize{vsize},
          m_base_fees(fees),
          m_effective_feerate(effective_feerate),
          m_wtxids_fee_calculations(wtxids_fee_calculations) {}

    /** Constructor for fee-related failure case */
    explicit MempoolAcceptResult(TxValidationState state,
                                 CFeeRate effective_feerate,
                                 const std::vector<Wtxid>& wtxids_fee_calculations)
        : m_result_type(ResultType::INVALID),
          m_state(state),
          m_effective_feerate(effective_feerate),
          m_wtxids_fee_calculations(wtxids_fee_calculations) {}

    /** Constructor for already-in-mempool case. It wouldn't replace any transactions. */
    explicit MempoolAcceptResult(int64_t vsize, CAmount fees)
        : m_result_type(ResultType::MEMPOOL_ENTRY), m_vsize{vsize}, m_base_fees(fees) {}

    /** Constructor for witness-swapped case. */
    explicit MempoolAcceptResult(const Wtxid& other_wtxid)
        : m_result_type(ResultType::DIFFERENT_WITNESS), m_other_wtxid(other_wtxid) {}
};

/**
 * Validation result for package mempool acceptance.
 */
struct PackageMempoolAcceptResult {
    PackageValidationState m_state;
    /**
     * Map from wtxid to finished MempoolAcceptResults. The client is responsible
     * for keeping track of the transaction objects themselves. If a result is not
     * present, it means validation was unfinished for that transaction. If there
     * was a package-wide error (see result in m_state), m_tx_results will be empty.
     */
    std::map<Wtxid, MempoolAcceptResult> m_tx_results;

    explicit PackageMempoolAcceptResult(PackageValidationState state,
                                        std::map<Wtxid, MempoolAcceptResult>&& results)
        : m_state{state}, m_tx_results(std::move(results)) {}

    /** Constructor to create a PackageMempoolAcceptResult from a single MempoolAcceptResult */
    explicit PackageMempoolAcceptResult(const Wtxid& wtxid, const MempoolAcceptResult& result)
        : m_tx_results{{wtxid, result}} {}
};

/**
 * Process a transaction: validate and (optionally) submit it to the mempool.
 *
 * @param[in]  chainman     The chain manager.
 * @param[in]  tx           The transaction to validate.
 * @param[in]  test_accept  When true, run validation checks but don't submit to mempool.
 * @returns a MempoolAcceptResult indicating whether the transaction was accepted/rejected with reason.
 */
MempoolAcceptResult ProcessTransaction(ChainstateManager& chainman, const CTransactionRef& tx, bool test_accept = false)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Try to add a transaction to the mempool. This is an internal function and is exposed only for testing.
 * Client code should use ProcessTransaction()
 *
 * @param[in]  active_chainstate  Reference to the active chainstate.
 * @param[in]  tx                 The transaction to submit for mempool acceptance.
 * @param[in]  accept_time        The timestamp for adding the transaction to the mempool.
 *                                It is also used to determine when the entry expires.
 * @param[in]  bypass_limits      When true, don't enforce mempool fee and capacity limits,
 *                                and set entry_sequence to zero.
 * @param[in]  test_accept        When true, run validation checks but don't submit to mempool.
 *
 * @returns a MempoolAcceptResult indicating whether the transaction was accepted/rejected with reason.
 */
MempoolAcceptResult AcceptToMemoryPool(Chainstate& active_chainstate, const CTransactionRef& tx,
                                       int64_t accept_time, bool bypass_limits, bool test_accept)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Validate (and maybe submit) a package to the mempool. See doc/policy/packages.md for full details
 * on package validation rules.
 * @param[in]    test_accept         When true, run validation checks but don't submit to mempool.
 * @param[in]    client_maxfeerate    If exceeded by an individual transaction, rest of (sub)package evaluation is aborted.
 *                                   Only for sanity checks against local submission of transactions.
 * @returns a PackageMempoolAcceptResult which includes a MempoolAcceptResult for each transaction.
 * If a transaction fails, validation will exit early and some results may be missing. It is also
 * possible for the package to be partially submitted.
 */
PackageMempoolAcceptResult ProcessNewPackage(Chainstate& active_chainstate, CTxMemPool& pool,
                                             const Package& txns, bool test_accept, const std::optional<CFeeRate>& client_maxfeerate)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Expire old mempool transactions and trim to max size.
 */
void LimitMempoolSize(CTxMemPool& pool, CCoinsViewCache& coins_cache)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main, pool.cs);

/**
 * Calculate LockPoints required to check if transaction will be BIP68 final in the next block
 * to be created on top of tip.
 *
 * @param[in]   tip             Chain tip for which tx sequence locks are calculated. For
 *                              example, the tip of the current active chain.
 * @param[in]   coins_view      Any CCoinsView that provides access to the relevant coins for
 *                              checking sequence locks. For example, it can be a CCoinsViewCache
 *                              that isn't connected to anything but contains all the relevant
 *                              coins, or a CCoinsViewMemPool that is connected to the
 *                              mempool and chainstate UTXO set. In the latter case, the caller
 *                              is responsible for holding the appropriate locks to ensure that
 *                              calls to GetCoin() return correct coins.
 * @param[in]   tx              The transaction being evaluated.
 *
 * @returns The resulting height and time calculated and the hash of the block needed for
 *          calculation, or std::nullopt if there is an error.
 */
std::optional<LockPoints> CalculateLockPointsAtTip(
    CBlockIndex* tip,
    const CCoinsView& coins_view,
    const CTransaction& tx);

/**
 * Check if transaction will be BIP68 final in the next block to be created on top of tip.
 * @param[in]   tip             Chain tip to check tx sequence locks against. For example,
 *                              the tip of the current active chain.
 * @param[in]   lock_points     LockPoints containing the height and time at which this
 *                              transaction is final.
 * Simulates calling SequenceLocks() with data from the tip passed in.
 * The LockPoints should not be considered valid if CheckSequenceLocksAtTip returns false.
 */
bool CheckSequenceLocksAtTip(CBlockIndex* tip,
                             const LockPoints& lock_points);

/**
 * Re-add disconnected transactions to the mempool after a reorg.
 *
 * @param[in]  chainstate      The chainstate whose mempool to update.
 * @param[in]  mempool         The mempool to update.
 * @param[in]  disconnectpool  Transactions disconnected during reorg.
 * @param[in]  fAddToMempool   When true, attempt to re-add transactions to the mempool.
 */
void MaybeUpdateMempoolForReorg(
    Chainstate& chainstate,
    CTxMemPool& mempool,
    DisconnectedBlockTransactions& disconnectpool,
    bool fAddToMempool) EXCLUSIVE_LOCKS_REQUIRED(cs_main, mempool.cs);

#endif // BITCOIN_MEMPOOL_VALIDATION_H
