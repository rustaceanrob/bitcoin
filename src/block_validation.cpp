// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <block_validation.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainstate.h>
#include <checkqueue.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <flatfile.h>
#include <hash.h>
#include <kernel/chainparams.h>
#include <kernel/notifications_interface.h>
#include <node/blockstorage.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/sigcache.h>
#include <signet.h>
#include <tinyformat.h>
#include <txdb.h>
#include <uint256.h>
#include <undo.h>
#include <util/check.h>
#include <util/log.h>
#include <util/moneystr.h>
#include <util/signalinterrupt.h>
#include <util/time.h>
#include <util/trace.h>
#include <util/translation.h>
#include <validationinterface.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <utility>

using kernel::Notifications;

using fsbridge::FopenFn;
using node::BlockMap;

TRACEPOINT_SEMAPHORE(validation, block_connected);

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  When FAILED is returned, view is left in an indeterminate state. */
DisconnectResult DisconnectBlock(Chainstate& chainstate, const CBlock& block, const CBlockIndex* pindex, CCoinsViewCache& view)
{
    AssertLockHeld(::cs_main);
    bool fClean = true;

    CBlockUndo blockUndo;
    if (!chainstate.m_blockman.ReadBlockUndo(blockUndo, *pindex)) {
        LogError("DisconnectBlock(): failure reading undo data\n");
        return DISCONNECT_FAILED;
    }

    if (blockUndo.vtxundo.size() + 1 != block.vtx.size()) {
        LogError("DisconnectBlock(): block and undo data inconsistent\n");
        return DISCONNECT_FAILED;
    }

    // Ignore blocks that contain transactions which are 'overwritten' by later transactions,
    // unless those are already completely spent.
    // See https://github.com/bitcoin/bitcoin/issues/22596 for additional information.
    // Note: the blocks specified here are different than the ones used in ConnectBlock because DisconnectBlock
    // unwinds the blocks in reverse. As a result, the inconsistency is not discovered until the earlier
    // blocks with the duplicate coinbase transactions are disconnected.
    bool fEnforceBIP30 = !((pindex->nHeight == 91722 && pindex->GetBlockHash() == uint256{"00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"}) ||
                           (pindex->nHeight == 91812 && pindex->GetBlockHash() == uint256{"00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"}));

    // undo transactions in reverse order
    for (int i = block.vtx.size() - 1; i >= 0; i--) {
        const CTransaction& tx = *(block.vtx[i]);
        Txid hash = tx.GetHash();
        bool is_coinbase = tx.IsCoinBase();
        bool is_bip30_exception = (is_coinbase && !fEnforceBIP30);

        // Check that all outputs are available and match the outputs in the block itself
        // exactly.
        for (size_t o = 0; o < tx.vout.size(); o++) {
            if (!tx.vout[o].scriptPubKey.IsUnspendable()) {
                COutPoint out(hash, o);
                Coin coin;
                bool is_spent = view.SpendCoin(out, &coin);
                if (!is_spent || tx.vout[o] != coin.out || pindex->nHeight != coin.nHeight || is_coinbase != coin.IsCoinBase()) {
                    if (!is_bip30_exception) {
                        fClean = false; // transaction output mismatch
                    }
                }
            }
        }

        // restore inputs
        if (i > 0) { // not coinbases
            CTxUndo& txundo = blockUndo.vtxundo[i - 1];
            if (txundo.vprevout.size() != tx.vin.size()) {
                LogError("DisconnectBlock(): transaction and undo data inconsistent\n");
                return DISCONNECT_FAILED;
            }
            for (unsigned int j = tx.vin.size(); j > 0;) {
                --j;
                const COutPoint& out = tx.vin[j].prevout;
                int res = ApplyTxInUndo(std::move(txundo.vprevout[j]), view, out);
                if (res == DISCONNECT_FAILED) return DISCONNECT_FAILED;
                fClean = fClean && res != DISCONNECT_UNCLEAN;
            }
            // At this point, all of txundo.vprevout should have been moved out.
        }
    }

    // move best block pointer to prevout block
    view.SetBestBlock(pindex->pprev->GetBlockHash());

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

script_verify_flags GetBlockScriptFlags(const CBlockIndex& block_index, const ChainstateManager& chainman)
{
    const Consensus::Params& consensusparams = chainman.GetConsensus();

    // BIP16 didn't become active until Apr 1 2012 (on mainnet, and
    // retroactively applied to testnet)
    // However, only one historical block violated the P2SH rules (on both
    // mainnet and testnet).
    // Similarly, only one historical block violated the TAPROOT rules on
    // mainnet.
    // For simplicity, always leave P2SH+WITNESS+TAPROOT on except for the two
    // violating blocks.
    script_verify_flags flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT};
    const auto it{consensusparams.script_flag_exceptions.find(*Assert(block_index.phashBlock))};
    if (it != consensusparams.script_flag_exceptions.end()) {
        flags = it->second;
    }

    // Enforce the DERSIG (BIP66) rule
    if (DeploymentActiveAt(block_index, chainman, Consensus::DEPLOYMENT_DERSIG)) {
        flags |= SCRIPT_VERIFY_DERSIG;
    }

    // Enforce CHECKLOCKTIMEVERIFY (BIP65)
    if (DeploymentActiveAt(block_index, chainman, Consensus::DEPLOYMENT_CLTV)) {
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    // Enforce CHECKSEQUENCEVERIFY (BIP112)
    if (DeploymentActiveAt(block_index, chainman, Consensus::DEPLOYMENT_CSV)) {
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    }

    // Enforce BIP147 NULLDUMMY (activated simultaneously with segwit)
    if (DeploymentActiveAt(block_index, chainman, Consensus::DEPLOYMENT_SEGWIT)) {
        flags |= SCRIPT_VERIFY_NULLDUMMY;
    }

    return flags;
}


/** Apply the effects of this block (with given index) on the UTXO set represented by coins.
 *  Validity checks that depend on the UTXO set are also done; ConnectBlock()
 *  can fail if those validity checks fail (among other reasons). */
bool ConnectBlock(Chainstate& chainstate, const CBlock& block, BlockValidationState& state, CBlockIndex* pindex,
                  CCoinsViewCache& view, bool fJustCheck)
{
    AssertLockHeld(cs_main);
    assert(pindex);

    uint256 block_hash{block.GetHash()};
    assert(*pindex->phashBlock == block_hash);

    const auto time_start{SteadyClock::now()};
    const CChainParams& params{chainstate.m_chainman.GetParams()};

    // Check it again in case a previous version let a bad block in
    // NOTE: We don't currently (re-)invoke ContextualCheckBlock() or
    // ContextualCheckBlockHeader() here. This means that if we add a new
    // consensus rule that is enforced in one of those two functions, then we
    // may have let in a block that violates the rule prior to updating the
    // software, and we would NOT be enforcing the rule here. Fully solving
    // upgrade from one software version to the next after a consensus rule
    // change is potentially tricky and issue-specific (see NeedsRedownload()
    // for one approach that was used for BIP 141 deployment).
    // Also, currently the rule against blocks more than 2 hours in the future
    // is enforced in ContextualCheckBlockHeader(); we wouldn't want to
    // re-enforce that rule here (at least until we make it impossible for
    // the clock to go backward).
    if (!CheckBlock(block, state, params.GetConsensus(), !fJustCheck, !fJustCheck)) {
        if (state.GetResult() == BlockValidationResult::BLOCK_MUTATED) {
            // We don't write down blocks to disk if they may have been
            // corrupted, so this should be impossible unless we're having hardware
            // problems.
            return FatalError(chainstate.m_chainman.GetNotifications(), state, _("Corrupt block found indicating potential hardware failure."));
        }
        LogError("%s: Consensus::CheckBlock: %s\n", __func__, state.ToString());
        return false;
    }

    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == nullptr ? uint256() : pindex->pprev->GetBlockHash();
    assert(hashPrevBlock == view.GetBestBlock());

    chainstate.m_chainman.NumBlocksTotal()++;

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    if (block_hash == params.GetConsensus().hashGenesisBlock) {
        if (!fJustCheck)
            view.SetBestBlock(pindex->GetBlockHash());
        return true;
    }

    const char* script_check_reason;
    if (chainstate.m_chainman.AssumedValidBlock().IsNull()) {
        script_check_reason = "assumevalid=0 (always verify)";
    } else {
        constexpr int64_t TWO_WEEKS_IN_SECONDS{60 * 60 * 24 * 7 * 2};
        // We've been configured with the hash of a block which has been externally verified to have a valid history.
        // A suitable default value is included with the software and updated from time to time.  Because validity
        //  relative to a piece of software is an objective fact these defaults can be easily reviewed.
        // This setting doesn't force the selection of any particular chain but makes validating some faster by
        //  effectively caching the result of part of the verification.
        BlockMap::const_iterator it{chainstate.m_blockman.m_block_index.find(chainstate.m_chainman.AssumedValidBlock())};
        if (it == chainstate.m_blockman.m_block_index.end()) {
            script_check_reason = "assumevalid hash not in headers";
        } else if (it->second.GetAncestor(pindex->nHeight) != pindex) {
            script_check_reason = (pindex->nHeight > it->second.nHeight) ? "block height above assumevalid height" : "block not in assumevalid chain";
        } else if (chainstate.m_chainman.m_best_header->GetAncestor(pindex->nHeight) != pindex) {
            script_check_reason = "block not in best header chain";
        } else if (chainstate.m_chainman.m_best_header->nChainWork < chainstate.m_chainman.MinimumChainWork()) {
            script_check_reason = "best header chainwork below minimumchainwork";
        } else if (GetBlockProofEquivalentTime(*chainstate.m_chainman.m_best_header, *pindex, *chainstate.m_chainman.m_best_header, params.GetConsensus()) <= TWO_WEEKS_IN_SECONDS) {
            script_check_reason = "block too recent relative to best header";
        } else {
            // This block is a member of the assumed verified chain and an ancestor of the best header.
            // Script verification is skipped when connecting blocks under the
            //  assumevalid block. Assuming the assumevalid block is valid this
            //  is safe because block merkle hashes are still computed and checked,
            // Of course, if an assumed valid block is invalid due to false scriptSigs
            //  this optimization would allow an invalid chain to be accepted.
            // The equivalent time check discourages hash power from extorting the network via DOS attack
            //  into accepting an invalid block through telling users they must manually set assumevalid.
            //  Requiring a software change or burying the invalid block, regardless of the setting, makes
            //  it hard to hide the implication of the demand. This also avoids having release candidates
            //  that are hardly doing any signature verification at all in testing without having to
            //  artificially set the default assumed verified block further back.
            // The test against the minimum chain work prevents the skipping when denied access to any chain at
            //  least as good as the expected chain.
            script_check_reason = nullptr;
        }
    }

    const auto time_1{SteadyClock::now()};
    chainstate.m_chainman.TimeCheck() += time_1 - time_start;
    LogDebug(BCLog::BENCH, "    - Sanity checks: %.2fms [%.2fs (%.2fms/blk)]\n",
             Ticks<MillisecondsDouble>(time_1 - time_start),
             Ticks<SecondsDouble>(chainstate.m_chainman.TimeCheck()),
             Ticks<MillisecondsDouble>(chainstate.m_chainman.TimeCheck()) / chainstate.m_chainman.NumBlocksTotal());

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30, CVE-2012-1909, and https://r6.ca/blog/20120206T005236Z.html for more information.
    // This rule was originally applied to all blocks with a timestamp after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes during their
    // initial block download.
    bool fEnforceBIP30 = !IsBIP30Repeat(*pindex);

    // Once BIP34 activated it was not possible to create new duplicate coinbases and thus other than starting
    // with the 2 existing duplicate coinbase pairs, not possible to create overwriting txs.  But by the
    // time BIP34 activated, in each of the existing pairs the duplicate coinbase had overwritten the first
    // before the first had been spent.  Since those coinbases are sufficiently buried it's no longer possible to create further
    // duplicate transactions descending from the known pairs either.
    // If we're on the known chain at height greater than where BIP34 activated, we can save the db accesses needed for the BIP30 check.

    // BIP34 requires that a block at height X (block X) has its coinbase
    // scriptSig start with a CScriptNum of X (indicated height X).  The above
    // logic of no longer requiring BIP30 once BIP34 activates is flawed in the
    // case that there is a block X before the BIP34 height of 227,931 which has
    // an indicated height Y where Y is greater than X.  The coinbase for block
    // X would also be a valid coinbase for block Y, which could be a BIP30
    // violation.  An exhaustive search of all mainnet coinbases before the
    // BIP34 height which have an indicated height greater than the block height
    // reveals many occurrences. The 3 lowest indicated heights found are
    // 209,921, 490,897, and 1,983,702 and thus coinbases for blocks at these 3
    // heights would be the first opportunity for BIP30 to be violated.

    // The search reveals a great many blocks which have an indicated height
    // greater than 1,983,702, so we simply remove the optimization to skip
    // BIP30 checking for blocks at height 1,983,702 or higher.  Before we reach
    // that block in another 25 years or so, we should take advantage of a
    // future consensus change to do a new and improved version of BIP34 that
    // will actually prevent ever creating any duplicate coinbases in the
    // future.
    static constexpr int BIP34_IMPLIES_BIP30_LIMIT = 1983702;

    // There is no potential to create a duplicate coinbase at block 209,921
    // because this is still before the BIP34 height and so explicit BIP30
    // checking is still active.

    // The final case is block 176,684 which has an indicated height of
    // 490,897. Unfortunately, this issue was not discovered until about 2 weeks
    // before block 490,897 so there was not much opportunity to address this
    // case other than to carefully analyze it and determine it would not be a
    // problem. Block 490,897 was, in fact, mined with a different coinbase than
    // block 176,684, but it is important to note that even if it hadn't been or
    // is remined on an alternate fork with a duplicate coinbase, we would still
    // not run into a BIP30 violation.  This is because the coinbase for 176,684
    // is spent in block 185,956 in transaction
    // d4f7fbbf92f4a3014a230b2dc70b8058d02eb36ac06b4a0736d9d60eaa9e8781.  This
    // spending transaction can't be duplicated because it also spends coinbase
    // 0328dd85c331237f18e781d692c92de57649529bd5edf1d01036daea32ffde29.  This
    // coinbase has an indicated height of over 4.2 billion, and wouldn't be
    // duplicatable until that height, and it's currently impossible to create a
    // chain that long. Nevertheless we may wish to consider a future soft fork
    // which retroactively prevents block 490,897 from creating a duplicate
    // coinbase. The two historical BIP30 violations often provide a confusing
    // edge case when manipulating the UTXO and it would be simpler not to have
    // another edge case to deal with.

    // testnet3 has no blocks before the BIP34 height with indicated heights
    // post BIP34 before approximately height 486,000,000. After block
    // 1,983,702 testnet3 starts doing unnecessary BIP30 checking again.
    assert(pindex->pprev);
    CBlockIndex* pindexBIP34height = pindex->pprev->GetAncestor(params.GetConsensus().BIP34Height);
    // Only continue to enforce if we're below BIP34 activation height or the block hash at that height doesn't correspond.
    fEnforceBIP30 = fEnforceBIP30 && (!pindexBIP34height || !(pindexBIP34height->GetBlockHash() == params.GetConsensus().BIP34Hash));

    // TODO: Remove BIP30 checking from block height 1,983,702 on, once we have a
    // consensus change that ensures coinbases at those heights cannot
    // duplicate earlier coinbases.
    if (fEnforceBIP30 || pindex->nHeight >= BIP34_IMPLIES_BIP30_LIMIT) {
        for (const auto& tx : block.vtx) {
            for (size_t o = 0; o < tx->vout.size(); o++) {
                if (view.HaveCoin(COutPoint(tx->GetHash(), o))) {
                    state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-BIP30",
                                  "tried to overwrite transaction");
                }
            }
        }
    }

    // Enforce BIP68 (sequence locks)
    int nLockTimeFlags = 0;
    if (DeploymentActiveAt(*pindex, chainstate.m_chainman, Consensus::DEPLOYMENT_CSV)) {
        nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE;
    }

    // Get the script flags for this block
    script_verify_flags flags{GetBlockScriptFlags(*pindex, chainstate.m_chainman)};

    const auto time_2{SteadyClock::now()};
    chainstate.m_chainman.TimeForks() += time_2 - time_1;
    LogDebug(BCLog::BENCH, "    - Fork checks: %.2fms [%.2fs (%.2fms/blk)]\n",
             Ticks<MillisecondsDouble>(time_2 - time_1),
             Ticks<SecondsDouble>(chainstate.m_chainman.TimeForks()),
             Ticks<MillisecondsDouble>(chainstate.m_chainman.TimeForks()) / chainstate.m_chainman.NumBlocksTotal());

    const bool fScriptChecks{!!script_check_reason};
    if (script_check_reason != chainstate.LastScriptCheckReasonLogged()) {
        if (fScriptChecks) {
            LogInfo("Enabling script verification at block #%d (%s): %s.",
                    pindex->nHeight, block_hash.ToString(), script_check_reason);
        } else {
            LogInfo("Disabling script verification at block #%d (%s).",
                    pindex->nHeight, block_hash.ToString());
        }
        chainstate.LastScriptCheckReasonLogged() = script_check_reason;
    }

    CBlockUndo blockundo;

    // Precomputed transaction data pointers must not be invalidated
    // until after `control` has run the script checks (potentially
    // in multiple threads). Preallocate the vector size so a new allocation
    // doesn't invalidate pointers into the vector, and keep txsdata in scope
    // for as long as `control`.
    std::vector<PrecomputedTransactionData> txsdata(block.vtx.size());
    std::optional<CCheckQueueControl<CScriptCheck>> control;
    if (auto& queue = chainstate.m_chainman.GetCheckQueue(); queue.HasThreads() && fScriptChecks) control.emplace(queue);

    std::vector<int> prevheights;
    CAmount nFees = 0;
    int nInputs = 0;
    int64_t nSigOpsCost = 0;
    blockundo.vtxundo.reserve(block.vtx.size() - 1);
    for (unsigned int i = 0; i < block.vtx.size(); i++) {
        if (!state.IsValid()) break;
        const CTransaction& tx = *(block.vtx[i]);

        nInputs += tx.vin.size();

        if (!tx.IsCoinBase()) {
            CAmount txfee = 0;
            TxValidationState tx_state;
            if (!Consensus::CheckTxInputs(tx, tx_state, view, pindex->nHeight, txfee)) {
                // Any transaction validation failure in ConnectBlock is a block consensus failure
                state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                              tx_state.GetRejectReason(),
                              tx_state.GetDebugMessage() + " in transaction " + tx.GetHash().ToString());
                break;
            }
            nFees += txfee;
            if (!MoneyRange(nFees)) {
                state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-accumulated-fee-outofrange",
                              "accumulated fee in the block out of range");
                break;
            }

            // Check that transaction is BIP68 final
            // BIP68 lock checks (as opposed to nLockTime checks) must
            // be in ConnectBlock because they require the UTXO set
            prevheights.resize(tx.vin.size());
            for (size_t j = 0; j < tx.vin.size(); j++) {
                prevheights[j] = view.AccessCoin(tx.vin[j].prevout).nHeight;
            }

            if (!SequenceLocks(tx, nLockTimeFlags, prevheights, *pindex)) {
                state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-nonfinal",
                              "contains a non-BIP68-final transaction " + tx.GetHash().ToString());
                break;
            }
        }

        // GetTransactionSigOpCost counts 3 types of sigops:
        // * legacy (always)
        // * p2sh (when P2SH enabled in flags and excludes coinbase)
        // * witness (when witness enabled in flags and excludes coinbase)
        nSigOpsCost += GetTransactionSigOpCost(tx, view, flags);
        if (nSigOpsCost > MAX_BLOCK_SIGOPS_COST) {
            state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-sigops", "too many sigops");
            break;
        }

        if (!tx.IsCoinBase() && fScriptChecks) {
            bool fCacheResults = fJustCheck; /* Don't cache results if we're actually connecting blocks (still consult the cache, though) */
            bool tx_ok;
            TxValidationState tx_state;
            // If CheckInputScripts is called with a pointer to a checks vector, the resulting checks are appended to it. In that case
            // they need to be added to control which runs them asynchronously. Otherwise, CheckInputScripts runs the checks before returning.
            if (control) {
                std::vector<CScriptCheck> vChecks;
                tx_ok = CheckInputScripts(tx, tx_state, view, flags, fCacheResults, fCacheResults, txsdata[i], chainstate.m_chainman.m_validation_cache, &vChecks);
                if (tx_ok) control->Add(std::move(vChecks));
            } else {
                tx_ok = CheckInputScripts(tx, tx_state, view, flags, fCacheResults, fCacheResults, txsdata[i], chainstate.m_chainman.m_validation_cache);
            }
            if (!tx_ok) {
                // Any transaction validation failure in ConnectBlock is a block consensus failure
                state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                              tx_state.GetRejectReason(), tx_state.GetDebugMessage());
                break;
            }
        }

        CTxUndo undoDummy;
        if (i > 0) {
            blockundo.vtxundo.emplace_back();
        }
        UpdateCoins(tx, view, i == 0 ? undoDummy : blockundo.vtxundo.back(), pindex->nHeight);
    }
    const auto time_3{SteadyClock::now()};
    chainstate.m_chainman.TimeConnect() += time_3 - time_2;
    LogDebug(BCLog::BENCH, "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs (%.2fms/blk)]\n", (unsigned)block.vtx.size(),
             Ticks<MillisecondsDouble>(time_3 - time_2), Ticks<MillisecondsDouble>(time_3 - time_2) / block.vtx.size(),
             nInputs <= 1 ? 0 : Ticks<MillisecondsDouble>(time_3 - time_2) / (nInputs - 1),
             Ticks<SecondsDouble>(chainstate.m_chainman.TimeConnect()),
             Ticks<MillisecondsDouble>(chainstate.m_chainman.TimeConnect()) / chainstate.m_chainman.NumBlocksTotal());

    CAmount blockReward = nFees + GetBlockSubsidy(pindex->nHeight, params.GetConsensus());
    if (block.vtx[0]->GetValueOut() > blockReward && state.IsValid()) {
        state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-amount",
                      strprintf("coinbase pays too much (actual=%d vs limit=%d)", block.vtx[0]->GetValueOut(), blockReward));
    }
    if (control) {
        auto parallel_result = control->Complete();
        if (parallel_result.has_value() && state.IsValid()) {
            state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, strprintf("block-script-verify-flag-failed (%s)", ScriptErrorString(parallel_result->first)), parallel_result->second);
        }
    }
    if (!state.IsValid()) {
        LogInfo("Block validation error: %s", state.ToString());
        return false;
    }
    const auto time_4{SteadyClock::now()};
    chainstate.m_chainman.TimeVerify() += time_4 - time_2;
    LogDebug(BCLog::BENCH, "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs (%.2fms/blk)]\n", nInputs - 1,
             Ticks<MillisecondsDouble>(time_4 - time_2),
             nInputs <= 1 ? 0 : Ticks<MillisecondsDouble>(time_4 - time_2) / (nInputs - 1),
             Ticks<SecondsDouble>(chainstate.m_chainman.TimeVerify()),
             Ticks<MillisecondsDouble>(chainstate.m_chainman.TimeVerify()) / chainstate.m_chainman.NumBlocksTotal());

    if (fJustCheck) {
        return true;
    }

    if (!chainstate.m_blockman.WriteBlockUndo(blockundo, state, *pindex)) {
        return false;
    }

    const auto time_5{SteadyClock::now()};
    chainstate.m_chainman.TimeUndo() += time_5 - time_4;
    LogDebug(BCLog::BENCH, "    - Write undo data: %.2fms [%.2fs (%.2fms/blk)]\n",
             Ticks<MillisecondsDouble>(time_5 - time_4),
             Ticks<SecondsDouble>(chainstate.m_chainman.TimeUndo()),
             Ticks<MillisecondsDouble>(chainstate.m_chainman.TimeUndo()) / chainstate.m_chainman.NumBlocksTotal());

    if (!pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
        pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
        chainstate.m_blockman.DirtyBlockIndex().insert(pindex);
    }

    // add this block to the view's block chain
    view.SetBestBlock(pindex->GetBlockHash());

    const auto time_6{SteadyClock::now()};
    chainstate.m_chainman.TimeIndex() += time_6 - time_5;
    LogDebug(BCLog::BENCH, "    - Index writing: %.2fms [%.2fs (%.2fms/blk)]\n",
             Ticks<MillisecondsDouble>(time_6 - time_5),
             Ticks<SecondsDouble>(chainstate.m_chainman.TimeIndex()),
             Ticks<MillisecondsDouble>(chainstate.m_chainman.TimeIndex()) / chainstate.m_chainman.NumBlocksTotal());

    TRACEPOINT(validation, block_connected,
               block_hash.data(),
               pindex->nHeight,
               block.vtx.size(),
               nInputs,
               nSigOpsCost,
               Ticks<std::chrono::nanoseconds>(time_5 - time_start));

    return true;
}

static bool CheckBlockHeader(const CBlockHeader& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true)
{
    // Check proof of work matches claimed amount
    if (fCheckPOW && !CheckProofOfWork(block.GetHash(), block.nBits, consensusParams))
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "high-hash", "proof of work failed");

    return true;
}

static bool CheckMerkleRoot(const CBlock& block, BlockValidationState& state)
{
    if (block.m_checked_merkle_root) return true;

    bool mutated;
    uint256 merkle_root = BlockMerkleRoot(block, &mutated);
    if (block.hashMerkleRoot != merkle_root) {
        return state.Invalid(
            /*result=*/BlockValidationResult::BLOCK_MUTATED,
            /*reject_reason=*/"bad-txnmrklroot",
            /*debug_message=*/"hashMerkleRoot mismatch");
    }

    // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
    // of transactions in a block without affecting the merkle root of a block,
    // while still invalidating it.
    if (mutated) {
        return state.Invalid(
            /*result=*/BlockValidationResult::BLOCK_MUTATED,
            /*reject_reason=*/"bad-txns-duplicate",
            /*debug_message=*/"duplicate transaction");
    }

    block.m_checked_merkle_root = true;
    return true;
}

/** CheckWitnessMalleation performs checks for block malleation with regard to
 * its witnesses.
 *
 * Note: If the witness commitment is expected (i.e. `expect_witness_commitment
 * = true`), then the block is required to have at least one transaction and the
 * first transaction needs to have at least one input. */
static bool CheckWitnessMalleation(const CBlock& block, bool expect_witness_commitment, BlockValidationState& state)
{
    if (expect_witness_commitment) {
        if (block.m_checked_witness_commitment) return true;

        int commitpos = GetWitnessCommitmentIndex(block);
        if (commitpos != NO_WITNESS_COMMITMENT) {
            assert(!block.vtx.empty() && !block.vtx[0]->vin.empty());
            const auto& witness_stack{block.vtx[0]->vin[0].scriptWitness.stack};

            if (witness_stack.size() != 1 || witness_stack[0].size() != 32) {
                return state.Invalid(
                    /*result=*/BlockValidationResult::BLOCK_MUTATED,
                    /*reject_reason=*/"bad-witness-nonce-size",
                    /*debug_message=*/strprintf("%s : invalid witness reserved value size", __func__));
            }

            // The malleation check is ignored; as the transaction tree itself
            // already does not permit it, it is impossible to trigger in the
            // witness tree.
            uint256 hash_witness = BlockWitnessMerkleRoot(block);

            CHash256().Write(hash_witness).Write(witness_stack[0]).Finalize(hash_witness);
            if (memcmp(hash_witness.begin(), &block.vtx[0]->vout[commitpos].scriptPubKey[6], 32)) {
                return state.Invalid(
                    /*result=*/BlockValidationResult::BLOCK_MUTATED,
                    /*reject_reason=*/"bad-witness-merkle-match",
                    /*debug_message=*/strprintf("%s : witness merkle commitment mismatch", __func__));
            }

            block.m_checked_witness_commitment = true;
            return true;
        }
    }

    // No witness data is allowed in blocks that don't commit to witness data, as this would otherwise leave room for spam
    for (const auto& tx : block.vtx) {
        if (tx->HasWitness()) {
            return state.Invalid(
                /*result=*/BlockValidationResult::BLOCK_MUTATED,
                /*reject_reason=*/"unexpected-witness",
                /*debug_message=*/strprintf("%s : unexpected witness data found", __func__));
        }
    }

    return true;
}

bool CheckBlock(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW, bool fCheckMerkleRoot)
{
    // These are checks that are independent of context.

    if (block.fChecked)
        return true;

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, consensusParams, fCheckPOW))
        return false;

    // Signet only: check block solution
    if (consensusParams.signet_blocks && fCheckPOW && !CheckSignetBlockSolution(block, consensusParams)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-signet-blksig", "signet block signature validation failure");
    }

    // Check the merkle root.
    if (fCheckMerkleRoot && !CheckMerkleRoot(block, state)) {
        return false;
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.
    // Note that witness malleability is checked in ContextualCheckBlock, so no
    // checks that use witness data may be performed here.

    // Size limits
    if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || ::GetSerializeSize(TX_NO_WITNESS(block)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-length", "size limits failed");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-missing", "first tx is not coinbase");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinBase())
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-multiple", "more than one coinbase");

    // Check transactions
    // Must check for duplicate inputs (see CVE-2018-17144)
    for (const auto& tx : block.vtx) {
        TxValidationState tx_state;
        if (!CheckTransaction(*tx, tx_state)) {
            // CheckBlock() does context-free validation checks. The only
            // possible failures are consensus failures.
            assert(tx_state.GetResult() == TxValidationResult::TX_CONSENSUS);
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, tx_state.GetRejectReason(),
                                 strprintf("Transaction check failed (tx hash %s) %s", tx->GetHash().ToString(), tx_state.GetDebugMessage()));
        }
    }
    // This underestimates the number of sigops, because unlike ConnectBlock it
    // does not count witness and p2sh sigops.
    unsigned int nSigOps = 0;
    for (const auto& tx : block.vtx) {
        nSigOps += GetLegacySigOpCount(*tx);
    }
    if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST)
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-sigops", "out-of-bounds SigOpCount");

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;

    return true;
}

void UpdateUncommittedBlockStructures(const ChainstateManager& chainman, CBlock& block, const CBlockIndex* pindexPrev)
{
    int commitpos = GetWitnessCommitmentIndex(block);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != NO_WITNESS_COMMITMENT && DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_SEGWIT) && !block.vtx[0]->HasWitness()) {
        CMutableTransaction tx(*block.vtx[0]);
        tx.vin[0].scriptWitness.stack.resize(1);
        tx.vin[0].scriptWitness.stack[0] = nonce;
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
}

CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams)
{
    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
    // Force block reward to zero when right shift is undefined.
    if (halvings >= 64)
        return 0;

    CAmount nSubsidy = 50 * COIN;
    // Subsidy is cut in half every 210,000 blocks which will occur approximately every 4 years.
    nSubsidy >>= halvings;
    return nSubsidy;
}

bool HasValidProofOfWork(std::span<const CBlockHeader> headers, const Consensus::Params& consensusParams)
{
    return std::ranges::all_of(headers,
                               [&](const auto& header) { return CheckProofOfWork(header.GetHash(), header.nBits, consensusParams); });
}

void GenerateCoinbaseCommitment(const ChainstateManager& chainman, CBlock& block, const CBlockIndex* pindexPrev)
{
    int commitpos = GetWitnessCommitmentIndex(block);
    std::vector<unsigned char> ret(32, 0x00);
    if (commitpos == NO_WITNESS_COMMITMENT) {
        uint256 witnessroot = BlockWitnessMerkleRoot(block);
        CHash256().Write(witnessroot).Write(ret).Finalize(witnessroot);
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey.resize(MINIMUM_WITNESS_COMMITMENT);
        out.scriptPubKey[0] = OP_RETURN;
        out.scriptPubKey[1] = 0x24;
        out.scriptPubKey[2] = 0xaa;
        out.scriptPubKey[3] = 0x21;
        out.scriptPubKey[4] = 0xa9;
        out.scriptPubKey[5] = 0xed;
        memcpy(&out.scriptPubKey[6], witnessroot.begin(), 32);
        CMutableTransaction tx(*block.vtx[0]);
        tx.vout.push_back(out);
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
    UpdateUncommittedBlockStructures(chainman, block, pindexPrev);
}

bool IsBlockMutated(const CBlock& block, bool check_witness_root)
{
    BlockValidationState state;
    if (!CheckMerkleRoot(block, state)) {
        LogDebug(BCLog::VALIDATION, "Block mutated: %s\n", state.ToString());
        return true;
    }

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        // Consider the block mutated if any transaction is 64 bytes in size (see 3.1
        // in "Weaknesses in Bitcoin's Merkle Root Construction":
        // https://lists.linuxfoundation.org/pipermail/bitcoin-dev/attachments/20190225/a27d8837/attachment-0001.pdf).
        //
        // Note: This is not a consensus change as this only applies to blocks that
        // don't have a coinbase transaction and would therefore already be invalid.
        return std::any_of(block.vtx.begin(), block.vtx.end(),
                           [](auto& tx) { return GetSerializeSize(TX_NO_WITNESS(tx)) == 64; });
    } else {
        // Theoretically it is still possible for a block with a 64 byte
        // coinbase transaction to be mutated but we neglect that possibility
        // here as it requires at least 224 bits of work.
    }

    if (!CheckWitnessMalleation(block, check_witness_root, state)) {
        LogDebug(BCLog::VALIDATION, "Block mutated: %s\n", state.ToString());
        return true;
    }

    return false;
}

arith_uint256 CalculateClaimedHeadersWork(std::span<const CBlockHeader> headers)
{
    arith_uint256 total_work{0};
    for (const CBlockHeader& header : headers) {
        total_work += GetBlockProof(header);
    }
    return total_work;
}

/** Context-dependent validity checks.
 *  By "context", we mean only the previous block headers, but not the UTXO
 *  set; UTXO-related validity checks are done in ConnectBlock().
 *  NOTE: This function is not currently invoked by ConnectBlock(), so we
 *  should consider upgrade issues if we change which consensus rules are
 *  enforced in this function (eg by adding a new consensus rule). See comment
 *  in ConnectBlock().
 *  Note that -reindex-chainstate skips the validation that happens here!
 *
 *  NOTE: failing to check the header's height against the last checkpoint's opened a DoS vector between
 *  v0.12 and v0.15 (when no additional protection was in place) whereby an attacker could unboundedly
 *  grow our in-memory block index. See https://bitcoincore.org/en/2024/07/03/disclose-header-spam.
 */
static bool ContextualCheckBlockHeader(const CBlockHeader& block, BlockValidationState& state, const ChainstateManager& chainman, const CBlockIndex* pindexPrev) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);
    assert(pindexPrev != nullptr);
    const int nHeight = pindexPrev->nHeight + 1;

    // Check proof of work
    const Consensus::Params& consensusParams = chainman.GetConsensus();
    if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "bad-diffbits", "incorrect proof of work");

    // Check timestamp against prev
    if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "time-too-old", "block's timestamp is too early");

    // Testnet4 and regtest only: Check timestamp against prev for difficulty-adjustment
    // blocks to prevent timewarp attacks (see https://github.com/bitcoin/bitcoin/pull/15482).
    if (consensusParams.enforce_BIP94) {
        // Check timestamp for the first block of each difficulty adjustment
        // interval, except the genesis block.
        if (nHeight % consensusParams.DifficultyAdjustmentInterval() == 0) {
            if (block.GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP) {
                return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, "time-timewarp-attack", "block's timestamp is too early on diff adjustment block");
            }
        }
    }

    // Check timestamp
    if (block.Time() > NodeClock::now() + std::chrono::seconds{MAX_FUTURE_BLOCK_TIME}) {
        return state.Invalid(BlockValidationResult::BLOCK_TIME_FUTURE, "time-too-new", "block timestamp too far in the future");
    }

    // Reject blocks with outdated version
    if ((block.nVersion < 2 && DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_HEIGHTINCB)) ||
        (block.nVersion < 3 && DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_DERSIG)) ||
        (block.nVersion < 4 && DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_CLTV))) {
        return state.Invalid(BlockValidationResult::BLOCK_INVALID_HEADER, strprintf("bad-version(0x%08x)", block.nVersion),
                             strprintf("rejected nVersion=0x%08x block", block.nVersion));
    }

    return true;
}

/** NOTE: This function is not currently invoked by ConnectBlock(), so we
 *  should consider upgrade issues if we change which consensus rules are
 *  enforced in this function (eg by adding a new consensus rule). See comment
 *  in ConnectBlock().
 *  Note that -reindex-chainstate skips the validation that happens here!
 */
static bool ContextualCheckBlock(const CBlock& block, BlockValidationState& state, const ChainstateManager& chainman, const CBlockIndex* pindexPrev)
{
    const int nHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;

    // Enforce BIP113 (Median Time Past).
    bool enforce_locktime_median_time_past{false};
    if (DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_CSV)) {
        assert(pindexPrev != nullptr);
        enforce_locktime_median_time_past = true;
    }

    const int64_t nLockTimeCutoff{enforce_locktime_median_time_past ?
                                      pindexPrev->GetMedianTimePast() :
                                      block.GetBlockTime()};

    // Check that all transactions are finalized
    for (const auto& tx : block.vtx) {
        if (!IsFinalTx(*tx, nHeight, nLockTimeCutoff)) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-txns-nonfinal", "non-final transaction");
        }
    }

    // Enforce rule that the coinbase starts with serialized block height
    if (DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_HEIGHTINCB)) {
        CScript expect = CScript() << nHeight;
        if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin())) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cb-height", "block height mismatch in coinbase");
        }
    }

    // Validation for witness commitments.
    // * We compute the witness hash (which is the hash including witnesses) of all the block's transactions, except the
    //   coinbase (where 0x0000....0000 is used instead).
    // * The coinbase scriptWitness is a stack of a single 32-byte vector, containing a witness reserved value (unconstrained).
    // * We build a merkle tree with all those witness hashes as leaves (similar to the hashMerkleRoot in the block header).
    // * There must be at least one output whose scriptPubKey is a single 36-byte push, the first 4 bytes of which are
    //   {0xaa, 0x21, 0xa9, 0xed}, and the following 32 bytes are SHA256^2(witness root, witness reserved value). In case there are
    //   multiple, the last one is used.
    if (!CheckWitnessMalleation(block, DeploymentActiveAfter(pindexPrev, chainman, Consensus::DEPLOYMENT_SEGWIT), state)) {
        return false;
    }

    // After the coinbase witness reserved value and commitment are verified,
    // we can check if the block weight passes (before we've checked the
    // coinbase witness, it would be possible for the weight to be too
    // large by filling up the coinbase witness, which doesn't change
    // the block hash, so we couldn't mark the block as permanently
    // failed).
    if (GetBlockWeight(block) > MAX_BLOCK_WEIGHT) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-blk-weight", strprintf("%s : weight limit failed", __func__));
    }

    return true;
}

static bool AcceptBlockHeader(ChainstateManager& chainman, const CBlockHeader& block, BlockValidationState& state, CBlockIndex** ppindex, bool min_pow_checked) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);

    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator miSelf{chainman.m_blockman.m_block_index.find(hash)};
    if (hash != chainman.GetConsensus().hashGenesisBlock) {
        if (miSelf != chainman.m_blockman.m_block_index.end()) {
            // Block header is already known.
            CBlockIndex* pindex = &(miSelf->second);
            if (ppindex)
                *ppindex = pindex;
            if (pindex->nStatus & BLOCK_FAILED_VALID) {
                LogDebug(BCLog::VALIDATION, "%s: block %s is marked invalid\n", __func__, hash.ToString());
                return state.Invalid(BlockValidationResult::BLOCK_CACHED_INVALID, "duplicate-invalid",
                                     strprintf("block %s was previously marked invalid", hash.ToString()));
            }
            return true;
        }

        if (!CheckBlockHeader(block, state, chainman.GetConsensus())) {
            LogDebug(BCLog::VALIDATION, "%s: Consensus::CheckBlockHeader: %s, %s\n", __func__, hash.ToString(), state.ToString());
            return false;
        }

        // Get prev block index
        CBlockIndex* pindexPrev = nullptr;
        BlockMap::iterator mi{chainman.m_blockman.m_block_index.find(block.hashPrevBlock)};
        if (mi == chainman.m_blockman.m_block_index.end()) {
            LogDebug(BCLog::VALIDATION, "header %s has prev block not found: %s\n", hash.ToString(), block.hashPrevBlock.ToString());
            return state.Invalid(BlockValidationResult::BLOCK_MISSING_PREV, "prev-blk-not-found");
        }
        pindexPrev = &((*mi).second);
        if (pindexPrev->nStatus & BLOCK_FAILED_VALID) {
            LogDebug(BCLog::VALIDATION, "header %s has prev block invalid: %s\n", hash.ToString(), block.hashPrevBlock.ToString());
            return state.Invalid(BlockValidationResult::BLOCK_INVALID_PREV, "bad-prevblk");
        }
        if (!ContextualCheckBlockHeader(block, state, chainman, pindexPrev)) {
            LogDebug(BCLog::VALIDATION, "%s: Consensus::ContextualCheckBlockHeader: %s, %s\n", __func__, hash.ToString(), state.ToString());
            return false;
        }
    }
    if (!min_pow_checked) {
        LogDebug(BCLog::VALIDATION, "%s: not adding new block header %s, missing anti-dos proof-of-work validation\n", __func__, hash.ToString());
        return state.Invalid(BlockValidationResult::BLOCK_HEADER_LOW_WORK, "too-little-chainwork");
    }
    CBlockIndex* pindex{chainman.m_blockman.AddToBlockIndex(block, chainman.m_best_header)};

    if (ppindex)
        *ppindex = pindex;

    return true;
}

// Exposed wrapper for AcceptBlockHeader
bool ProcessNewBlockHeaders(ChainstateManager& chainman, std::span<const CBlockHeader> headers, bool min_pow_checked, BlockValidationState& state, const CBlockIndex** ppindex)
{
    AssertLockNotHeld(cs_main);
    {
        LOCK(cs_main);
        for (const CBlockHeader& header : headers) {
            CBlockIndex* pindex = nullptr; // Use a temp pindex instead of ppindex to avoid a const_cast
            bool accepted{AcceptBlockHeader(chainman, header, state, &pindex, min_pow_checked)};
            chainman.CheckBlockIndex();

            if (!accepted) {
                return false;
            }
            if (ppindex) {
                *ppindex = pindex;
            }
        }
    }
    if (chainman.NotifyHeaderTip()) {
        if (chainman.IsInitialBlockDownload() && ppindex && *ppindex) {
            const CBlockIndex& last_accepted{**ppindex};
            int64_t blocks_left{(NodeClock::now() - last_accepted.Time()) / chainman.GetConsensus().PowTargetSpacing()};
            blocks_left = std::max<int64_t>(0, blocks_left);
            const double progress{100.0 * last_accepted.nHeight / (last_accepted.nHeight + blocks_left)};
            LogInfo("Synchronizing blockheaders, height: %d (~%.2f%%)\n", last_accepted.nHeight, progress);
        }
    }
    return true;
}


/** Store block on disk. If dbp is non-nullptr, the file is known to already reside on disk */
bool AcceptBlock(ChainstateManager& chainman, const std::shared_ptr<const CBlock>& pblock, BlockValidationState& state, CBlockIndex** ppindex, bool fRequested, const FlatFilePos* dbp, bool* fNewBlock, bool min_pow_checked)
{
    const CBlock& block = *pblock;

    if (fNewBlock) *fNewBlock = false;
    AssertLockHeld(cs_main);

    CBlockIndex* pindexDummy = nullptr;
    CBlockIndex*& pindex = ppindex ? *ppindex : pindexDummy;

    bool accepted_header{AcceptBlockHeader(chainman, block, state, &pindex, min_pow_checked)};
    chainman.CheckBlockIndex();

    if (!accepted_header)
        return false;

    // Check all requested blocks that we do not already have for validity and
    // save them to disk. Skip processing of unrequested blocks as an anti-DoS
    // measure, unless the blocks have more work than the active chain tip, and
    // aren't too far ahead of it, so are likely to be attached soon.
    bool fAlreadyHave = pindex->nStatus & BLOCK_HAVE_DATA;
    bool fHasMoreOrSameWork = (chainman.ActiveTip() ? pindex->nChainWork >= chainman.ActiveTip()->nChainWork : true);
    // Blocks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete block files that contain any
    // blocks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested blocks.
    bool fTooFarAhead{pindex->nHeight > chainman.ActiveHeight() + int(MIN_BLOCKS_TO_KEEP)};

    // TODO: Decouple this function from the block download logic by removing fRequested
    // This requires some new chain data structure to efficiently look up if a
    // block is in a chain leading to a candidate for best tip, despite not
    // being such a candidate itself.
    // Note that this would break the getblockfrompeer RPC

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave) return true;
    if (!fRequested) {                        // If we didn't ask for it:
        if (pindex->nTx != 0) return true;    // This is a previously-processed block that was pruned
        if (!fHasMoreOrSameWork) return true; // Don't process less-work chains
        if (fTooFarAhead) return true;        // Block height is too high

        // Protect against DoS attacks from low-work chains.
        // If our tip is behind, a peer could try to send us
        // low-work blocks on a fake chain that we would never
        // request; don't process these.
        if (pindex->nChainWork < chainman.MinimumChainWork()) return true;
    }

    const CChainParams& params{chainman.GetParams()};

    if (!CheckBlock(block, state, params.GetConsensus()) ||
        !ContextualCheckBlock(block, state, chainman, pindex->pprev)) {
        if (Assume(state.IsInvalid())) {
            chainman.ActiveChainstate().InvalidBlockFound(pindex, state);
        }
        LogError("%s: %s\n", __func__, state.ToString());
        return false;
    }

    // Header is valid/has work, merkle tree and segwit merkle tree are good...RELAY NOW
    // (but if it does not build on our best tip, let the SendMessages loop relay it)
    if (!chainman.IsInitialBlockDownload() && chainman.ActiveTip() == pindex->pprev && chainman.m_options.signals) {
        chainman.m_options.signals->NewPoWValidBlock(pindex, pblock);
    }

    // Write block to history file
    if (fNewBlock) *fNewBlock = true;
    try {
        FlatFilePos blockPos{};
        if (dbp) {
            blockPos = *dbp;
            chainman.m_blockman.UpdateBlockInfo(block, pindex->nHeight, blockPos);
        } else {
            blockPos = chainman.m_blockman.WriteBlock(block, pindex->nHeight);
            if (blockPos.IsNull()) {
                state.Error(strprintf("%s: Failed to find position to write new block to disk", __func__));
                return false;
            }
        }
        chainman.ReceivedBlockTransactions(block, pindex, blockPos);
    } catch (const std::runtime_error& e) {
        return FatalError(chainman.GetNotifications(), state, strprintf(_("System error while saving block to disk: %s"), e.what()));
    }

    // TODO: FlushStateToDisk() handles flushing of both block and chainstate
    // data, so we should move this to ChainstateManager so that we can be more
    // intelligent about how we flush.
    // For now, since FlushStateMode::NONE is used, all that can happen is that
    // the block files may be pruned, so we can just call this on one
    // chainstate (particularly if we haven't implemented pruning with
    // background validation yet).
    chainman.ActiveChainstate().FlushStateToDisk(state, FlushStateMode::NONE);

    chainman.CheckBlockIndex();

    return true;
}

bool ProcessNewBlock(ChainstateManager& chainman, const std::shared_ptr<const CBlock>& block, bool force_processing, bool min_pow_checked, bool* new_block)
{
    AssertLockNotHeld(cs_main);

    {
        CBlockIndex* pindex = nullptr;
        if (new_block) *new_block = false;
        BlockValidationState state;

        // CheckBlock() does not support multi-threaded block validation because CBlock::fChecked can cause data race.
        // Therefore, the following critical section must include the CheckBlock() call as well.
        LOCK(cs_main);

        // Skipping AcceptBlock() for CheckBlock() failures means that we will never mark a block as invalid if
        // CheckBlock() fails.  This is protective against consensus failure if there are any unknown forms of block
        // malleability that cause CheckBlock() to fail; see e.g. CVE-2012-2459 and
        // https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2019-February/016697.html.  Because CheckBlock() is
        // not very expensive, the anti-DoS benefits of caching failure (of a definitely-invalid block) are not substantial.
        bool ret = CheckBlock(*block, state, chainman.GetConsensus());
        if (ret) {
            // Store to disk
            ret = AcceptBlock(chainman, block, state, &pindex, force_processing, nullptr, new_block, min_pow_checked);
        }
        if (!ret) {
            if (chainman.m_options.signals) {
                chainman.m_options.signals->BlockChecked(block, state);
            }
            LogError("%s: AcceptBlock FAILED (%s)\n", __func__, state.ToString());
            return false;
        }
    }

    chainman.NotifyHeaderTip();

    BlockValidationState state; // Only used to report errors, not invalidity - ignore it
    if (!chainman.ActiveChainstate().ActivateBestChain(state, block)) {
        LogError("%s: ActivateBestChain failed (%s)\n", __func__, state.ToString());
        return false;
    }

    return true;
}

BlockValidationState TestBlockValidity(
    Chainstate& chainstate,
    const CBlock& block,
    const bool check_pow,
    const bool check_merkle_root)
{
    // Lock must be held throughout this function for two reasons:
    // 1. We don't want the tip to change during several of the validation steps
    // 2. To prevent a CheckBlock() race condition for fChecked, see ProcessNewBlock()
    AssertLockHeld(chainstate.m_chainman.GetMutex());

    BlockValidationState state;
    CBlockIndex* tip{Assert(chainstate.m_chain.Tip())};

    if (block.hashPrevBlock != *Assert(tip->phashBlock)) {
        state.Invalid({}, "inconclusive-not-best-prevblk");
        return state;
    }

    // For signets CheckBlock() verifies the challenge iff fCheckPow is set.
    if (!CheckBlock(block, state, chainstate.m_chainman.GetConsensus(), /*fCheckPow=*/check_pow, /*fCheckMerkleRoot=*/check_merkle_root)) {
        // This should never happen, but belt-and-suspenders don't approve the
        // block if it does.
        if (state.IsValid()) NONFATAL_UNREACHABLE();
        return state;
    }

    /**
     * At this point ProcessNewBlock would call AcceptBlock(), but we
     * don't want to store the block or its header. Run individual checks
     * instead:
     * - skip AcceptBlockHeader() because:
     *   - we don't want to update the block index
     *   - we do not care about duplicates
     *   - we already ran CheckBlockHeader() via CheckBlock()
     *   - we already checked for prev-blk-not-found
     *   - we know the tip is valid, so no need to check bad-prevblk
     * - we already ran CheckBlock()
     * - do run ContextualCheckBlockHeader()
     * - do run ContextualCheckBlock()
     */

    if (!ContextualCheckBlockHeader(block, state, chainstate.m_chainman, tip)) {
        if (state.IsValid()) NONFATAL_UNREACHABLE();
        return state;
    }

    if (!ContextualCheckBlock(block, state, chainstate.m_chainman, tip)) {
        if (state.IsValid()) NONFATAL_UNREACHABLE();
        return state;
    }

    // We don't want ConnectBlock to update the actual chainstate, so create
    // a cache on top of it, along with a dummy block index.
    CBlockIndex index_dummy{block};
    uint256 block_hash(block.GetHash());
    index_dummy.pprev = tip;
    index_dummy.nHeight = tip->nHeight + 1;
    index_dummy.phashBlock = &block_hash;
    CCoinsViewCache view_dummy(&chainstate.CoinsTip());

    // Set fJustCheck to true in order to update, and not clear, validation caches.
    if (!ConnectBlock(chainstate, block, state, &index_dummy, view_dummy, /*fJustCheck=*/true)) {
        if (state.IsValid()) NONFATAL_UNREACHABLE();
        return state;
    }

    // Ensure no check returned successfully while also setting an invalid state.
    if (!state.IsValid()) NONFATAL_UNREACHABLE();

    return state;
}

CVerifyDB::CVerifyDB(Notifications& notifications)
    : m_notifications{notifications}
{
    m_notifications.progress(_("Verifying blocks…"), 0, false);
}

CVerifyDB::~CVerifyDB()
{
    m_notifications.progress(bilingual_str{}, 100, false);
}

VerifyDBResult CVerifyDB::VerifyDB(
    Chainstate& chainstate,
    const Consensus::Params& consensus_params,
    CCoinsView& coinsview,
    int nCheckLevel, int nCheckDepth)
{
    AssertLockHeld(cs_main);

    if (chainstate.m_chain.Tip() == nullptr || chainstate.m_chain.Tip()->pprev == nullptr) {
        return VerifyDBResult::SUCCESS;
    }

    // Verify blocks in the best chain
    if (nCheckDepth <= 0 || nCheckDepth > chainstate.m_chain.Height()) {
        nCheckDepth = chainstate.m_chain.Height();
    }
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogInfo("Verifying last %i blocks at level %i", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(&coinsview);
    CBlockIndex* pindex;
    CBlockIndex* pindexFailure = nullptr;
    int nGoodTransactions = 0;
    BlockValidationState state;
    int reportDone = 0;
    bool skipped_no_block_data{false};
    bool skipped_l3_checks{false};
    LogInfo("Verification progress: 0%%");

    for (pindex = chainstate.m_chain.Tip(); pindex && pindex->pprev; pindex = pindex->pprev) {
        const int percentageDone = std::max(1, std::min(99, (int)(((double)(chainstate.m_chain.Height() - pindex->nHeight)) / (double)nCheckDepth * (nCheckLevel >= 4 ? 50 : 100))));
        if (reportDone < percentageDone / 10) {
            // report every 10% step
            LogInfo("Verification progress: %d%%", percentageDone);
            reportDone = percentageDone / 10;
        }
        m_notifications.progress(_("Verifying blocks…"), percentageDone, false);
        if (pindex->nHeight <= chainstate.m_chain.Height() - nCheckDepth) {
            break;
        }
        if (chainstate.m_blockman.IsPruneMode() && !(pindex->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning, only go back as far as we have data.
            LogInfo("Block verification stopping at height %d (no data). This could be due to pruning.", pindex->nHeight);
            skipped_no_block_data = true;
            break;
        }
        CBlock block;
        // check level 0: read from disk
        if (!chainstate.m_blockman.ReadBlock(block, *pindex)) {
            LogError("Verification error: ReadBlock failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            return VerifyDBResult::CORRUPTED_BLOCK_DB;
        }
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state, consensus_params)) {
            LogError("Verification error: found bad block at %d, hash=%s (%s)",
                     pindex->nHeight, pindex->GetBlockHash().ToString(), state.ToString());
            return VerifyDBResult::CORRUPTED_BLOCK_DB;
        }
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            if (!pindex->GetUndoPos().IsNull()) {
                if (!chainstate.m_blockman.ReadBlockUndo(undo, *pindex)) {
                    LogError("Verification error: found bad undo data at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
                    return VerifyDBResult::CORRUPTED_BLOCK_DB;
                }
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        size_t curr_coins_usage = coins.DynamicMemoryUsage() + chainstate.CoinsTip().DynamicMemoryUsage();

        if (nCheckLevel >= 3) {
            if (curr_coins_usage <= chainstate.m_coinstip_cache_size_bytes) {
                assert(coins.GetBestBlock() == pindex->GetBlockHash());
                DisconnectResult res = DisconnectBlock(chainstate, block, pindex, coins);
                if (res == DISCONNECT_FAILED) {
                    LogError("Verification error: irrecoverable inconsistency in block data at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
                    return VerifyDBResult::CORRUPTED_BLOCK_DB;
                }
                if (res == DISCONNECT_UNCLEAN) {
                    nGoodTransactions = 0;
                    pindexFailure = pindex;
                } else {
                    nGoodTransactions += block.vtx.size();
                }
            } else {
                skipped_l3_checks = true;
            }
        }
        if (chainstate.m_chainman.m_interrupt) return VerifyDBResult::INTERRUPTED;
    }
    if (pindexFailure) {
        LogError("Verification error: coin database inconsistencies found (last %i blocks, %i good transactions before that)", chainstate.m_chain.Height() - pindexFailure->nHeight + 1, nGoodTransactions);
        return VerifyDBResult::CORRUPTED_BLOCK_DB;
    }
    if (skipped_l3_checks) {
        LogWarning("Skipped verification of level >=3 (insufficient database cache size). Consider increasing -dbcache.");
    }

    // store block count as we move pindex at check level >= 4
    int block_count = chainstate.m_chain.Height() - pindex->nHeight;

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4 && !skipped_l3_checks) {
        while (pindex != chainstate.m_chain.Tip()) {
            const int percentageDone = std::max(1, std::min(99, 100 - (int)(((double)(chainstate.m_chain.Height() - pindex->nHeight)) / (double)nCheckDepth * 50)));
            if (reportDone < percentageDone / 10) {
                // report every 10% step
                LogInfo("Verification progress: %d%%", percentageDone);
                reportDone = percentageDone / 10;
            }
            m_notifications.progress(_("Verifying blocks…"), percentageDone, false);
            pindex = chainstate.m_chain.Next(*pindex);
            CBlock block;
            if (!chainstate.m_blockman.ReadBlock(block, *pindex)) {
                LogError("Verification error: ReadBlock failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
                return VerifyDBResult::CORRUPTED_BLOCK_DB;
            }
            if (!ConnectBlock(chainstate, block, state, pindex, coins)) {
                LogError("Verification error: found unconnectable block at %d, hash=%s (%s)", pindex->nHeight, pindex->GetBlockHash().ToString(), state.ToString());
                return VerifyDBResult::CORRUPTED_BLOCK_DB;
            }
            if (chainstate.m_chainman.m_interrupt) return VerifyDBResult::INTERRUPTED;
        }
    }

    LogInfo("Verification: No coin database inconsistencies in last %i blocks (%i transactions)", block_count, nGoodTransactions);

    if (skipped_l3_checks) {
        return VerifyDBResult::SKIPPED_L3_CHECKS;
    }
    if (skipped_no_block_data) {
        return VerifyDBResult::SKIPPED_MISSING_BLOCKS;
    }
    return VerifyDBResult::SUCCESS;
}

/** Apply the effects of a block on the utxo cache, ignoring that it may already have been applied. */
bool RollforwardBlock(Chainstate& chainstate, const CBlockIndex* pindex, CCoinsViewCache& inputs)
{
    AssertLockHeld(cs_main);
    // TODO: merge with ConnectBlock
    CBlock block;
    if (!chainstate.m_blockman.ReadBlock(block, *pindex)) {
        LogError("ReplayBlock(): ReadBlock failed at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
        return false;
    }

    for (const CTransactionRef& tx : block.vtx) {
        if (!tx->IsCoinBase()) {
            for (const CTxIn& txin : tx->vin) {
                inputs.SpendCoin(txin.prevout);
            }
        }
        // Pass check = true as every addition may be an overwrite.
        AddCoins(inputs, *tx, pindex->nHeight, true);
    }
    return true;
}

bool ReplayBlocks(Chainstate& chainstate)
{
    LOCK(cs_main);

    CCoinsView& db = chainstate.CoinsDB();
    CCoinsViewCache cache(&db);

    std::vector<uint256> hashHeads = db.GetHeadBlocks();
    if (hashHeads.empty()) return true; // We're already in a consistent state.
    if (hashHeads.size() != 2) {
        LogError("ReplayBlocks(): unknown inconsistent state\n");
        return false;
    }

    chainstate.m_chainman.GetNotifications().progress(_("Replaying blocks…"), 0, false);
    LogInfo("Replaying blocks");

    const CBlockIndex* pindexOld = nullptr;  // Old tip during the interrupted flush.
    const CBlockIndex* pindexNew;            // New tip during the interrupted flush.
    const CBlockIndex* pindexFork = nullptr; // Latest block common to both the old and the new tip.

    if (!chainstate.m_blockman.m_block_index.contains(hashHeads[0])) {
        LogError("ReplayBlocks(): reorganization to unknown block requested\n");
        return false;
    }
    pindexNew = &(chainstate.m_blockman.m_block_index[hashHeads[0]]);

    if (!hashHeads[1].IsNull()) { // The old tip is allowed to be 0, indicating it's the first flush.
        if (!chainstate.m_blockman.m_block_index.contains(hashHeads[1])) {
            LogError("ReplayBlocks(): reorganization from unknown block requested\n");
            return false;
        }
        pindexOld = &(chainstate.m_blockman.m_block_index[hashHeads[1]]);
        pindexFork = LastCommonAncestor(pindexOld, pindexNew);
        assert(pindexFork != nullptr);
    }

    // Rollback along the old branch.
    const int nForkHeight{pindexFork ? pindexFork->nHeight : 0};
    if (pindexOld != pindexFork) {
        LogInfo("Rolling back from %s (%i to %i)", pindexOld->GetBlockHash().ToString(), pindexOld->nHeight, nForkHeight);
        while (pindexOld != pindexFork) {
            if (pindexOld->nHeight > 0) { // Never disconnect the genesis block.
                CBlock block;
                if (!chainstate.m_blockman.ReadBlock(block, *pindexOld)) {
                    LogError("RollbackBlock(): ReadBlock() failed at %d, hash=%s\n", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
                    return false;
                }
                if (pindexOld->nHeight % 10'000 == 0) {
                    LogInfo("Rolling back %s (%i)", pindexOld->GetBlockHash().ToString(), pindexOld->nHeight);
                }
                DisconnectResult res = DisconnectBlock(chainstate, block, pindexOld, cache);
                if (res == DISCONNECT_FAILED) {
                    LogError("RollbackBlock(): DisconnectBlock failed at %d, hash=%s\n", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
                    return false;
                }
                // If DISCONNECT_UNCLEAN is returned, it means a non-existing UTXO was deleted, or an existing UTXO was
                // overwritten. It corresponds to cases where the block-to-be-disconnect never had all its operations
                // applied to the UTXO set. However, as both writing a UTXO and deleting a UTXO are idempotent operations,
                // the result is still a version of the UTXO set with the effects of that block undone.
            }
            pindexOld = pindexOld->pprev;
        }
        LogInfo("Rolled back to %s", pindexFork->GetBlockHash().ToString());
    }

    // Roll forward from the forking point to the new tip.
    if (nForkHeight < pindexNew->nHeight) {
        LogInfo("Rolling forward to %s (%i to %i)", pindexNew->GetBlockHash().ToString(), nForkHeight, pindexNew->nHeight);
        for (int nHeight = nForkHeight + 1; nHeight <= pindexNew->nHeight; ++nHeight) {
            const CBlockIndex& pindex{*Assert(pindexNew->GetAncestor(nHeight))};

            if (nHeight % 10'000 == 0) {
                LogInfo("Rolling forward %s (%i)", pindex.GetBlockHash().ToString(), nHeight);
            }
            chainstate.m_chainman.GetNotifications().progress(_("Replaying blocks…"), (int)((nHeight - nForkHeight) * 100.0 / (pindexNew->nHeight - nForkHeight)), false);
            if (!RollforwardBlock(chainstate, &pindex, cache)) return false;
        }
        LogInfo("Rolled forward to %s", pindexNew->GetBlockHash().ToString());
    }

    cache.SetBestBlock(pindexNew->GetBlockHash());
    cache.Flush(/*reallocate_cache=*/false); // local CCoinsViewCache goes out of scope
    chainstate.m_chainman.GetNotifications().progress(bilingual_str{}, 100, false);
    return true;
}

/**
 * Check whether all of this transaction's input scripts succeed.
 *
 * This involves ECDSA signature checks so can be computationally intensive. This function should
 * only be called after the cheap sanity checks in CheckTxInputs passed.
 *
 * If pvChecks is not nullptr, script checks are pushed onto it instead of being performed inline. Any
 * script checks which are not necessary (eg due to script execution cache hits) are, obviously,
 * not pushed onto pvChecks/run.
 *
 * Setting cacheSigStore/cacheFullScriptStore to false will remove elements from the corresponding cache
 * which are matched. This is useful for checking blocks where we will likely never need the cache
 * entry again.
 *
 * Note that we may set state.reason to NOT_STANDARD for extra soft-fork flags in flags, block-checking
 * callers should probably reset it to CONSENSUS in such cases.
 *
 * Non-static (and redeclared) in src/test/txvalidationcache_tests.cpp
 */
bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, script_verify_flags flags, bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       ValidationCache& validation_cache,
                       std::vector<CScriptCheck>* pvChecks)
{
    if (tx.IsCoinBase()) return true;

    if (pvChecks) {
        pvChecks->reserve(tx.vin.size());
    }

    // First check if script executions have been cached with the same
    // flags. Note that this assumes that the inputs provided are
    // correct (ie that the transaction hash which is in tx's prevouts
    // properly commits to the scriptPubKey in the inputs view of that
    // transaction).
    uint256 hashCacheEntry;
    CSHA256 hasher = validation_cache.ScriptExecutionCacheHasher();
    hasher.Write(UCharCast(tx.GetWitnessHash().begin()), 32).Write((unsigned char*)&flags, sizeof(flags)).Finalize(hashCacheEntry.begin());
    AssertLockHeld(cs_main); // TODO: Remove this requirement by making CuckooCache not require external locks
    if (validation_cache.m_script_execution_cache.contains(hashCacheEntry, !cacheFullScriptStore)) {
        return true;
    }

    if (!txdata.m_spent_outputs_ready) {
        std::vector<CTxOut> spent_outputs;
        spent_outputs.reserve(tx.vin.size());

        for (const auto& txin : tx.vin) {
            const COutPoint& prevout = txin.prevout;
            const Coin& coin = inputs.AccessCoin(prevout);
            assert(!coin.IsSpent());
            spent_outputs.emplace_back(coin.out);
        }
        txdata.Init(tx, std::move(spent_outputs));
    }
    assert(txdata.m_spent_outputs.size() == tx.vin.size());

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        // We very carefully only pass in things to CScriptCheck which
        // are clearly committed to by tx' witness hash. This provides
        // a sanity check that our caching is not introducing consensus
        // failures through additional data in, eg, the coins being
        // spent being checked as a part of CScriptCheck.

        // Verify signature
        CScriptCheck check(txdata.m_spent_outputs[i], tx, validation_cache.m_signature_cache, i, flags, cacheSigStore, &txdata);
        if (pvChecks) {
            pvChecks->emplace_back(std::move(check));
        } else if (auto result = check(); result.has_value()) {
            // Tx failures never trigger disconnections/bans.
            // This is so that network splits aren't triggered
            // either due to non-consensus relay policies (such as
            // non-standard DER encodings or non-null dummy
            // arguments) or due to new consensus rules introduced in
            // soft forks.
            if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS) {
                return state.Invalid(TxValidationResult::TX_NOT_STANDARD, strprintf("mempool-script-verify-flag-failed (%s)", ScriptErrorString(result->first)), result->second);
            } else {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, strprintf("block-script-verify-flag-failed (%s)", ScriptErrorString(result->first)), result->second);
            }
        }
    }

    if (cacheFullScriptStore && !pvChecks) {
        // We executed all of the provided scripts, and were told to
        // cache the result. Do so now.
        validation_cache.m_script_execution_cache.insert(hashCacheEntry);
    }

    return true;
}


/** Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS). */

bool IsBIP30Repeat(const CBlockIndex& block_index)
{
    return (block_index.nHeight == 91842 && block_index.GetBlockHash() == uint256{"00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"}) ||
           (block_index.nHeight == 91880 && block_index.GetBlockHash() == uint256{"00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"});
}

bool IsBIP30Unspendable(const uint256& block_hash, int block_height)
{
    return (block_height == 91722 && block_hash == uint256{"00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"}) ||
           (block_height == 91812 && block_hash == uint256{"00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"});
}
