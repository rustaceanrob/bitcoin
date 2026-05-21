// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_VALIDATION_H
#define BITCOIN_BLOCK_VALIDATION_H

#include <arith_uint256.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <kernel/cs_main.h>
#include <primitives/block.h>
#include <script/script_check.h>
#include <script/verify_flags.h>

#include <memory>
#include <span>
#include <vector>

class CBlockIndex;
class Chainstate;
class ChainstateManager;
class ValidationCache;
class ValidationSignals;
class CTransaction;

/** Identifies blocks that overwrote an existing coinbase output in the UTXO set (see BIP30) */
bool IsBIP30Repeat(const CBlockIndex& block_index);

/** Identifies blocks which coinbase output was subsequently overwritten in the UTXO set (see BIP30) */
bool IsBIP30Unspendable(const uint256& block_hash, int block_height);

struct FlatFilePos;

DisconnectResult DisconnectBlock(Chainstate& chainstate, const CBlock& block, const CBlockIndex* pindex, CCoinsViewCache& view) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
bool ConnectBlock(Chainstate& chainstate, const CBlock& block, BlockValidationState& state, CBlockIndex* pindex, CCoinsViewCache& view, bool fJustCheck = false) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
bool RollforwardBlock(Chainstate& chainstate, const CBlockIndex* pindex, CCoinsViewCache& inputs) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
bool ReplayBlocks(Chainstate& chainstate);
void UpdateUncommittedBlockStructures(const ChainstateManager& chainman, CBlock& block, const CBlockIndex* pindexPrev);
void GenerateCoinbaseCommitment(const ChainstateManager& chainman, CBlock& block, const CBlockIndex* pindexPrev);
bool ProcessNewBlockHeaders(ChainstateManager& chainman, std::span<const CBlockHeader> headers, bool min_pow_checked, BlockValidationState& state, const CBlockIndex** ppindex = nullptr) LOCKS_EXCLUDED(cs_main);
bool AcceptBlock(ChainstateManager& chainman, const std::shared_ptr<const CBlock>& pblock, BlockValidationState& state, CBlockIndex** ppindex, bool fRequested, const FlatFilePos* dbp, bool* fNewBlock, bool min_pow_checked) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
bool ProcessNewBlock(ChainstateManager& chainman, const std::shared_ptr<const CBlock>& block, bool force_processing, bool min_pow_checked, bool* new_block) LOCKS_EXCLUDED(cs_main);

/** Context-independent validity checks */
bool CheckBlock(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true, bool fCheckMerkleRoot = true);

/** Check that the proof of work on each block header matches the value in nBits */
bool HasValidProofOfWork(std::span<const CBlockHeader> headers, const Consensus::Params& consensusParams);

/** Compute the block subsidy at a given height. */
CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams);

/** Check if a block has been mutated (with respect to its merkle root and witness commitments). */
bool IsBlockMutated(const CBlock& block, bool check_witness_root);

/** Return the sum of the claimed work on a given set of headers. No verification of PoW is done. */
arith_uint256 CalculateClaimedHeadersWork(std::span<const CBlockHeader> headers);

/**
 * Verify a block, including transactions.
 *
 * @param[in]   block       The block we want to process. Must connect to the
 *                          current tip.
 * @param[in]   chainstate  The chainstate to connect to.
 * @param[in]   check_pow   perform proof-of-work check, nBits in the header
 *                          is always checked
 * @param[in]   check_merkle_root check the merkle root
 *
 * @return Valid or Invalid state. This doesn't currently return an Error state,
 *         and shouldn't unless there is something wrong with the existing
 *         chainstate. (This is different from functions like AcceptBlock which
 *         can fail trying to save new data.)
 *
 * For signets the challenge verification is skipped when check_pow is false.
 */
BlockValidationState TestBlockValidity(
    Chainstate& chainstate,
    const CBlock& block,
    bool check_pow,
    bool check_merkle_root) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** Return the script verification flags which should be checked for a given block */
script_verify_flags GetBlockScriptFlags(const CBlockIndex& block_index, const ChainstateManager& chainman);

void LimitValidationInterfaceQueue(ValidationSignals& signals) LOCKS_EXCLUDED(cs_main);

bool CheckInputScripts(const CTransaction& tx, TxValidationState& state,
                       const CCoinsViewCache& inputs, script_verify_flags flags, bool cacheSigStore,
                       bool cacheFullScriptStore, PrecomputedTransactionData& txdata,
                       ValidationCache& validation_cache,
                       std::vector<CScriptCheck>* pvChecks = nullptr) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

#endif // BITCOIN_BLOCK_VALIDATION_H
