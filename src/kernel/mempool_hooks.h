// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_MEMPOOL_HOOKS_H
#define BITCOIN_KERNEL_MEMPOOL_HOOKS_H

#include <primitives/transaction.h>
#include <sync.h>

#include <cstddef>
#include <memory>
#include <vector>

class CBlock;
class CBlockIndex;
class Chainstate;

namespace kernel {

/**
 * Synchronous hooks through which a Chainstate keeps an external transaction
 * pool consistent with its active chain. The kernel only calls these; it does
 * not ship an implementation.
 *
 * Every chain update method is called with cs_main and GetMutex() held.
 */
class MempoolHooks
{
public:
    virtual ~MempoolHooks() = default;

    //! Held for the duration of a chain update so the pool is never observed half-updated.
    virtual RecursiveMutex& GetMutex() const = 0;

    //! Memory budget of the pool. The unused part of it is lent to the coins cache.
    virtual size_t MaxSizeBytes() const = 0;
    virtual size_t DynamicMemoryUsage() const = 0;
    virtual bool IsEmpty() const = 0;

    //! The active chain tip moved.
    virtual void TipChanged() = 0;
    //! The tip block was disconnected. Its transactions may be resurrected by ReorgFinished().
    virtual void BlockDisconnected(const std::vector<CTransactionRef>& vtx) = 0;
    //! A block was connected to the tip. Called after the tip was updated.
    virtual void BlockConnected(Chainstate& chainstate, const std::shared_ptr<const CBlock>& block, const CBlockIndex& index) = 0;
    //! A series of BlockDisconnected() calls ended. If resurrect is false, disconnected transactions are dropped.
    virtual void ReorgFinished(Chainstate& chainstate, bool resurrect) = 0;
    //! Optional consistency check, run after every chain update step.
    virtual void Check(Chainstate& chainstate) = 0;
};

} // namespace kernel

#endif // BITCOIN_KERNEL_MEMPOOL_HOOKS_H
