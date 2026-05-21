// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_BLOCKIMPORT_H
#define BITCOIN_NODE_BLOCKIMPORT_H

#include <util/fs.h>

#include <span>

class ChainstateManager;

namespace node {

// Calls ActivateBestChain() even if no blocks are imported.
void ImportBlocks(ChainstateManager& chainman, std::span<const fs::path> import_paths);

} // namespace node

#endif // BITCOIN_NODE_BLOCKIMPORT_H
