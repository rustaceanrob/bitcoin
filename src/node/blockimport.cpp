// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/blockimport.h>

#include <flatfile.h>
#include <kernel/cs_main.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <streams.h>
#include <sync.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/result.h>
#include <util/signalinterrupt.h>
#include <validation.h>

#include <atomic>
#include <cassert>
#include <map>
#include <span>

namespace node {

class ImportingNow
{
    std::atomic<bool>& m_importing;

public:
    ImportingNow(std::atomic<bool>& importing) : m_importing{importing}
    {
        assert(m_importing == false);
        m_importing = true;
    }
    ~ImportingNow()
    {
        assert(m_importing == true);
        m_importing = false;
    }
};

void ImportBlocks(ChainstateManager& chainman, std::span<const fs::path> import_paths)
{
    ImportingNow imp{chainman.m_blockman.m_importing};

    // -reindex
    if (!chainman.m_blockman.m_blockfiles_indexed) {
        int total_files{0};
        while (fs::exists(chainman.m_blockman.GetBlockPosFilename(FlatFilePos(total_files, 0)))) {
            total_files++;
        }

        // Map of disk positions for blocks with unknown parent (only used for reindex);
        // parent hash -> child disk position, multiple children can have the same parent.
        std::multimap<uint256, FlatFilePos> blocks_with_unknown_parent;

        for (int nFile{0}; nFile < total_files; ++nFile) {
            FlatFilePos pos(nFile, 0);
            AutoFile file{chainman.m_blockman.OpenBlockFile(pos, /*fReadOnly=*/true)};
            if (file.IsNull()) {
                break; // This error is logged in OpenBlockFile
            }
            LogInfo("Reindexing block file blk%05u.dat (%d%% complete)...", (unsigned int)nFile, nFile * 100 / total_files);
            chainman.LoadExternalBlockFile(file, &pos, &blocks_with_unknown_parent);
            if (chainman.m_interrupt) {
                LogInfo("Interrupt requested. Exit reindexing.");
                return;
            }
        }
        WITH_LOCK(::cs_main, chainman.m_blockman.m_block_tree_db->WriteReindexing(false));
        chainman.m_blockman.m_blockfiles_indexed = true;
        LogInfo("Reindexing finished");
        // To avoid ending up in a situation without genesis block, re-try initializing (no-op if reindexing worked):
        chainman.ActiveChainstate().LoadGenesisBlock();
    }

    // -loadblock=
    for (const fs::path& path : import_paths) {
        AutoFile file{fsbridge::fopen(path, "rb")};
        if (!file.IsNull()) {
            LogInfo("Importing blocks file %s...", fs::PathToString(path));
            chainman.LoadExternalBlockFile(file);
            if (chainman.m_interrupt) {
                LogInfo("Interrupt requested. Exit block importing.");
                return;
            }
        } else {
            LogWarning("Could not open blocks file %s", fs::PathToString(path));
        }
    }

    // scan for better chains in the block chain database, that are not yet connected in the active best chain
    if (auto result = chainman.ActivateBestChains(); !result) {
        chainman.GetNotifications().fatalError(util::ErrorString(result));
    }
    // End scope of ImportingNow
}

} // namespace node
