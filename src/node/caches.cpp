// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/caches.h>

#include <common/args.h>
#include <common/system.h>
#include <kernel/caches.h>
#include <logging.h>
#include <node/interface_ui.h>
#include <tinyformat.h>
#include <util/byte_units.h>
#include <util/translation.h>

#include <algorithm>
#include <string>

//! Maximum dbcache size on 32-bit systems.
static constexpr size_t MAX_32BIT_DBCACHE{1_GiB};
//! Larger default dbcache on 64-bit systems with enough RAM.
static constexpr size_t HIGH_DEFAULT_DBCACHE{1_GiB};
//! Minimum detected RAM required for HIGH_DEFAULT_DBCACHE.
static constexpr uint64_t HIGH_DEFAULT_DBCACHE_MIN_TOTAL_RAM{4_GiB};

namespace node {
size_t GetDefaultDBCache()
{
    if constexpr (sizeof(void*) >= 8) {
        if (GetTotalRAM().value_or(0) >= HIGH_DEFAULT_DBCACHE_MIN_TOTAL_RAM) {
            return HIGH_DEFAULT_DBCACHE;
        }
    }
    return DEFAULT_DB_CACHE;
}

size_t CalculateDbCacheBytes(const ArgsManager& args)
{
    if (auto db_cache{args.GetIntArg("-dbcache")}) {
        if (*db_cache < 0) db_cache = 0;
        const uint64_t db_cache_bytes{SaturatingLeftShift<uint64_t>(*db_cache, 20)};
        constexpr auto max_db_cache{sizeof(void*) == 4 ? MAX_32BIT_DBCACHE : std::numeric_limits<size_t>::max()};
        return std::max<size_t>(MIN_DB_CACHE, std::min<uint64_t>(db_cache_bytes, max_db_cache));
    }
    return GetDefaultDBCache();
}

CacheSizes CalculateCacheSizes(const ArgsManager& args)
{
    size_t total_cache{CalculateDbCacheBytes(args)};
    return {kernel::CacheSizes{total_cache}};
}

void LogOversizedDbCache(const ArgsManager& args) noexcept
{
    if (const auto total_ram{GetTotalRAM()}) {
        const size_t db_cache{CalculateDbCacheBytes(args)};
        if (ShouldWarnOversizedDbCache(db_cache, *total_ram)) {
            InitWarning(bilingual_str{tfm::format(_("A %zu MiB dbcache may be too large for a system memory of only %zu MiB."),
                        db_cache >> 20, *total_ram >> 20)});
        }
    }
}
} // namespace node
