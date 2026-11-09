// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BITCOINMEMPOOL_BUILD

#include <mempool/bitcoinmempool.h>

#include <blockencodings.h>
#include <coins.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <kernel/chainparams.h>
#include <kernel/context.h>
#include <kernel/cs_main.h>
#include <kernel/disconnected_transactions.h>
#include <kernel/mempool_entry.h>
#include <kernel/mempool_removal_reason.h>
#include <mempool_accept.h>
#include <policy/feerate.h>
#include <policy/packages.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <randomenv.h>
#include <script/script.h>
#include <script/verify_flags.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <sync.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <util/log.h>
#include <util/task_runner.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation_common.h>
#include <validationinterface.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include <deque>
#include <exception>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

// Define G_TRANSLATION_FUN symbol in libbitcoinmempool library so users of the
// library aren't required to export this symbol
extern const TranslateFn G_TRANSLATION_FUN{nullptr};

// The library does not inspect its host environment (files, network
// interfaces, process information) for extra entropy. Randomness comes from
// the operating system's getrandom() and the CPU's hardware generators.
void RandAddDynamicEnv(CSHA512&) {}
void RandAddStaticEnv(CSHA512&) {}

namespace {

const kernel::Context g_context{};

std::mutex g_log_mutex;
btcm_LogCallback g_log_callback{nullptr};
void* g_log_user_data{nullptr};

constexpr size_t VALIDATION_CACHE_BYTES{4 << 20};

//! How often coins are fetched again because the tip or the pool moved during a lookup.
constexpr int MAX_COIN_ROUNDS{16};

template <typename C, typename CPP>
struct Handle {
    static C* ref(CPP* cpp_type) { return reinterpret_cast<C*>(cpp_type); }
    static const C* ref(const CPP* cpp_type) { return reinterpret_cast<const C*>(cpp_type); }

    template <typename... Args>
    static C* create(Args&&... args)
    {
        return ref(std::make_unique<CPP>(std::forward<Args>(args)...).release());
    }

    static const CPP& get(const C* ptr) { return *reinterpret_cast<const CPP*>(ptr); }
    static CPP& get(C* ptr) { return *reinterpret_cast<CPP*>(ptr); }

    static void operator delete(void* ptr) { delete reinterpret_cast<CPP*>(ptr); }
};

//! Copy a caller's versioned struct over defaults, reading only the fields the caller knows about.
template <typename T>
T ReadVersioned(const T& in, T defaults)
{
    std::memcpy(&defaults, &in, std::min(in.struct_size, sizeof(T)));
    defaults.struct_size = sizeof(T);
    return defaults;
}

//! Write a versioned struct, only as many fields as the caller's struct has.
template <typename T>
void WriteVersioned(T& out, const T& value)
{
    const size_t size{out.struct_size};
    std::memcpy(&out, &value, std::min(size, sizeof(T)));
    out.struct_size = size;
}

template <typename T>
T InitVersioned()
{
    T t{};
    t.struct_size = sizeof(T);
    return t;
}

btcm_StringView View(const std::string& str) { return {str.data(), str.size()}; }
void Write32(const auto& hash, uint8_t out[32]) { std::memcpy(out, hash.data(), 32); }
uint256 Read32(const uint8_t in[32]) { return uint256{std::span<const unsigned char, 32>{in, 32}}; }
Txid ReadTxid(const uint8_t in[32]) { return Txid::FromUint256(Read32(in)); }

template <typename T>
int WriteSerialized(const T& obj, btcm_WriteBytes writer, void* user_data)
{
    DataStream stream;
    stream << obj;
    return writer(stream.data(), stream.size(), user_data);
}

btcm_RemovalReason ToC(MemPoolRemovalReason reason)
{
    switch (reason) {
    case MemPoolRemovalReason::EXPIRY: return btcm_RemovalReason_EXPIRY;
    case MemPoolRemovalReason::SIZELIMIT: return btcm_RemovalReason_SIZELIMIT;
    case MemPoolRemovalReason::REORG: return btcm_RemovalReason_REORG;
    case MemPoolRemovalReason::BLOCK: return btcm_RemovalReason_BLOCK;
    case MemPoolRemovalReason::CONFLICT: return btcm_RemovalReason_CONFLICT;
    case MemPoolRemovalReason::REPLACED: return btcm_RemovalReason_REPLACED;
    }
    assert(false);
}

btcm_ReadStatus ToC(ReadStatus status)
{
    switch (status) {
    case READ_STATUS_OK: return btcm_ReadStatus_OK;
    case READ_STATUS_INVALID: return btcm_ReadStatus_INVALID;
    case READ_STATUS_FAILED: return btcm_ReadStatus_FAILED;
    }
    assert(false);
}

std::unique_ptr<const CChainParams> MakeParams(btcm_ChainType chain_type)
{
    switch (chain_type) {
    case btcm_ChainType_MAINNET: return CChainParams::Main();
    case btcm_ChainType_TESTNET: return CChainParams::TestNet();
    case btcm_ChainType_TESTNET_4: return CChainParams::TestNet4();
    case btcm_ChainType_SIGNET: return CChainParams::SigNet(CChainParams::SigNetOptions{});
    case btcm_ChainType_REGTEST: return CChainParams::RegTest(CChainParams::RegTestOptions{});
    }
    return nullptr;
}

struct Tip {
    int height;
    uint256 hash;
    int64_t median_time_past;
};

Tip ToTip(const btcm_Tip& in)
{
    const btcm_Tip tip{ReadVersioned(in, InitVersioned<btcm_Tip>())};
    return Tip{tip.height, Read32(tip.hash), tip.median_time_past};
}

struct Event {
    bool added;
    CTransactionRef tx;
    CAmount fee{-1};
    int64_t vsize{-1};
    MemPoolRemovalReason reason{};
    uint64_t sequence;
};

/** Buffers pool events until the pool's locks are released. */
class EventQueue final : public CValidationInterface
{
    std::mutex m_mutex;
    std::deque<Event> m_events;

public:
    void TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t sequence) override
    {
        std::lock_guard lock{m_mutex};
        m_events.push_back({.added = true, .tx = tx.info.m_tx, .fee = tx.info.m_fee,
                            .vsize = tx.info.m_virtual_transaction_size, .sequence = sequence});
    }

    void TransactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason, uint64_t sequence) override
    {
        Removed(tx, reason, sequence);
    }

    void Removed(const CTransactionRef& tx, MemPoolRemovalReason reason, uint64_t sequence)
    {
        std::lock_guard lock{m_mutex};
        m_events.push_back({.added = false, .tx = tx, .reason = reason, .sequence = sequence});
    }

    std::optional<Event> Pop()
    {
        std::lock_guard lock{m_mutex};
        if (m_events.empty()) return std::nullopt;
        Event e{std::move(m_events.front())};
        m_events.pop_front();
        return e;
    }
};

/** Coins fetched from the embedder for one operation, with their chain context. */
struct FetchedCoins {
    std::map<COutPoint, Coin> coins;
    std::set<COutPoint> spent;
    //! Hashes of the blocks the coins were created in, by height.
    std::map<int, uint256> block_hashes;
    //! Median time past of the blocks before the coins' blocks, by height.
    std::map<int, int64_t> median_time_pasts;

    bool Knows(const COutPoint& outpoint) const { return coins.contains(outpoint) || spent.contains(outpoint); }
};

class FetchedCoinsView final : public CoinsViewEmpty
{
    const FetchedCoins& m_fetched;
    const uint256 m_tip;

public:
    FetchedCoinsView(const FetchedCoins& fetched, const uint256& tip) : m_fetched{fetched}, m_tip{tip} {}

    std::optional<Coin> GetCoin(const COutPoint& outpoint) const override
    {
        const auto it{m_fetched.coins.find(outpoint)};
        if (it == m_fetched.coins.end()) return std::nullopt;
        return it->second;
    }
    std::optional<Coin> PeekCoin(const COutPoint& outpoint) const override { return GetCoin(outpoint); }
    bool HaveCoin(const COutPoint& outpoint) const override { return m_fetched.coins.contains(outpoint); }
    uint256 GetBestBlock() const override { return m_tip; }
};

struct TransactionResult {
    MempoolAcceptResult result;
    std::string reject_reason{result.m_state.GetRejectReason()};
    std::string debug_message{result.m_state.GetDebugMessage()};
};

struct SubmitResult {
    Package txs;
    std::vector<std::optional<TransactionResult>> results;
    std::string package_error;
};

struct Snapshot {
    std::vector<btcm_EntryInfo> entries;
    std::vector<CTransactionRef> txs;
    uint64_t sequence;
};

struct OwnedCallbacks {
    btcm_Callbacks cbs;
    explicit OwnedCallbacks(const btcm_Callbacks& c) : cbs{c} {}
    OwnedCallbacks(const OwnedCallbacks&) = delete;
    OwnedCallbacks& operator=(const OwnedCallbacks&) = delete;
    ~OwnedCallbacks()
    {
        if (cbs.user_data && cbs.user_data_destroy) cbs.user_data_destroy(cbs.user_data);
    }
};

} // namespace

struct btcm_Transaction : Handle<btcm_Transaction, CTransactionRef> {};
struct btcm_Block : Handle<btcm_Block, std::shared_ptr<const CBlock>> {};
struct btcm_SubmitResult : Handle<btcm_SubmitResult, SubmitResult> {};
struct btcm_Snapshot : Handle<btcm_Snapshot, Snapshot> {};

struct btcm_CoinBatch {
    std::vector<std::optional<std::pair<Coin, btcm_Coin>>> coins;
};

struct btcm_Reconstruction {
    PartiallyDownloadedBlock partial;
    size_t tx_count;
    bool segwit_active;
    std::vector<uint32_t> missing;
    bool finished{false};
};

struct btcm_Mempool {
    std::unique_ptr<const CChainParams> params;
    OwnedCallbacks callbacks;
    ValidationSignals signals{std::make_unique<util::ImmediateTaskRunner>()};
    EventQueue events;
    //! Serializes event delivery. Recursive, because a callback may call back into the pool.
    std::recursive_mutex dispatch_mutex;
    ValidationCache validation_cache{VALIDATION_CACHE_BYTES, VALIDATION_CACHE_BYTES};
    std::unique_ptr<CTxMemPool> pool;
    Tip tip GUARDED_BY(::cs_main);
    //! Bumped on every block notification. Coins fetched in an older generation are discarded.
    uint64_t generation GUARDED_BY(::cs_main){0};
    DisconnectedBlockTransactions disconnectpool GUARDED_BY(::cs_main){MAX_DISCONNECTED_TX_POOL_BYTES};
    //! Lowest height disconnected by the reorg in progress. Blocks below it are untouched.
    std::optional<int> fork_height GUARDED_BY(::cs_main);
    //! Blocks connected since fork_height, by height.
    std::map<int, uint256> reorg_blocks GUARDED_BY(::cs_main);

    btcm_Mempool(std::unique_ptr<const CChainParams> p, const Tip& t, const btcm_Callbacks& cbs, CTxMemPool::Options opts)
        : params{std::move(p)}, callbacks{cbs}, tip{t}
    {
        signals.RegisterValidationInterface(&events);
        opts.signals = &signals;
        bilingual_str error;
        pool = std::make_unique<CTxMemPool>(opts, error);
        if (!error.empty()) throw std::runtime_error{error.original};
    }

    ~btcm_Mempool()
    {
        WITH_LOCK(::cs_main, disconnectpool.clear());
        pool.reset();
        signals.UnregisterValidationInterface(&events);
    }

    //! Deliver buffered events. Called at the end of every API call, with no pool lock held.
    void Dispatch()
    {
        std::lock_guard lock{dispatch_mutex};
        const btcm_Callbacks& cbs{callbacks.cbs};
        while (auto e{events.Pop()}) {
            if (e->added && cbs.transaction_added) {
                cbs.transaction_added(cbs.user_data, btcm_Transaction::ref(&e->tx), e->fee, e->vsize, e->sequence);
            } else if (!e->added && cbs.transaction_removed) {
                cbs.transaction_removed(cbs.user_data, btcm_Transaction::ref(&e->tx), ToC(e->reason), e->sequence);
            }
        }
    }

    //! Ask the embedder for outpoints. Called with no pool lock held.
    void Fetch(const std::vector<COutPoint>& outpoints, FetchedCoins& fetched)
    {
        std::vector<btcm_OutPoint> request(outpoints.size());
        for (size_t i{0}; i < outpoints.size(); ++i) {
            Write32(outpoints[i].hash, request[i].txid);
            request[i].index = outpoints[i].n;
        }
        btcm_CoinBatch batch;
        batch.coins.resize(outpoints.size());
        callbacks.cbs.get_coins(callbacks.cbs.user_data, request.data(), request.size(), &batch);
        for (size_t i{0}; i < outpoints.size(); ++i) {
            if (!batch.coins[i]) {
                fetched.spent.insert(outpoints[i]);
                continue;
            }
            const auto& [coin, raw]{*batch.coins[i]};
            fetched.coins.insert_or_assign(outpoints[i], coin);
            fetched.block_hashes.insert_or_assign(raw.height, Read32(raw.block_hash));
            fetched.median_time_pasts.insert_or_assign(std::max(raw.height - 1, 0), raw.prev_median_time_past);
        }
    }

    /**
     * Fetch the coins `missing` asks for until it asks for none, then run
     * `work` with them. Both run under the pool's locks; fetching does not.
     * Returns false if the chain kept moving for MAX_COIN_ROUNDS.
     */
    template <typename Missing, typename Work>
    bool WithCoins(Missing&& missing, Work&& work)
    {
        FetchedCoins fetched;
        uint64_t fetched_generation{WITH_LOCK(::cs_main, return generation)};
        for (int round{0}; round < MAX_COIN_ROUNDS; ++round) {
            std::vector<COutPoint> need;
            {
                LOCK2(::cs_main, pool->cs);
                if (fetched_generation != generation) {
                    fetched = {};
                    fetched_generation = generation;
                }
                need = missing(fetched);
                if (need.empty()) {
                    work(fetched);
                    return true;
                }
            }
            Fetch(need, fetched);
        }
        return false;
    }

    void FinishReorg();
};

namespace {

/** The chain as far as one operation knows it: the pushed tip, the reorg in progress and the fetched coins. */
class FetchedChainView final : public MempoolChainView
{
    btcm_Mempool& m_mempool;
    const FetchedCoins& m_fetched;
    CCoinsViewCache& m_coins;

public:
    FetchedChainView(btcm_Mempool& mempool, const FetchedCoins& fetched, CCoinsViewCache& coins)
        : m_mempool{mempool}, m_fetched{fetched}, m_coins{coins} {}

    CCoinsViewCache& CoinsTip() override { return m_coins; }

    int TipHeight() override EXCLUSIVE_LOCKS_REQUIRED(::cs_main) { return m_mempool.tip.height; }

    std::optional<uint256> BlockHash(int height) override EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        if (height > m_mempool.tip.height) return std::nullopt;
        if (height == m_mempool.tip.height) return m_mempool.tip.hash;
        if (height == 0) return m_mempool.params->GenesisBlock().GetHash();
        if (const auto it{m_mempool.reorg_blocks.find(height)}; it != m_mempool.reorg_blocks.end()) return it->second;
        if (const auto it{m_fetched.block_hashes.find(height)}; it != m_fetched.block_hashes.end()) return it->second;
        return std::nullopt;
    }

    bool IsInActiveChain(int height, const uint256& hash) override EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        // Lock points of pool transactions were valid before the reorg in
        // progress, so blocks below its fork are still in the chain.
        if (height <= m_mempool.tip.height && (!m_mempool.fork_height || height < *m_mempool.fork_height)) return true;
        return BlockHash(height) == hash;
    }

    int64_t MedianTimePast(int height) override EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        if (height == m_mempool.tip.height) return m_mempool.tip.median_time_past;
        const auto it{m_fetched.median_time_pasts.find(height)};
        // Every height asked for belongs to a fetched coin. Should that ever
        // not hold, treat time locks as unsatisfied rather than guessing.
        if (!Assume(it != m_fetched.median_time_pasts.end())) return std::numeric_limits<int64_t>::max();
        return it->second;
    }

    script_verify_flags TipScriptFlags() override EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        const Consensus::Params& consensus{m_mempool.params->GetConsensus()};
        const int tip_height{m_mempool.tip.height};
        script_verify_flags flags{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT};
        if (const auto it{consensus.script_flag_exceptions.find(m_mempool.tip.hash)}; it != consensus.script_flag_exceptions.end()) {
            flags = it->second;
        }
        if (tip_height >= consensus.DeploymentHeight(Consensus::DEPLOYMENT_DERSIG)) flags |= SCRIPT_VERIFY_DERSIG;
        if (tip_height >= consensus.DeploymentHeight(Consensus::DEPLOYMENT_CLTV)) flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
        if (tip_height >= consensus.DeploymentHeight(Consensus::DEPLOYMENT_CSV)) flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
        if (tip_height >= consensus.DeploymentHeight(Consensus::DEPLOYMENT_SEGWIT)) flags |= SCRIPT_VERIFY_NULLDUMMY;
        return flags;
    }

    script_verify_flags AllConsensusScriptFlags() const override
    {
        return SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_DERSIG |
               SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_NULLDUMMY;
    }

    ValidationCache& GetValidationCache() override { return m_mempool.validation_cache; }
    bool IsCurrentForFeeEstimation() override { return true; }
};

/** Outpoints spent by txs that neither txs, the pool nor the coins fetched so far provide. */
std::vector<COutPoint> FindMissing(const CTxMemPool& pool, const std::vector<CTransactionRef>& txs, const FetchedCoins& fetched)
    EXCLUSIVE_LOCKS_REQUIRED(pool.cs)
{
    std::set<Txid> created;
    for (const auto& tx : txs) created.insert(tx->GetHash());
    std::set<COutPoint> missing;
    for (const auto& tx : txs) {
        if (tx->IsCoinBase() || pool.exists(tx->GetWitnessHash())) continue;
        for (const CTxIn& txin : tx->vin) {
            if (created.contains(txin.prevout.hash) || pool.exists(txin.prevout.hash) || fetched.Knows(txin.prevout)) continue;
            missing.insert(txin.prevout);
        }
    }
    return {missing.begin(), missing.end()};
}

std::vector<COutPoint> FindMissingForEntries(const CTxMemPool& pool, const std::vector<CTxMemPoolEntryRef>& entries, const FetchedCoins& fetched)
    EXCLUSIVE_LOCKS_REQUIRED(pool.cs)
{
    std::set<COutPoint> missing;
    for (const CTxMemPoolEntry& entry : entries) {
        for (const CTxIn& txin : entry.GetTx().vin) {
            if (pool.exists(txin.prevout.hash) || fetched.Knows(txin.prevout)) continue;
            missing.insert(txin.prevout);
        }
    }
    return {missing.begin(), missing.end()};
}

btcm_EntryInfo ToEntryInfo(const CTxMemPool& pool, const CTxMemPoolEntry& entry) EXCLUSIVE_LOCKS_REQUIRED(pool.cs)
{
    btcm_EntryInfo info{InitVersioned<btcm_EntryInfo>()};
    const FeePerWeight chunk{pool.GetMainChunkFeerate(entry)};
    Write32(entry.GetTx().GetHash(), info.txid);
    Write32(entry.GetTx().GetWitnessHash(), info.wtxid);
    info.fee = entry.GetFee();
    info.modified_fee = entry.GetModifiedFee();
    info.vsize = entry.GetTxSize();
    info.weight = entry.GetTxWeight();
    info.chunk_fee = chunk.fee;
    info.chunk_weight = chunk.size;
    info.ancestor_count = pool.GetAncestorCount(entry);
    info.descendant_count = pool.GetDescendantCount(entry);
    info.cluster_count = pool.GetCluster(entry.GetTx().GetHash()).size();
    info.time = count_seconds(entry.GetTime());
    info.height = entry.GetHeight();
    return info;
}

} // namespace

void btcm_Mempool::FinishReorg()
{
    // Coins are needed for the disconnected transactions, and for pool
    // transactions whose lock points or coinbase maturity must be re-checked.
    const auto needs_coins{[&](const CTxMemPoolEntry& entry, FetchedChainView& view) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return entry.GetSpendsCoinbase() || !TestLockPointValidity(view, entry.GetLockPoints());
    }};
    WithCoins(
        [&](const FetchedCoins& fetched) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, pool->cs) {
            if (!fork_height) return std::vector<COutPoint>{};
            CCoinsViewCache unused{&CoinsViewEmpty::Get()};
            FetchedChainView view{*this, fetched, unused};
            const auto& disconnected{disconnectpool.Transactions()};
            auto missing{FindMissing(*pool, {disconnected.begin(), disconnected.end()}, fetched)};
            std::vector<CTxMemPoolEntryRef> recheck;
            for (const CTxMemPoolEntry& entry : pool->entryAll()) {
                if (needs_coins(entry, view)) recheck.emplace_back(entry);
            }
            const auto more{FindMissingForEntries(*pool, recheck, fetched)};
            missing.insert(missing.end(), more.begin(), more.end());
            return missing;
        },
        [&](const FetchedCoins& fetched) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, pool->cs) {
            if (!fork_height) return;
            FetchedCoinsView base{fetched, tip.hash};
            CCoinsViewCache coins{&base};
            FetchedChainView view{*this, fetched, coins};
            // Pool transactions spending coins the new chain no longer has
            // would trip the reorg filter's consistency checks, so they leave first.
            for (const CTxMemPoolEntry& entry : pool->entryAll()) {
                if (std::ranges::any_of(entry.GetTx().vin, [&](const CTxIn& in) { return fetched.spent.contains(in.prevout); })) {
                    pool->removeRecursive(entry.GetTx(), MemPoolRemovalReason::REORG);
                }
            }
            UpdateMempoolForReorg(*pool, view, disconnectpool, /*add_to_mempool=*/true);
            fork_height.reset();
            reorg_blocks.clear();
        });
}

namespace util::log {
bool ShouldDebugLog(Category) { return false; }
bool ShouldTraceLog(Category) { return false; }
void Log(Entry entry)
{
    std::lock_guard lock{g_log_mutex};
    if (g_log_callback) g_log_callback(g_log_user_data, View(entry.message));
}
} // namespace util::log

void btcm_set_log_callback(btcm_LogCallback callback, void* user_data)
{
    std::lock_guard lock{g_log_mutex};
    g_log_callback = callback;
    g_log_user_data = user_data;
}

void btcm_config_init(btcm_Config* config, btcm_ChainType chain_type)
{
    const kernel::MemPoolOptions defaults{};
    btcm_Config value{InitVersioned<btcm_Config>()};
    value.chain_type = chain_type;
    value.max_size_bytes = defaults.max_size_bytes;
    value.expiry_seconds = count_seconds(defaults.expiry);
    value.min_relay_feerate = defaults.min_relay_feerate.GetFeePerK();
    value.incremental_relay_feerate = defaults.incremental_relay_feerate.GetFeePerK();
    value.require_standard = defaults.require_standard;
    value.check_ratio = defaults.check_ratio;
    *config = value;
}

void btcm_tip_init(btcm_Tip* tip) { *tip = InitVersioned<btcm_Tip>(); }
void btcm_coin_init(btcm_Coin* coin) { *coin = InitVersioned<btcm_Coin>(); }
void btcm_tx_outcome_init(btcm_TxOutcome* outcome) { *outcome = InitVersioned<btcm_TxOutcome>(); }
void btcm_entry_info_init(btcm_EntryInfo* info) { *info = InitVersioned<btcm_EntryInfo>(); }

void btcm_coin_batch_set(btcm_CoinBatch* batch, size_t index, const btcm_Coin* coin)
{
    btcm_Coin c{ReadVersioned(*coin, InitVersioned<btcm_Coin>())};
    Coin parsed{CTxOut{c.amount, CScript(c.script_pubkey, c.script_pubkey + c.script_pubkey_len)}, c.height, c.is_coinbase != 0};
    c.script_pubkey = nullptr;
    c.script_pubkey_len = 0;
    batch->coins.at(index).emplace(std::move(parsed), c);
}

btcm_Transaction* btcm_transaction_create(const void* raw, size_t raw_len)
{
    try {
        SpanReader stream{std::span{reinterpret_cast<const std::byte*>(raw), raw_len}};
        auto tx{std::make_shared<const CTransaction>(deserialize, TX_WITH_WITNESS, stream)};
        if (!stream.empty()) return nullptr;
        return btcm_Transaction::create(std::move(tx));
    } catch (const std::exception&) {
        return nullptr;
    }
}

btcm_Transaction* btcm_transaction_copy(const btcm_Transaction* tx)
{
    return btcm_Transaction::create(btcm_Transaction::get(tx));
}

void btcm_transaction_get_txid(const btcm_Transaction* tx, uint8_t txid[32])
{
    Write32(btcm_Transaction::get(tx)->GetHash(), txid);
}

void btcm_transaction_get_wtxid(const btcm_Transaction* tx, uint8_t wtxid[32])
{
    Write32(btcm_Transaction::get(tx)->GetWitnessHash(), wtxid);
}

int btcm_transaction_to_bytes(const btcm_Transaction* tx, btcm_WriteBytes writer, void* user_data)
{
    return WriteSerialized(TX_WITH_WITNESS(*btcm_Transaction::get(tx)), writer, user_data);
}

void btcm_transaction_destroy(btcm_Transaction* tx)
{
    delete tx;
}

btcm_Block* btcm_block_create(const void* raw, size_t raw_len)
{
    try {
        SpanReader stream{std::span{reinterpret_cast<const std::byte*>(raw), raw_len}};
        auto block{std::make_shared<CBlock>()};
        stream >> TX_WITH_WITNESS(*block);
        if (!stream.empty()) return nullptr;
        return btcm_Block::create(std::move(block));
    } catch (const std::exception&) {
        return nullptr;
    }
}

void btcm_block_get_hash(const btcm_Block* block, uint8_t hash[32])
{
    Write32(btcm_Block::get(block)->GetHash(), hash);
}

size_t btcm_block_count_transactions(const btcm_Block* block)
{
    return btcm_Block::get(block)->vtx.size();
}

const btcm_Transaction* btcm_block_get_transaction_at(const btcm_Block* block, size_t index)
{
    return btcm_Transaction::ref(&btcm_Block::get(block)->vtx.at(index));
}

int btcm_block_to_bytes(const btcm_Block* block, btcm_WriteBytes writer, void* user_data)
{
    return WriteSerialized(TX_WITH_WITNESS(*btcm_Block::get(block)), writer, user_data);
}

void btcm_block_destroy(btcm_Block* block)
{
    delete block;
}

btcm_Mempool* btcm_mempool_create(const btcm_Config* config, const btcm_Tip* tip, const btcm_Callbacks* callbacks)
{
    if (!callbacks->get_coins) return nullptr;
    btcm_Config defaults;
    btcm_config_init(&defaults, config->chain_type);
    const btcm_Config cfg{ReadVersioned(*config, defaults)};
    auto params{MakeParams(cfg.chain_type)};
    if (!params) return nullptr;
    CTxMemPool::Options opts{};
    opts.check_ratio = cfg.check_ratio;
    opts.max_size_bytes = cfg.max_size_bytes;
    opts.expiry = std::chrono::seconds{cfg.expiry_seconds};
    opts.min_relay_feerate = CFeeRate{cfg.min_relay_feerate};
    opts.incremental_relay_feerate = CFeeRate{cfg.incremental_relay_feerate};
    opts.require_standard = cfg.require_standard != 0;
    try {
        return new btcm_Mempool{std::move(params), ToTip(*tip), *callbacks, opts};
    } catch (const std::exception& e) {
        LogError("%s", e.what());
        return nullptr;
    }
}

void btcm_mempool_destroy(btcm_Mempool* mempool)
{
    delete mempool;
}

int btcm_mempool_block_connected(btcm_Mempool* mempool, const btcm_Block* block, const btcm_Tip* new_tip)
{
    const CBlock& b{*btcm_Block::get(block)};
    const Tip tip{ToTip(*new_tip)};
    bool reorg_pending;
    {
        LOCK2(::cs_main, mempool->pool->cs);
        if (b.hashPrevBlock != mempool->tip.hash || tip.hash != b.GetHash() || tip.height != mempool->tip.height + 1) return -1;
        mempool->tip = tip;
        ++mempool->generation;
        for (const auto& removed : mempool->pool->removeForBlock(b.vtx)) {
            mempool->events.Removed(removed.info.m_tx, MemPoolRemovalReason::BLOCK, /*sequence=*/0);
        }
        mempool->disconnectpool.removeForBlock(b.vtx);
        mempool->pool->AddTransactionsUpdated(1);
        if (mempool->fork_height) mempool->reorg_blocks.insert_or_assign(tip.height, tip.hash);
        reorg_pending = mempool->fork_height.has_value();
    }
    if (reorg_pending) mempool->FinishReorg();
    mempool->Dispatch();
    return 0;
}

int btcm_mempool_block_disconnected(btcm_Mempool* mempool, const btcm_Block* block, const btcm_Tip* new_tip)
{
    const CBlock& b{*btcm_Block::get(block)};
    const Tip tip{ToTip(*new_tip)};
    {
        LOCK2(::cs_main, mempool->pool->cs);
        if (b.GetHash() != mempool->tip.hash || tip.hash != b.hashPrevBlock || tip.height != mempool->tip.height - 1) return -1;
        for (auto&& evicted_tx : mempool->disconnectpool.AddTransactionsFromBlock(b.vtx)) {
            mempool->pool->removeRecursive(*evicted_tx, MemPoolRemovalReason::REORG);
        }
        mempool->reorg_blocks.erase(mempool->tip.height);
        mempool->fork_height = std::min(mempool->fork_height.value_or(mempool->tip.height), mempool->tip.height);
        mempool->tip = tip;
        ++mempool->generation;
        mempool->pool->AddTransactionsUpdated(1);
    }
    mempool->Dispatch();
    return 0;
}

btcm_SubmitResult* btcm_mempool_submit(btcm_Mempool* mempool, const btcm_Transaction* const* txs, size_t txs_len, btcm_SubmitFlags flags)
{
    if (txs_len == 0) return nullptr;
    SubmitResult out;
    for (size_t i{0}; i < txs_len; ++i) out.txs.push_back(btcm_Transaction::get(txs[i]));
    const bool test_accept{(flags & btcm_SubmitFlags_TEST_ACCEPT) != 0};
    const bool completed{mempool->WithCoins(
        [&](const FetchedCoins& fetched) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
            LOCK(mempool->pool->cs); // Already held by WithCoins.
            return FindMissing(*mempool->pool, out.txs, fetched);
        },
        [&](const FetchedCoins& fetched) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
            LOCK(mempool->pool->cs); // Already held by WithCoins.
            FetchedCoinsView base{fetched, mempool->tip.hash};
            CCoinsViewCache coins{&base};
            FetchedChainView view{*mempool, fetched, coins};
            if (out.txs.size() == 1) {
                out.results.emplace_back(TransactionResult{AcceptToMemoryPool(*mempool->pool, view, out.txs.front(), GetTime(),
                                                                              /*bypass_limits=*/false, test_accept)});
                return;
            }
            const auto res{ProcessNewPackage(*mempool->pool, view, out.txs, test_accept, /*client_maxfeerate=*/std::nullopt)};
            if (res.m_state.IsInvalid()) out.package_error = res.m_state.GetRejectReason();
            for (const auto& tx : out.txs) {
                const auto it{res.m_tx_results.find(tx->GetWitnessHash())};
                out.results.push_back(it == res.m_tx_results.end() ? std::nullopt : std::optional{TransactionResult{it->second}});
            }
        })};
    if (!completed) {
        out.package_error = "chain-tip-unstable";
        out.results.clear();
        out.results.resize(out.txs.size());
    }
    mempool->Dispatch();
    return btcm_SubmitResult::create(std::move(out));
}

void btcm_mempool_prioritise_transaction(btcm_Mempool* mempool, const uint8_t txid[32], int64_t delta)
{
    mempool->pool->PrioritiseTransaction(ReadTxid(txid), delta);
}

void btcm_mempool_check(btcm_Mempool* mempool)
{
    mempool->WithCoins(
        [&](const FetchedCoins& fetched) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
            LOCK(mempool->pool->cs); // Already held by WithCoins.
            return FindMissingForEntries(*mempool->pool, mempool->pool->entryAll(), fetched);
        },
        [&](const FetchedCoins& fetched) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
            LOCK(mempool->pool->cs); // Already held by WithCoins.
            FetchedCoinsView base{fetched, mempool->tip.hash};
            CCoinsViewCache coins{&base};
            mempool->pool->check(coins, mempool->tip.height + 1);
        });
}

size_t btcm_mempool_size(const btcm_Mempool* mempool)
{
    return mempool->pool->size();
}

size_t btcm_mempool_dynamic_memory_usage(const btcm_Mempool* mempool)
{
    return mempool->pool->DynamicMemoryUsage();
}

int64_t btcm_mempool_min_feerate(const btcm_Mempool* mempool)
{
    return std::max(mempool->pool->GetMinFee(), mempool->pool->m_opts.min_relay_feerate).GetFeePerK();
}

btcm_Transaction* btcm_mempool_get_transaction(const btcm_Mempool* mempool, const uint8_t txid[32])
{
    CTransactionRef tx{mempool->pool->get(ReadTxid(txid))};
    return tx ? btcm_Transaction::create(std::move(tx)) : nullptr;
}

int btcm_mempool_get_entry(const btcm_Mempool* mempool, const uint8_t txid[32], btcm_EntryInfo* info)
{
    const CTxMemPool& pool{*mempool->pool};
    LOCK(pool.cs);
    const CTxMemPoolEntry* entry{pool.GetEntry(ReadTxid(txid))};
    if (!entry) return -1;
    WriteVersioned(*info, ToEntryInfo(pool, *entry));
    return 0;
}

btcm_Snapshot* btcm_mempool_snapshot(const btcm_Mempool* mempool)
{
    const CTxMemPool& pool{*mempool->pool};
    LOCK(pool.cs);
    Snapshot snapshot{.entries = {}, .txs = {}, .sequence = pool.GetSequence()};
    for (const CTxMemPoolEntry& entry : pool.entryAll()) {
        snapshot.entries.push_back(ToEntryInfo(pool, entry));
        snapshot.txs.push_back(entry.GetSharedTx());
    }
    return btcm_Snapshot::create(std::move(snapshot));
}

size_t btcm_submit_result_count(const btcm_SubmitResult* result)
{
    return btcm_SubmitResult::get(result).txs.size();
}

void btcm_submit_result_get(const btcm_SubmitResult* result, size_t index, btcm_TxOutcome* outcome)
{
    const SubmitResult& res{btcm_SubmitResult::get(result)};
    const CTransaction& tx{*res.txs.at(index)};
    btcm_TxOutcome value{InitVersioned<btcm_TxOutcome>()};
    Write32(tx.GetHash(), value.txid);
    Write32(tx.GetWitnessHash(), value.wtxid);
    value.fee = value.vsize = value.effective_feerate = -1;
    const auto& tx_result{res.results.at(index)};
    if (!tx_result) {
        value.status = btcm_AcceptStatus_NOT_EVALUATED;
        WriteVersioned(*outcome, value);
        return;
    }
    const MempoolAcceptResult& r{tx_result->result};
    switch (r.m_result_type) {
    case MempoolAcceptResult::ResultType::VALID: value.status = btcm_AcceptStatus_VALID; break;
    case MempoolAcceptResult::ResultType::INVALID: value.status = btcm_AcceptStatus_INVALID; break;
    case MempoolAcceptResult::ResultType::MEMPOOL_ENTRY: value.status = btcm_AcceptStatus_MEMPOOL_ENTRY; break;
    case MempoolAcceptResult::ResultType::DIFFERENT_WITNESS: value.status = btcm_AcceptStatus_DIFFERENT_WITNESS; break;
    }
    value.fee = r.m_base_fees.value_or(-1);
    value.vsize = r.m_vsize.value_or(-1);
    value.effective_feerate = r.m_effective_feerate ? r.m_effective_feerate->GetFeePerK() : -1;
    if (r.m_other_wtxid) Write32(*r.m_other_wtxid, value.other_wtxid);
    value.reject_reason = View(tx_result->reject_reason);
    value.debug_message = View(tx_result->debug_message);
    WriteVersioned(*outcome, value);
}

btcm_StringView btcm_submit_result_get_package_error(const btcm_SubmitResult* result)
{
    return View(btcm_SubmitResult::get(result).package_error);
}

void btcm_submit_result_destroy(btcm_SubmitResult* result)
{
    delete result;
}

size_t btcm_snapshot_count(const btcm_Snapshot* snapshot)
{
    return btcm_Snapshot::get(snapshot).entries.size();
}

uint64_t btcm_snapshot_get_sequence(const btcm_Snapshot* snapshot)
{
    return btcm_Snapshot::get(snapshot).sequence;
}

void btcm_snapshot_get_entry(const btcm_Snapshot* snapshot, size_t index, btcm_EntryInfo* info)
{
    WriteVersioned(*info, btcm_Snapshot::get(snapshot).entries.at(index));
}

const btcm_Transaction* btcm_snapshot_get_transaction(const btcm_Snapshot* snapshot, size_t index)
{
    return btcm_Transaction::ref(&btcm_Snapshot::get(snapshot).txs.at(index));
}

void btcm_snapshot_destroy(btcm_Snapshot* snapshot)
{
    delete snapshot;
}

int btcm_compact_block_encode(const btcm_Block* block, uint64_t nonce, btcm_WriteBytes writer, void* user_data)
{
    return WriteSerialized(CBlockHeaderAndShortTxIDs{*btcm_Block::get(block), nonce}, writer, user_data);
}

btcm_Reconstruction* btcm_reconstruction_create(btcm_Mempool* mempool, const void* cmpctblock, size_t cmpctblock_len, btcm_ReadStatus* status)
{
    CBlockHeaderAndShortTxIDs cmpct;
    try {
        SpanReader stream{std::span{reinterpret_cast<const std::byte*>(cmpctblock), cmpctblock_len}};
        stream >> cmpct;
    } catch (const std::exception&) {
        *status = btcm_ReadStatus_INVALID;
        return nullptr;
    }
    const int next_height{WITH_LOCK(::cs_main, return mempool->tip.height + 1)};
    const bool segwit_active{next_height >= mempool->params->GetConsensus().DeploymentHeight(Consensus::DEPLOYMENT_SEGWIT)};
    auto rec{std::make_unique<btcm_Reconstruction>(PartiallyDownloadedBlock{mempool->pool.get()}, cmpct.BlockTxCount(), segwit_active)};
    const ReadStatus res{rec->partial.InitData(cmpct, /*extra_txn=*/{})};
    *status = ToC(res);
    if (res != READ_STATUS_OK) return nullptr;
    for (size_t i{0}; i < rec->tx_count; ++i) {
        if (!rec->partial.IsTxAvailable(i)) rec->missing.push_back(i);
    }
    return rec.release();
}

size_t btcm_reconstruction_missing_count(const btcm_Reconstruction* reconstruction)
{
    return reconstruction->missing.size();
}

uint32_t btcm_reconstruction_missing_index(const btcm_Reconstruction* reconstruction, size_t i)
{
    return reconstruction->missing.at(i);
}

btcm_Block* btcm_reconstruction_finish(btcm_Reconstruction* reconstruction, const btcm_Transaction* const* txs, size_t txs_len, btcm_ReadStatus* status)
{
    if (reconstruction->finished) {
        *status = btcm_ReadStatus_FAILED;
        return nullptr;
    }
    reconstruction->finished = true;
    std::vector<CTransactionRef> missing;
    for (size_t i{0}; i < txs_len; ++i) missing.push_back(btcm_Transaction::get(txs[i]));
    auto block{std::make_shared<CBlock>()};
    const ReadStatus res{reconstruction->partial.FillBlock(*block, missing, reconstruction->segwit_active)};
    *status = ToC(res);
    if (res != READ_STATUS_OK) return nullptr;
    return btcm_Block::create(std::move(block));
}

void btcm_reconstruction_destroy(btcm_Reconstruction* reconstruction)
{
    delete reconstruction;
}
