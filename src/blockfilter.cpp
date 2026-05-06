// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cassert>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <mutex>
#include <queue>
#include <set>
#include <stack>
#include <string_view>

#include <blockfilter.h>
#include "util/overflow.h"
#include <crypto/siphash.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <undo.h>
#include <util/golombrice.h>
#include <util/string.h>

using util::Join;

static const std::map<BlockFilterType, std::string> g_filter_types = {
    {BlockFilterType::BASIC, "basic"},
};

uint64_t GCSFilter::HashToRange(const Element& element) const
{
    uint64_t hash = CSipHasher(m_params.m_siphash_k0, m_params.m_siphash_k1)
        .Write(element)
        .Finalize();
    return FastRange64(hash, m_F);
}

std::vector<uint64_t> GCSFilter::BuildHashedSet(const ElementSet& elements) const
{
    std::vector<uint64_t> hashed_elements;
    hashed_elements.reserve(elements.size());
    for (const Element& element : elements) {
        hashed_elements.push_back(HashToRange(element));
    }
    std::sort(hashed_elements.begin(), hashed_elements.end());
    return hashed_elements;
}

GCSFilter::GCSFilter(const Params& params)
    : m_params(params), m_N(0), m_F(0), m_encoded{0}
{}

GCSFilter::GCSFilter(const Params& params, std::vector<unsigned char> encoded_filter, bool skip_decode_check)
    : m_params(params), m_encoded(std::move(encoded_filter))
{
    SpanReader stream{m_encoded};

    uint64_t N = ReadCompactSize(stream);
    m_N = static_cast<uint32_t>(N);
    if (m_N != N) {
        throw std::ios_base::failure("N must be <2^32");
    }
    m_F = static_cast<uint64_t>(m_N) * static_cast<uint64_t>(m_params.m_M);

    if (skip_decode_check) return;

    // Verify that the encoded filter contains exactly N elements. If it has too much or too little
    // data, a std::ios_base::failure exception will be raised.
    BitStreamReader bitreader{stream};
    for (uint64_t i = 0; i < m_N; ++i) {
        GolombRiceDecode(bitreader, m_params.m_P);
    }
    if (!stream.empty()) {
        throw std::ios_base::failure("encoded_filter contains excess data");
    }
}

GCSFilter::GCSFilter(const Params& params, const ElementSet& elements)
    : m_params(params)
{
    size_t N = elements.size();
    m_N = static_cast<uint32_t>(N);
    if (m_N != N) {
        throw std::invalid_argument("N must be <2^32");
    }
    m_F = static_cast<uint64_t>(m_N) * static_cast<uint64_t>(m_params.m_M);

    VectorWriter stream{m_encoded, 0};

    WriteCompactSize(stream, m_N);

    if (elements.empty()) {
        return;
    }

    BitStreamWriter bitwriter{stream};

    uint64_t last_value = 0;
    for (uint64_t value : BuildHashedSet(elements)) {
        uint64_t delta = value - last_value;
        GolombRiceEncode(bitwriter, m_params.m_P, delta);
        last_value = value;
    }

    bitwriter.Flush();
}

bool GCSFilter::MatchInternal(const uint64_t* element_hashes, size_t size) const
{
    SpanReader stream{m_encoded};

    // Seek forward by size of N
    uint64_t N = ReadCompactSize(stream);
    assert(N == m_N);

    BitStreamReader bitreader{stream};

    uint64_t value = 0;
    size_t hashes_index = 0;
    for (uint32_t i = 0; i < m_N; ++i) {
        uint64_t delta = GolombRiceDecode(bitreader, m_params.m_P);
        value += delta;

        while (true) {
            if (hashes_index == size) {
                return false;
            } else if (element_hashes[hashes_index] == value) {
                return true;
            } else if (element_hashes[hashes_index] > value) {
                break;
            }

            hashes_index++;
        }
    }

    return false;
}

bool GCSFilter::Match(const Element& element)
{
    uint64_t query = HashToRange(element);
    return MatchInternal(&query, 1);
}

bool GCSFilter::MatchAny(const ElementSet& elements)
{
    const std::vector<uint64_t> queries = BuildHashedSet(elements);
    return MatchInternal(queries.data(), queries.size());
}

uint64_t BinaryFuseFilter::Hash(const BinaryFuseFilter::Element& element)
{
    return CSipHasher(m_siphash_k0, m_siphash_k1)
        .Write(element)
        .Finalize();
}

uint64_t BinaryFuseFilter::Mix(uint64_t key, uint8_t times) {
    auto x = key;
    for (uint8_t i{0}; i < times; ++i) {
        x ^= x >> 33;
        x *= 0xff51afd7ed558ccdULL;
        x ^= x >> 33;
        x *= 0xc4ceb9fe1a85ec53ULL;
        x ^= x >> 33;
    }
    return x;
}

uint16_t BinaryFuseFilter::Fingerprint(uint64_t key)
{
    return static_cast<uint16_t>(Mix(key, 4));
}

std::tuple<uint32_t, uint32_t, uint32_t> BinaryFuseFilter::Slots(const uint64_t key)
{
    uint32_t start_seg = key & (m_num_segments - m_arity);
    const auto h0_entropy = Mix(key, 1);
    const auto h1_entropy = Mix(key, 2);
    const auto h2_entropy = Mix(key, 3);
    uint32_t h0 = static_cast<uint32_t>((start_seg + 0) * m_segment_len + FastRange32(h0_entropy, m_segment_len));
    uint32_t h1 = static_cast<uint32_t>((start_seg + 1) * m_segment_len + FastRange32(h1_entropy, m_segment_len));
    uint32_t h2 = static_cast<uint32_t>((start_seg + 2) * m_segment_len + FastRange32(h2_entropy, m_segment_len));
    return {h0, h1, h2};
}

bool BinaryFuseFilter::Query(const Element& element)
{
    const auto key = Hash(element);
    const auto [h0, h1, h2] = Slots(key);
    const auto f = Fingerprint(key);
    return f == (m_fingerprints[h0] ^ m_fingerprints[h1] ^ m_fingerprints[h2]);
}

BinaryFuseFilter::BinaryFuseFilter(const ElementSet& elements, const uint256& hash) {
    m_siphash_k0 = hash.GetUint64(0);
    m_siphash_k1 = hash.GetUint64(1);
    const uint32_t n = static_cast<uint32_t>(elements.size());
    const double exp = std::floor((std::log(static_cast<double>(n)) / std::log(3.33) + 2.25));
    m_segment_len = std::max(uint32_t{4}, uint32_t{1} << static_cast<uint32_t>(exp));
    auto array_len = static_cast<uint32_t>(std::ceil(n * 1.125));
    m_num_segments = std::max(CeilDiv(array_len, m_segment_len), m_arity);
    array_len = m_num_segments * m_segment_len;
    m_fingerprints.assign(array_len, 0);
    std::vector degrees = std::vector<Degree>(array_len);
    degrees.assign(array_len, 0);
    for (const auto& element : elements) {
        const auto key = Hash(element);
        auto [h0, h1, h2] = Slots(key);
        degrees[h0].m_degree++; degrees[h0].m_xor ^= key;
        degrees[h1].m_degree++; degrees[h1].m_xor ^= key;
        degrees[h2].m_degree++; degrees[h2].m_xor ^= key;
    }
    std::queue q = std::queue<uint32_t>{};
    for (uint32_t i{0}; i < array_len; ++i) {
        if (degrees[i].m_degree == 1) {
            q.push(i);
        }
    }
    assert(q.size() > 1);
    std::stack p = std::stack<Assignment>{};
    while (!q.empty()) {
        const auto index = q.front();
        q.pop();
        if (degrees[index].m_degree != 1) continue;
        uint64_t hash = degrees[index].m_xor;
        p.emplace(index, hash);
        const auto [h0, h1, h2] = Slots(hash);
        degrees[h0].m_degree--;
        degrees[h1].m_degree--;
        degrees[h2].m_degree--;
        degrees[h0].m_xor ^= hash;
        degrees[h1].m_xor ^= hash;
        degrees[h2].m_xor ^= hash;
        if (degrees[h0].m_degree == 1) q.push(h0);
        if (degrees[h1].m_degree == 1) q.push(h1);
        if (degrees[h2].m_degree == 1) q.push(h2);
    }
    // check P is size N
    assert(p.size() == n);
    while (!p.empty()) {
        const auto assignment = p.top();
        p.pop();
        const auto hash = assignment.m_hash;
        const auto f = Fingerprint(hash);
        const auto [h0, h1, h2] = Slots(hash);
        const auto i = assignment.m_index;
        m_fingerprints[i] = f ^ m_fingerprints[h0] ^ m_fingerprints[h1] ^ m_fingerprints[h2];
    }
    DataStream writer{m_encoded};
    this->Serialize(writer);
}

bool BinaryFuseFilter::MatchAny(const ElementSet& elements) {
    for (const auto& element : elements) {
        if (Match(element)) {
            return true;
        }
    }
    return false;
}

bool BinaryFuseFilter::Match(const Element& element) {
    return Query(element);
}

const std::string& BlockFilterTypeName(BlockFilterType filter_type)
{
    static std::string unknown_retval;
    auto it = g_filter_types.find(filter_type);
    return it != g_filter_types.end() ? it->second : unknown_retval;
}

bool BlockFilterTypeByName(std::string_view name, BlockFilterType& filter_type)
{
    for (const auto& entry : g_filter_types) {
        if (entry.second == name) {
            filter_type = entry.first;
            return true;
        }
    }
    return false;
}

const std::set<BlockFilterType>& AllBlockFilterTypes()
{
    static std::set<BlockFilterType> types;

    static std::once_flag flag;
    std::call_once(flag, []() {
            for (const auto& entry : g_filter_types) {
                types.insert(entry.first);
            }
        });

    return types;
}

const std::string& ListBlockFilterTypes()
{
    static std::string type_list{Join(g_filter_types, ", ", [](const auto& entry) { return entry.second; })};

    return type_list;
}

static BlockFilterBase::ElementSet BasicFilterElements(const CBlock& block,
                                                 const CBlockUndo& block_undo)
{
    BlockFilterBase::ElementSet elements;

    for (const CTransactionRef& tx : block.vtx) {
        for (const CTxOut& txout : tx->vout) {
            const CScript& script = txout.scriptPubKey;
            if (script.empty() || script[0] == OP_RETURN) continue;
            elements.emplace(script.begin(), script.end());
        }
    }

    for (const CTxUndo& tx_undo : block_undo.vtxundo) {
        for (const Coin& prevout : tx_undo.vprevout) {
            const CScript& script = prevout.out.scriptPubKey;
            if (script.empty()) continue;
            elements.emplace(script.begin(), script.end());
        }
    }

    return elements;
}

BlockFilter::BlockFilter(BlockFilterType filter_type, const uint256& block_hash,
                         std::vector<unsigned char> filter, bool skip_decode_check)
    : m_filter_type(filter_type), m_block_hash(block_hash)
{
    GCSFilter::Params params;
    if (!BuildParams(params)) {
        throw std::invalid_argument("unknown filter_type");
    }
    m_filter = std::make_unique<GCSFilter>(params, std::move(filter), skip_decode_check);
}

BlockFilter::BlockFilter(BlockFilterType filter_type, const CBlock& block, const CBlockUndo& block_undo)
    : m_filter_type(filter_type), m_block_hash(block.GetHash())
{
    GCSFilter::Params params;
    if (!BuildParams(params)) {
        throw std::invalid_argument("unknown filter_type");
    }
    m_filter = std::make_unique<GCSFilter>(params, BasicFilterElements(block, block_undo));
}

bool BlockFilter::BuildParams(GCSFilter::Params& params) const
{
    switch (m_filter_type) {
    case BlockFilterType::BASIC:
        params.m_siphash_k0 = m_block_hash.GetUint64(0);
        params.m_siphash_k1 = m_block_hash.GetUint64(1);
        params.m_P = BASIC_FILTER_P;
        params.m_M = BASIC_FILTER_M;
        return true;
    case BlockFilterType::INVALID:
        return false;
    }

    return false;
}

uint256 BlockFilter::GetHash() const
{
    return Hash(GetEncodedFilter());
}

uint256 BlockFilter::ComputeHeader(const uint256& prev_header) const
{
    return Hash(GetHash(), prev_header);
}
