#include <array>
#include <cstddef>
#include <cstdint>
#include <primitives/transaction.h>
#include <random.h>
#include <serialize.h>
#include <streams.h>
#include <swiftsync.h>
#include <uint256.h>
#include <vector>

using namespace swiftsync;

Aggregate::Aggregate() : m_limb0(0), m_limb1(0)
{
    std::array<std::byte, 32> salt;
    FastRandomContext{}.fillrand(salt);
    HashWriter m_salted_hasher;
    m_salted_hasher.write(salt);
}

void Aggregate::Add(const COutPoint& outpoint)
{
    auto hash = (HashWriter(m_salted_hasher) << outpoint).GetSHA256();
    m_limb0 += hash.GetUint64(0);
    m_limb1 += hash.GetUint64(1);
}

void Aggregate::Spend(const COutPoint& outpoint)
{
    auto hash = (HashWriter(m_salted_hasher) << outpoint).GetSHA256();
    m_limb0 -= hash.GetUint64(0);
    m_limb1 -= hash.GetUint64(1);
}

Hintfile::Hintfile(AutoFile& file) : m_file(file.release())
{
    uint256 m_stop_hash;
    uint32_t m_stop_height;
    m_file >> m_stop_height;
    m_file >> m_stop_hash;
}

Hintfile Hintfile::FromExisting(AutoFile& file)
{
    return Hintfile(file);
}

Hintfile::Hintfile(AutoFile& file, const uint256& stop_hash, const uint32_t& stop_height) : m_file(file.release())
{
    m_file << stop_height;
    m_file << stop_hash;
}

Hintfile Hintfile::CreateNew(AutoFile& file, const uint256& stop_hash, const uint32_t& stop_height)
{
    return Hintfile(file, stop_hash, stop_height);
}

BlockUnspentHints::BlockUnspentHints(const std::vector<uint64_t> offsets)
{
    // Assuming a vector of ordered offsets is given, unpack into the literal indexes.
    std::vector<uint64_t> m_unspent_indexes;
    uint64_t prev = 0;
    for (const auto& offset : offsets) {
        auto next = prev + offset;
        m_unspent_indexes.push_back(next);
        prev = next;
    }
}

bool BlockUnspentHints::IsUnspent(const uint64_t index)
{
    auto found = std::find(m_unspent_indexes.begin(), m_unspent_indexes.end(), index);
    return found != m_unspent_indexes.end();
}

BlockUnspentHints Hintfile::ReadNextBlock()
{
    uint64_t num_unspent = ReadCompactSize(m_file);
    std::vector<uint64_t> offsets;
    offsets.reserve(num_unspent);
    for (uint64_t i = 0; i < num_unspent; i++) {
        offsets.push_back(ReadCompactSize(m_file));
    }
    return BlockUnspentHints(offsets);
}

bool Hintfile::WriteNextBlock(const std::vector<uint64_t>& unspent_offsets)
{
    WriteCompactSize(m_file, unspent_offsets.size());
    for (const auto& offset : unspent_offsets) {
        WriteCompactSize(m_file, offset);
    }
    return m_file.Commit();
}
