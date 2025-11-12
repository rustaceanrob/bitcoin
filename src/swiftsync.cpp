#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ios>
#include <primitives/transaction.h>
#include <random.h>
#include <serialize.h>
#include <streams.h>
#include <swiftsync.h>
#include <uint256.h>
#include <vector>

using namespace swiftsync;

Aggregate::Aggregate()
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

HintfileWriter::HintfileWriter(AutoFile& file, const uint32_t& preallocate) : m_file(file.release())
{
    uint64_t dummy_file_pos{0};
    m_file << FILE_MAGIC;
    m_file << preallocate;
    for (uint32_t i = 0; i < preallocate; i++) {
        m_file << dummy_file_pos;
    }
}

bool HintfileWriter::WriteNextUnspents(const std::vector<uint64_t>& unspent_offsets)
{
    // First write the current file position for the current height in the header section.
    uint64_t curr_pos = m_file.size();
    uint64_t cursor = HEADER_LEN + (m_index * sizeof(uint64_t));
    m_file.seek(cursor, SEEK_SET);
    m_file << curr_pos;
    // Next append the positions of the unspent offsets in the block at this height.
    m_file.seek(curr_pos, SEEK_SET);
    WriteCompactSize(m_file, unspent_offsets.size());
    for (const auto& offset : unspent_offsets) {
        WriteCompactSize(m_file, offset);
    }
    m_index++;
    return m_file.Commit();
}

HintfileReader::HintfileReader(AutoFile& file) : m_file(file.release())
{
    uint32_t m_stop_height;
    std::array<uint8_t, 4> magic{};
    m_file >> magic;
    if (magic != FILE_MAGIC) {
        throw std::ios_base::failure("HintfileReader: This is not a hint file.");
    }
    m_file >> m_stop_height;
    for (uint32_t height = 1; height <= m_stop_height; height++) {
        uint64_t file_pos;
        m_file >> file_pos;
        m_height_to_file_pos.emplace(height, file_pos);
    }
}

std::vector<uint64_t> HintfileReader::ReadBlock(const uint32_t& height)
{
    uint64_t file_pos = m_height_to_file_pos.at(height);
    m_file.seek(file_pos, SEEK_SET);
    uint64_t num_unspents = ReadCompactSize(m_file);
    std::vector<uint64_t> offsets{};
    offsets.reserve(num_unspents);
    for (uint64_t i = 0; i < num_unspents; i++) {
        offsets.push_back(ReadCompactSize(m_file));
    }
    return offsets;
}
