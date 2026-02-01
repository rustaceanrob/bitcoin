#include <swiftsync.h>

#include <serialize.h>
#include <streams.h>

using namespace swiftsync;

std::vector<uint8_t> BlockHintsWriter::EncodeBitset()
{
    std::vector<uint8_t> enc{};
    uint8_t bit_pos{0};
    uint8_t curr_byte{0x00};
    for (const bool bit : m_hints) {
        curr_byte |= bit << bit_pos;
        bit_pos += 1;
        if (bit_pos == 8) {
            enc.emplace_back(curr_byte);
            curr_byte = 0x00;
            bit_pos = 0;
        }
    }
    if (bit_pos != 0 && curr_byte != 0x00) {
        enc.emplace_back(curr_byte);
        return enc;
    }
    // Remove trailing zeros. If an index is not present in the hints it is interpreted as spent.
    while (!enc.empty() && enc.back() == 0x00) {
        enc.pop_back();
    }
    return enc;
}

std::vector<uint8_t> BlockHintsWriter::EncodeRunlength()
{
    std::vector<uint8_t> buf{};
    VectorWriter writer{buf, 0};
    uint64_t curr_rl{0};
    for (const bool bit : m_hints) {
        if (bit) {
            writer << VARINT(curr_rl);
            curr_rl = 0;
        } else {
            ++curr_rl;
        }
    }
    return buf;
}

HintsfileWriter::HintsfileWriter(AutoFile& file, uint32_t preallocate) : m_file(file.release())
{
    uint64_t dummy_file_pos{};
    m_file << FILE_MAGIC;
    m_file << FILE_VERSION;
    m_file << preallocate;
    for (uint32_t height{}; height < preallocate; ++height) {
        m_file << height;
        m_file << dummy_file_pos;
    }
}

bool HintsfileWriter::WriteHints(BlockHintsWriter& hints, uint32_t height)
{
    auto bitset_encode = hints.EncodeBitset();
    auto rle_encode = hints.EncodeRunlength();
    Encoding enc{Encoding::Bitset};
    if (rle_encode.size() < bitset_encode.size()) {
        enc = Encoding::Runlength;
    }
    uint64_t curr_pos = m_file.size();
    uint64_t cursor = FILE_HEADER_LEN + (m_index * (sizeof(uint64_t) + sizeof(uint32_t)));
    m_file.seek(cursor, SEEK_SET);
    m_file << uint32_t{height * 2 + static_cast<bool>(enc)};
    m_file << curr_pos;
    ++m_index;
    m_file.seek(curr_pos, SEEK_SET);
    switch (enc) {
    case Encoding::Bitset: {
        m_file << VARINT(bitset_encode.size());
        m_file << bitset_encode;
        break;
    }
    case Encoding::Runlength: {
        m_file << VARINT(rle_encode.size());
        m_file << rle_encode;
        break;
    }
    }
    return m_file.Commit();
}
