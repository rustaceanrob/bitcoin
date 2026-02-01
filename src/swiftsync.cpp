#include <swiftsync.h>

using namespace swiftsync;

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

bool HintsfileWriter::WriteNextUnspents(BlockHintsWriter& hints, uint32_t height)
{
    // First write the current file position for the current height in the header section.
    uint64_t curr_pos = m_file.size();
    uint64_t cursor = FILE_HEADER_LEN + (m_index * (sizeof(uint64_t) + sizeof(uint32_t)));
    m_file.seek(cursor, SEEK_SET);
    m_file << height;
    m_file << curr_pos;
    // Next append the positions of the unspent offsets in the block at this height.
    ++m_index;
    m_file.seek(curr_pos, SEEK_SET);
    m_file << BITSET(hints);
    return m_file.Commit();
}
