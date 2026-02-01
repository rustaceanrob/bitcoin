#ifndef BITCOIN_SWIFTSYNC_H
#define BITCOIN_SWIFTSYNC_H
#include <serialize.h>
#include <streams.h>

#include <array>
#include <cstdint>
#include <vector>

namespace swiftsync {
inline constexpr std::array<uint8_t, 4> FILE_MAGIC = {0x55, 0x54, 0x58, 0x4f};
const uint8_t FILE_VERSION = 0x00;
// file magic length + version + height
const uint64_t FILE_HEADER_LEN = 9;

enum class Encoding : bool {
    Bitset = true,
    Runlength = false,
};

class BlockHintsWriter
{
private:
    std::vector<bool> m_hints{};

public:
    std::vector<uint8_t> EncodeBitset();
    std::vector<uint8_t> EncodeRunlength();
    void PushHighBit() noexcept { m_hints.push_back(true); };
    void PushLowBit() noexcept { m_hints.push_back(false); };
};

/**
 * Create a new hint file for writing.
 */
class HintsfileWriter
{
private:
    AutoFile m_file;
    uint32_t m_index{};

public:
    // Create a new hint file writer that will encode `preallocate` number of blocks.
    HintsfileWriter(AutoFile& file, uint32_t preallocate);
    ~HintsfileWriter()
    {
        (void)m_file.fclose();
    }
    // Write the next hints to file.
    bool WriteHints(BlockHintsWriter& hints, uint32_t height);
    // Close the underlying file.
    int Close() { return m_file.fclose(); };
    // Size of the file in megabytes.
    double SizeMb() { return double(m_file.size()) / 1000000.0; };
};
} // namespace swiftsync
#endif // BITCOIN_SWIFTSYNC_H
