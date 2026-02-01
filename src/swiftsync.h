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

enum Encoding {
    Bitset,
};

struct HintsEncodeParams {
    const Encoding encoding;
    SER_PARAMS_OPFUNC
};

static constexpr HintsEncodeParams BITSET{.encoding = Encoding::Bitset};

class BlockHintsWriter
{
private:
    std::vector<bool> m_hints{};

public:
    void PushHighBit() noexcept { m_hints.push_back(true); };
    void PushLowBit() noexcept { m_hints.push_back(false); };

    template <typename Stream>
    inline void Serialize(Stream& s) const
    {
        SerializeHints(m_hints, s, s.template GetParams<HintsEncodeParams>());
    };
};

template <typename Stream>
void SerializeHints(const std::vector<bool> hints, Stream& s, const HintsEncodeParams& params)
{
    WriteCompactSize(s, hints.size());
    auto bit_pos{0};
    uint8_t curr_byte{0x00};
    for (const bool bit : hints) {
        curr_byte |= bit << bit_pos;
        bit_pos += 1;
        if (bit_pos == 8) {
            s << curr_byte;
            curr_byte = 0x00;
            bit_pos = 0;
        }
    }
    if (bit_pos != 0) {
        s << curr_byte;
    }
}

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
    bool WriteNextUnspents(BlockHintsWriter& hints, uint32_t height);
    // Close the underlying file.
    int Close() { return m_file.fclose(); };
    // Size of the file in megabytes.
    double SizeMb() { return double(m_file.size()) / 1000000.0; };
};
} // namespace swiftsync
#endif // BITCOIN_SWIFTSYNC_H
