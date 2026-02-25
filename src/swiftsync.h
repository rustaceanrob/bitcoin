// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SWIFTSYNC_H
#define BITCOIN_SWIFTSYNC_H

#include <serialize.h>
#include <span.h>
#include <streams.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <vector>

namespace swiftsync {
inline constexpr std::array<uint8_t, 4> FILE_MAGIC = {0x55, 0x54, 0x58, 0x4f};
const uint8_t FILE_VERSION = 0x00;

/**
 * Elias-Fano is a representation of monotonically increasing elements that efficiently represents `n` elements in a universe of `[0, m)`.
 * The low bits of a number are represented in a bitset, while the high bits are encoded unary.
 */
class EliasFano
{
private:
    uint32_t m{};
    uint32_t n{};
    std::vector<uint8_t> low{};
    std::vector<uint8_t> high{};

    EliasFano(uint32_t m, uint32_t n, std::vector<uint8_t> low, std::vector<uint8_t> high) : m{m}, n{n}, low{low}, high{high} {}

    /**
     * The number of low bits to use in the representation is computed as `floor(log_2((m + 1 / n)))` where `n` is the size of the list and `m` is the largest element.
     * The bit width is `1 + floor(log_2(x))`.
     */
    static inline uint8_t ComputeL(uint32_t m, uint32_t n)
    {
        return std::bit_width((m + 1) / n) - 1;
    }

    /**
     * This function takes the first `l` bits of a list of numbers and packs them in a bitmap.
     * The bits are inserted in most significant bit order.
     */
    static inline std::vector<uint8_t> PackLowBits(std::span<uint32_t> elements, uint8_t l)
    {
        std::vector<uint8_t> low_bits{};
        if (l == 0) {
            return low_bits;
        }
        uint32_t mask = (1 << l) - 1;
        uint8_t curr_byte{};
        uint8_t bit_pos{};
        for (const uint32_t element : elements) {
            uint32_t low = element & mask;
            for (uint8_t shift{}; shift < l; ++shift) {
                uint8_t bit = ((low >> shift) & 1);
                curr_byte |= bit << (7 - bit_pos);
                ++bit_pos;
                if (bit_pos == 8) {
                    low_bits.push_back(curr_byte);
                    bit_pos = 0x00;
                    curr_byte = 0x00;
                }
            }
        }
        if (bit_pos > 0) {
            low_bits.push_back(curr_byte);
        }
        return low_bits;
    }
    /**
     * Encode the high bits of an element with unary. For example, if the high bits are 3, unary encoding will be `0001`, with `1` being the termination bit.
     * Rather than encoding the literal high bits, the difference between the previous and next high bits are encoded. So for 3 and 7, the subsequent encoding
     * is `000100001`
     */
    static inline std::vector<uint8_t> UnaryEncodeHighBits(std::span<uint32_t> elements, uint8_t l)
    {
        std::vector<uint8_t> high_enc{};
        uint8_t curr_byte{};
        uint8_t bit_pos{};
        uint32_t prev{};
        for (const uint32_t element : elements) {
            uint32_t current{element >> l};
            uint32_t delta{current - prev};
            prev = current;
            for (uint32_t no_op = 0; no_op < delta; ++no_op) {
                ++bit_pos;
                if (bit_pos == 8) {
                    high_enc.push_back(curr_byte);
                    bit_pos = 0x00;
                    curr_byte = 0x00;
                }
            }
            curr_byte |= 1 << (7 - bit_pos);
            ++bit_pos;
            if (bit_pos == 8) {
                high_enc.push_back(curr_byte);
                bit_pos = 0x00;
                curr_byte = 0x00;
            }
        }
        if (bit_pos > 0) {
            high_enc.push_back(curr_byte);
        }
        return high_enc;
    }

public:
    EliasFano() = default;
    /**
     * Compress an ascending list of elements.
     */
    static EliasFano Compress(std::span<uint32_t> elements)
    {
        assert(std::is_sorted(elements.begin(), elements.end()));
        if (elements.empty()) {
            return EliasFano();
        }
        // The list is sorted, so `back` is the largest element.
        uint32_t m = elements.back();
        uint32_t n = elements.size();
        uint8_t l = EliasFano::ComputeL(m, n);
        auto low = EliasFano::PackLowBits(elements, l);
        auto high = EliasFano::UnaryEncodeHighBits(elements, l);
        return EliasFano(m, n, low, high);
    }

    /**
     * Decompress an ascending list of elements.
     */
    std::vector<uint32_t> Decompress()
    {
        std::vector<uint32_t> elements{};
        elements.reserve(n);
        if (n == 0) {
            return elements;
        }
        uint8_t l = ComputeL(m, n);
        size_t low_byte_pos{};
        uint8_t low_bit_pos{};
        size_t high_byte_pos{};
        uint8_t high_bit_pos{};
        uint32_t high_prefix{};
        for (uint32_t i{0}; i < n; ++i) {
            uint32_t low_val{};
            for (uint8_t shift{}; shift < l; ++shift) {
                uint32_t bit = (low[low_byte_pos] >> (7 - low_bit_pos)) & 1;
                low_val |= bit << shift;
                ++low_bit_pos;
                if (low_bit_pos == 8) {
                    ++low_byte_pos;
                    low_bit_pos = 0;
                }
            }
            for (;;) {
                uint32_t bit = (high[high_byte_pos] >> (7 - high_bit_pos)) & 1;
                high_bit_pos += 1;
                if (high_bit_pos == 8) {
                    ++high_byte_pos;
                    high_bit_pos = 0;
                }
                if (bit == 1) {
                    break;
                }
                ++high_prefix;
            }
            elements.push_back((high_prefix << l) | low_val);
        }
        return elements;
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        WriteCompactSize(s, n);
        if (n == 0) {
            return;
        }
        WriteCompactSize(s, m);
        ::Serialize(s, MakeByteSpan(low));
        ::Serialize(s, MakeByteSpan(high));
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        n = ReadCompactSize(s);
        if (n == 0) {
            return;
        }
        m = ReadCompactSize(s);
        size_t l{EliasFano::ComputeL(m, n)};
        // Replace with CeilDiv
        size_t low_bytes = ((n * l) + 7) / 8;
        low.resize(low_bytes);
        ::Unserialize(s, MakeWritableByteSpan(low));
        size_t high_bytes = ((n + (m >> l)) + 7) / 8;
        high.resize(high_bytes);
        ::Unserialize(s, MakeWritableByteSpan(high));
    }
};

/**
 * Simple wrapper class to assist in writing UTXO set hints to file.
 *
 * The hints of a block are represented as the Elias-Fano encoding of the indices within a block that will remain unspent.
 */
class HintsfileWriter
{
private:
    AutoFile m_file;

public:
    /**
     * Write the file magic and version number to file.
     */
    HintsfileWriter(AutoFile& file);
    /**
     * Write the termination height this file encodes for.
     */
    bool WriteStopHeight(uint32_t stop);
    /**
     * Write the hints for a block.
     */
    bool WriteHints(const EliasFano& ef);
};
} // namespace swiftsync

#endif // BITCOIN_SWIFTSYNC_H
