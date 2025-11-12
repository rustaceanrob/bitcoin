#include <cstdint>
#include <hash.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <uint256.h>
#include <vector>

/** An aggregate for the SwiftSync protocol.
 * This class is intentionally left opaque, as internal changes may occur,
 * but all aggregates will have the concept of "adding" and "spending" an
 * outpoint.
 *
 * The current implementation uses a salted SHA-256 hash and updates a single
 * 64-bit integer by taking the first 8 bytes of the hash and adding or
 * subtracting according to if the outpoint was added or spent.
 * */
class Aggregate
{
private:
    uint64_t m_limb0, m_limb1, m_limb2, m_limb3;
    HashWriter m_salted_hasher;

public:
    Aggregate();
    bool IsZero() const { return m_limb0 == 0 && m_limb1 == 0 && m_limb2 == 0 && m_limb3 == 0; }
    void Add(const COutPoint& outpoint);
    void Spend(const COutPoint& outpoint);
};

/**
 * The unspent indexes of a block, assuming the list of block
 * outputs has been flattened.
 * */
class BlockUnspentHints
{
private:
    std::vector<uint64_t> m_unspent_indexes;

public:
    BlockUnspentHints(const std::vector<uint64_t> offsets);
    bool IsUnspent(const uint64_t index);
};

/**
 * A file that encodes the UTXO set state at a particular block hash.
 */
class Hintfile
{
private:
    AutoFile m_file;
    uint256 m_stop_hash;
    uint32_t m_stop_height;
    uint32_t m_curr_height;

public:
    // Construct a hint file and immediately read the stop hash and height.
    Hintfile(AutoFile file);
    // Construct a hint file and write the stop hash and height.
    Hintfile(AutoFile file, const uint256& stop_hash, const uint32_t& stop_height);
    BlockUnspentHints ReadNextBlock();
    bool WriteNextBlock(const std::vector<uint64_t>& unspent_offsets);
    uint256 StopHash() { return m_stop_hash; };
    uint32_t StopHeight() { return m_stop_height; };
    uint32_t CurrentHeight() { return m_curr_height; };
};
