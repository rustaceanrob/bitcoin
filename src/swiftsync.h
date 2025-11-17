#include <cstdint>
#include <hash.h>
#include <optional>
#include <primitives/transaction.h>
#include <streams.h>
#include <uint256.h>
#include <vector>

namespace swiftsync {
/** An aggregate for the SwiftSync protocol.
 * This class is intentionally left opaque, as internal changes may occur,
 * but all aggregates will have the concept of "adding" and "spending" an
 * outpoint.
 *
 * The current implementation uses a salted SHA-256 hash and updates two
 * 64-bit integers by taking the first 16 bytes of the hash and adding or
 * subtracting according to if the outpoint was added or spent.
 * */
class Aggregate
{
private:
    uint64_t m_limb0, m_limb1;
    HashWriter m_salted_hasher;

public:
    Aggregate();
    bool IsZero() const { return m_limb0 == 0 && m_limb1 == 0; }
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
    Hintfile(AutoFile& file, const uint256& stop_hash, const uint32_t& stop_height);

public:
    Hintfile(AutoFile& file);
    // Construct a hint file and write the stop hash and height.
    static Hintfile CreateNew(AutoFile& file, const uint256& stop_hash, const uint32_t& stop_height);
    BlockUnspentHints ReadNextBlock();
    // Write the offsets of the unspent indexes to file, returning if the file commitment was successful.
    bool WriteNextBlock(const std::vector<uint64_t>& unspent_offsets);
    uint256 StopHash() { return m_stop_hash; };
    uint32_t StopHeight() { return m_stop_height; };
};

class Context
{
private:
    std::optional<Hintfile> m_hintfile{};
    Aggregate m_agg{};
    bool m_connecting_to_genesis{false};

public:
    Context();
    bool IsStartBlockGenesis() { return m_connecting_to_genesis; };
    bool IsActive() { return m_connecting_to_genesis && m_hintfile.has_value(); };
    void LoadHints(AutoFile& file);
    void StartBlockIsGenesis() { m_connecting_to_genesis = true; };
    uint256 StopHash() { return m_hintfile->StopHash(); };
    uint32_t StopHeight() { return m_hintfile->StopHeight(); };
    BlockUnspentHints ReadNextBlock() { return m_hintfile->ReadNextBlock(); };
    void Add(const COutPoint& outpoint) { m_agg.Add(outpoint); };
    void Spend(const COutPoint& outpoint) { m_agg.Spend(outpoint); };
    bool EmptySet() { return m_agg.IsZero(); };
};
} // namespace swiftsync
