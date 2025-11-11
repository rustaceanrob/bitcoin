#include <cstdint>
#include <hash.h>
#include <primitives/transaction.h>

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
