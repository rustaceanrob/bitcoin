#include "primitives/transaction.h"
#include <hash.h>
#include <cstdint>

/** An aggregate for the SwiftSync protocol.
 *This class is intentionally left opaque, as internal changes may occur,
 * but all aggregates will have the concept of "adding" and "spending" an
 * outpoint.
 *
 * The current implementation uses a salted SHA-256 hash, and updates 4
 * independent 32-bit limbs by dividing the hash into 4 parts and adding
 * or subtracting accordingly.
 * */
class Aggregate
{
private:
    uint64_t limb0, limb1, limb2, limb3;
    HashWriter m_salted_hasher;
public:
    Aggregate();
    bool IsZero() const { return limb0 == 0 && limb1 == 0 && limb2 == 0 && limb3 == 0; }
    void Add(const COutPoint& outpoint);
    void Spend(const COutPoint& outpoint);
};
