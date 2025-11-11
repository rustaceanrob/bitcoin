#include "primitives/transaction.h"
#include <array>
#include <cstddef>
#include <random.h>
#include <swiftsync.h>

Aggregate::Aggregate() : limb0(0), limb1(0), limb2(0), limb3(0)
{
    std::array<std::byte, 32> salt;
    FastRandomContext{}.fillrand(salt);
    HashWriter m_salted_hasher;
    m_salted_hasher.write(salt);
}

void Aggregate::Add(const COutPoint& outpoint)
{
    auto hash = (HashWriter(m_salted_hasher) << outpoint).GetSHA256();
    auto a0 = hash.GetUint64(0);
    auto a1 = hash.GetUint64(1);
    auto a2 = hash.GetUint64(2);
    auto a3 = hash.GetUint64(3);
    limb0 += a0;
    limb1 += a1;
    limb2 += a2;
    limb3 += a3;
}

void Aggregate::Spend(const COutPoint& outpoint)
{
    auto hash = (HashWriter(m_salted_hasher) << outpoint).GetSHA256();
    auto a0 = hash.GetUint64(0);
    auto a1 = hash.GetUint64(1);
    auto a2 = hash.GetUint64(2);
    auto a3 = hash.GetUint64(3);
    limb0 -= a0;
    limb1 -= a1;
    limb2 -= a2;
    limb3 -= a3;
}
