#include <array>
#include <primitives/transaction.h>
#include <random.h>
#include <swiftsync.h>
#include <uint256.h>

Aggregate::Aggregate() : m_limb0(0), m_limb1(0)
{
    std::array<std::byte, 32> salt;
    FastRandomContext{}.fillrand(salt);
    HashWriter m_salted_hasher;
    m_salted_hasher.write(salt);
}

void Aggregate::Add(const COutPoint& outpoint)
{
    auto hash = (HashWriter(m_salted_hasher) << outpoint).GetSHA256();
    m_limb0 += hash.GetUint64(0);
    m_limb1 += hash.GetUint64(1);
}

void Aggregate::Spend(const COutPoint& outpoint)
{
    auto hash = (HashWriter(m_salted_hasher) << outpoint).GetSHA256();
    m_limb0 -= hash.GetUint64(0);
    m_limb1 -= hash.GetUint64(1);
}
