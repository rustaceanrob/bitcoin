// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_PAYMENTDESTINATION_H
#define BITCOIN_COMMON_PAYMENTDESTINATION_H

#include <addresstype.h>
#include <common/bip352.h>
#include <consensus/amount.h>
#include <util/expected.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

class CFeeRate;

/**
 * A target destination for a payment. This class contains some meta information,
 * like the serialized size of the output or if the payment is considered dust.
 * However, the final output script may not be determined until a later point in the
 * transaction construction process.
 */
class PaymentDestination
{
private:
    std::variant<CTxDestination, bip352::SilentPaymentsDestination> m_destination;

    explicit PaymentDestination(CTxDestination dest) : m_destination(std::move(dest)) {}
    explicit PaymentDestination(bip352::SilentPaymentsDestination dest) : m_destination(std::move(dest)) {}

public:
    /** Parse a string as a destination for payment or error if the string is invalid. */
    static util::Expected<PaymentDestination, std::string> FromString(std::string_view str);

    /** Build a payment destination from an existing `CTxDestination`. This does not validate the `CTxDestination`. */
    static PaymentDestination FromTxDestination(const CTxDestination& dest);

    /** Would an output to this destination be economically spendable in the future. */
    bool IsDust(CAmount amt, const CFeeRate& dust_relay_fee) const;

    /** Get the serialized size of the destination. */
    uint64_t GetSerializeSize() const;

    /** Access the underlying alternative or nullptr if it is not present. */
    template<typename T>
    const T* get_if() const { return std::get_if<T>(&m_destination); }
};

#endif // BITCOIN_COMMON_PAYMENTDESTINATION_H
