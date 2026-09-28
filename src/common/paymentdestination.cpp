// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/paymentdestination.h>

#include <addresstype.h>
#include <chainparams.h>
#include <common/bip352.h>
#include <consensus/amount.h>
#include <key_io.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <util/expected.h>
#include <util/overloaded.h>
#include <util/strencodings.h>

#include <string>
#include <string_view>
#include <utility>
#include <variant>

class CFeeRate;

util::Expected<PaymentDestination, std::string> PaymentDestination::FromString(std::string_view str)
{
    const CChainParams& params = Params();
    const std::string& sp_hrp = params.SilentPaymentsHRP();
    if (ToLower(str.substr(0, sp_hrp.size())) == sp_hrp) {
        auto sp = bip352::DecodeSilentPaymentsAddress(std::string{str}, params);
        if (!sp) return util::Unexpected{std::move(sp.error())};
        return PaymentDestination(std::move(*sp));
    }

    std::string err;
    CTxDestination dest = DecodeDestination(std::string{str}, err);
    if (!IsValidDestination(dest)) {
        return util::Unexpected{err.empty() ? std::string{"Invalid address"} : std::move(err)};
    }
    return PaymentDestination(std::move(dest));
}

PaymentDestination PaymentDestination::FromTxDestination(const CTxDestination& dest)
{
    return PaymentDestination(dest);
}

uint64_t PaymentDestination::GetSerializeSize() const
{
    return std::visit(util::Overloaded{
        [](const CTxDestination& dest) -> uint64_t {
            return ::GetSerializeSize(CTxOut(0, GetScriptForDestination(dest)));
        },
        [](const bip352::SilentPaymentsDestination&) -> uint64_t {
            return ::GetSerializeSize(CTxOut(0, GetScriptForDestination(WitnessV1Taproot{})));
        },
    }, m_destination);
}

bool PaymentDestination::IsDust(CAmount amt, const CFeeRate& dust_relay_fee) const
{
    return std::visit(util::Overloaded{
        [amt, &dust_relay_fee](const CTxDestination& dest) {
            return ::IsDust(CTxOut(amt, GetScriptForDestination(dest)), dust_relay_fee);
        },
        [amt, &dust_relay_fee](const bip352::SilentPaymentsDestination&) {
            return ::IsDust(CTxOut(amt, GetScriptForDestination(WitnessV1Taproot{})), dust_relay_fee);
        },
    }, m_destination);
}

