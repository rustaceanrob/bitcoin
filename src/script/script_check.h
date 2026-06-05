// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SCRIPT_CHECK_H
#define BITCOIN_SCRIPT_SCRIPT_CHECK_H

#include <primitives/transaction.h>
#include <script/script_error.h>
#include <script/verify_flags.h>

#include <optional>
#include <string>
#include <type_traits>
#include <utility>

class SignatureCache;
struct PrecomputedTransactionData;

/**
 * Closure representing one script verification
 * Note that this stores references to the spending transaction
 */
class CScriptCheck
{
private:
    CTxOut m_tx_out;
    const CTransaction* ptxTo;
    unsigned int nIn;
    script_verify_flags m_flags;
    bool cacheStore;
    PrecomputedTransactionData* txdata;
    SignatureCache* m_signature_cache;

public:
    CScriptCheck(const CTxOut& outIn, const CTransaction& txToIn, SignatureCache& signature_cache, unsigned int nInIn, script_verify_flags flags, bool cacheIn, PrecomputedTransactionData* txdataIn) : m_tx_out(outIn), ptxTo(&txToIn), nIn(nInIn), m_flags(flags), cacheStore(cacheIn), txdata(txdataIn), m_signature_cache(&signature_cache) {}

    CScriptCheck(const CScriptCheck&) = delete;
    CScriptCheck& operator=(const CScriptCheck&) = delete;
    CScriptCheck(CScriptCheck&&) = default;
    CScriptCheck& operator=(CScriptCheck&&) = default;

    std::optional<std::pair<ScriptError, std::string>> operator()();
};

// CScriptCheck is used a lot in std::vector, make sure that's efficient
static_assert(std::is_nothrow_move_assignable_v<CScriptCheck>);
static_assert(std::is_nothrow_move_constructible_v<CScriptCheck>);
static_assert(std::is_nothrow_destructible_v<CScriptCheck>);

#endif // BITCOIN_SCRIPT_SCRIPT_CHECK_H
