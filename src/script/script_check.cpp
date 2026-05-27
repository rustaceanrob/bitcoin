// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/script_check.h>

#include <script/interpreter.h>
#include <tinyformat.h>

std::optional<std::pair<ScriptError, std::string>> CScriptCheck::operator()()
{
    const CScript& scriptSig = ptxTo->vin[nIn].scriptSig;
    const CScriptWitness* witness = &ptxTo->vin[nIn].scriptWitness;
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    if (VerifyScript(scriptSig, m_tx_out.scriptPubKey, witness, m_flags, CachingTransactionSignatureChecker(ptxTo, nIn, m_tx_out.nValue, cacheStore, *m_signature_cache, *txdata), &error)) {
        return std::nullopt;
    } else {
        auto debug_str = strprintf("input %i of %s (wtxid %s), spending %s:%i", nIn, ptxTo->GetHash().ToString(), ptxTo->GetWitnessHash().ToString(), ptxTo->vin[nIn].prevout.hash.ToString(), ptxTo->vin[nIn].prevout.n);
        return std::make_pair(error, std::move(debug_str));
    }
}
