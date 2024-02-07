// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KEY_IO_H
#define BITCOIN_KEY_IO_H

#include <addresstype.h>
#include <chainparams.h>
#include <common/bip352.h>
#include <key.h>
#include <pubkey.h>

#include <optional>
#include <string>

CKey DecodeSecret(const std::string& str);
std::string EncodeSecret(const CKey& key);

CExtKey DecodeExtKey(const std::string& str);
std::string EncodeExtKey(const CExtKey& extkey);
CExtPubKey DecodeExtPubKey(const std::string& str);
std::string EncodeExtPubKey(const CExtPubKey& extpubkey);

std::string EncodeDestination(const CTxDestination& dest);
CTxDestination DecodeDestination(const std::string& str);
CTxDestination DecodeDestination(const std::string& str, std::string& error_msg, std::vector<int>* error_locations = nullptr);
bool IsValidDestinationString(const std::string& str);
bool IsValidDestinationString(const std::string& str, const CChainParams& params);

//! Decode a BIP352 "sp1..." address. Returns nullopt on failure; sets error_str with the reason.
std::optional<SilentPaymentsDestination> DecodeSilentPaymentsAddress(
    const std::string& str, const CChainParams& params, std::string& error_str);

#endif // BITCOIN_KEY_IO_H
