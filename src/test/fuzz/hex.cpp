// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <primitives/block.h>
#include <primitives/transaction_identifier.h>
#include <pubkey.h>
#include <test/fuzz/fuzz.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

FUZZ_TARGET(hex)
{
    const std::string random_hex_string(buffer.begin(), buffer.end());
    const std::vector<unsigned char> data = ParseHex(random_hex_string);
    const std::vector<std::byte> bytes{ParseHex<std::byte>(random_hex_string)};
    assert(std::ranges::equal(std::as_bytes(std::span{data}), bytes));
    const std::string hex_data = HexStr(data);
    if (IsHex(random_hex_string)) {
        assert(ToLower(random_hex_string) == hex_data);
    }
    if (uint256::FromHex(random_hex_string)) {
        assert(random_hex_string.length() == 64);
        assert(Txid::FromHex(random_hex_string));
        assert(Wtxid::FromHex(random_hex_string));
        assert(uint256::FromUserHex(random_hex_string));
    }
    if (const auto result{uint256::FromUserHex(random_hex_string)}) {
        const auto result_string{result->ToString()}; // ToString() returns a fixed-length string without "0x" prefix
        assert(result_string.length() == 64);
        assert(IsHex(result_string));
        assert(TryParseHex(result_string));
        assert(Txid::FromHex(result_string));
        assert(Wtxid::FromHex(result_string));
        assert(uint256::FromHex(result_string));
    }
    if (IsHex(random_hex_string) && (random_hex_string.size() == 66 || random_hex_string.size() == 130)) {
        CPubKey pubkey(ParseHex(random_hex_string));
        (void)pubkey.IsFullyValid();
    }
    CBlockHeader block_header;
    (void)DecodeHexBlockHeader(block_header, random_hex_string);
    CBlock block;
    (void)DecodeHexBlk(block, random_hex_string);
}
