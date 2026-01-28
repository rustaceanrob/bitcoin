// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <arith_uint256.h>
#include <coins.h>
#include <consensus/amount.h>
#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <random.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <undo.h>

#include <boost/test/unit_test.hpp>

namespace {
CAmount amt_1{111};
CAmount amt_2{4321};
CAmount amt_3{12345};
CAmount amt_4{94949};
CAmount amt_5{5222322};
CAmount amt_6{34112};
int height_1{20};
int height_2{424002};
int height_3{2244002};
int height_4{983999};
int height_5{2455};
int height_6{3};
} // namespace

BOOST_FIXTURE_TEST_SUITE(undo_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(network_undo_serialization)
{
    CPubKey key_1 = GenerateRandomKey().GetPubKey();
    CScript script_1 = CScript() << OP_DUP << OP_HASH160 << ToByteVector(key_1.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
    Coin coin_1{
        CTxOut{amt_1, script_1},
        height_1,
        false,
    };
    CScript redeem{};
    CScript script_2 = CScript() << OP_HASH160 << ToByteVector(CScriptID(redeem)) << OP_EQUAL;
    Coin coin_2{
        CTxOut{amt_2, script_2},
        height_2,
        false,
    };
    CKey key_2 = GenerateRandomKey();
    CScript script_3 = CScript() << ToByteVector(key_2.GetPubKey()) << OP_CHECKSIG;
    Coin coin_3{
        CTxOut{amt_3, script_3},
        height_3,
        false,
    };
    CKey key_3 = GenerateRandomKey(/*compressed=*/false);
    CScript script_4 = CScript() << ToByteVector(key_3.GetPubKey()) << OP_CHECKSIG;
    Coin coin_4{
        CTxOut{amt_4, script_4},
        height_4,
        false,
    };
    CKey key_4 = GenerateRandomKey();
    XOnlyPubKey x_only{key_4.GetPubKey()};
    CScript script_5 = CScript() << OP_1 << ToByteVector(x_only);
    Coin coin_5{
        CTxOut{amt_5, script_5},
        height_5,
        false,
    };
    CPubKey key_5 = GenerateRandomKey().GetPubKey();
    CScript script_6 = CScript() << OP_DUP << OP_HASH160 << ToByteVector(key_5.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
    Coin coin_6{
        CTxOut{amt_6, script_6},
        height_6,
        true,
    };

    CTxUndo undo_1{std::vector{coin_1, coin_2}};
    CTxUndo undo_2{std::vector{coin_3, coin_4}};
    CTxUndo undo_3{std::vector{coin_5, coin_6}};
    CBlockUndo undo{std::vector{undo_1, undo_2, undo_3}};
    uint256 block_hash{GetRandHash()};
    NetworkBlockUndo want{block_hash, undo, 0};
    BOOST_CHECK(want.m_coins.size() > 0);
    DataStream undo_byte_stream{};
    Serialize(undo_byte_stream, want);
    BOOST_CHECK(undo_byte_stream.size() > 0);
    NetworkBlockUndo got;
    Unserialize(undo_byte_stream, got);
    BOOST_CHECK_EQUAL(want.m_coins.size(), got.m_coins.size());
    for (size_t i = 0; i < want.m_coins.size(); ++i) {
        const auto& coin_1 = want.m_coins[i].m_coin;
        const auto& coin_2 = got.m_coins[i].m_coin;
        BOOST_CHECK_EQUAL(coin_1.fCoinBase, coin_2.fCoinBase);
        BOOST_CHECK_EQUAL(coin_1.nHeight, coin_2.nHeight);
        BOOST_CHECK_EQUAL(coin_1.out.nValue, coin_2.out.nValue);
        const auto spk_1{coin_1.out.scriptPubKey};
        const auto spk_2{coin_2.out.scriptPubKey};
        BOOST_CHECK(spk_1 == spk_2);
    }
    NetworkBlockUndo want_filtered{block_hash, undo, 20};
    BOOST_CHECK(want_filtered.m_coins.size() > 0);
    BOOST_CHECK_EQUAL(want_filtered.m_coins.size(), 1);
    DataStream filtered_undo_byte_stream{};
    Serialize(filtered_undo_byte_stream, want_filtered);
    BOOST_CHECK(filtered_undo_byte_stream.size() > 0);
    NetworkBlockUndo got_filtered;
    Unserialize(filtered_undo_byte_stream, got_filtered);
    const auto index_got = got_filtered.m_coins[0].m_index;
    BOOST_CHECK_EQUAL(index_got, 5);
    const auto& coin_want = want_filtered.m_coins[0].m_coin;
    const auto& coin_got = got_filtered.m_coins[0].m_coin;
    BOOST_CHECK_EQUAL(coin_want.fCoinBase, coin_got.fCoinBase);
    BOOST_CHECK_EQUAL(coin_want.nHeight, coin_got.nHeight);
    BOOST_CHECK_EQUAL(coin_want.out.nValue, coin_got.out.nValue);
    const auto spk_1{coin_want.out.scriptPubKey};
    const auto spk_2{coin_got.out.scriptPubKey};
    BOOST_CHECK(spk_1 == spk_2);
}

BOOST_AUTO_TEST_SUITE_END();
