// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compressor.h>
#include <script/script.h>
#include <streams.h>
#include <serialize.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>

#include <cstdint>

#include <boost/test/unit_test.hpp>

// amounts 0.00000001 .. 0.00100000
#define NUM_MULTIPLES_UNIT 100000

// amounts 0.01 .. 100.00
#define NUM_MULTIPLES_CENT 10000

// amounts 1 .. 10000
#define NUM_MULTIPLES_1BTC 10000

// amounts 50 .. 21000000
#define NUM_MULTIPLES_50BTC 420000

BOOST_FIXTURE_TEST_SUITE(compress_tests, BasicTestingSetup)

bool static TestEncode(uint64_t in) {
    return in == DecompressAmount(CompressAmount(in));
}

bool static TestDecode(uint64_t in) {
    return in == CompressAmount(DecompressAmount(in));
}

bool static TestPair(uint64_t dec, uint64_t enc) {
    return CompressAmount(dec) == enc &&
           DecompressAmount(enc) == dec;
}

BOOST_AUTO_TEST_CASE(compress_amounts)
{
    BOOST_CHECK(TestPair(            0,       0x0));
    BOOST_CHECK(TestPair(            1,       0x1));
    BOOST_CHECK(TestPair(         CENT,       0x7));
    BOOST_CHECK(TestPair(         COIN,       0x9));
    BOOST_CHECK(TestPair(      50*COIN,      0x32));
    BOOST_CHECK(TestPair(21000000*COIN, 0x1406f40));

    for (uint64_t i = 1; i <= NUM_MULTIPLES_UNIT; i++)
        BOOST_CHECK(TestEncode(i));

    for (uint64_t i = 1; i <= NUM_MULTIPLES_CENT; i++)
        BOOST_CHECK(TestEncode(i * CENT));

    for (uint64_t i = 1; i <= NUM_MULTIPLES_1BTC; i++)
        BOOST_CHECK(TestEncode(i * COIN));

    for (uint64_t i = 1; i <= NUM_MULTIPLES_50BTC; i++)
        BOOST_CHECK(TestEncode(i * 50 * COIN));

    for (uint64_t i = 0; i < 100000; i++)
        BOOST_CHECK(TestDecode(i));
}

BOOST_AUTO_TEST_CASE(compress_script_to_ckey_id)
{
    // case CKeyID
    CKey key = GenerateRandomKey();
    CPubKey pubkey = key.GetPubKey();

    CScript script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkey.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(script.size(), 25U);

    CompressedScript out;
    bool done = CompressScript(script, out);
    BOOST_CHECK_EQUAL(done, true);

    // Check compressed script
    BOOST_CHECK_EQUAL(out.size(), 21U);
    BOOST_CHECK_EQUAL(out[0], 0x00);
    BOOST_CHECK_EQUAL(memcmp(out.data() + 1, script.data() + 3, 20), 0); // compare the 20 relevant chars of the CKeyId in the script
}

BOOST_AUTO_TEST_CASE(compress_script_to_cscript_id)
{
    // case CScriptID
    CScript script, redeemScript;
    script << OP_HASH160 << ToByteVector(CScriptID(redeemScript)) << OP_EQUAL;
    BOOST_CHECK_EQUAL(script.size(), 23U);

    CompressedScript out;
    bool done = CompressScript(script, out);
    BOOST_CHECK_EQUAL(done, true);

    // Check compressed script
    BOOST_CHECK_EQUAL(out.size(), 21U);
    BOOST_CHECK_EQUAL(out[0], 0x01);
    BOOST_CHECK_EQUAL(memcmp(out.data() + 1, script.data() + 2, 20), 0); // compare the 20 relevant chars of the CScriptId in the script
}

BOOST_AUTO_TEST_CASE(compress_script_to_compressed_pubkey_id)
{
    CKey key = GenerateRandomKey(); // case compressed PubKeyID

    CScript script = CScript() << ToByteVector(key.GetPubKey()) << OP_CHECKSIG; // COMPRESSED_PUBLIC_KEY_SIZE (33)
    BOOST_CHECK_EQUAL(script.size(), 35U);

    CompressedScript out;
    bool done = CompressScript(script, out);
    BOOST_CHECK_EQUAL(done, true);

    // Check compressed script
    BOOST_CHECK_EQUAL(out.size(), 33U);
    BOOST_CHECK_EQUAL(memcmp(out.data(), script.data() + 1, 1), 0);
    BOOST_CHECK_EQUAL(memcmp(out.data() + 1, script.data() + 2, 32), 0); // compare the 32 chars of the compressed CPubKey
}

BOOST_AUTO_TEST_CASE(compress_script_to_uncompressed_pubkey_id)
{
    CKey key = GenerateRandomKey(/*compressed=*/false); // case uncompressed PubKeyID
    CScript script =  CScript() << ToByteVector(key.GetPubKey()) << OP_CHECKSIG; // PUBLIC_KEY_SIZE (65)
    BOOST_CHECK_EQUAL(script.size(), 67U);                   // 1 char code + 65 char pubkey + OP_CHECKSIG

    CompressedScript out;
    bool done = CompressScript(script, out);
    BOOST_CHECK_EQUAL(done, true);

    // Check compressed script
    BOOST_CHECK_EQUAL(out.size(), 33U);
    BOOST_CHECK_EQUAL(memcmp(out.data() + 1, script.data() + 2, 32), 0); // first 32 chars of CPubKey are copied into out[1:]
    BOOST_CHECK_EQUAL(out[0], 0x04 | (script[65] & 0x01)); // least significant bit (lsb) of last char of pubkey is mapped into out[0]
}

BOOST_AUTO_TEST_CASE(compress_p2pk_scripts_not_on_curve)
{
    XOnlyPubKey x_not_on_curve;
    do {
        x_not_on_curve = XOnlyPubKey(m_rng.randbytes(32));
    } while (x_not_on_curve.IsFullyValid());

    // Check that P2PK script with uncompressed pubkey [=> OP_PUSH65 <0x04 .....> OP_CHECKSIG]
    // which is not fully valid (i.e. point is not on curve) can't be compressed
    std::vector<unsigned char> pubkey_raw(65, 0);
    pubkey_raw[0] = 4;
    std::copy(x_not_on_curve.begin(), x_not_on_curve.end(), &pubkey_raw[1]);
    CPubKey pubkey_not_on_curve(pubkey_raw);
    assert(pubkey_not_on_curve.IsValid());
    assert(!pubkey_not_on_curve.IsFullyValid());
    CScript script = CScript() << ToByteVector(pubkey_not_on_curve) << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(script.size(), 67U);

    CompressedScript out;
    bool done = CompressScript(script, out);
    BOOST_CHECK_EQUAL(done, false);

    // Check that compressed P2PK script with uncompressed pubkey that is not fully
    // valid (i.e. x coordinate of the pubkey is not on curve) can't be decompressed
    CompressedScript compressed_script(x_not_on_curve.begin(), x_not_on_curve.end());
    for (unsigned int compression_id : {4, 5}) {
        CScript uncompressed_script;
        bool success = DecompressScript(uncompressed_script, compression_id, compressed_script);
        BOOST_CHECK_EQUAL(success, false);
    }
}

BOOST_AUTO_TEST_CASE(reconstructable_script_p2pkh)
{
    std::vector<uint8_t> buf{};
    VectorWriter s{buf, 0};
    CPubKey key = GenerateRandomKey().GetPubKey();
    CKeyID key_id = key.GetID();
    // BOOST_TEST_MESSAGE("Generated Key ID: " << HexStr(key_id));
    CScript want =  CScript() << OP_DUP << OP_HASH160 << ToByteVector(key_id) << OP_EQUALVERIFY << OP_CHECKSIG;
    // BOOST_TEST_MESSAGE("P2PKH Script: " << HexStr(want));
    s << Using<ReconstructableScript>(want);
    // BOOST_TEST_MESSAGE("Reconstructable script produced: " << HexStr(buf));
    BOOST_CHECK_EQUAL(buf[0], static_cast<uint8_t>(ReconstructableScriptType::P2pkh));
    BOOST_CHECK_EQUAL_COLLECTIONS(buf.begin() + 1, buf.end(), key_id.begin(), key_id.end());
    CScript got;
    SpanReader span{buf};
    Unserialize(span, Using<ReconstructableScript>(got));
    // BOOST_TEST_MESSAGE("Script decoded: " << HexStr(got));
    BOOST_CHECK_EQUAL_COLLECTIONS(want.begin(), want.end(), got.begin(), got.end());
}

BOOST_AUTO_TEST_CASE(reconstructable_script_p2sh)
{
    std::vector<uint8_t> buf{};
    VectorWriter s{buf, 0};
    CScript redeem_script;
    CScriptID redeem_id{redeem_script};
    // BOOST_TEST_MESSAGE("Generated script hash ID: " << HexStr(redeem_id));
    CScript want = CScript() << OP_HASH160 << ToByteVector(redeem_id) << OP_EQUAL;
    // BOOST_TEST_MESSAGE("P2SH Script: " << HexStr(want));
    s << Using<ReconstructableScript>(want);
    // BOOST_TEST_MESSAGE("Reconstructable script produced: " << HexStr(buf));
    BOOST_CHECK_EQUAL(buf[0], static_cast<uint8_t>(ReconstructableScriptType::P2sh));
    BOOST_CHECK_EQUAL_COLLECTIONS(buf.begin() + 1, buf.end(), redeem_id.begin(), redeem_id.end());
    CScript got;
    SpanReader span{buf};
    Unserialize(span, Using<ReconstructableScript>(got));
    // BOOST_TEST_MESSAGE("Script decoded: " << HexStr(got));
    BOOST_CHECK_EQUAL_COLLECTIONS(want.begin(), want.end(), got.begin(), got.end());
}

BOOST_AUTO_TEST_CASE(reconstructable_script_p2tr)
{
    std::vector<uint8_t> buf{};
    VectorWriter s{buf, 0};
    CPubKey key = GenerateRandomKey().GetPubKey();
    XOnlyPubKey x_only{key};
    // BOOST_TEST_MESSAGE("Generated X-only public key: " << HexStr(x_only));
    CScript want =  CScript() << OP_1 << ToByteVector(x_only);
    // BOOST_TEST_MESSAGE("P2TR Script: " << HexStr(want));
    s << Using<ReconstructableScript>(want);
    // BOOST_TEST_MESSAGE("Reconstructable script produced: " << HexStr(buf));
    BOOST_CHECK_EQUAL(buf[0], static_cast<uint8_t>(ReconstructableScriptType::P2tr));
    BOOST_CHECK_EQUAL_COLLECTIONS(buf.begin() + 1, buf.end(), x_only.begin(), x_only.end());
    CScript got;
    SpanReader span{buf};
    Unserialize(span, Using<ReconstructableScript>(got));
    // BOOST_TEST_MESSAGE("Script decoded: " << HexStr(got));
    BOOST_CHECK_EQUAL_COLLECTIONS(want.begin(), want.end(), got.begin(), got.end());
}

BOOST_AUTO_TEST_CASE(reconstructable_script_p2wpkh)
{
    std::vector<uint8_t> buf{};
    VectorWriter s{buf, 0};
    CPubKey key = GenerateRandomKey().GetPubKey();
    CKeyID key_id = key.GetID();
    // BOOST_TEST_MESSAGE("Generated Key ID: " << HexStr(key_id));
    CScript want = CScript() << OP_0 << ToByteVector(key_id);
    // BOOST_TEST_MESSAGE("P2WPKH Script: " << HexStr(want));
    s << Using<ReconstructableScript>(want);
    // BOOST_TEST_MESSAGE("Reconstructable script produced: " << HexStr(buf));
    BOOST_CHECK_EQUAL(buf[0], static_cast<uint8_t>(ReconstructableScriptType::P2wpkh));
    BOOST_CHECK_EQUAL_COLLECTIONS(buf.begin() + 1, buf.end(), key_id.begin(), key_id.end());
    CScript got;
    SpanReader span{buf};
    Unserialize(span, Using<ReconstructableScript>(got));
    // BOOST_TEST_MESSAGE("Script decoded: " << HexStr(got));
    BOOST_CHECK_EQUAL_COLLECTIONS(want.begin(), want.end(), got.begin(), got.end());
}

BOOST_AUTO_TEST_CASE(reconstructable_script_p2wsh)
{
    std::vector<uint8_t> buf{};
    VectorWriter s{buf, 0};
    uint256 hash;
    // BOOST_TEST_MESSAGE("Generated script hash ID: " << HexStr(hash));
    CScript want = CScript() << OP_0 << ToByteVector(hash);
    // BOOST_TEST_MESSAGE("P2SH Script: " << HexStr(want));
    s << Using<ReconstructableScript>(want);
    // BOOST_TEST_MESSAGE("Reconstructable script produced: " << HexStr(buf));
    BOOST_CHECK_EQUAL(buf[0], static_cast<uint8_t>(ReconstructableScriptType::P2wsh));
    BOOST_CHECK_EQUAL_COLLECTIONS(buf.begin() + 1, buf.end(), hash.begin(), hash.end());
    CScript got;
    SpanReader span{buf};
    Unserialize(span, Using<ReconstructableScript>(got));
    // BOOST_TEST_MESSAGE("Script decoded: " << HexStr(got));
    BOOST_CHECK_EQUAL_COLLECTIONS(want.begin(), want.end(), got.begin(), got.end());
}

BOOST_AUTO_TEST_CASE(reconstructable_script_p2pk_odd)
{
    std::vector<uint8_t> buf{};
    VectorWriter s{buf, 0};
    CKey key_odd;
    do {
        key_odd.MakeNewKey(true);
    } while (key_odd.GetPubKey()[0] != 0x03);
    CPubKey pk{key_odd.GetPubKey()};
    // BOOST_TEST_MESSAGE("Odd parity public key: " << HexStr(pk));
    CScript want = CScript() << ToByteVector(pk) << OP_CHECKSIG;
    // BOOST_TEST_MESSAGE("P2PK Script: " << HexStr(want));
    s << Using<ReconstructableScript>(want);
    // BOOST_TEST_MESSAGE("Reconstructable script produced: " << HexStr(buf));
    BOOST_CHECK_EQUAL_COLLECTIONS(buf.begin(), buf.end(), pk.begin(), pk.end());
    CScript got;
    SpanReader span{buf};
    Unserialize(span, Using<ReconstructableScript>(got));
    // BOOST_TEST_MESSAGE("Script decoded: " << HexStr(got));
    BOOST_CHECK_EQUAL_COLLECTIONS(want.begin(), want.end(), got.begin(), got.end());
}

BOOST_AUTO_TEST_CASE(reconstructable_script_p2pk_even)
{
    std::vector<uint8_t> buf{};
    VectorWriter s{buf, 0};
    CKey key_even;
    do {
        key_even.MakeNewKey(true);
    } while (key_even.GetPubKey()[0] != 0x02);
    CPubKey pk{key_even.GetPubKey()};
    // BOOST_TEST_MESSAGE("Even parity public key: " << HexStr(pk));
    CScript want = CScript() << ToByteVector(pk) << OP_CHECKSIG;
    // BOOST_TEST_MESSAGE("P2PK Script: " << HexStr(want));
    s << Using<ReconstructableScript>(want);
    // BOOST_TEST_MESSAGE("Reconstructable script produced: " << HexStr(buf));
    BOOST_CHECK_EQUAL_COLLECTIONS(buf.begin(), buf.end(), pk.begin(), pk.end());CScript got;
    SpanReader span{buf};
    Unserialize(span, Using<ReconstructableScript>(got));
    // BOOST_TEST_MESSAGE("Script decoded: " << HexStr(got));
    BOOST_CHECK_EQUAL_COLLECTIONS(want.begin(), want.end(), got.begin(), got.end());
}

BOOST_AUTO_TEST_CASE(reconstructable_script_p2pk_uncompressed)
{
    std::vector<uint8_t> buf{};
    VectorWriter s{buf, 0};
    CKey key;
    key.MakeNewKey(false);
    CPubKey pk{key.GetPubKey()};
    // BOOST_TEST_MESSAGE("Uncompressed public key: " << HexStr(pk));
    CScript want = CScript() << ToByteVector(pk) << OP_CHECKSIG;
    // BOOST_TEST_MESSAGE("P2PK Script: " << HexStr(want));
    s << Using<ReconstructableScript>(want);
    // BOOST_TEST_MESSAGE("Reconstructable script produced: " << HexStr(buf));
    BOOST_CHECK_EQUAL_COLLECTIONS(buf.begin(), buf.end(), pk.begin(), pk.end());
    CScript got;
    SpanReader span{buf};
    Unserialize(span, Using<ReconstructableScript>(got));
    // BOOST_TEST_MESSAGE("Script decoded: " << HexStr(got));
    BOOST_CHECK_EQUAL_COLLECTIONS(want.begin(), want.end(), got.begin(), got.end());
}

BOOST_AUTO_TEST_CASE(reconstructable_script_unknown) {
    std::vector<uint8_t> buf{};
    VectorWriter s{buf, 0};
    CScript want = CScript() << OP_RETURN;
    // BOOST_TEST_MESSAGE("Unknown reconstructable script: " << HexStr(want));
    s << Using<ReconstructableScript>(want);
    // BOOST_TEST_MESSAGE("Reconstructable script produced: " << HexStr(buf));
    BOOST_CHECK_EQUAL_COLLECTIONS(buf.begin() + 2, buf.end(), want.begin(), want.end());
    CScript got;
    SpanReader span{buf};
    Unserialize(span, Using<ReconstructableScript>(got));
    // BOOST_TEST_MESSAGE("Script decoded: " << HexStr(got));
    BOOST_CHECK_EQUAL_COLLECTIONS(want.begin(), want.end(), got.begin(), got.end());
}

BOOST_AUTO_TEST_SUITE_END()
