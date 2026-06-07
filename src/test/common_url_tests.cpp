// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <common/url.h>

#include <string>

#include <test/util/framework.hpp>
TEST_SUITE_BEGIN(common_url_tests)

TEST_CASE(encode_decode_test) {
    CHECK(UrlDecode("Hello") == "Hello");
    CHECK(UrlDecode("99") == "99");
    CHECK(UrlDecode("") == "");
    CHECK(UrlDecode("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789-.~_") == "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789-.~_");
    CHECK(UrlDecode("%20") == " ");
    CHECK(UrlDecode("%FF%F0%E0") == "\xff\xf0\xe0");
    CHECK(UrlDecode("%01%19") == "\x01\x19");
    CHECK(UrlDecode("http%3A%2F%2Fwww.ietf.org%2Frfc%2Frfc3986.txt") == "http://www.ietf.org/rfc/rfc3986.txt");
    CHECK(UrlDecode("1%2B2%3D3") == "1+2=3");
}

TEST_CASE(decode_malformed_test) {
    CHECK(UrlDecode("%%xhello th+ere \xff") == "%%xhello th+ere \xff");

    CHECK(UrlDecode("%") == "%");
    CHECK(UrlDecode("%%") == "%%");
    CHECK(UrlDecode("%%%") == "%%%");
    CHECK(UrlDecode("%%%%") == "%%%%");

    CHECK(UrlDecode("+") == "+");
    CHECK(UrlDecode("++") == "++");

    CHECK(UrlDecode("?") == "?");
    CHECK(UrlDecode("??") == "??");

    CHECK(UrlDecode("%G1") == "%G1");
    CHECK(UrlDecode("%2") == "%2");
    CHECK(UrlDecode("%ZX") == "%ZX");

    CHECK(UrlDecode("valid%20string%G1") == "valid string%G1");
    CHECK(UrlDecode("%20invalid%ZX") == " invalid%ZX");
    CHECK(UrlDecode("%20%G1%ZX") == " %G1%ZX");

    CHECK(UrlDecode("%1 ") == "%1 ");
    CHECK(UrlDecode("% 9") == "% 9");
    CHECK(UrlDecode(" %Z ") == " %Z ");
    CHECK(UrlDecode(" % X") == " % X");

    CHECK(UrlDecode("%%ffg") == "%\xffg");
    CHECK(UrlDecode("%fg") == "%fg");

    CHECK(UrlDecode("%-1") == "%-1");
    CHECK(UrlDecode("%1-") == "%1-");
}

TEST_CASE(decode_lowercase_hex_test) {
    CHECK(UrlDecode("%f0%a0%b0") == "\xf0\xa0\xb0");
}

TEST_CASE(decode_internal_nulls_test) {
    std::string result1{"\0\0x\0\0", 5};
    CHECK(UrlDecode("%00%00x%00%00") == result1);
    std::string result2{"abc\0\0", 5};
    CHECK(UrlDecode("abc%00%00") == result2);
}

TEST_SUITE_END()
