#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Routines for compressing transaction output amounts and scripts."""
import unittest

from .messages import COIN


def compress_amount(n):
    if n == 0:
        return 0
    e = 0
    while ((n % 10) == 0) and (e < 9):
        n //= 10
        e += 1
    if e < 9:
        d = n % 10
        assert (d >= 1 and d <= 9)
        n //= 10
        return 1 + (n*9 + d - 1)*10 + e
    else:
        return 1 + (n - 1)*10 + 9


def decompress_amount(x):
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    n = 0
    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    while e > 0:
        n *= 10
        e -= 1
    return n


def decompress_script(f):
    """Equivalent of `DecompressScript()` (see compressor module)."""
    size =  int.from_bytes(f.read(1), "little") # sizes 0-5 encode compressed script types
    if size == 0:  # P2PKH
        return bytes([0x76, 0xa9, 20]) + f.read(20) + bytes([0x88, 0xac])
    elif size == 1:  # P2SH
        return bytes([0xa9, 20]) + f.read(20) + bytes([0x87])
    elif size in (2, 3):  # P2PK (compressed)
        return bytes([33, size]) + f.read(32) + bytes([0xac])
    elif size in (4, 5):  # P2PK (uncompressed)
        compressed_pubkey = bytes([size - 2]) + f.read(32)
        return bytes([65]) + decompress_pubkey(compressed_pubkey) + bytes([0xac])
    else:  # others (bare multisig, segwit etc.)
        size -= 6
        assert size <= 10000, f"too long script with size {size}"
        return f.read(size)


def decompress_pubkey(compressed_pubkey):
    """Decompress pubkey by calculating y = sqrt(x^3 + 7) % p
       (see functions `secp256k1_eckey_pubkey_parse` and `secp256k1_ge_set_xo_var`).
    """
    P = 2**256 - 2**32 - 977  # secp256k1 field size
    assert len(compressed_pubkey) == 33 and compressed_pubkey[0] in (2, 3)
    x = int.from_bytes(compressed_pubkey[1:], 'big')
    rhs = (x**3 + 7) % P
    y = pow(rhs, (P + 1)//4, P)  # get sqrt using Tonelli-Shanks algorithm (for p % 4 = 3)
    assert pow(y, 2, P) == rhs, f"pubkey is not on curve ({compressed_pubkey.hex()})"
    tag_is_odd = compressed_pubkey[0] == 3
    y_is_odd = (y & 1) == 1
    if tag_is_odd != y_is_odd:  # fix parity (even/odd) if necessary
        y = P - y
    return bytes([4]) + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')




class TestFrameworkCompressor(unittest.TestCase):
    from .messages import COIN
    def test_amount_compress_decompress(self):
        def check_amount(amount, expected_compressed):
            self.assertEqual(compress_amount(amount), expected_compressed)
            self.assertEqual(decompress_amount(expected_compressed), amount)

        # test cases from compress_tests.cpp:compress_amounts
        check_amount(0, 0x0)
        check_amount(1, 0x1)
        check_amount(1000000, 0x7)
        check_amount(COIN, 0x9)
        check_amount(50*COIN, 0x32)
        check_amount(21000000*COIN, 0x1406f40)
