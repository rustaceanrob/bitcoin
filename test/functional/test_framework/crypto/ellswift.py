#!/usr/bin/env python3
# Copyright (c) 2022-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test-only Elligator Swift implementation

Encoding and decoding of public keys are performed by libsecp256k1. The inverse
map (xswiftec_inv) is implemented in Python, as libsecp256k1 does not expose it.

WARNING: This code uses bad randomness.
Do not use for anything but tests."""

import csv
import ctypes
import os
import random
import unittest

from test_framework.crypto.secp256k1 import FE, GE, lib
from test_framework.util import assert_equal

# Precomputed constant square root of -3 (mod p).
MINUS_3_SQRT = FE(-3).sqrt()

def ellswift_decode(ellswift):
    """Decode a 64-byte ellswift encoding to a group element."""
    pubkey = ctypes.create_string_buffer(64)
    assert lib.secp256k1_ellswift_decode(pubkey, ellswift)
    return GE.from_pubkey(pubkey.raw)

def xswiftec(u, t):
    """Decode field elements (u, t) to an X coordinate on the curve."""
    return ellswift_decode(u.to_bytes() + t.to_bytes()).x

def xswiftec_inv(x, u, case):
    """Given x and u, find t such that xswiftec(u, t) = x, or return None.

    Case selects which of the up to 8 results to return."""

    if case & 2 == 0:
        if GE.is_valid_x(-x - u):
            return None
        v = x
        s = -(u**3 + 7) / (u**2 + u*v + v**2)
    else:
        s = x - u
        if s == 0:
            return None
        r = (-s * (4 * (u**3 + 7) + 3 * s * u**2)).sqrt()
        if r is None:
            return None
        if case & 1 and r == 0:
            return None
        v = (-u + r / s) / 2
    w = s.sqrt()
    if w is None:
        return None
    if case & 5 == 0:
        return -w * (u * (1 - MINUS_3_SQRT) / 2 + v)
    if case & 5 == 1:
        return w * (u * (1 + MINUS_3_SQRT) / 2 + v)
    if case & 5 == 4:
        return w * (u * (1 - MINUS_3_SQRT) / 2 + v)
    if case & 5 == 5:
        return -w * (u * (1 + MINUS_3_SQRT) / 2 + v)

def xelligatorswift(x):
    """Given a field element X on the curve, find (u, t) that encode them."""
    assert GE.is_valid_x(x)
    while True:
        u = FE(random.randrange(1, FE.SIZE))
        case = random.randrange(0, 8)
        t = xswiftec_inv(x, u, case)
        if t is not None:
            return u, t

def ellswift_create():
    """Generate a (privkey, ellswift_pubkey) pair."""
    priv = random.randrange(1, GE.ORDER).to_bytes(32, 'big')
    ellswift = ctypes.create_string_buffer(64)
    assert lib.secp256k1_ellswift_create(ellswift, priv, random.randbytes(32))
    return priv, ellswift.raw

def ellswift_ecdh_xonly(pubkey_theirs, privkey):
    """Compute X coordinate of shared ECDH point between ellswift pubkey and privkey."""
    d = int.from_bytes(privkey, 'big')
    return (d * ellswift_decode(pubkey_theirs)).to_bytes_xonly()


class TestFrameworkEllSwift(unittest.TestCase):
    def test_xswiftec(self):
        """Verify that xswiftec maps all inputs to the curve."""
        for _ in range(32):
            u = FE(random.randrange(0, FE.SIZE))
            t = FE(random.randrange(0, FE.SIZE))
            x = xswiftec(u, t)
            self.assertTrue(GE.is_valid_x(x))

        # Check that inputs which are considered undefined in the original
        # SwiftEC paper can also be decoded successfully (by remapping)
        undefined_inputs = [
            (FE(0), FE(23)),  # u = 0
            (FE(42), FE(0)),  # t = 0
            (FE(5), FE(-132).sqrt()),  # u^3 + t^2 + 7 = 0
        ]
        assert_equal(undefined_inputs[-1][0]**3 + undefined_inputs[-1][1]**2 + 7, 0)
        for u, t in undefined_inputs:
            x = xswiftec(u, t)
            self.assertTrue(GE.is_valid_x(x))

    def test_elligator_roundtrip(self):
        """Verify that encoding using xelligatorswift decodes back using xswiftec."""
        for _ in range(32):
            while True:
                # Loop until we find a valid X coordinate on the curve.
                x = FE(random.randrange(1, FE.SIZE))
                if GE.is_valid_x(x):
                    break
            # Encoding it to (u, t), decode it back, and compare.
            u, t = xelligatorswift(x)
            x2 = xswiftec(u, t)
            self.assertEqual(x2, x)

    def test_ellswift_ecdh_xonly(self):
        """Verify that shared secret computed by ellswift_ecdh_xonly match."""
        for _ in range(32):
            privkey1, encoding1 = ellswift_create()
            privkey2, encoding2 = ellswift_create()
            shared_secret1 = ellswift_ecdh_xonly(encoding1, privkey2)
            shared_secret2 = ellswift_ecdh_xonly(encoding2, privkey1)
            self.assertEqual(shared_secret1, shared_secret2)

    def test_elligator_encode_testvectors(self):
        """Implement the BIP324 test vectors for ellswift encoding (read from xswiftec_inv_test_vectors.csv)."""
        vectors_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'xswiftec_inv_test_vectors.csv')
        with open(vectors_file, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                u = FE.from_bytes(bytes.fromhex(row['u']))
                x = FE.from_bytes(bytes.fromhex(row['x']))
                for case in range(8):
                    ret = xswiftec_inv(x, u, case)
                    if ret is None:
                        self.assertEqual(row[f"case{case}_t"], "")
                    else:
                        self.assertEqual(row[f"case{case}_t"], ret.to_bytes().hex())
                        self.assertEqual(xswiftec(u, ret), x)

    def test_elligator_decode_testvectors(self):
        """Implement the BIP324 test vectors for ellswift decoding (read from ellswift_decode_test_vectors.csv)."""
        vectors_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'ellswift_decode_test_vectors.csv')
        with open(vectors_file, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                encoding = bytes.fromhex(row['ellswift'])
                assert_equal(len(encoding), 64)
                expected_x = FE(int(row['x'], 16))
                u = FE(int.from_bytes(encoding[:32], 'big'))
                t = FE(int.from_bytes(encoding[32:], 'big'))
                x = xswiftec(u, t)
                self.assertEqual(x, expected_x)
                self.assertTrue(GE.is_valid_x(x))
