# Copyright (c) 2022-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test-only secp256k1 field and group arithmetic

Group operations are performed by libsecp256k1, loaded from the build directory via ctypes.
Field arithmetic is implemented in Python.

WARNING: This code is trivially vulnerable to side channel attacks. Do not use for
anything but tests.

Exports:
* FE: class for secp256k1 field elements
* GE: class for secp256k1 group elements
* G: the secp256k1 generator point
* lib: libsecp256k1, loaded on first use
"""

import configparser
import ctypes
import functools
import glob
import os
import sys
import unittest
from hashlib import sha256
from test_framework.util import assert_equal, assert_not_equal

class FE:
    """Objects of this class represent elements of the field GF(2**256 - 2**32 - 977).

    They are represented internally in numerator / denominator form, in order to delay inversions.
    """

    # The size of the field (also its modulus and characteristic).
    SIZE = 2**256 - 2**32 - 977

    def __init__(self, a=0, b=1):
        """Initialize a field element a/b; both a and b can be ints or field elements."""
        if isinstance(a, FE):
            num = a._num
            den = a._den
        else:
            num = a % FE.SIZE
            den = 1
        if isinstance(b, FE):
            den = (den * b._num) % FE.SIZE
            num = (num * b._den) % FE.SIZE
        else:
            den = (den * b) % FE.SIZE
        assert_not_equal(den, 0)
        if num == 0:
            den = 1
        self._num = num
        self._den = den

    def __add__(self, a):
        """Compute the sum of two field elements (second may be int)."""
        if isinstance(a, FE):
            return FE(self._num * a._den + self._den * a._num, self._den * a._den)
        return FE(self._num + self._den * a, self._den)

    def __radd__(self, a):
        """Compute the sum of an integer and a field element."""
        return FE(a) + self

    def __sub__(self, a):
        """Compute the difference of two field elements (second may be int)."""
        if isinstance(a, FE):
            return FE(self._num * a._den - self._den * a._num, self._den * a._den)
        return FE(self._num - self._den * a, self._den)

    def __rsub__(self, a):
        """Compute the difference of an integer and a field element."""
        return FE(a) - self

    def __mul__(self, a):
        """Compute the product of two field elements (second may be int)."""
        if isinstance(a, FE):
            return FE(self._num * a._num, self._den * a._den)
        return FE(self._num * a, self._den)

    def __rmul__(self, a):
        """Compute the product of an integer with a field element."""
        return FE(a) * self

    def __truediv__(self, a):
        """Compute the ratio of two field elements (second may be int)."""
        return FE(self, a)

    def __pow__(self, a):
        """Raise a field element to an integer power."""
        return FE(pow(self._num, a, FE.SIZE), pow(self._den, a, FE.SIZE))

    def __neg__(self):
        """Negate a field element."""
        return FE(-self._num, self._den)

    def __int__(self):
        """Convert a field element to an integer in range 0..p-1. The result is cached."""
        if self._den != 1:
            self._num = (self._num * pow(self._den, -1, FE.SIZE)) % FE.SIZE
            self._den = 1
        return self._num

    def sqrt(self):
        """Compute the square root of a field element if it exists (None otherwise).

        Due to the fact that our modulus is of the form (p % 4) == 3, the Tonelli-Shanks
        algorithm (https://en.wikipedia.org/wiki/Tonelli-Shanks_algorithm) is simply
        raising the argument to the power (p + 1) / 4.

        To see why: (p-1) % 2 = 0, so 2 divides the order of the multiplicative group,
        and thus only half of the non-zero field elements are squares. An element a is
        a (nonzero) square when Euler's criterion, a^((p-1)/2) = 1 (mod p), holds. We're
        looking for x such that x^2 = a (mod p). Given a^((p-1)/2) = 1, that is equivalent
        to x^2 = a^(1 + (p-1)/2) mod p. As (1 + (p-1)/2) is even, this is equivalent to
        x = a^((1 + (p-1)/2)/2) mod p, or x = a^((p+1)/4) mod p."""
        v = int(self)
        s = pow(v, (FE.SIZE + 1) // 4, FE.SIZE)
        if s**2 % FE.SIZE == v:
            return FE(s)
        return None

    def is_square(self):
        """Determine if this field element has a square root."""
        # A more efficient algorithm is possible here (Jacobi symbol).
        return self.sqrt() is not None

    def is_even(self):
        """Determine whether this field element, represented as integer in 0..p-1, is even."""
        return int(self) & 1 == 0

    def __eq__(self, a):
        """Check whether two field elements are equal (second may be an int)."""
        if isinstance(a, FE):
            return (self._num * a._den - self._den * a._num) % FE.SIZE == 0
        return (self._num - self._den * a) % FE.SIZE == 0

    def to_bytes(self):
        """Convert a field element to a 32-byte array (BE byte order)."""
        return int(self).to_bytes(32, 'big')

    @staticmethod
    def from_bytes(b):
        """Convert a 32-byte array to a field element (BE byte order, no overflow allowed)."""
        v = int.from_bytes(b, 'big')
        if v >= FE.SIZE:
            return None
        return FE(v)

    def __str__(self):
        """Convert this field element to a 64 character hex string."""
        return f"{int(self):064x}"

    def __repr__(self):
        """Get a string representation of this field element."""
        return f"FE(0x{int(self):x})"


SECP256K1_CONTEXT_NONE = 1
SECP256K1_EC_COMPRESSED = (1 << 1) | (1 << 8)
SECP256K1_EC_UNCOMPRESSED = 1 << 1


_c_int = ctypes.c_int
_c_buf = ctypes.c_char_p
_c_ptr = ctypes.c_void_p
_c_size = ctypes.c_size_t

_FUNCTIONS = {
    "secp256k1_context_create": (_c_ptr, [ctypes.c_uint]),
    "secp256k1_ec_pubkey_parse": (_c_int, [_c_ptr, _c_buf, _c_buf, _c_size]),
    "secp256k1_ec_pubkey_serialize": (_c_int, [_c_ptr, _c_buf, ctypes.POINTER(_c_size), _c_buf, ctypes.c_uint]),
    "secp256k1_ec_pubkey_create": (_c_int, [_c_ptr, _c_buf, _c_buf]),
    "secp256k1_ec_pubkey_negate": (_c_int, [_c_ptr, _c_buf]),
    "secp256k1_ec_pubkey_tweak_mul": (_c_int, [_c_ptr, _c_buf, _c_buf]),
    "secp256k1_ec_pubkey_combine": (_c_int, [_c_ptr, _c_buf, ctypes.POINTER(_c_buf), _c_size]),
}


class Library:
    """The libsecp256k1 built for the functional tests (BUILD_SECP256K1_TEST_LIB), loaded on first use.

    Functions are called with the context argument already bound, e.g. lib.secp256k1_ec_pubkey_negate(pubkey).
    The library path can be overridden with the SECP256K1_TEST_LIB environment variable. Otherwise it is
    found through config, which the test framework sets, or else the config.ini next to the running script."""

    def __init__(self):
        self.config = None

    def _path(self):
        path = os.getenv("SECP256K1_TEST_LIB")
        if path is not None:
            return path
        config = self.config
        if config is None:
            config_path = os.path.join(os.path.dirname(os.path.abspath(sys.modules["__main__"].__file__)), "..", "config.ini")
            config = configparser.ConfigParser()
            if not config.read(config_path):
                raise RuntimeError(f"{config_path} not found, cannot locate libsecp256k1. Set SECP256K1_TEST_LIB to its path.")
        test_lib_dir = os.path.join(config["environment"]["BUILDDIR"], "secp256k1_test_lib")
        if os.name == "nt":
            return next(iter(glob.glob(os.path.join(test_lib_dir, "bin", "libsecp256k1-*.dll"))), os.path.join(test_lib_dir, "bin", "libsecp256k1.dll"))
        return os.path.join(test_lib_dir, "lib", "libsecp256k1.dylib" if sys.platform == "darwin" else "libsecp256k1.so")

    @functools.cached_property
    def _loaded(self):
        path = self._path()
        if not os.path.isfile(path):
            raise RuntimeError(f"{path} not found. Configure with -DBUILD_SECP256K1_TEST_LIB=ON and rebuild, or set SECP256K1_TEST_LIB.")
        cdll = ctypes.CDLL(path)
        for function_name, (restype, argtypes) in _FUNCTIONS.items():
            function = getattr(cdll, function_name)
            function.restype = restype
            function.argtypes = argtypes
        return cdll, ctypes.c_void_p(cdll.secp256k1_context_create(SECP256K1_CONTEXT_NONE))

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        cdll, ctx = self._loaded
        return functools.partial(getattr(cdll, name), ctx)


lib = Library()


class GE:
    """Objects of this class represent secp256k1 group elements (curve points or infinity)

    The point is held as a 64-byte libsecp256k1 secp256k1_pubkey in the pubkey field, which is
    None for the point at infinity.

    Normal points on the curve have properties:
    * x: the x coordinate (a field element)
    * y: the y coordinate (a field element, satisfying y^2 = x^3 + 7)
    * infinity: False

    The point at infinity has property:
    * infinity: True
    """

    # Order of the group (number of points on the curve, plus 1 for infinity)
    ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    # Number of valid distinct x coordinates on the curve.
    ORDER_HALF = ORDER // 2

    def __init__(self, x=None, y=None):
        """Initialize a group element with specified x and y coordinates, or infinity."""
        if x is None:
            assert y is None
            self.pubkey = None
        else:
            r = GE.from_bytes(b'\x04' + FE(x).to_bytes() + FE(y).to_bytes())
            assert r is not None, "point is not on the curve"
            self.pubkey = r.pubkey

    @staticmethod
    def from_pubkey(pubkey):
        """Construct a group element from a 64-byte secp256k1_pubkey (None for infinity)."""
        r = GE()
        r.pubkey = pubkey
        return r

    @property
    def infinity(self):
        return self.pubkey is None

    @property
    def x(self):
        assert not self.infinity
        return FE.from_bytes(self.to_bytes_uncompressed()[1:33])

    @property
    def y(self):
        assert not self.infinity
        return FE.from_bytes(self.to_bytes_uncompressed()[33:])

    @staticmethod
    def _sum(pubkeys):
        """Add up a list of 64-byte secp256k1_pubkeys."""
        if len(pubkeys) == 0:
            return GE()
        if len(pubkeys) == 1:
            return GE.from_pubkey(pubkeys[0])
        out = ctypes.create_string_buffer(64)
        ins = (ctypes.c_char_p * len(pubkeys))(*pubkeys)
        if not lib.secp256k1_ec_pubkey_combine(out, ins, len(pubkeys)):
            return GE()
        return GE.from_pubkey(out.raw)

    def __add__(self, a):
        """Add two group elements together."""
        return GE._sum([p.pubkey for p in (self, a) if not p.infinity])

    @staticmethod
    def mul(*aps):
        """Compute a (batch) scalar group element multiplication.

        GE.mul((a1, p1), (a2, p2), (a3, p3)) is identical to a1*p1 + a2*p2 + a3*p3."""
        terms = []
        for a, p in aps:
            a %= GE.ORDER
            if a == 0 or p.infinity:
                continue
            out = ctypes.create_string_buffer(64)
            if p is G:
                assert lib.secp256k1_ec_pubkey_create(out, a.to_bytes(32, 'big'))
            else:
                ctypes.memmove(out, p.pubkey, 64)
                assert lib.secp256k1_ec_pubkey_tweak_mul(out, a.to_bytes(32, 'big'))
            terms.append(out.raw)
        return GE._sum(terms)

    def __rmul__(self, a):
        """Multiply an integer with a group element."""
        return GE.mul((a, self))

    def __neg__(self):
        """Compute the negation of a group element."""
        if self.infinity:
            return self
        out = ctypes.create_string_buffer(self.pubkey, 64)
        assert lib.secp256k1_ec_pubkey_negate(out)
        return GE.from_pubkey(out.raw)

    def _serialize(self, size, flags):
        assert not self.infinity
        out = ctypes.create_string_buffer(size)
        outlen = ctypes.c_size_t(size)
        assert lib.secp256k1_ec_pubkey_serialize(out, ctypes.byref(outlen), self.pubkey, flags)
        return out.raw

    def to_bytes_compressed(self):
        """Convert a non-infinite group element to 33-byte compressed encoding."""
        return self._serialize(33, SECP256K1_EC_COMPRESSED)

    def to_bytes_uncompressed(self):
        """Convert a non-infinite group element to 65-byte uncompressed encoding."""
        return self._serialize(65, SECP256K1_EC_UNCOMPRESSED)

    def to_bytes_xonly(self):
        """Convert (the x coordinate of) a non-infinite group element to 32-byte xonly encoding."""
        return self.to_bytes_compressed()[1:]

    @staticmethod
    def lift_x(x):
        """Return group element with specified field element as x coordinate (and even y)."""
        return GE.from_bytes(b'\x02' + FE(x).to_bytes())

    @staticmethod
    def from_bytes(b):
        """Convert a compressed or uncompressed encoding to a group element."""
        assert len(b) in (33, 65)
        if b[0] not in ((2, 3) if len(b) == 33 else (4,)):
            return None
        out = ctypes.create_string_buffer(64)
        if not lib.secp256k1_ec_pubkey_parse(out, b, len(b)):
            return None
        return GE.from_pubkey(out.raw)

    @staticmethod
    def from_bytes_xonly(b):
        """Convert a point given in xonly encoding to a group element."""
        assert_equal(len(b), 32)
        if FE.from_bytes(b) is None:
            return None
        return GE.from_bytes(b'\x02' + b)

    @staticmethod
    def is_valid_x(x):
        """Determine whether the provided field element is a valid X coordinate."""
        return GE.lift_x(x) is not None

    def __str__(self):
        """Convert this group element to a string."""
        if self.infinity:
            return "(inf)"
        return f"({self.x},{self.y})"

    def __repr__(self):
        """Get a string representation for this group element."""
        if self.infinity:
            return "GE()"
        return f"GE(0x{int(self.x):x},0x{int(self.y):x})"

class Generator(GE):
    """The secp256k1 generator point, converted by libsecp256k1 on first use."""

    def __init__(self):
        pass

    @functools.cached_property
    def pubkey(self):
        return GE.lift_x(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798).pubkey

G = Generator()

class TestFrameworkSecp256k1(unittest.TestCase):
    def test_H(self):
        H = sha256(G.to_bytes_uncompressed()).digest()
        assert GE.lift_x(FE.from_bytes(H)) is not None
        self.assertEqual(H.hex(), "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
