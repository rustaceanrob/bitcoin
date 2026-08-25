/** Copyright (c) 2026-present The Bitcoin Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */
#ifndef BITCOIN_TEST_UTIL_DISPLAY_H
#define BITCOIN_TEST_UTIL_DISPLAY_H

#include <addresstype.h>
#include <addrman.h>
#include <crypto/hex_base.h>
#include <index/txindex_key.h>
#include <key.h>
#include <key_io.h>
#include <netaddress.h>
#include <protocol.h>
#include <pubkey.h>
#include <script/keyorigin.h>
#include <tinyformat.h>
#include <util/bip32.h>
#include <util/feefrac.h>

#include <concepts>
#include <ostream>
#include <utility>

inline std::ostream& operator<<(std::ostream& os, const AddressPosition& pos)
{
    return os << strprintf("AddressPosition(tried=%d, multiplicity=%d, bucket=%d, position=%d)", pos.tried, pos.multiplicity, pos.bucket, pos.position);
}

inline std::ostream& operator<<(std::ostream& os, const CService& service)
{
    return os << service.ToStringAddrPort();
}

inline std::ostream& operator<<(std::ostream& os, const CAddress& addr)
{
    return os << addr.ToStringAddrPort();
}

inline std::ostream& operator<<(std::ostream& os, const CTxDestination& dest)
{
    return os << strprintf("CTxDestination(%s)", EncodeDestination(dest));
}

inline std::ostream& operator<<(std::ostream& os, const CExtKey& k)
{
    unsigned char code[BIP32_EXTKEY_SIZE];
    k.Encode(code);
    return os << strprintf("CExtKey(%s)", HexStr(code));
}

inline std::ostream& operator<<(std::ostream& os, const CExtPubKey& k)
{
    unsigned char code[BIP32_EXTKEY_SIZE];
    k.Encode(code);
    return os << strprintf("CExtPubKey(%s)", HexStr(code));
}

template <std::derived_from<FeeFrac> T>
inline std::ostream& operator<<(std::ostream& os, const T& ff)
{
    return os << strprintf("FeeFrac(fee=%d, size=%d)", ff.fee, ff.size);
}

template <std::derived_from<FeeFrac> T>
inline std::ostream& operator<<(std::ostream& os, const ByRatioNegSize<T>& b)
{
    return os << "ByRatioNegSize(" << static_cast<const T&>(b) << ")";
}

inline std::ostream& operator<<(std::ostream& os, const CNoDestination& dest)
{
    return os << strprintf("CNoDestination(%s)", HexStr(dest.GetScript()));
}

inline std::ostream& operator<<(std::ostream& os, const PubKeyDestination& dest)
{
    return os << strprintf("PubKeyDestination(%s)", HexStr(dest.GetPubKey()));
}

inline std::ostream& operator<<(std::ostream& os, const WitnessUnknown& w)
{
    return os << strprintf("WitnessUnknown(version=%u, program=%s)", w.GetWitnessVersion(), HexStr(w.GetWitnessProgram()));
}

inline std::ostream& operator<<(std::ostream& os, const PayToAnchor& p)
{
    return os << strprintf("PayToAnchor(version=%u, program=%s)", p.GetWitnessVersion(), HexStr(p.GetWitnessProgram()));
}

inline std::ostream& operator<<(std::ostream& os, const CPubKey& pk)
{
    return os << strprintf("CPubKey(%s)", HexStr(pk));
}

inline std::ostream& operator<<(std::ostream& os, const KeyOriginInfo& info)
{
    return os << strprintf("KeyOriginInfo(fingerprint=%s, path=%s)", HexStr(info.fingerprint), FormatHDKeypath(info.path));
}

inline std::ostream& operator<<(std::ostream& os, const std::pair<CPubKey, KeyOriginInfo>& p)
{
    return os << strprintf("(%s, %s)", p.first, p.second);
}

namespace txindex {
inline std::ostream& operator<<(std::ostream& os, const BlockTxPosition& pos)
{
    return os << strprintf("BlockTxPosition(block_seq=%u, tx_offset_in_block=%u)", pos.block_seq, pos.tx_offset_in_block);
}
} // namespace txindex

#endif // BITCOIN_TEST_UTIL_DISPLAY_H
