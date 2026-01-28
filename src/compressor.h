// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPRESSOR_H
#define BITCOIN_COMPRESSOR_H

#include <prevector.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <span.h>

/**
 * This saves us from making many heap allocations when serializing
 * and deserializing compressed scripts.
 *
 * This prevector size is determined by the largest .resize() in the
 * CompressScript function. The largest compressed script format is a
 * compressed public key, which is 33 bytes.
 */
using CompressedScript = prevector<33, unsigned char>;


bool CompressScript(const CScript& script, CompressedScript& out);
unsigned int GetSpecialScriptSize(unsigned int nSize);
bool DecompressScript(CScript& script, unsigned int nSize, const CompressedScript& in);

/**
 * Compress amount.
 *
 * nAmount is of type uint64_t and thus cannot be negative. If you're passing in
 * a CAmount (int64_t), make sure to properly handle the case where the amount
 * is negative before calling CompressAmount(...).
 *
 * @pre Function defined only for 0 <= nAmount <= MAX_MONEY.
 */
uint64_t CompressAmount(uint64_t nAmount);

uint64_t DecompressAmount(uint64_t nAmount);

/** Compact serializer for scripts.
 *
 *  It detects common cases and encodes them much more efficiently.
 *  3 special cases are defined:
 *  * Pay to pubkey hash (encoded as 21 bytes)
 *  * Pay to script hash (encoded as 21 bytes)
 *  * Pay to pubkey starting with 0x02, 0x03 or 0x04 (encoded as 33 bytes)
 *
 *  Other scripts up to 121 bytes require 1 byte + script length. Above
 *  that, scripts up to 16505 bytes require 2 bytes + script length.
 */
struct ScriptCompression
{
    /**
     * make this static for now (there are only 6 special scripts defined)
     * this can potentially be extended together with a new version for
     * transactions, in which case this value becomes dependent on version
     * and nHeight of the enclosing transaction.
     */
    static const unsigned int nSpecialScripts = 6;

    template<typename Stream>
    void Ser(Stream &s, const CScript& script) {
        CompressedScript compr;
        if (CompressScript(script, compr)) {
            s << std::span{compr};
            return;
        }
        unsigned int nSize = script.size() + nSpecialScripts;
        s << VARINT(nSize);
        s << std::span{script};
    }

    template<typename Stream>
    void Unser(Stream &s, CScript& script) {
        unsigned int nSize = 0;
        s >> VARINT(nSize);
        if (nSize < nSpecialScripts) {
            CompressedScript vch(GetSpecialScriptSize(nSize), 0x00);
            s >> std::span{vch};
            DecompressScript(script, nSize, vch);
            return;
        }
        nSize -= nSpecialScripts;
        if (nSize > MAX_SCRIPT_SIZE) {
            // Overly long script, replace with a short invalid one
            script << OP_RETURN;
            s.ignore(nSize);
        } else {
            script.resize(nSize);
            s >> std::span{script};
        }
    }
};

enum class ReconstructableScriptType: unsigned char {
    Unknown = 0x00,
    P2pkh = 0x01,
    P2pkEven = 0x02,
    P2pkOdd = 0x03,
    P2pkUncompressed = 0x04,
    P2sh = 0x05,
    P2wsh = 0x06,
    P2wpkh = 0x07,
    P2tr = 0x08,
};

template <typename Stream>
void Serialize(Stream& s, ReconstructableScriptType type)
{
    ::Serialize(s, static_cast<uint8_t>(type));
}

struct ReconstructableScript {
    template<typename Stream>
    void Ser(Stream& s, const CScript& script)
    {
        if (script.IsPayToTaproot()) {
            ::Serialize(s, ReconstructableScriptType::P2tr);
            ::Serialize(s, MakeByteSpan(script).subspan(2, 32));
            return;
        }
        if (script.IsPayToWitnessScriptHash()) {
            ::Serialize(s, ReconstructableScriptType::P2wsh);
            ::Serialize(s, MakeByteSpan(script).subspan(2, 32));
            return;
        }
        if (script.size() == 22 && script[0] == OP_0 && script[1] == 20) {
            ::Serialize(s, ReconstructableScriptType::P2wpkh);
            ::Serialize(s, MakeByteSpan(script).subspan(2, 20));
            return;
        }
        if (script.IsPayToScriptHash()) {
            ::Serialize(s, ReconstructableScriptType::P2sh);
            ::Serialize(s, MakeByteSpan(script).subspan(2, 20));
            return;
        }
        if  (script.size() == 25 && script[0] == OP_DUP && script[1] == OP_HASH160
                            && script[2] == 20 && script[23] == OP_EQUALVERIFY
                            && script[24] == OP_CHECKSIG) {
            ::Serialize(s, ReconstructableScriptType::P2pkh);
            ::Serialize(s, MakeByteSpan(script).subspan(3, 20));
            return;
        }
        if (script.size() == 35 && script[0] == 33 && script[34] == OP_CHECKSIG) {
            if (script[1] == 0x02) {
                ::Serialize(s, ReconstructableScriptType::P2pkEven);
                ::Serialize(s, MakeByteSpan(script).subspan(2, 32));
                return;
            }
            if (script[1] == 0x03) {
                ::Serialize(s, ReconstructableScriptType::P2pkOdd);
                ::Serialize(s, MakeByteSpan(script).subspan(2, 32));
                return;
            }
        }
        if (script.size() == 67 && script[0] == 65 && script[66] == OP_CHECKSIG && script[1] == 0x04) {
            ::Serialize(s, ReconstructableScriptType::P2pkUncompressed);
            ::Serialize(s, MakeByteSpan(script).subspan(2, 64));
            return;
        }
        ::Serialize(s, ReconstructableScriptType::Unknown);
        ::Serialize(s, script);
    }

    template<typename Stream>
    void Unser(Stream& s, CScript& script)
    {
        unsigned char type;
        ::Unserialize(s, type);
        ReconstructableScriptType s_type{type};
        switch (s_type) {
            case ReconstructableScriptType::P2tr: {
                std::array<unsigned char, 32> x_only;
                ::Unserialize(s, std::span{x_only});
                script.resize(34);
                script[0] = OP_1;
                script[1] = 32;
                memcpy(&script[2], x_only.data(), 32);
                break;
            }
            case ReconstructableScriptType::P2wsh: {
                uint256 hash;
                ::Unserialize(s, hash);
                script.resize(34);
                script[0] = OP_0;
                script[1] = 32;
                memcpy(&script[2], hash.data(), 32);
                break;
            }
            case ReconstructableScriptType::P2wpkh: {
                uint160 hash;
                ::Unserialize(s, hash);
                script.resize(22);
                script[0] = OP_0;
                script[1] = 20;
                memcpy(&script[2], hash.data(), 20);
                break;
            }
            case ReconstructableScriptType::P2sh: {
                uint160 hash;
                ::Unserialize(s, hash);
                script.resize(23);
                script[0] = OP_HASH160;
                script[1] = 20;
                memcpy(&script[2], hash.data(), 20);
                script[22] = OP_EQUAL;
                break;
            }
            case ReconstructableScriptType::P2pkh: {
                uint160 hash;
                ::Unserialize(s, hash);
                script.resize(25);
                script[0] = OP_DUP;
                script[1] = OP_HASH160;
                script[2] = 20;
                memcpy(&script[3], hash.data(), 20);
                script[23] = OP_EQUALVERIFY;
                script[24] = OP_CHECKSIG;
                break;
            }
            case ReconstructableScriptType::P2pkEven:
            case ReconstructableScriptType::P2pkOdd: {
                std::array<unsigned char, 32> xcoord;
                ::Unserialize(s, std::span{xcoord});
                script.resize(35);
                script[0] = 33;
                script[1] = type;
                memcpy(&script[2], xcoord.data(), 32);
                script[34] = OP_CHECKSIG;
                break;
            }
            case ReconstructableScriptType::P2pkUncompressed: {
                std::array<unsigned char, 64> public_key;
                ::Unserialize(s, std::span{public_key});
                script.resize(67);
                script[0] = 65;
                script[1] = 0x04;
                memcpy(&script[2], public_key.data(), 64);
                script[66] = OP_CHECKSIG;
                break;
            }
            case ReconstructableScriptType::Unknown: {
                ::Unserialize(s, script);
                break;
            }
            default: break;
        }
    }
};

struct AmountCompression
{
    template<typename Stream, typename I> void Ser(Stream& s, I val)
    {
        s << VARINT(CompressAmount(val));
    }
    template<typename Stream, typename I> void Unser(Stream& s, I& val)
    {
        uint64_t v;
        s >> VARINT(v);
        val = DecompressAmount(v);
    }
};

/** wrapper for CTxOut that provides a more compact serialization */
struct TxOutCompression
{
    FORMATTER_METHODS(CTxOut, obj) { READWRITE(Using<AmountCompression>(obj.nValue), Using<ScriptCompression>(obj.scriptPubKey)); }
};

#endif // BITCOIN_COMPRESSOR_H
