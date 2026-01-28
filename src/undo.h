// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UNDO_H
#define BITCOIN_UNDO_H

#include <coins.h>
#include <compressor.h>
#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

/** Formatter for undo information for a CTxIn
 *
 *  Contains the prevout's CTxOut being spent, and its metadata as well
 *  (coinbase or not, height). The serialization contains a dummy value of
 *  zero. This is compatible with older versions which expect to see
 *  the transaction version there.
 */
struct TxInUndoFormatter
{
    template<typename Stream>
    void Ser(Stream &s, const Coin& txout) {
        ::Serialize(s, VARINT(txout.nHeight * uint32_t{2} + txout.fCoinBase ));
        if (txout.nHeight > 0) {
            // Required to maintain compatibility with older undo format.
            ::Serialize(s, (unsigned char)0);
        }
        ::Serialize(s, Using<TxOutCompression>(txout.out));
    }

    template<typename Stream>
    void Unser(Stream &s, Coin& txout) {
        uint32_t nCode = 0;
        ::Unserialize(s, VARINT(nCode));
        txout.nHeight = nCode >> 1;
        txout.fCoinBase = nCode & 1;
        if (txout.nHeight > 0) {
            // Old versions stored the version number for the last spend of
            // a transaction's outputs. Non-final spends were indicated with
            // height = 0.
            unsigned int nVersionDummy;
            ::Unserialize(s, VARINT(nVersionDummy));
        }
        ::Unserialize(s, Using<TxOutCompression>(txout.out));
    }
};

struct NetworkCoinFormatter
{
    template<typename Stream>
    void Ser(Stream& s, const Coin& coin) {
        ::Serialize(s, coin.nHeight * uint32_t{2} + coin.fCoinBase);
        ::Serialize(s, Using<AmountCompression>(coin.out.nValue));
        ::Serialize(s, Using<ReconstructableScript>(coin.out.scriptPubKey));
    }

    template<typename Stream>
    void Unser(Stream& s, Coin& coin) {
        uint32_t n_code = 0x00;
        ::Unserialize(s, n_code);
        coin.nHeight = n_code >> 1;
        coin.fCoinBase = n_code & 1;
        ::Unserialize(s, Using<AmountCompression>(coin.out.nValue));
        ::Unserialize(s, Using<ReconstructableScript>(coin.out.scriptPubKey));
    }
};

class InputCoin {
public:
    Coin m_coin;
    uint32_t m_index{};
};

struct InputCoinFormatter {
    template <typename Stream>
    void Ser(Stream& s, const InputCoin& coin) {
        ::Serialize(s, coin.m_index);
        ::Serialize(s, Using<NetworkCoinFormatter>(coin.m_coin));
    }

    template <typename Stream>
    void Unser(Stream& s, InputCoin& coin) {
        ::Unserialize(s, coin.m_index);
        ::Unserialize(s, Using<NetworkCoinFormatter>(coin.m_coin));
    }
};

/** Undo information for a CTransaction */
class CTxUndo
{
public:
    // undo information for all txins
    std::vector<Coin> vprevout;

    SERIALIZE_METHODS(CTxUndo, obj) { READWRITE(Using<VectorFormatter<TxInUndoFormatter>>(obj.vprevout)); }
};

/** Undo information for a CBlock */
class CBlockUndo
{
public:
    std::vector<CTxUndo> vtxundo; // for all but the coinbase

    SERIALIZE_METHODS(CBlockUndo, obj) { READWRITE(obj.vtxundo); }
};

class NetworkBlockUndo
{
public:
    std::vector<InputCoin> m_coins;
    uint256 m_hash;

    NetworkBlockUndo(): m_coins{}, m_hash{} {};

    NetworkBlockUndo(uint256 hash, CBlockUndo& undo, uint32_t cutoff): m_hash{hash} {
        uint32_t index{0};
        for (const auto& tx_undo : undo.vtxundo) {
            for (const auto& coin : tx_undo.vprevout) {
                if (cutoff == 0x00 || coin.nHeight < cutoff) {
                    m_coins.emplace_back(coin, index);
                }
                ++index;
            }
        }
    }

    template <typename Stream>
    void Serialize(Stream& s) const {
        ::Serialize(s, m_hash);
        ::Serialize(s, Using<VectorFormatter<InputCoinFormatter>>(m_coins));
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        ::Unserialize(s, m_hash);
        ::Unserialize(s, Using<VectorFormatter<InputCoinFormatter>>(m_coins));
    }
};
#endif // BITCOIN_UNDO_H
