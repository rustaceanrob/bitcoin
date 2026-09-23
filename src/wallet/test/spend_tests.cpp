// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <coins.h>
#include <common/bip352.h>
#include <consensus/amount.h>
#include <key.h>
#include <key_io.h>
#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(spend_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(max_signed_input_size_uses_external_outpoint)
{
    const CKey key{GenerateRandomKey()};
    FillableSigningProvider provider;
    BOOST_REQUIRE(provider.AddKey(key));

    const CTxOut txout{COIN, GetScriptForDestination(PKHash{key.GetPubKey()})};
    const COutPoint outpoint{Txid{}, 0};
    CCoinControl coin_control;
    coin_control.Select(outpoint).SetTxOut(txout);

    const int low_r{CalculateMaximumSignedInputSize(txout, COutPoint{}, &provider, /*can_grind_r=*/true, &coin_control)};
    const int high_r{CalculateMaximumSignedInputSize(txout, outpoint, &provider, /*can_grind_r=*/true, &coin_control)};
    BOOST_CHECK_EQUAL(high_r, low_r + 1);
}

BOOST_FIXTURE_TEST_CASE(SubtractFee, TestChain100Setup)
{
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    // Check that a subtract-from-recipient transaction slightly less than the
    // coinbase input amount does not create a change output (because it would
    // be uneconomical to add and spend the output), and make sure it pays the
    // leftover input amount which would have been change to the recipient
    // instead of the miner.
    auto check_tx = [&wallet](CAmount leftover_input_amount) {
        CRecipient recipient{PubKeyDestination({}), 50 * COIN - leftover_input_amount, /*subtract_fee=*/true};
        CCoinControl coin_control;
        coin_control.m_feerate.emplace(10000);
        coin_control.fOverrideFeeRate = true;
        // We need to use a change type with high cost of change so that the leftover amount will be dropped to fee instead of added as a change output
        coin_control.m_change_type = OutputType::LEGACY;
        auto res = CreateTransaction(*wallet, {recipient}, /*change_pos=*/std::nullopt, coin_control);
        BOOST_CHECK(res);
        const auto& txr = *res;
        BOOST_CHECK_EQUAL(txr.tx->vout.size(), 1);
        BOOST_CHECK_EQUAL(txr.tx->vout[0].nValue, recipient.nAmount + leftover_input_amount - txr.fee);
        BOOST_CHECK_GT(txr.fee, 0);
        return txr.fee;
    };

    // Send full input amount to recipient, check that only nonzero fee is
    // subtracted (to_reduce == fee).
    const CAmount fee{check_tx(0)};

    // Send slightly less than full input amount to recipient, check leftover
    // input amount is paid to recipient not the miner (to_reduce == fee - 123)
    BOOST_CHECK_EQUAL(fee, check_tx(123));

    // Send full input minus fee amount to recipient, check leftover input
    // amount is paid to recipient not the miner (to_reduce == 0)
    BOOST_CHECK_EQUAL(fee, check_tx(fee));

    // Send full input minus more than the fee amount to recipient, check
    // leftover input amount is paid to recipient not the miner (to_reduce ==
    // -123). This overpays the recipient instead of overpaying the miner more
    // than double the necessary fee.
    BOOST_CHECK_EQUAL(fee, check_tx(fee + 123));
}

BOOST_FIXTURE_TEST_CASE(wallet_duplicated_preset_inputs_test, TestChain100Setup)
{
    // Verify that the wallet's Coin Selection process does not include pre-selected inputs twice in a transaction.

    // Add 4 spendable UTXO, 50 BTC each, to the wallet (total balance 200 BTC)
    for (int i = 0; i < 4; i++) CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);

    LOCK(wallet->cs_wallet);
    auto available_coins = AvailableCoins(*wallet);
    std::vector<COutput> coins = available_coins.All();
    // Preselect the first 3 UTXO (150 BTC total)
    std::set<COutPoint> preset_inputs = {coins[0].outpoint, coins[1].outpoint, coins[2].outpoint};

    // Try to create a tx that spends more than what preset inputs + wallet selected inputs are covering for.
    // The wallet can cover up to 200 BTC, and the tx target is 299 BTC.
    std::vector<CRecipient> recipients{{*Assert(wallet->GetNewDestination(OutputType::BECH32, "dummy")),
                                           /*nAmount=*/299 * COIN, /*fSubtractFeeFromAmount=*/true}};
    CCoinControl coin_control;
    coin_control.m_allow_other_inputs = true;
    for (const auto& outpoint : preset_inputs) {
        coin_control.Select(outpoint);
    }

    // Attempt to send 299 BTC from a wallet that only has 200 BTC. The wallet should exclude
    // the preset inputs from the pool of available coins, realize that there is not enough
    // money to fund the 299 BTC payment, and fail with "Insufficient funds".
    //
    // Even with SFFO, the wallet can only afford to send 200 BTC.
    // If the wallet does not properly exclude preset inputs from the pool of available coins
    // prior to coin selection, it may create a transaction that does not fund the full payment
    // amount or, through SFFO, incorrectly reduce the recipient's amount by the difference
    // between the original target and the wrongly counted inputs (in this case 99 BTC)
    // so that the recipient's amount is no longer equal to the user's selected target of 299 BTC.

    // First case, use 'subtract_fee_from_outputs=true'
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));

    // Second case, don't use 'subtract_fee_from_outputs'.
    recipients[0].fSubtractFeeFromAmount = false;
    BOOST_CHECK(!CreateTransaction(*wallet, recipients, /*change_pos=*/std::nullopt, coin_control));
}

/**
 * Scan a transaction with a silent payments receiver and return the tweaks and
 * matching output indexes for every output found.
 */
static std::map<uint32_t, uint256> ScanSilentPayments(const CKey& scan_key, const CPubKey& spend_pubkey, const CTransaction& tx, const std::map<COutPoint, Coin>& coins)
{
    const auto prevouts_summary{bip352::GetSilentPaymentsPrevoutsSummary(tx.vin, coins)};
    BOOST_REQUIRE(prevouts_summary.has_value());
    std::vector<XOnlyPubKey> tx_outputs;
    std::vector<uint32_t> tr_indexes;
    for (uint32_t i = 0; i < tx.vout.size(); ++i) {
        std::vector<std::vector<unsigned char>> solutions;
        if (Solver(tx.vout[i].scriptPubKey, solutions) == TxoutType::WITNESS_V1_TAPROOT) {
            tr_indexes.push_back(i);
            tx_outputs.emplace_back(solutions[0]);
        }
    }
    bip352::SilentPaymentsReceiver receiver{scan_key, spend_pubkey};
    const auto found_outputs{receiver.Scan(*prevouts_summary, tx_outputs)};
    BOOST_REQUIRE(found_outputs.has_value());
    std::map<uint32_t, uint256> found;
    for (const auto& output : *found_outputs) {
        // Find which output index this key belongs to
        const auto it{std::find(tx_outputs.begin(), tx_outputs.end(), output.output)};
        BOOST_REQUIRE(it != tx_outputs.end());
        found.emplace(tr_indexes.at(it - tx_outputs.begin()), output.tweak);
    }
    return found;
}

BOOST_FIXTURE_TEST_CASE(silent_payments_sending, TestChain100Setup)
{
    // Fund the wallet with one P2WPKH and one P2TR coin. The mined coinbase outputs
    // are bare P2PK, which is not in BIP352's "Inputs For Shared Secret Derivation" list.
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    auto wallet{CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey)};
    {
        // Add a tr() and a rawtr() descriptor for the coinbase key
        LOCK(wallet->cs_wallet);
        FlatSigningProvider provider;
        std::string error;
        auto descs{Parse("tr(" + EncodeSecret(coinbaseKey) + ")", provider, error, /*require_checksum=*/false)};
        assert(descs.size() == 1);
        WalletDescriptor w_desc(std::move(descs.at(0)), 0, 0, 1, 1);
        Assert(wallet->AddWalletDescriptor(w_desc, provider, "", false));
        auto rawtr_descs{Parse("rawtr(" + EncodeSecret(coinbaseKey) + ")", provider, error, /*require_checksum=*/false)};
        assert(rawtr_descs.size() == 1);
        WalletDescriptor rawtr_desc(std::move(rawtr_descs.at(0)), 0, 0, 1, 1);
        Assert(wallet->AddWalletDescriptor(rawtr_desc, provider, "", false));
    }

    CCoinControl coin_control;
    coin_control.m_feerate.emplace(10000);
    coin_control.fOverrideFeeRate = true;
    CScript wpkh_spk, tr_spk, rawtr_spk;
    {
        LOCK(wallet->cs_wallet);
        const CTxDestination wpkh_dest{*Assert(wallet->GetNewDestination(OutputType::BECH32, ""))};
        const CTxDestination tr_dest{*Assert(wallet->GetNewDestination(OutputType::BECH32M, ""))};
        wpkh_spk = GetScriptForDestination(wpkh_dest);
        tr_spk = GetScriptForDestination(tr_dest);
        // The rawtr() script for the coinbase key's x-only public key
        const CTxDestination rawtr_dest{WitnessV1Taproot{XOnlyPubKey{coinbaseKey.GetPubKey()}}};
        rawtr_spk = GetScriptForDestination(rawtr_dest);
        const auto self_transfer{CreateTransaction(*wallet, {{wpkh_dest, 5 * COIN, /*fSubtractFeeFromAmount=*/false}, {tr_dest, 5 * COIN, /*fSubtractFeeFromAmount=*/false}, {rawtr_dest, 5 * COIN, /*fSubtractFeeFromAmount=*/false}}, /*change_pos=*/std::nullopt, coin_control)};
        BOOST_REQUIRE(self_transfer);
        wallet->CommitTransaction(self_transfer->tx);
        CreateAndProcessBlock({CMutableTransaction{*self_transfer->tx}}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        LOCK(Assert(m_node.chainman)->GetMutex());
        wallet->SetLastBlockProcessed(wallet->GetLastBlockHeight() + 1, m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        auto it{wallet->mapWallet.find(self_transfer->tx->GetHash())};
        BOOST_REQUIRE(it != wallet->mapWallet.end());
        it->second.m_state = TxStateConfirmed{m_node.chainman->ActiveChain().Tip()->GetBlockHash(), m_node.chainman->ActiveChain().Height(), /*index=*/1};
    }

    const CKey scan_key{GenerateRandomKey()};
    const CKey spend_key{GenerateRandomKey()};
    const bip352::SilentPaymentsDestination sp_dest{*Assert(bip352::SilentPaymentsDestination::From(scan_key.GetPubKey(), spend_key.GetPubKey()))};

    // Send to the silent payments address spending `funding_spk`, and check that the
    // receiver finds the output by scanning the transaction and can spend it.
    const auto check_silent_payment{[&](const CScript& funding_spk) {
        std::map<COutPoint, Coin> coins;
        CTransactionRef sp_tx;
        {
            LOCK(wallet->cs_wallet);
            CCoinControl select_one;
            select_one.m_allow_other_inputs = false;
            select_one.m_feerate.emplace(10000);
            select_one.fOverrideFeeRate = true;
            for (const auto& coin : AvailableCoins(*wallet, &select_one).All()) {
                if (coin.txout.scriptPubKey == funding_spk) select_one.Select(coin.outpoint);
                coins.emplace(coin.outpoint, Coin{coin.txout, /*nHeightIn=*/1, /*fCoinBaseIn=*/false});
            }
            const auto res{CreateTransaction(*wallet, {{sp_dest, 2 * COIN, /*fSubtractFeeFromAmount=*/false}}, /*change_pos=*/std::nullopt, select_one)};
            BOOST_REQUIRE(res);
            sp_tx = res->tx;
        }

        const auto found{ScanSilentPayments(scan_key, spend_key.GetPubKey(), *sp_tx, coins)};
        BOOST_REQUIRE_EQUAL(found.size(), 1U);
        const auto& [sp_vout, tweak]{*found.begin()};
        BOOST_CHECK_EQUAL(sp_tx->vout.at(sp_vout).nValue, 2 * COIN);
        // The change output is a fresh wallet output and is not found by the receiver
        BOOST_REQUIRE_EQUAL(sp_tx->vout.size(), 2U);

        // The receiver can spend the output with (spend_key + tweak) as the private key
        secp256k1_context* ctx{GetSecp256k1SignContext()};
        std::array<unsigned char, 32> spend_seckey;
        memcpy(spend_seckey.data(), spend_key.data(), spend_seckey.size());
        BOOST_CHECK(secp256k1_ec_seckey_tweak_add(ctx, spend_seckey.data(), tweak.data()));
        secp256k1_keypair keypair;
        BOOST_CHECK(secp256k1_keypair_create(ctx, &keypair, spend_seckey.data()));
        secp256k1_xonly_pubkey xonly_pubkey;
        BOOST_CHECK(secp256k1_keypair_xonly_pub(ctx, &xonly_pubkey, nullptr, &keypair));
        std::array<unsigned char, 32> xonly_bytes;
        BOOST_CHECK(secp256k1_xonly_pubkey_serialize(ctx, xonly_bytes.data(), &xonly_pubkey));
        BOOST_CHECK(sp_tx->vout.at(sp_vout).scriptPubKey == GetScriptForDestination(WitnessV1Taproot{XOnlyPubKey{xonly_bytes}}));

        // Every input is fully signed
        for (const CTxIn& txin : sp_tx->vin) {
            BOOST_CHECK(!txin.scriptWitness.IsNull() || !txin.scriptSig.empty());
        }
        return sp_tx;
    }};

    // Spending any of the eligible input types must find and fund the recipient;
    // spending different input types must produce different outputs, as the input
    // keys and smallest outpoint differ.
    const CTransactionRef wpkh_tx{check_silent_payment(wpkh_spk)};
    const CTransactionRef tr_tx{check_silent_payment(tr_spk)};
    const CTransactionRef rawtr_tx{check_silent_payment(rawtr_spk)};
    BOOST_CHECK(wpkh_tx->vout != tr_tx->vout);

    // Spending only non-eligible inputs fails: bare P2PK coinbase coins are not in
    // the derivation list.
    CCoinControl p2pk_only;
    p2pk_only.m_allow_other_inputs = false;
    p2pk_only.m_feerate.emplace(10000);
    p2pk_only.fOverrideFeeRate = true;
    {
        LOCK(wallet->cs_wallet);
        for (const auto& coin : AvailableCoins(*wallet, &p2pk_only).All()) {
            if (coin.txout.scriptPubKey == GetScriptForRawPubKey(coinbaseKey.GetPubKey())) {
                p2pk_only.Select(coin.outpoint);
                break;
            }
        }
        const auto ineligible_res{CreateTransaction(*wallet, {{sp_dest, 2 * COIN, /*fSubtractFeeFromAmount=*/false}}, /*change_pos=*/std::nullopt, p2pk_only)};
        BOOST_REQUIRE(!ineligible_res);
        BOOST_CHECK(util::ErrorString(ineligible_res).original.find("none of the selected inputs is eligible") != std::string::npos);
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
