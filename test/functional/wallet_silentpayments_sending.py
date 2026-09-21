#!/usr/bin/env python3
# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test sending to BIP352 silent payments addresses."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than

# A valid BIP352 v0 silent payments address for regtest (HRP "sprt").
SP_ADDR = "sprt1qq04xgllnqqfdlxjkr355rmsahfn9t8l6sd0k20t4uka4c73nvvpnwqu4kvg0nm62d5jtmqp54lkc7tul0dzt25ejtn4f80505z3u0h5jag59rdg4"


class WalletSilentPaymentsSendingTest(BitcoinTestFramework):
    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def assert_taproot_output(self, txid):
        decoded = self.wallet.decoderawtransaction(self.wallet.gettransaction(txid)["hex"])
        taproot = [o for o in decoded["vout"] if o["scriptPubKey"]["type"] == "witness_v1_taproot"]
        assert_greater_than(len(taproot), 0)
        return taproot

    def run_test(self):
        self.wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        node = self.nodes[0]

        self.generate(node, 101)

        # Fund the wallet with bech32 (BIP352-eligible) coins.
        self.wallet.sendtoaddress(self.wallet.getnewaddress("", "bech32"), 10)
        self.generate(node, 1)
        assert_greater_than(self.wallet.getbalance(), 0)

        # sendtoaddress to a silent payments address.
        txid = self.wallet.sendtoaddress(SP_ADDR, 1)
        self.assert_taproot_output(txid)

        # RBF must be able to recompute the silent payments output for the replacement.
        bump = self.wallet.bumpfee(txid)
        self.assert_taproot_output(bump["txid"])
        self.generate(node, 1)

        # send RPC (PSBT based funding path).
        send_res = self.wallet.send(outputs={SP_ADDR: 1})
        self.assert_taproot_output(send_res["txid"])
        self.generate(node, 1)

        # walletcreatefundedpsbt / walletprocesspsbt path.
        funded = self.wallet.walletcreatefundedpsbt([], {SP_ADDR: 1})
        processed = self.wallet.walletprocesspsbt(funded["psbt"])
        assert_equal(processed["complete"], True)
        self.generate(node, 1)

        # sendall to a silent payments address.
        sendall_res = self.wallet.sendall([SP_ADDR])
        self.assert_taproot_output(sendall_res["txid"])


if __name__ == '__main__':
    WalletSilentPaymentsSendingTest(__file__).main()
