#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
""" Testing related to SwiftSync initial block download protocol.
"""
from test_framework.util import assert_equal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet

BASE_BLOCKS = 200
NUM_SWIFTSYNC_BLOCKS = 100
NUM_ADDITIONAL_BLOCKS = 100
GOOD_FILE = "good.hints"
BAD_FILE = "bad.hints"

class SwiftSyncTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.add_nodes(2)

    def run_test(self):
        full_node = self.nodes[0]
        sync_node = self.nodes[1]
        self.start_node(0)
        mini_wallet = MiniWallet(full_node)
        ## Coinbase outputs are treated differently by the SwiftSync protocol as their inputs are ignored.
        ## To ensure the hash aggregate is working correctly, we also create non-coinbase transactions.
        self.log.info(f"Generating {BASE_BLOCKS} blocks to a source node")
        self.generate(mini_wallet, BASE_BLOCKS, sync_fun=self.no_op)
        self.log.info(f"Sending {NUM_SWIFTSYNC_BLOCKS} self transfers")
        for i in range(NUM_SWIFTSYNC_BLOCKS):
            mini_wallet.send_self_transfer(from_node=full_node)
            self.generate(full_node, nblocks=1, sync_fun=self.no_op)

        self.log.info("Creating hints file")
        result = full_node.generatetxohints(GOOD_FILE)
        hints_path = result["path"]
        self.log.info(f"Created hints file at {hints_path}")
        assert_equal(full_node.getblockcount(), NUM_SWIFTSYNC_BLOCKS + BASE_BLOCKS)
        self.log.info(f"Generating {NUM_ADDITIONAL_BLOCKS} blocks with additional self transfers")
        for i in range(NUM_ADDITIONAL_BLOCKS):
            mini_wallet.send_self_transfer(from_node=full_node)
            self.generate(full_node, nblocks=1, sync_fun=self.no_op)
        self.log.info("Starting a pruned node with a hints file and performing IBD")
        self.start_node(1, extra_args=["-prune=1", f"-utxohints={hints_path}"])
        assert_equal(sync_node.getblockcount(), 0)
        self.connect_nodes(0, 1)
        self.log.info("Asserting sync is successful")
        self.sync_blocks([full_node, sync_node])
        assert_equal(full_node.getblockcount(), sync_node.getblockcount())
        self.log.info("Sync successful")
        self.log.info("Creating a hints file from a stale block")
        self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())
        mini_wallet.send_self_transfer(from_node=full_node)
        self.generate(full_node, nblocks=1, sync_fun=self.no_op)
        result = full_node.generatetxohints(BAD_FILE)
        bad_hints_path = result["path"]
        self.log.info(f"Created defect hints file at {bad_hints_path}")
        self.log.info("Creating heavier chain")
        self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())
        mini_wallet.send_self_transfer(from_node=full_node)
        self.generate(full_node, nblocks=2, sync_fun=self.no_op)
        self.log.info("Asserting pruned node can reorganize")
        self.connect_nodes(0, 1)
        self.sync_blocks([full_node, sync_node])
        assert_equal(full_node.getbestblockhash(), sync_node.getbestblockhash())
        self.log.info("Reorganize successful")

if __name__ == '__main__':
    SwiftSyncTest(__file__).main()
