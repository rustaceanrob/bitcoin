#!/usr/bin/env python3
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.p2p import P2PInterface
from test_framework.util import assert_equal
from test_framework.messages import (
    NODE_BLOCK_UNDO,
    MSG_BLOCK_UNDO,
    msg_getdata,
    CInv,
)

class BlockUndoClient(P2PInterface):
    def __init__(self) -> None:
        super().__init__()

class BlockUndoTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [
            ["-peerblockinputs"],
            [],
        ]

    def run_test(self):
        peer_0 = self.nodes[0].add_p2p_connection(BlockUndoClient())
        peer_1 = self.nodes[1].add_p2p_connection(BlockUndoClient())
        self.log.info("Checking advertised feature bits are correct")
        assert_equal(peer_0.nServices & NODE_BLOCK_UNDO, NODE_BLOCK_UNDO)
        assert_equal(peer_1.nServices & NODE_BLOCK_UNDO, 0)
        request = msg_getdata([CInv(MSG_BLOCK_UNDO, 0)])

if __name__ == "__main__":
    BlockUndoTest(__file__).main()
