#!/usr/bin/env python3
# Copyright (c) 2020-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests that a mempool transaction expires after a given timeout and that its
children are removed as well.

Both the default expiry timeout defined by DEFAULT_MEMPOOL_EXPIRY_HOURS and a user
definable expiry timeout via the '-mempoolexpiry=<n>' command line argument
(<n> is the timeout in hours) are tested.

Also demonstrates a bug where a high-fee CPFP child is incorrectly expired
because the time-based index only considers the parent's entry time, not the
child's fee rate or the package fee rate.
"""

from datetime import timedelta
from decimal import Decimal

from test_framework.messages import (
    COIN,
    DEFAULT_MEMPOOL_EXPIRY_HOURS,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet

CUSTOM_MEMPOOL_EXPIRY = 10  # hours


class MempoolExpiryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def test_transaction_expiry(self, timeout):
        """Tests that a transaction expires after the expiry timeout and its
        children are removed as well."""
        node = self.nodes[0]

        # Send a parent transaction that will expire.
        parent = self.wallet.send_self_transfer(from_node=node)
        parent_txid = parent["txid"]
        parent_utxo = self.wallet.get_utxo(txid=parent_txid)
        independent_utxo = self.wallet.get_utxo()

        # Add prioritisation to this transaction to check that it persists after the expiry
        node.prioritisetransaction(parent_txid, 0, COIN)
        assert_equal(node.getprioritisedtransactions()[parent_txid], { "fee_delta" : COIN, "in_mempool" : True, "modified_fee": COIN + COIN * parent["fee"] })

        # Ensure the transactions we send to trigger the mempool check spend utxos that are independent of
        # the transactions being tested for expiration.
        trigger_utxo1 = self.wallet.get_utxo()
        trigger_utxo2 = self.wallet.get_utxo()

        # Set the mocktime to the arrival time of the parent transaction.
        entry_time = node.getmempoolentry(parent_txid)['time']
        node.setmocktime(entry_time)

        # Let half of the timeout elapse and broadcast the child transaction spending the parent transaction.
        half_expiry_time = entry_time + int(60 * 60 * timeout/2)
        node.setmocktime(half_expiry_time)
        child_txid = self.wallet.send_self_transfer(from_node=node, utxo_to_spend=parent_utxo)['txid']
        assert_equal(parent_txid, node.getmempoolentry(child_txid)['depends'][0])
        self.log.info('Broadcast child transaction after {} hours.'.format(
            timedelta(seconds=(half_expiry_time-entry_time))))

        # Broadcast another (independent) transaction.
        independent_txid = self.wallet.send_self_transfer(from_node=node, utxo_to_spend=independent_utxo)['txid']

        # Let most of the timeout elapse and check that the parent tx is still
        # in the mempool.
        nearly_expiry_time = entry_time + 60 * 60 * timeout - 5
        node.setmocktime(nearly_expiry_time)
        # Broadcast a transaction as the expiry of transactions in the mempool is only checked
        # when a new transaction is added to the mempool.
        self.wallet.send_self_transfer(from_node=node, utxo_to_spend=trigger_utxo1)
        self.log.info('Test parent tx not expired after {} hours.'.format(
            timedelta(seconds=(nearly_expiry_time-entry_time))))
        assert_equal(entry_time, node.getmempoolentry(parent_txid)['time'])

        # Transaction should be evicted from the mempool after the expiry time
        # has passed.
        expiry_time = entry_time + 60 * 60 * timeout + 5
        node.setmocktime(expiry_time)
        # Again, broadcast a transaction so the expiry of transactions in the mempool is checked.
        self.wallet.send_self_transfer(from_node=node, utxo_to_spend=trigger_utxo2)
        self.log.info('Test parent tx expiry after {} hours.'.format(
            timedelta(seconds=(expiry_time-entry_time))))
        assert_raises_rpc_error(-5, 'Transaction not in mempool',
                                node.getmempoolentry, parent_txid)

        # Prioritisation does not disappear when transaction expires
        assert_equal(node.getprioritisedtransactions()[parent_txid], { "fee_delta" : COIN, "in_mempool" : False})

        # The child transaction should be removed from the mempool as well.
        self.log.info('Test child tx is evicted as well.')
        assert_raises_rpc_error(-5, 'Transaction not in mempool',
                                node.getmempoolentry, child_txid)

        # Check that the independent tx is still in the mempool.
        self.log.info('Test the independent tx not expired after {} hours.'.format(
            timedelta(seconds=(expiry_time-half_expiry_time))))
        assert_equal(half_expiry_time, node.getmempoolentry(independent_txid)['time'])

    def test_cpfp_parent_expiry(self, timeout):
        """Demonstrates that a CPFP child with a high fee rate is incorrectly
        expired because the time-based index only considers the parent's entry
        time. Expire() marks the parent as expired, then CalculateDescendants()
        sweeps the child out along with it — regardless of the child's fee rate
        or how recently it arrived."""
        node = self.nodes[0]

        # Send a low-fee parent that will eventually expire.
        parent = self.wallet.send_self_transfer(from_node=node, fee_rate=Decimal("0.001"))
        parent_txid = parent["txid"]
        parent_utxo = self.wallet.get_utxo(txid=parent_txid)
        trigger_utxo = self.wallet.get_utxo()

        entry_time = node.getmempoolentry(parent_txid)['time']
        node.setmocktime(entry_time)

        # Advance to just before the parent expires. This simulates a real-world
        # scenario: a transaction has been sitting unconfirmed for a long time and
        # the user sends a high-fee CPFP child to get it confirmed before it drops.
        nearly_expired_time = entry_time + int(60 * 60 * timeout) - 30
        node.setmocktime(nearly_expired_time)

        # Send a high-fee CPFP child. Its individual fee rate is far above the
        # parent's, and the package fee rate is also high.
        child = self.wallet.send_self_transfer(from_node=node, utxo_to_spend=parent_utxo, fee_rate=Decimal("10.0"))
        child_txid = child["txid"]

        parent_entry = node.getmempoolentry(parent_txid)
        child_entry = node.getmempoolentry(child_txid)
        parent_feerate = float(parent_entry['fees']['base']) / parent_entry['vsize'] * 1e8 * 1000
        child_feerate = float(child_entry['fees']['base']) / child_entry['vsize'] * 1e8 * 1000
        self.log.info(f"Parent fee rate: {parent_feerate:.1f} sat/kvB, Child fee rate: {child_feerate:.1f} sat/kvB")

        # The child entered the mempool only 30 seconds before the parent expires.
        assert_equal(child_entry['time'], nearly_expired_time)

        # Advance past the parent's expiry window and trigger the expiry check.
        expiry_time = entry_time + int(60 * 60 * timeout) + 5
        node.setmocktime(expiry_time)
        self.wallet.send_self_transfer(from_node=node, utxo_to_spend=trigger_utxo)

        # The parent has expired, as expected.
        assert_raises_rpc_error(-5, 'Transaction not in mempool', node.getmempoolentry, parent_txid)

        # BUG: the high-fee CPFP child is also evicted even though it entered
        # the mempool only 35 seconds ago. Expire() decides to remove the parent
        # based solely on the parent's entry time, then CalculateDescendants()
        # sweeps the child out without consulting the child's entry time or fee
        # rate. The package fee rate is never considered.
        assert_raises_rpc_error(-5, 'Transaction not in mempool', node.getmempoolentry, child_txid)
        self.log.info("Bug confirmed: high-fee CPFP child evicted solely because its parent was old.")

    def run_test(self):
        self.wallet = MiniWallet(self.nodes[0])

        self.log.info('Test default mempool expiry timeout of %d hours.' %
                      DEFAULT_MEMPOOL_EXPIRY_HOURS)
        self.test_transaction_expiry(DEFAULT_MEMPOOL_EXPIRY_HOURS)

        self.log.info('Test custom mempool expiry timeout of %d hours.' %
                      CUSTOM_MEMPOOL_EXPIRY)
        self.restart_node(0, ['-mempoolexpiry=%d' % CUSTOM_MEMPOOL_EXPIRY])
        self.test_transaction_expiry(CUSTOM_MEMPOOL_EXPIRY)

        self.log.info('Test CPFP child incorrectly expired with old parent (default timeout).')
        self.restart_node(0, ['-mempoolexpiry=%d' % DEFAULT_MEMPOOL_EXPIRY_HOURS])
        self.test_cpfp_parent_expiry(DEFAULT_MEMPOOL_EXPIRY_HOURS)

        self.log.info('Test CPFP child incorrectly expired with old parent (custom timeout).')
        self.restart_node(0, ['-mempoolexpiry=%d' % CUSTOM_MEMPOOL_EXPIRY])
        self.test_cpfp_parent_expiry(CUSTOM_MEMPOOL_EXPIRY)


if __name__ == '__main__':
    MempoolExpiryTest(__file__).main()
