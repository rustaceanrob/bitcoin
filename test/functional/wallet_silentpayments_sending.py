#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test sending to silent payment addresses (BIP-352)."""

from test_framework.crypto import secp256k1
from test_framework.key import ECKey, TaggedHash
from test_framework.messages import COIN
from test_framework.segwit_addr import Encoding, bech32_encode, convertbits
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

GE = secp256k1.GE
ORDER = GE.ORDER
SP_HRP = "sprt"  # regtest silent payments HRP


def sp_address(scan_pubkey: bytes, spend_pubkey: bytes, version: int = 0) -> str:
    """Encode a silent payments address for regtest."""
    data = [version] + convertbits(scan_pubkey + spend_pubkey, 8, 5)
    return bech32_encode(Encoding.BECH32M, SP_HRP, data)


def ser_outpoint(txid: str, vout: int) -> bytes:
    """The 36-byte little-endian serialization of an outpoint, per BIP-352."""
    return bytes.fromhex(txid)[::-1] + vout.to_bytes(4, 'little')


def input_pubkey(vin: dict):
    """Extract the public key from a silent payments eligible input, or None."""
    spk = vin['prevout']['scriptPubKey']['hex']
    if spk.startswith('5120') and len(spk) == 68:
        # P2TR: the output key, assuming an even Y coordinate
        return GE.from_bytes(b'\x02' + bytes.fromhex(spk[4:]))
    if spk.startswith('0014') and len(spk) == 44:
        # P2WPKH: the last witness item
        return GE.from_bytes(bytes.fromhex(vin['txinwitness'][-1]))
    if spk.startswith('a914') and spk.endswith('87'):
        # P2SH: only P2SH-P2WPKH is eligible
        redeem = bytes.fromhex(vin['scriptSig']['hex'])[-22:]
        if redeem.hex().startswith('0014'):
            return GE.from_bytes(bytes.fromhex(vin['txinwitness'][-1]))
        return None
    if spk.startswith('76a9') and spk.endswith('88ac'):
        # P2PKH: the last scriptSig push (a compressed pubkey for our wallet's spends)
        return GE.from_bytes(bytes.fromhex(vin['scriptSig']['hex'])[-33:])
    return None


def get_sp_tx(node, txid: str) -> dict:
    """Fetch a decoded transaction and enrich each vin with its prevout."""
    tx = node.getrawtransaction(txid, 1)
    for vin in tx['vin']:
        # The prevouts are spent by this (mempool) transaction, so the mempool must
        # be excluded from the UTXO set lookup
        prevout = node.gettxout(vin['txid'], vin['vout'], False)
        if prevout is None:
            # Unconfirmed parent: take the output from the transaction itself
            parent = node.getrawtransaction(vin['txid'], 1)
            prevout = {'scriptPubKey': parent['vout'][vin['vout']]['scriptPubKey']}
        vin['prevout'] = prevout
    return tx


def compute_sp_output(scan_priv: int, spend_pub: bytes, decoded_tx: dict, k: int = 0):
    """Compute the k-th expected BIP-352 output key (x-only) for a transaction.

    This is an independent, python reimplementation of the receiver-side
    shared secret derivation.
    """
    A = GE()
    outpoints = []
    for vin in decoded_tx['vin']:
        pub = input_pubkey(vin)
        if pub is not None:
            A += pub
        outpoints.append(ser_outpoint(vin['txid'], vin['vout']))
    assert not A.infinity
    smallest = min(outpoints)
    input_hash = int.from_bytes(TaggedHash('BIP0352/Inputs', smallest + A.to_bytes_compressed()), 'big')
    ecdh = ((input_hash * scan_priv) % ORDER) * A
    tweak = int.from_bytes(TaggedHash('BIP0352/SharedSecret', ecdh.to_bytes_compressed() + k.to_bytes(4, 'big')), 'big')
    P = GE.from_bytes(spend_pub) + tweak * secp256k1.G
    return P.to_bytes_xonly(), tweak


def find_sp_output(vout, expected_program: bytes) -> dict:
    """Find the P2TR output paying to expected_program."""
    matches = [o for o in vout if o['scriptPubKey']['hex'] == '5120' + expected_program.hex()]
    assert_equal(len(matches), 1)
    return matches[0]


def find_all_sp_outputs(tx, recipients):
    """Match every tx output against the expected BIP-352 outputs of the recipients."""
    found = []
    for o in tx['vout']:
        spk = o['scriptPubKey']['hex']
        if not spk.startswith('5120'):
            continue
        program = bytes.fromhex(spk[4:])
        for (scan_priv, spend_pub, spend_priv) in recipients:
            for k in range(len(recipients)):
                expected, tweak = compute_sp_output(scan_priv, spend_pub, tx, k)
                if expected == program:
                    found.append((o, spend_pub, spend_priv, tweak))
    return found


class WalletSilentPaymentsSendingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def make_sp_recipient(self):
        """Generate fresh scan/spend keys and the corresponding address."""
        scan_key = ECKey()
        scan_key.generate()
        spend_key = ECKey()
        spend_key.generate()
        scan_priv = int.from_bytes(scan_key.get_bytes(), 'big')
        spend_priv = int.from_bytes(spend_key.get_bytes(), 'big')
        address = sp_address(scan_key.get_pubkey().get_bytes(), spend_key.get_pubkey().get_bytes())
        return address, scan_priv, spend_key.get_pubkey().get_bytes(), spend_priv

    def check_spendable(self, spend_pub: bytes, spend_priv: int, program: bytes, tweak: int):
        """Check the receiver can spend the output with (spend_priv + tweak)."""
        d = (spend_priv + tweak) % ORDER
        assert_equal((d * secp256k1.G).to_bytes_xonly(), program)

    def run_test(self):
        node = self.nodes[0]

        # Cross-check the python address encoder against the C++ unit test vector
        assert_equal(
            sp_address(bytes.fromhex('03ea647ff30012df9a561c6941ee1dba66559ffa835f653d75e5bb5c7a33630337'),
                       bytes.fromhex('0395b310f9ef4a6d24bd8034afed8f2f9f7b44b553325cea93be8fa0a3c7de92ea')),
            'sprt1qq04xgllnqqfdlxjkr355rmsahfn9t8l6sd0k20t4uka4c73nvvpnwqu4kvg0nm62d5jtmqp54lkc7tul0dzt25ejtn4f80505z3u0h5jag59rdg4')

        wallet = node.get_wallet_rpc(node.createwallet('sp_sending')['name'])
        self.generatetoaddress(node, 101, wallet.getnewaddress())

        address, scan_priv, spend_pub, spend_priv = self.make_sp_recipient()

        self.log.info("sendtoaddress to a silent payments address")
        txid = wallet.sendtoaddress(address, 1.0)
        tx = get_sp_tx(node, txid)
        program, tweak = compute_sp_output(scan_priv, spend_pub, tx)
        out = find_sp_output(tx['vout'], program)
        assert_equal(out['value'], 1.0)
        self.check_spendable(spend_pub, spend_priv, program, tweak)
        # The change output is a plain taproot output and is not affected
        assert_equal(len(tx['vout']), 2)

        self.log.info("sendmany to silent payments and regular addresses")
        address2, scan_priv2, spend_pub2, spend_priv2 = self.make_sp_recipient()
        regular = wallet.getnewaddress()
        txid = wallet.sendmany('', {address: 0.5, address2: 0.25, regular: 0.25})
        tx = get_sp_tx(node, txid)
        # The wallet shuffles the recipients, so the output indexes are not
        # predictable; match all outputs against both recipients instead
        found = find_all_sp_outputs(tx, [(scan_priv, spend_pub, spend_priv),
                                         (scan_priv2, spend_pub2, spend_priv2)])
        assert_equal(len(found), 2)
        assert_equal(sorted(o['value'] for o, _, _, _ in found), [0.25, 0.5])
        for o, pub, priv, tweak in found:
            self.check_spendable(pub, priv, bytes.fromhex(o['scriptPubKey']['hex'][4:]), tweak)

        self.log.info("send RPC with a silent payments recipient and an explicit P2TR input")
        tr_address = wallet.getnewaddress(address_type='bech32m')
        fund_txid = wallet.sendtoaddress(tr_address, 3.0)
        fund_tx = node.getrawtransaction(fund_txid, 1)
        tr_vout = next(o['n'] for o in fund_tx['vout'] if o['scriptPubKey'].get('address') == tr_address)
        self.generate(node, 1)
        result = wallet.send(outputs={address: 1.5},
                             options={'inputs': [{'txid': fund_txid, 'vout': tr_vout}]})
        assert result['complete']
        tx = get_sp_tx(node, result["txid"])
        # The transaction spends only the taproot UTXO
        assert_equal([(i['txid'], i['vout']) for i in tx['vin']], [(fund_txid, tr_vout)])
        program, tweak = compute_sp_output(scan_priv, spend_pub, tx)
        find_sp_output(tx['vout'], program)
        self.check_spendable(spend_pub, spend_priv, program, tweak)

        self.log.info("v1 silent payments address (with extension data) is accepted")
        scan_key = ECKey()
        scan_key.generate()
        spend_key = ECKey()
        spend_key.generate()
        v1_address = sp_address(scan_key.get_pubkey().get_bytes(), spend_key.get_pubkey().get_bytes() + bytes.fromhex('deadbeef'), version=1)
        txid = wallet.sendtoaddress(v1_address, 0.4)
        tx = get_sp_tx(node, txid)
        program, tweak = compute_sp_output(int.from_bytes(scan_key.get_bytes(), 'big'), spend_key.get_pubkey().get_bytes(), tx)
        find_sp_output(tx['vout'], program)

        self.log.info("Error cases")
        # Invalid characters / checksum
        assert_raises_rpc_error(-5, 'Invalid Bitcoin address', wallet.sendtoaddress, address[:-1] + 'x', 1.0)
        # Wrong network (mainnet HRP)
        mainnet_address = bech32_encode(Encoding.BECH32M, 'sp', [0] + convertbits(b'\x02' * 33 + b'\x03' * 33, 8, 5))
        assert_raises_rpc_error(-5, 'Invalid Bitcoin address', wallet.sendtoaddress, mainnet_address, 1.0)
        # Version 31 is reserved for a backwards incompatible change
        v31_address = sp_address(scan_key.get_pubkey().get_bytes(), spend_key.get_pubkey().get_bytes(), version=31)
        assert_raises_rpc_error(-5, 'Invalid Bitcoin address', wallet.sendtoaddress, v31_address, 1.0)
        # Dust amount
        assert_raises_rpc_error(-6, 'Transaction amount too small', wallet.sendtoaddress, address, 0.000001)
        # Silent payments addresses can not be used in raw transactions
        assert_raises_rpc_error(-5, 'not supported in raw transactions', node.createrawtransaction, [], {address: 1.0})
        assert_raises_rpc_error(-5, 'not supported in raw transactions', wallet.sendall, [address])

        self.log.info("A locked wallet can not send to a silent payments address")
        wallet.encryptwallet('passphrase')
        assert_raises_rpc_error(-4, 'Wallet must be unlocked to send to silent payment addresses',
                                wallet.send, {address: 1.0}, None, None, None, {'add_to_wallet': False})
        wallet.walletpassphrase('passphrase', 60)
        # After unlocking, sending works again
        txid = wallet.sendtoaddress(address, 1.0)
        tx = get_sp_tx(node, txid)
        program, _ = compute_sp_output(scan_priv, spend_pub, tx)
        find_sp_output(tx['vout'], program)


if __name__ == '__main__':
    WalletSilentPaymentsSendingTest(__file__).main()
