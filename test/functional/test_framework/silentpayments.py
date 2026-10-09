#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test-only BIP352 silent payments receiver."""

from test_framework.crypto.secp256k1 import G, GE
from test_framework.key import H_POINT, ORDER, TaggedHash
from test_framework.script import hash160

NUMS_H = bytes.fromhex(H_POINT)


def is_compressed_pubkey(pubkey):
    return len(pubkey) == 33 and pubkey[0] in (2, 3)


def is_p2pkh(spk):
    return len(spk) == 25 and spk[:3] == b'\x76\xa9\x14' and spk[23:] == b'\x88\xac'


def is_p2sh(spk):
    return len(spk) == 23 and spk[:2] == b'\xa9\x14' and spk[22:] == b'\x87'


def is_p2wpkh(spk):
    return len(spk) == 22 and spk[:2] == b'\x00\x14'


def is_p2tr(spk):
    return len(spk) == 34 and spk[:2] == b'\x51\x20'


def is_witness_v2_plus(spk):
    return 4 <= len(spk) <= 42 and 0x52 <= spk[0] <= 0x60 and spk[1] == len(spk) - 2


def get_input_pubkey(script_sig, witness_stack, spk):
    """Return the compressed public key BIP352 uses for an input, or None if the input is skipped."""
    if is_p2pkh(spk):
        for i in range(len(script_sig), 32, -1):
            pubkey = script_sig[i - 33:i]
            if hash160(pubkey) == spk[3:23] and is_compressed_pubkey(pubkey):
                return pubkey
    elif is_p2sh(spk):
        redeem_script = script_sig[1:]
        if is_p2wpkh(redeem_script) and witness_stack and is_compressed_pubkey(witness_stack[-1]):
            return witness_stack[-1]
    elif is_p2wpkh(spk):
        if witness_stack and is_compressed_pubkey(witness_stack[-1]):
            return witness_stack[-1]
    elif is_p2tr(spk):
        stack = list(witness_stack)
        if len(stack) > 1 and stack[-1][:1] == b'\x50':
            stack.pop()
        if len(stack) > 1 and stack[-1][1:33] == NUMS_H:
            return None
        return b'\x02' + spk[2:]
    return None


def scan_transaction(tx, prevout_spks, scan_key, spend_pubkey):
    """Return the x-only keys of the outputs of tx paying to the address of (scan_key, spend_pubkey)."""
    if any(is_witness_v2_plus(spk) for spk in prevout_spks):
        return []
    pubkeys = []
    for i, (txin, spk) in enumerate(zip(tx.vin, prevout_spks)):
        witness_stack = tx.wit.vtxinwit[i].scriptWitness.stack if i < len(tx.wit.vtxinwit) else []
        pubkey = get_input_pubkey(txin.scriptSig, witness_stack, spk)
        if pubkey is not None:
            pubkeys.append(GE.from_bytes(pubkey))
    input_pubkey_sum = sum(pubkeys, GE())
    if input_pubkey_sum.infinity:
        return []

    smallest_outpoint = min(txin.prevout.serialize() for txin in tx.vin)
    input_hash = int.from_bytes(TaggedHash("BIP0352/Inputs", smallest_outpoint + input_pubkey_sum.to_bytes_compressed()), 'big')
    shared_secret = (input_hash * int.from_bytes(scan_key.get_bytes(), 'big') % ORDER) * input_pubkey_sum

    taproot_outputs = {txout.scriptPubKey[2:] for txout in tx.vout if is_p2tr(txout.scriptPubKey)}
    spend_point = GE.from_bytes(spend_pubkey.get_bytes())
    found = []
    while True:
        tweak = int.from_bytes(TaggedHash("BIP0352/SharedSecret", shared_secret.to_bytes_compressed() + len(found).to_bytes(4, 'big')), 'big')
        output = (spend_point + tweak * G).to_bytes_xonly()
        if output not in taproot_outputs:
            return found
        found.append(output)
