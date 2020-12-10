/*******************************************************************************

    Contains the flash Channel definition

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.Scripts;

import agora.common.Amount;
import agora.common.crypto.ECC;
import agora.common.crypto.Schnorr;
import agora.common.Hash;
import agora.common.Types;
import agora.consensus.data.Transaction;
import agora.flash.Config;
import agora.flash.Types;
import agora.script.Lock;
import agora.script.Opcodes;
import agora.script.Script;

import std.bitmanip;

/*******************************************************************************

    Create a Flash lock script.

    This lock is based on the Eltoo protocol, with some security modifications.

    Params:
        age = the age constraint for using the settlement keypair
        first_utxo = the first input's UTXO of the funding transaction.
                     used to be able to derive unique update & settlement
                     keypairs by using the UTXO as an offset.
        pair_pk = the Schnorr sum of the multi-party public keys.
                  The update an settlement keys will be derived from this
                  origin.
        seq_id = the sequence ID to use for the settlement branch. For the
            update branch `seq_id + 1` will be used.

    Returns:
        a lock script which can be unlocked instantly with an update key-pair,
        or with a settlement key-pair if the age constraint of the input
        is satisfied.

*******************************************************************************/

public Lock createFlashLock (uint age, Hash first_utxo, Point pair_pk,
    ulong seq_id, uint num_peers)
    nothrow @safe
{
    /*
        Eltoo whitepaper Figure 4:

        Key pairs must be different for the if/else branch,
        otherwise an attacker could just steal the signature
        and use a different PUSH to evaluate the other branch.

        To force only a specific settlement tx to be valid we need to make
        the settle key derived for each sequence ID. That way an attacker
        cannot attach any arbitrary settlement to any other update.

        Differences to whitepaper:
        - we use naive schnorr multisig for simplicity
        - we use VERIFY_SIG rather than CHECK_SIG, it improves testing
          reliability by ensuring the right failure reason is emitted.
          We manually push OP.TRUE to the stack after the verify. (temporary)
        - VERIFY_SEQ_SIG expects a push of the sequence on the stack by
          the unlock script, and hashes the sequence to produce a signature.

        Explanation:
        [sig] - signature pushed by the unlock script.
        [spend_seq] - sequence ID pushed by the unlock script in the spending tx.
        <seq + 1> - minimum sequence ID as set by the lock script. It's +1
            to allow binding of the next update tx (or any future update tx).
        OP.VERIFY_SEQ_SIG - verifies that [spend_seq] >= <seq + 1>.
            Hashes the blanked Input together with the [spend_seq] that was
            pushed to the stack and then verifies the signature.

        OP.IF
            [sig] [spend_seq] <seq + 1> <update_pub_multi> OP.VERIFY_SEQ_SIG OP.TRUE
        OP_ELSE
            <age> OP.VERIFY_UNLOCK_AGE
            [sig] [spend_seq] <seq> <settle_pub_multi[spend_seq]> OP.VERIFY_SEQ_SIG OP.TRUE
        OP_ENDIF
    */

    const update_pair_pk = getUpdatePk(pair_pk, first_utxo, num_peers);
    const settle_pair_pk = getSettlePk(pair_pk, first_utxo, seq_id, num_peers);
    const age_bytes = nativeToLittleEndian(age);
    const ubyte[8] seq_id_bytes = nativeToLittleEndian(seq_id);
    const ubyte[8] next_seq_id_bytes = nativeToLittleEndian(seq_id + 1);

    return Lock(LockType.Script,
        [ubyte(OP.IF)]
            ~ [ubyte(32)] ~ update_pair_pk[] ~ toPushOpcode(next_seq_id_bytes)
            ~ [ubyte(OP.VERIFY_SEQ_SIG), ubyte(OP.TRUE),
         ubyte(OP.ELSE)]
             ~ toPushOpcode(age_bytes) ~ [ubyte(OP.VERIFY_UNLOCK_AGE)]
            ~ [ubyte(32)] ~ settle_pair_pk[] ~ toPushOpcode(seq_id_bytes)
                ~ [ubyte(OP.VERIFY_SEQ_SIG), ubyte(OP.TRUE),
         ubyte(OP.END_IF)]);
}

/*******************************************************************************

    Create an unlock script for the settlement branch for Eltoo Figure 4.

    Params:
        sig = the signature

    Returns:
        an unlock script

*******************************************************************************/

public Unlock createUnlockUpdate (Signature sig, in ulong sequence)
    nothrow @safe
{
    // remember it's LIFO when popping, TRUE is pushed last
    const seq_bytes = nativeToLittleEndian(sequence);
    return Unlock([ubyte(64)] ~ sig[] ~ toPushOpcode(seq_bytes)
        ~ [ubyte(OP.TRUE)]);
}

/*******************************************************************************

    Create an unlock script for the settlement branch for Eltoo Figure 4.

    Params:
        sig = the signature

    Returns:
        an unlock script

*******************************************************************************/

public Unlock createUnlockSettle (Signature sig, in ulong sequence)
    nothrow @safe
{
    // remember it's LIFO when popping, FALSE is pushed last
    const seq_bytes = nativeToLittleEndian(sequence);
    return Unlock([ubyte(64)] ~ sig[] ~ toPushOpcode(seq_bytes)
        ~ [ubyte(OP.FALSE)]);
}

///
public Transaction createSettleTx (in Transaction prev_tx,
    in uint settle_age, in Output[] outputs) nothrow @safe
{
    Transaction settle_tx = {
        type: TxType.Payment,
        inputs: [Input(prev_tx, 0 /* index */, settle_age)],
        outputs: outputs.dup,
    };

    return settle_tx;
}

///
public Transaction createFundingTx (in Hash utxo, in Amount funding_amount,
    in Point pair_pk) nothrow @safe
{
    Transaction funding_tx = {
        type: TxType.Payment,
        inputs: [Input(utxo)],
        outputs: [
            Output(funding_amount,
                Lock(LockType.Key, pair_pk[].dup))]
    };

    return funding_tx;
}

///
public Transaction createClosingTx (in Hash utxo, in Balance balance)
    nothrow @safe
{
    Transaction closing_tx = {
        type: TxType.Payment,
        inputs: [Input(utxo)],
        outputs: balance.outputs.dup,
    };

    return closing_tx;
}

///
public Transaction createUpdateTx (in ChannelConfig chan_conf,
    in uint seq_id, in Transaction prev_tx) nothrow @safe
{
    const Lock = createFlashLock(chan_conf.settle_time,
        chan_conf.funding_tx_hash, chan_conf.pair_pk, seq_id,
        chan_conf.num_peers);

    Transaction update_tx = {
        type: TxType.Payment,
        inputs: [Input(prev_tx, 0 /* index */, 0 /* unlock age */)],
        outputs: [
            Output(chan_conf.funding_amount, Lock)]
    };

    return update_tx;
}

//
public Scalar getUpdateScalar (in Scalar origin, in Hash utxo)
    nothrow @safe
{
    const update_offset = Scalar(hashFull("update"));
    const seq_scalar = update_offset + Scalar(utxo);
    const derived = origin + seq_scalar;
    return derived;
}

//
public Point getUpdatePk (in Point origin, in Hash utxo, uint num_peers)
    nothrow @safe
{
    const update_offset = Scalar(hashFull("update"));
    const seq_scalar = update_offset + Scalar(utxo);

    Scalar sum_scalar = seq_scalar;
    while (--num_peers)  // add N-1 additional times
        sum_scalar = sum_scalar + seq_scalar;

    const derived = origin + sum_scalar.toPoint();
    return derived;
}

//
public Scalar getSettleScalar (in Scalar origin, in Hash utxo, in ulong seq_id)
    nothrow @safe
{
    const settle_offset = Scalar(hashFull("settle"));
    const seq_scalar = Scalar(hashFull(seq_id)) + Scalar(utxo) + settle_offset;
    const derived = origin + seq_scalar;
    return derived;
}

//
public Point getSettlePk (in Point origin, in Hash utxo, in ulong seq_id,
    uint num_peers) nothrow @safe
{
    const settle_offset = Scalar(hashFull("settle"));
    const seq_scalar = Scalar(hashFull(seq_id)) + Scalar(utxo) + settle_offset;

    Scalar sum_scalar = seq_scalar;
    while (--num_peers)  // add N-1 additional times
        sum_scalar = sum_scalar + seq_scalar;

    const derived = origin + sum_scalar.toPoint();
    return derived;
}

public PrivateNonce genPrivateNonce ()
{
    PrivateNonce priv_nonce =
    {
        settle : Pair.random(),
        update : Pair.random(),
    };

    return priv_nonce;
}

public PublicNonce getPublicNonce (in PrivateNonce priv_nonce)
{
    PublicNonce pub_nonce =
    {
        settle : priv_nonce.settle.V,
        update : priv_nonce.update.V,
    };

    return pub_nonce;
}
