/*******************************************************************************

    Contains the task which signs & shares the settlement & update transaction
    signatures for a given sequence ID.

    The `Channel` will run this task for the initial settlement & trigger
    transactions, as well as any subsequent channel balance updates.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.Signer;

import agora.common.crypto.Schnorr;
import agora.common.Serializer;
import agora.common.Task;
import agora.common.Types;
import agora.consensus.data.Transaction;
import agora.flash.API;
import agora.flash.Config;
import agora.flash.ErrorCode;
import agora.flash.Scripts;
import agora.flash.Types;
import agora.script.Engine;
import agora.script.Lock;
import agora.utils.Log;

mixin AddLogger!();

// todo: remove
import std.stdio;

import core.time;

/// Ditto
public class Signer
{
    /// Channel configuration
    private const ChannelConfig conf;

    /// Key-pair used for signing and deriving update / settlement key-pairs
    public const Pair kp;

    /// Peer we're communicating with
    private FlashAPI peer;

    /// Task manager
    private TaskManager taskman;

    /// Sequence ID we're trying to sign for
    /// Todo: we should also have some kind of incremental ID to be able to
    /// re-try the same sequence IDs
    private uint seq_id;

    private static struct PendingSettle
    {
        private Transaction tx;
        private Signature our_sig;
        private Signature peer_sig;
        private bool validated;
    }

    private static struct PendingUpdate
    {
        private Transaction tx;
        private Signature our_sig;
        private Signature peer_sig;
        private bool validated;
    }

    /// Pending signatures for the settlement transaction.
    /// Contains our own settlement signature, which is shared
    /// when the counter-party requests it via `requestSettleSig()`.
    private PendingSettle pending_settle;

    /// Pending signatures for the update transaction.
    /// Contains our own update signature, which is only shared
    /// when counter-parties' settlement signatures are all received
    /// and the settlement signature's multi-sig is considered valid.
    private PendingUpdate pending_update;

    /// Whether there is an active signature collecting process
    private bool is_collecting;

    /// Ctor
    public this (in ChannelConfig conf, in Pair kp, FlashAPI peer,
        TaskManager taskman)
    {
        this.conf = conf;
        this.kp = kp;
        this.peer = peer;
        this.taskman = taskman;
    }

    ///
    public bool isCollecting ()
    {
        return this.is_collecting;
    }

    // balance allready agreed upon!
    // todo: this can be a blocking call
    /// priv_nonce = The private nonce we'll use for this signing session
    /// peer_nonce = The nonce we expect the peer to use for this signing session
    public UpdatePair collectSignatures (in uint seq_id, in Balance balance,
        PrivateNonce priv_nonce, PublicNonce peer_nonce)
    {
        scope (exit) this.clearState();
        this.seq_id = seq_id;
        this.is_collecting = true;

        this.pending_update = this.createPendingUpdate(priv_nonce, peer_nonce);
        this.pending_settle = this.createPendingSettle(this.pending_update.tx,
            balance, priv_nonce, peer_nonce);

        // todo: work around this timing issue
        this.taskman.wait(500.msecs);

        auto settle_res = this.peer.requestSettleSig(this.conf.chan_id, seq_id);
        if (settle_res.error)
        {
            // todo: retry?
            writefln("Settlement signature request rejected: %s", settle_res);
            assert(0);
        }

        if (auto error = this.isInvalidSettleMultiSig(this.pending_settle,
            settle_res.value, priv_nonce, peer_nonce))
        {
            // todo: inform? ban?
            writefln("Error during validation: %s. For settle signature: %s",
                error, settle_res.value);
            assert(0);
        }
        this.pending_settle.peer_sig = settle_res.value;
        this.pending_settle.validated = true;

        // here it's a bit problematic because the counter-party will refuse
        // to reveal their update sig until they receive the settlement signature
        // todo: could we just share it in the single request API?
        auto update_res = this.peer.requestUpdateSig(this.conf.chan_id, seq_id);
        if (update_res.error)
        {
            // todo: retry?
            writefln("Update signature request rejected: %s", update_res);
            assert(0);
        }

        // todo: retry? add a better status code like NotReady?
        if (update_res.value == Signature.init)
            assert(0);

        if (auto error = this.isInvalidUpdateMultiSig(this.pending_update,
            update_res.value, priv_nonce, peer_nonce))
        {
            // todo: inform? ban?
            writefln("Error during validation: %s. For update signature: %s",
                error, update_res.value);
            assert(0);
        }
        this.pending_update.peer_sig = update_res.value;
        this.pending_update.validated = true;

        UpdatePair pair =
        {
            seq_id : this.seq_id,
            update_tx : this.pending_update.tx,
            settle_tx : this.pending_settle.tx,
        };

        return pair;
    }

    private Signature getUpdateSig (in Transaction update_tx,
        in PrivateNonce priv_nonce, in PublicNonce peer_nonce)
    {
        const nonce_pair_pk = priv_nonce.update.V + peer_nonce.update;

        // if the current sequence is 0 then the update tx is a trigger tx that
        // only needs a multi-sig and does not require a sequence.
        // Note that we cannot use a funding tx hash derived update key because
        // the funding tx's key lock is part of the hash (cyclic dependency).
        // Therefore we instead treat the trigger tx as special and simply
        // use a multisig with the pair_pk.
        // Note that an update tx with seq 0 do not exist.
        if (this.seq_id == 0)
        {
            return sign(this.kp.v, this.conf.pair_pk, nonce_pair_pk,
                priv_nonce.update.v, update_tx);
        }
        else
        {
            const update_key = getUpdateScalar(this.kp.v,
                this.conf.funding_tx_hash);
            const challenge_update = getSequenceChallenge(update_tx,
                this.seq_id, 0);  // todo: should not be hardcoded
            return sign(update_key, this.conf.update_pair_pk, nonce_pair_pk,
                priv_nonce.update.v, challenge_update);
        }
    }

    private PendingUpdate createPendingUpdate (in PrivateNonce priv_nonce,
        in PublicNonce peer_nonce)
    {
        auto update_tx = createUpdateTx(this.conf, seq_id);
        const sig = this.getUpdateSig(update_tx, priv_nonce, peer_nonce);

        PendingUpdate update =
        {
            tx        : update_tx,
            our_sig   : sig,
            validated : false,
        };

        return update;
    }

    private PendingSettle createPendingSettle (in Transaction update_tx,
        in Balance balance, in PrivateNonce priv_nonce,
        in PublicNonce peer_nonce)
    {
        const settle_key = getSettleScalar(this.kp.v, this.conf.funding_tx_hash,
            this.seq_id);
        const settle_pair_pk = getSettlePk(this.conf.pair_pk,
            this.conf.funding_tx_hash, this.seq_id, this.conf.num_peers);
        const nonce_pair_pk = priv_nonce.settle.V + peer_nonce.settle;

        const uint input_idx = 0;  // this should ideally not be hardcoded
        auto settle_tx = createSettleTx(update_tx, this.conf.settle_time,
            balance.outputs);
        const challenge_settle = getSequenceChallenge(settle_tx, this.seq_id,
            input_idx);

        const sig = sign(settle_key, settle_pair_pk, nonce_pair_pk,
            priv_nonce.settle.v, challenge_settle);

        PendingSettle settle =
        {
            tx        : settle_tx,
            our_sig   : sig,
            validated : false,
        };

        return settle;
    }

    private string isInvalidSettleMultiSig (ref PendingSettle settle,
        in Signature peer_sig, in PrivateNonce priv_nonce,
        in PublicNonce peer_nonce)
    {
        const nonce_pair_pk = priv_nonce.settle.V + peer_nonce.settle;
        const settle_multi_sig = Sig(nonce_pair_pk,
              Sig.fromBlob(settle.our_sig).s
            + Sig.fromBlob(peer_sig).s).toBlob();

        Transaction settle_tx
            = settle.tx.serializeFull().deserializeFull!Transaction;

        const Unlock settle_unlock = createUnlockSettle(settle_multi_sig,
            this.seq_id);
        settle_tx.inputs[0].unlock = settle_unlock;

        // note: must always use the execution engine to validate and never
        // try to validate the signatures manually.
        const TestStackMaxTotalSize = 16_384;
        const TestStackMaxItemSize = 512;
        scope engine = new Engine(TestStackMaxTotalSize, TestStackMaxItemSize);
        if (auto error = engine.execute(
            this.pending_update.tx.outputs[0].lock, settle_tx.inputs[0].unlock,
            settle_tx, settle_tx.inputs[0]))
            return error;

        settle.tx = settle_tx;
        return null;
    }

    private string isInvalidUpdateMultiSig (ref PendingUpdate update,
        in Signature peer_sig, in PrivateNonce priv_nonce,
        in PublicNonce peer_nonce)
    {
        const nonce_pair_pk = priv_nonce.update.V + peer_nonce.update;
        const update_multi_sig = Sig(nonce_pair_pk,
              Sig.fromBlob(update.our_sig).s
            + Sig.fromBlob(peer_sig).s).toBlob();

        Transaction update_tx
            = update.tx.serializeFull().deserializeFull!Transaction;

        const Unlock update_unlock = this.getUpdateUnlock(update_multi_sig);
        update_tx.inputs[0].unlock = update_unlock;
        const lock = this.getUpdateLock();

        // note: must always use the execution engine to validate and never
        // try to validate the signatures manually.
        const TestStackMaxTotalSize = 16_384;
        const TestStackMaxItemSize = 512;
        scope engine = new Engine(TestStackMaxTotalSize, TestStackMaxItemSize);
        if (auto error = engine.execute(lock, update_tx.inputs[0].unlock,
            update_tx, update_tx.inputs[0]))
            return error;

        update.tx = update_tx;
        return null;
    }

    private Unlock getUpdateUnlock (Signature update_multi_sig)
    {
        // if the current sequence is 0 then the update tx is a trigger tx that
        // only needs a multi-sig and does not require a sequence.
        // an update tx with seq 0 do not exist.
        if (this.seq_id == 0)
            return genKeyUnlock(update_multi_sig);
        else
            return createUnlockUpdate(update_multi_sig, this.seq_id);
    }

    private Lock getUpdateLock ()
    {
        // if the current sequence is 0 then the lock is the funding tx's lock,
        // otherwise it's the trigger tx's lock
        if (this.seq_id == 0)
        {
            return this.conf.funding_tx.outputs[0].lock;
        }
        else
        {
            const prev_seq = this.seq_id - 1;
            return createFlashLock(this.conf.settle_time,
                this.conf.funding_tx_hash, this.conf.pair_pk, prev_seq,
                this.conf.num_peers);
        }
    }

    ///
    public Result!Signature getSettleSig ()
    {
        // it's always safe to share our settlement signature because
        // it may only attach to the matching update tx which is signed later.
        return Result!Signature(this.pending_settle.our_sig);
    }

    ///
    public Result!Signature getUpdateSig ()
    {
        // sharing the update signature prematurely can lead to funds being
        // permanently locked if the settlement signature is missing and the
        // update transaction is externalized.
        if (!this.pending_settle.validated)
            return Result!Signature(ErrorCode.SettleNotReceived,
                "Cannot share update signature until the settlement "
                ~ "signature is received");

        return Result!Signature(this.pending_update.our_sig);
    }

    /// Clears the state so it's ready for another call to `run()`
    private void clearState ()
    {
        this.pending_settle = PendingSettle.init;
        this.pending_update = PendingUpdate.init;
        this.is_collecting = false;
    }
}
