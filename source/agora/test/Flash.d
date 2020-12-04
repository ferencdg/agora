/*******************************************************************************

    Contains flash layer tests.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.test.Flash;

version (unittest):

import agora.api.Validator;
import agora.common.Amount;
import agora.common.crypto.Key;
import agora.common.crypto.ECC;
import agora.common.crypto.Schnorr;
import agora.common.Hash;
import agora.common.Serializer;
import agora.common.Task;
import agora.common.Types;
import agora.consensus.data.genesis.Test;
import agora.consensus.data.Transaction;
import agora.consensus.data.UTXO;
import agora.script.Engine;
import agora.script.Lock;
import agora.script.Opcodes;
import agora.script.Script;
import agora.test.Base;

import geod24.Registry;

import libsodium.randombytes;

import std.bitmanip;
import std.container.dlist;
import std.conv;
import std.exception;
import std.format;

import core.thread;

alias LockType = agora.script.Lock.LockType;

// todo: add ability to renegotiate update TXs.
// but the trigger tx should be non-negotiable

// todo: there needs to be an invoice-based API like in c-lightning
// something like: `cli invoice <amount> <label>` which produces <UUID>
// and then `cli pay <UUID>`
// todo: a channel should be a struct. maybe it should have an ID like a Hash.

// todo: call each node a "peer" for better terminology.

// todo: for intermediary HTLC nodes we would call them "hops", or a "hop".

// todo: we might not need HTLC's if we use channel factories
// todo: we also might not need HTLC's if we can use multi-cosigners for the
// funding transaction

// todo: encryption

// todo: extensibility (and therefore backwards compatibility) of the protocol
// lightning uses "TLV stream"

// channel IDs are temporary (ephemeral) until the funding transaction is
// externalized. Then, we can easily derive a unique channel ID using the hash
// of the funding transaction.

// todo: base many things on https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md

// benefit to list in the demo: we don't have to wait for many confirmations
// before using a channel, but only 10 minutes until the first block is
// externalized.
// however: with channel factories we'll be able to reduce this to zero wait
// time. we should at least make a note of that.

// todo: use the hash of the genesis block as the chain_hash like in LN.

// todo: need to guard against replay attacks.

// todo: we need a state transition here:
// we need to track the funding UTXO, and then when the following is true
// we know the channel is read:
// - we have a valid trigger tx
// - we have a valid settlement tx
// - the funding utxo was published to the blockchain

// todo 'connect()' should be a separate API point. We need to connect to
// a node before establishing channels.

// todo: invoice() and pay(). should be usable both-ways
// see readme in https://github.com/ElementsProject/lightning

// todo: both parties could attempt to send each other invoices at the same
// time. how does C-LN handle this? Maybe the sequence ID should be part of
// the invoice, and only one can cooperatively be accepted.

public struct OpenResult
{
    string error;  // in case rejected
    Point settle_nonce;
    Point update_nonce;
}

public struct SigResult
{
    string error;  // in case rejected
    Signature sig;
}

/// This is the API that each flash-aware node must implement.
public interface FlashAPI
{
    /***************************************************************************

        Requests opening a channel with this node.

        Params:
            chan_conf = contains all the static configuration for this channel.

        Returns:
            null if agreed to open this channel, otherwise an error

    ***************************************************************************/

    public OpenResult openChannel (in ChannelConfig chan_conf,
        in Point settle_nonce, in Point update_nonce);

    /***************************************************************************

        Request the peer to create a floating settlement transaction that spends
        the outputs of the provided previous transaction, and creates the given
        new outputs and encodes the given signed sequence ID in the
        unlock script.

        The peer may reject to create such a settlement, for example if the
        sequence ID is outdated, or if the peer disagrees with the allocation
        of the funds in the new outputs, or if the outputs try to spend more
        than the allocated amount.

        Params:
            chan_id = A previously seen pending channel ID provided
                by the funder node through the call to `openChannel()`
            prev_tx = the transaction whose outputs should be spent
            outputs = the outputs reallocating the funds
            seq_id = the sequence ID
            peer_nonce = the nonce the calling peer is using for its
                own signature

        Returns:
            null, or an error string if the channel could not be created

    ***************************************************************************/

    public SigResult requestSettleSig (in Hash chan_id, in uint seq_id);

    /***************************************************************************

        Request the peer to sign the trigger transaction, from which the
        settlement transaction spends.

        The peer should use the agreed-upon update key-pair and the nonce
        sum of the provided nonce and the peer's own genereated nonce
        to enable schnorr multisig signatures.

        The peer should then call `receiveUpdateSig()` to return their
        end of the signature. The calling node will then also provide
        their part of the signature in a call to `receiveUpdateSig()`,
        making the symmetry complete.

        Params:
            chan_id = A previously seen pending channel ID provided
                by the funder node through the call to `openChannel()`
            peer_nonce = the nonce the calling peer is using for its
                own signature

        Returns:
            null, or an error string if the peer could not sign the trigger
            transaction for whatever reason

    ***************************************************************************/

    public SigResult requestUpdateSig (in Hash chan_id, in uint seq_id);
}

/// Channel configuration. These fields remain static throughout the
/// lifetime of the channel. All of these fields are public and known
/// by all participants in the channel.
public struct ChannelConfig
{
    /// Hash of the genesis block, used to determine which blockchain this
    /// channel belongs to
    public Hash gen_hash;

    /// Public key of the funder of the channel
    public Point funder_pk;

    /// Public key of the counter-party to the channel
    public Point peer_pk;

    /// Sum of `funder_pk + peer_pk`
    public Point pair_pk;

    /// Total number of co-signers needed to make update/settlement transactions
    /// in this channel. This does not include any HTLC intermediary peers.
    public const uint num_peers;

    /// The public key sum used for validating Update transactions.
    /// This key is derived and remains static throughout the
    /// lifetime of the channel.
    public const Point update_pair_pk;

    /// The funding transaction from which the trigger transaction may spend.
    /// This transaction is unsigned - only the funder may opt to send it
    /// to the agora network for externalization. The peer may opt to retrieve
    /// the signature when it detects this transaction is in the blockchain,
    /// but should prefer just using simple merkle root validation.
    public Transaction funding_tx;

    /// Hash of the funding transaction above.
    public Hash funding_tx_hash;

    /// The total amount funded in this channel. This information is
    /// derived from the Outputs of the funding transaction.
    public Amount funding_amount;

    /// The settle time to use for the settlement branch. This time is verified
    /// with the `OP.VERIFY_UNLOCK_AGE` opcode.
    public uint settle_time;

    /// The channel's ID is derived from the hash of the funding transaction
    public alias chan_id = funding_tx_hash;
}

/// Tracks the current stage of the channel.
/// Stages can only move forwards, and never back.
public enum Stage
{
    /// Cooperating on the initial trigger and settlement txs
    Setup,

    /// Waiting for the funding tx to appear in the blockchain
    WaitForFunding,

    /// The channel is open.
    Open,

    /// The channel is closed.
    Closed,
}

/// The update & settle pair for a given sequence ID
public class UpdatePair
{
    /// The sequence ID of this slot
    public uint seq_id;

    /// Update which spends the trigger tx's outputs and can replace
    /// any previous update containing a lower sequence ID than this one's.
    private Update update;

    /// Settle which spends from `update`
    private Settle settlement;
}

///
public class SignTask
{
    /// Channel configuration
    private const ChannelConfig conf;

    /// Key-pair used for signing and deriving update / settlement key-pairs
    public const Pair kp;

    /// Task manager to spawn fibers with
    public SchedulingTaskManager taskman;

    /// Peer we're communicating with
    private FlashAPI peer;

    /// Sequence ID we're trying to sign for
    /// Todo: we should also have some kind of incremental ID to be able to
    /// re-try the same sequence IDs
    private uint seq_id;

    /// The new balances we're trying to sign
    private Output[] balances;

    /// The private nonce we'll use for this signing session
    private PrivateNonce priv_nonce;

    /// The nonce we expect the peer to use for this signing session
    private PeerNonce peer_nonce;

    /// Called when the settlement & update are signed & validated
    private void delegate (UpdatePair) onComplete;

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

    private PendingSettle pending_settle;
    private PendingUpdate pending_update;

    /// Tasks for the various asynchronous API calls
    private ITimer request_task;
    /// Ditto
    private ITimer send_settle_task;
    /// Ditto
    private ITimer send_update_task;

    /// Ctor
    public this (in ChannelConfig conf,  in Pair kp,
        SchedulingTaskManager taskman, FlashAPI peer)
    {
        this.conf = conf;
        this.kp = kp;
        this.taskman = taskman;
        this.peer = peer;
    }

    // balances allready agreed upon!
    // todo: this can be a blocking call
    public void run (in uint seq_id, in Output[] balances,
        PrivateNonce priv_nonce, PeerNonce peer_nonce,
        void delegate (UpdatePair) onComplete)
    {
        this.clearState();
        this.seq_id = seq_id;
        this.balances = balances;
        this.priv_nonce = priv_nonce;
        this.peer_nonce = peer_nonce;
        this.onComplete = onComplete;

        this.pending_update = this.createPendingUpdate();
        this.pending_settle = this.createPendingSettle(this.pending_update.tx);

        auto status = this.peer.requestSettleSig(this.conf.chan_id,
            seq_id);
        if (status.error !is null)
        {
            // todo: retry?
            writefln("Requested settlement rejected: %s", error);
            assert(0);
        }

        if (auto error = this.isInvalidSettleMultiSig(
            this.pending_settle, status.sig))
        {
            // todo: inform? ban?
            writefln("Error during validation: %s For signature: %s",
                error, status.sig);
            assert(0);
        }
        this.pending_settle.peer_sig = status.sig;
        this.pending_settle.validated = true;

        // here it's a bit problematic because the counter-party will refuse
        // to reveal their update sig until they receive the settlement signature
        // todo: could we just share it in the single request API?
        status = this.peer.requestUpdateSig(this.conf.chan_id,
            seq_id);
        if (status.error !is null)
        {
            // todo: retry?
            writefln("Requested settlement rejected: %s", error);
            assert(0);
        }

        if (!this.isValidUpdateMultiSig(this.pending_update, status.sig))
        {
            // todo: inform? ban?
            writefln("Received invalid signaturee: %s", status.sig);
            assert(0);
        }
        this.pending_update.peer_sig = status.sig;
        this.pending_update.validated = true;

        // now we have our signature, check it and then request update sig
    }

    private Signature getUpdateSig (in Transaction update_tx)
    {
        const nonce_pair_pk = this.priv_nonce.update.V + this.peer_nonce.update;

        // if the current sequence is 0 then the update tx is a trigger tx that
        // only needs a multi-sig and does not require a sequence.
        // an update tx with seq 0 do not exist.
        if (this.seq_id == 0)
        {
            return sign(this.kp.v, this.conf.pair_pk, nonce_pair_pk,
                this.priv_nonce.v, update_tx);
        }
        else
        {
            const challenge_update = getSequenceChallenge(update_tx,
                this.seq_id, 0);  // todo: should not be hardcoded
            return sign(this.kp.v, settle_pair_pk, nonce_pair_pk,
                this.priv_nonce.settle.v, challenge_settle);
        }
    }

    private PendingUpdate createPendingUpdate ()
    {
        const update_tx = createUpdateTx(this.conf, seq_id);


        PendingUpdate update =
        {
            tx        : settle_tx,
            our_sig   : sig,
            validated : false,
        };

        return update;
    }

    private PendingSettle createPendingSettle (in Transaction update_tx)
    {
        const settle_key = getSettleScalar(this.kp.v, this.conf.funding_tx_hash,
            this.seq_id);
        const settle_pair_pk = getSettlePk(this.conf.pair_pk,
            this.conf.funding_tx_hash, this.seq_id, this.conf.num_peers);
        const nonce_pair_pk = this.priv_nonce.settle.V + this.peer_nonce.settle;

        const uint input_idx = 0;  // this should ideally not be hardcoded
        const settle_tx = createSettleTx(update_tx, this.conf.settle_time,
            this.balances);
        const challenge_settle = getSequenceChallenge(settle_tx, this.seq_id,
            input_idx);

        const sig = sign(settle_key, settle_pair_pk, nonce_pair_pk,
            this.priv_nonce.settle.v, challenge_settle);

        PendingSettle settle =
        {
            tx        : settle_tx,
            our_sig   : sig,
            validated : false,
        };

        return settle;
    }

    private string isInvalidSettleMultiSig (in PendingSettle settle,
        in Signature peer_sig)
    {
        const nonce_pair_pk = this.priv_nonce.settle.V + this.peer_nonce.settle;
        const settle_multi_sig = Sig(nonce_pair_pk,
              Sig.fromBlob(settle.our_sig).s
            + Sig.fromBlob(peer_sig).s).toBlob();

        const Unlock settle_unlock = createUnlockSettle(settle_multi_sig,
            this.seq_id);
        // todo: should not be hardcoded to idx 0
        settle.tx.inputs[0].unlock = settle_unlock;

        // note: must always use the execution engine to validate and never
        // try to validate the signatures manually.
        const TestStackMaxTotalSize = 16_384;
        const TestStackMaxItemSize = 512;
        scope engine = new Engine(TestStackMaxTotalSize, TestStackMaxItemSize);
        if (auto error = engine.execute(
            settle.prev_tx.outputs[0].lock, settle_unlock, settle.tx,
                settle.tx.inputs[0]))
        {
            return error;
        }

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

    private string isInvalidUpdateMultiSig (in PendingUpdate update,
        in Signature peer_sig)
    {
        const nonce_pair_pk = this.priv_nonce.update.V + this.peer_nonce.update;
        const update_multi_sig = Sig(nonce_pair_pk,
              Sig.fromBlob(update.our_sig).s
            + Sig.fromBlob(peer_sig).s).toBlob();

        const Unlock update_unlock = this.getUpdateUnlock(update_multi_sig,
            this.seq_id);
        // todo: should not be hardcoded to idx 0
        update.tx.inputs[0].unlock = update_unlock;

        // note: must always use the execution engine to validate and never
        // try to validate the signatures manually.
        const TestStackMaxTotalSize = 16_384;
        const TestStackMaxItemSize = 512;
        scope engine = new Engine(TestStackMaxTotalSize, TestStackMaxItemSize);
        if (auto error = engine.execute(
            update.prev_tx.outputs[0].lock, update_unlock, update.tx,
                update.tx.inputs[0]))
        {
            return error;
        }

        return null;
    }

    ///
    public SigResult requestSettleSig ()
    {
        // it's always safe to share our settlement signature because
        // it may only attach to the matching update tx which is signed later.
        return SigResult(null, this.pending_settle.our_sig);
    }

    ///
    public SigResult requestUpdateSig ()
    {
        // sharing the update signature prematurely can lead to funds being
        // permanently locked if the settlement signature is missing and the
        // update transaction is externalized.
        if (!this.pending_settle.validated)
            return SigResult("Cannot share update signature until "
                ~ "settlement signature is received");

        return SigResult(null, this.pending_update.our_sig);
    }

    ///
    public string receiveUpdateSig (in Point peer_nonce, in Signature peer_sig)
    {
        writefln("%s: receiveUpdateSig(%s)", this.kp.V.prettify,
            this.conf.chan_id.prettify);

        auto update = &this.pending_update;
        if (*update == Update.init)
            return "Could not find this pending update tx";

        auto settle = &this.pending_settle;
        if (*settle == Settle.init)
            return "Pending settlement with this channel ID not found";

        update.peer_nonce = peer_nonce;
        const nonce_pair_pk = update.our_nonce_kp.V + peer_nonce;

        const our_sig = sign(this.kp.v, this.conf.pair_pk,
            nonce_pair_pk, update.our_nonce_kp.v, update.tx);

        // verify signature first
        const update_multi_sig = Sig(nonce_pair_pk,
              Sig.fromBlob(our_sig).s
            + Sig.fromBlob(peer_sig).s).toBlob();

        const Unlock update_unlock = genKeyUnlock(update_multi_sig);
        update.tx.inputs[0].unlock = update_unlock;

        // when receiving the update transaction only the funder knows
        // the full funding transaction definition. Therefore the funder
        // should send us a non-signed funding tx here.
        const TestStackMaxTotalSize = 16_384;
        const TestStackMaxItemSize = 512;
        scope engine = new Engine(TestStackMaxTotalSize, TestStackMaxItemSize);
        if (auto error = engine.execute(
            this.conf.funding_tx.outputs[0].lock, update_unlock,
            update.tx, update.tx.inputs[0]))
        {
            assert(0, error);
        }

        writefln("%s: receiveUpdateSig(%s) VALIDATED", this.kp.V.prettify,
            this.conf.chan_id.prettify);

        // this prevents infinite loops, we may want to optimize this
        if (this.is_owner)
        {
            // send the update signature
            this.send_update_task = this.taskman.schedule(
            {
                if (auto error = this.peer.receiveUpdateSig(
                    this.conf.chan_id, update.our_nonce_kp.V,
                    our_sig))
                {
                    writefln("Error sending update signature back: %s", error);
                }
            });

            // also safe to finally send the settlement signature
            const seq_id_0 = 0;
            this.send_settle_task = this.taskman.schedule(
            {
                if (auto error = this.peer.receiveSettleSig(
                    this.conf.chan_id, seq_id_0,
                    settle.our_nonce_kp.V, settle.our_sig))
                {
                    writefln("Error sending settlement signature back: %s", error);
                }
            });

            // now ok to sign and publish funding tx
            writefln("%s: Sending funding tx(%s): %s", this.kp.V.prettify,
                this.conf.chan_id.prettify,
                this.conf.funding_tx.hashFull.prettify);

            this.taskman.schedule({
                this.onComplete(UpdatePair.init);  // todo
            });
        }

        return null;
    }

    /// Cancels any existing tasks and clears the state
    public void clearState ()
    {
        this.pending_settle = Settle.init;
        this.pending_update = Update.init;

        // cancel any pending tasks
        if (this.request_task !is null)
            this.request_task.stop();
        if (this.send_settle_task !is null)
            this.send_settle_task.stop();
        if (this.send_update_task !is null)
            this.send_update_task.stop();
    }
}

struct PrivateNonce
{
    Pair settle;
    Pair update;
}

public struct PeerNonce
{
    Point settle;
    Point update;
}

/// Contains all the logic for maintaining a channel
public class Channel
{
    /// The static information about this channel
    public const ChannelConfig conf;

    /// Key-pair used for signing and deriving update / settlement key-pairs
    public const Pair kp;

    /// Whether we are the funder of this channel (`funder_pk == this.kp.V`)
    public const bool is_owner;

    /// Used to publish funding / trigger / update / settlement txs to blockchain
    public const void delegate (in Transaction) txPublisher;

    /// The peer of the other end of the channel
    public FlashAPI peer;

    /// Task manager to spawn fibers with
    public SchedulingTaskManager taskman;

    /// Stored when the funding transaction is signed.
    /// For peers they receive this from the blockchain.
    public Transaction funding_tx_signed;

    /// Current stage of the channel
    private Stage stage;

    /// The signer for an update / settle pair
    private SignTask sign_task;

    /// Contains the trigger tx to initiate closing the channel,
    /// and the initial refund settlement.
    private UpdatePair trigger_pair;

    /// The list of any off-chain updates which happened on this channel
    private DList!UpdatePair channel_updates;

    /// The current sequence ID
    private uint cur_seq_id;

    /// The balances we're trying to sign for the current sequence ID
    private Output[] balances;

    /// Our private nonces for the current signing phase
    private PrivateNonce priv_nonce;

    /// The peer's public nonces for the current signing phase
    private PeerNonce peer_nonce;

    /// Ctor
    public this (in ChannelConfig conf, in Pair kp, PrivateNonce priv_nonce,
        PeerNonce peer_nonce, FlashAPI peer, SchedulingTaskManager taskman,
        void delegate (in Transaction) txPublisher)
    {
        this.conf = conf;
        this.kp = kp;
        this.priv_nonce = priv_nonce;
        this.peer_nonce = peer_nonce;
        this.is_owner = conf.funder_pk == kp.V;
        this.peer = peer;
        this.taskman = taskman;
        this.txPublisher = txPublisher;
        this.sign_task = new SignTask(this.conf, this.kp, this.taskman,
            this.peer);
        // initial output allocates all the funds back to the channel creator
        this.balances = [Output(this.conf.funding_amount,
            PublicKey(this.conf.funder_pk[]))];
    }

    /// Start routine for the channel
    public void start ()
    {
        assert(this.is_owner);  // only funder initiates the channel
        assert(this.stage == Stage.Setup);
        assert(this.cur_seq_id == 0);

        const seq_id = 0;
        this.sign_task.run(seq_id, this.conf.funding_tx, this.balances,
            this.priv_nonce, this.peer_nonce, &this.onSetupComplete);
    }

    ///
    private void onSetupComplete (UpdatePair trigger_pair)
    {
        this.stage = Stage.WaitForFunding;
        this.trigger_pair = update_pair;

        this.funding_tx_signed = this.conf.funding_tx.clone();
        this.funding_tx_signed.inputs[0].unlock
            = genKeyUnlock(sign(this.kp, this.conf.funding_tx));

        this.txPublisher(this.funding_tx_signed);
        this.sign_task.clearState();
        // only updated when we're ready to sign a new balance redistribution
        //this.cur_seq_id++;
    }

    ///
    public string requestSettleSig (in uint seq_id)
    {
        if (auto error = this.isInvalidSeq(seq_id))
            return error;

        return this.sign_task.requestSettleSig();
    }

    ///
    public string requestUpdateSig (in uint seq_id)
    {
        if (auto error = this.isInvalidSeq(seq_id))
            return error;

        return this.sign_task.requestUpdateSig();
    }

    ///
    private string isInvalidSeq (in uint seq_id)
    {
        if (seq_id != this.cur_seq_id)
            return "Invalid sequence ID";

        return null;
    }
}

/////
//public struct Update
//{
//    Transaction tx;
//}

/////
//public struct Settle
//{
//    Output[] outputs;

//    /// Our signature
//    Signature our_sig;

//    /// Peer's signature
//    Signature peer_sig;
//}

/// In addition to the Flash API, we provide controller methods to initiate
/// the channel creation procedures, and control each flash node's behavior.
public interface ControlAPI : FlashAPI
{
    /// Prepare timers
    public void prepare ();

    /// Open a channel with another flash node.
    public string ctrlOpenChannel (in Hash funding_hash,
        in Amount funding_amount, in uint settle_time, in Point peer_pk);

    public void sendFlash (in Amount amount);

    /// convenience
    public bool readyToExternalize ();

    /// ditto
    public bool isChannelOpen ();
}

/// Could be a payer, or a merchant. funds can go either way in the channel.
/// There may be any number of channels between two parties
/// (e.g. think multiple different micropayment services)
/// In this test we assume there may only be one payment channel between two parties.
public abstract class FlashNode : FlashAPI
{
    /// Schnorr key-pair belonging to this user
    private const Pair kp;
    private RemoteAPI!TestAPI agora_node;  // random agora node
    private Registry* flash_registry;
    private SchedulingTaskManager taskman;  // for scheduling

    // for sending tx's to the network
    private TestAPIManager api_manager;

    /// Channels which are pending and not accepted yet.
    /// Once the channel handshake is complete and only after the funding
    /// transaction is externalized, the Channel channel gets promoted
    /// to a Channel with a unique ID derived from the hash of the funding tx.
    private Channel[Hash] channels;

    private bool ready_to_externalize;

    /// Ctor
    public this (const Pair kp, Registry* agora_registry,
        string agora_address, Registry* flash_registry)
    {
        this.kp = kp;
        this.flash_registry = flash_registry;
        this.taskman = new SchedulingTaskManager();
        this.api_manager = api_manager;

        auto tid = agora_registry.locate(agora_address);
        assert(tid != typeof(tid).init, "Agora node not initialized");
        Duration timeout;
        this.agora_node = new RemoteAPI!TestAPI(tid, timeout);
    }

    /// publishes a transaction to the blockchain
    private void txPublisher (in Transaction tx)
    {
        this.agora_node.putTransaction(cast()tx);
        this.ready_to_externalize = true;
    }

    /// Called by a channel funder
    public override string openChannel (in ChannelConfig chan_conf,
        in Point peer_settle_nonce, in Point peer_udpate_nonce)
    {
        writefln("%s: openChannel()", this.kp.V.prettify);

        // todo: funding amount should be drived from the `funding_tx`
        // and not passed explicitly, else we would have to validate this.
        // add a sumOutputs thingy here.
        // todo: verify Outputs[] sum is equal to `funding_amoutn`
        // todo: verify `chan_conf.peer_pk` equals our own!

        // todo: need replay attack protection. adversary could feed us
        // a dupe temporary channel ID once it's removed from
        // `this.channels`
        if (chan_conf.chan_id in this.channels)
            return "There is already an open channel with this ID";

        auto peer = this.getFlashClient(chan_conf.funder_pk);

        const our_gen_hash = hashFull(GenesisBlock);
        if (chan_conf.gen_hash != our_gen_hash)
            return "Unrecognized blockchain genesis hash";

        const min_funding = Amount(1000);
        if (chan_conf.funding_amount < min_funding)
            return "Funding amount is too low";

        const min_settle_time = 5;
        const max_settle_time = 10;
        if (chan_conf.settle_time < min_settle_time ||
            chan_conf.settle_time > max_settle_time)
            return "Settle time is not within acceptable limits";

        Pair our_nonce_settle_kp = Pair.random();
        Pair our_nonce_update_kp = Pair.random();

        auto channel = new Channel(chan_conf, this.kp, our_nonce_settle_kp,
            our_nonce_update_kp, peer_settle_nonce, peer_udpate_nonce,
            peer, this.taskman, &this.txPublisher);
        this.channels[chan_conf.chan_id] = channel;

        this.taskman.schedule(
        {
            channel.start();
        });

        return null;
    }

    ///
    public override SigResult requestSettleSig (in Hash chan_id,
        in uint seq_id, in Transaction prev_tx, Output[] outputs,
        in Point peer_nonce)
    {
        if (auto channel = chan_id in this.channels)
            return channel.requestSettleSig(prev_tx, seq_id, outputs,
                peer_nonce);

        return SigResult("Channel ID not found");
    }

    ///
    public override string receiveSettleSig (in Hash chan_id,
        in uint seq_id, in Point peer_nonce, in Signature peer_sig)
    {
        if (auto channel = chan_id in this.channels)
            return channel.receiveSettleSig(seq_id, peer_nonce, peer_sig);

        return "Channel ID not found";
    }

    ///
    public override string requestUpdateSig (in Hash chan_id,
        in uint seq_id, in Point peer_nonce, Transaction update_tx)
    {
        if (auto channel = chan_id in this.channels)
            return channel.requestUpdateSig(seq_id, peer_nonce, update_tx);

        return "Channel ID not found";
    }

    ///
    public override string receiveUpdateSig (in Hash chan_id,
        in uint seq_id, in Point peer_nonce, in Signature peer_sig)
    {
        if (auto channel = chan_id in this.channels)
            return channel.receiveUpdateSig(seq_id, peer_nonce, peer_sig);

        return "Channel ID not found";
    }

    ///
    private FlashAPI getFlashClient (in Point peer_pk)
    {
        auto tid = this.flash_registry.locate(peer_pk.to!string);
        assert(tid != typeof(tid).init, "Flash node not initialized");
        Duration timeout;
        return new RemoteAPI!FlashAPI(tid, timeout);
    }

    /// listen for any funding transactions reaching the blockchain
    /// If we have the funding tx, and the signatures for the trigger and
    /// settlement transaction, it means the channel is open and may
    /// be promoted to a full channel.
    public void listenFundingEvent ()
    {
        // todo: we actually need a getUTXO API
        // we would probably have to contact Stoa,
        // for now we simulate it through getBlocksFrom(),
        // we could provide this in the TestAPI

        auto last_block = this.agora_node.getBlocksFrom(0, 1024)[$ - 1];

        Hash[] pending_chans_to_remove;
        foreach (hash, ref channel; this.channels)
        {
            // todo
            //if (channel.funding_externalized
            //    && channel.last_settlement != Settle.init
            //    && channel.trigger != Update.init)
            //{
            //    writefln("%s: Channel open(%s)", this.kp.V.prettify,
            //        hash.prettify);
            //    //open_channels[channel.conf.funding_tx_hash] = channel;
            //    pending_chans_to_remove ~= hash;
            //    continue;
            //}

            if (!channel.funding_externalized)
            foreach (tx; last_block.txs)
            {
                if (tx.hashFull() == channel.conf.funding_tx_hash)
                {
                    if (channel.funding_tx_signed != Transaction.init)
                        channel.funding_tx_signed = tx.clone();

                    channel.funding_externalized = true;
                    writefln("%s: Funding tx externalized(%s)",
                        this.kp.V.prettify, channel.conf.funding_tx_hash.prettify);
                    break;
                }
            }
        }

        foreach (id; pending_chans_to_remove)
            this.channels.remove(id);
    }
}

public class ControlFlashNode : FlashNode, ControlAPI
{
    public this (const Pair kp, Registry* agora_registry,
        string agora_address, Registry* flash_registry)
    {
        super(kp, agora_registry, agora_address, flash_registry);
    }

    /// Control API
    public override void prepare ()
    {
        this.taskman.setTimer(200.msecs, &this.listenFundingEvent, Periodic.Yes);
    }

    /// Control API
    public override string ctrlOpenChannel (in Hash funding_utxo,
        in Amount funding_amount, in uint settle_time, in Point peer_pk)
    {
        writefln("%s: ctrlOpenChannel(%s, %s, %s)", this.kp.V.prettify,
            funding_amount, settle_time, peer_pk.prettify);

        auto peer = this.getFlashClient(peer_pk);
        const pair_pk = this.kp.V + peer_pk;

        // create funding, don't sign it yet as we'll share it first
        auto funding_tx = createFundingTx(funding_utxo, funding_amount,
            pair_pk);

        const funding_tx_hash = hashFull(funding_tx);
        const Hash chan_id = funding_tx_hash;
        const num_peers = 2;

        const ChannelConfig chan_conf =
        {
            gen_hash        : hashFull(GenesisBlock),
            funder_pk       : this.kp.V,
            peer_pk         : peer_pk,
            pair_pk         : this.kp.V + peer_pk,
            num_peers       : num_peers,
            update_pair_pk  : getUpdatePk(pair_pk, funding_tx_hash, num_peers),
            funding_tx      : funding_tx,
            funding_tx_hash : funding_tx_hash,
            funding_amount  : funding_amount,
            settle_time     : settle_time,
        };

        Pair our_nonce_settle_kp = Pair.random();
        Pair our_nonce_update_kp = Pair.random();

        auto open_res = peer.openChannel(chan_conf, our_nonce_settle_kp.V,
            our_nonce_update_kp.V);
        if (open_res.error.length > 0)
        {
            writefln("Peer rejected openChannel() request: %s", open_res.error);
            return error;
        }

        our_nonce_settle_kp,
        our_nonce_update_kp, open_res.settle_nonce, open_res.update_nonce,

        PrivateNonce priv_nonce =
        {
            nonce_settle_kp : our_nonce_settle_kp,
            nonce_update_kp : our_nonce_update_kp,
        };

        PeerNonce peer_nonce =
        {
            settle_nonce : open_res.settle_nonce,
            update_nonce : open_res.update_nonce,
        };

        auto channel = new Channel(chan_conf, this.kp, priv_nonce, peer_nonce,
            peer, this.taskman, &this.txPublisher);
        this.channels[chan_id] = channel;
        channel.start();

        return null;
    }

    public void sendFlash (in Amount amount)
    {
        writefln("%s: sendFlash()", this.kp.V.prettify);

        //// todo: use actual channel IDs, or perhaps an invoice API
        //auto channel = this.open_channels[this.open_channels.byKey.front];

        //auto update_tx = this.createUpdateTx(channel.update_pair_pk,
        //    channel.trigger.tx,
        //    channel.funding_amount, channel.settle_time,
        //    channel.settle_origin_pair_pk);

        //this.peerrequestSettlementSig (in Hash chan_id,
        //    in Transaction prev_tx, Output[] outputs, in uint seq_id,
        //    in Point peer_nonce)
    }

    /// convenience
    public override bool readyToExternalize ()
    {
        return this.ready_to_externalize;
    }

    /// ditto
    public override bool isChannelOpen ()
    {
        //return this.open_channels.length > 0;
        return false;
    }
}

/// Is in charge of spawning the flash nodes
public class FlashNodeFactory
{
    /// Registry of nodes
    private Registry* agora_registry;

    /// we keep a separate LocalRest registry of the flash "nodes"
    private Registry flash_registry;

    /// list of flash addresses
    private Point[] addresses;

    /// list of flash nodes
    private RemoteAPI!ControlAPI[] nodes;

    /// Ctor
    public this (Registry* agora_registry)
    {
        this.agora_registry = agora_registry;
        this.flash_registry.initialize();
    }

    /// Create a new flash node user
    public RemoteAPI!ControlAPI create (const Pair pair, string agora_address)
    {
        RemoteAPI!ControlAPI api = RemoteAPI!ControlAPI.spawn!ControlFlashNode(pair,
            this.agora_registry, agora_address, &this.flash_registry);
        api.prepare();

        this.addresses ~= pair.V;
        this.nodes ~= api;
        this.flash_registry.register(pair.V.to!string, api.tid());

        return api;
    }

    /// Shut down all the nodes
    public void shutdown ()
    {
        foreach (address; this.addresses)
            enforce(this.flash_registry.unregister(address.to!string));

        foreach (node; this.nodes)
            node.ctrl.shutdown();
    }
}

///
private Transaction createSettleTx (in Transaction prev_tx,
    in uint settle_age, in Output[] outputs)
{
    Transaction settle_tx = {
        type: TxType.Payment,
        inputs: [Input(prev_tx, 0 /* index */, settle_age)],
        outputs: outputs.dup,
    };

    return settle_tx;
}

///
private Transaction createFundingTx (in Hash utxo, in Amount funding_amount,
    in Point pair_pk)
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
private Transaction createUpdateTx (in ChannelConfig chan_conf,
    in uint seq_id)
{
    const Lock = createLockEltoo(chan_conf.settle_time,
        chan_conf.funding_tx_hash, chan_conf.pair_pk, seq_id,
        chan_conf.num_peers);

    Transaction update_tx = {
        type: TxType.Payment,
        inputs: [Input(chan_conf.funding_tx, 0 /* index */, 0 /* unlock age */)],
        outputs: [
            Output(chan_conf.funding_amount, Lock)]
    };

    return update_tx;
}

private string prettify (T)(T input)
{
    return input.to!string[0 .. 6];
}

/*******************************************************************************

    Create an Eltoo lock script based on Figure 4 from the whitepaper.

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

public Lock createLockEltoo (uint age, Hash first_utxo, Point pair_pk,
    ulong seq_id, uint num_peers)
    //pure nothrow @safe
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
    pure nothrow @safe
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
    pure nothrow @safe
{
    // remember it's LIFO when popping, FALSE is pushed last
    const seq_bytes = nativeToLittleEndian(sequence);
    return Unlock([ubyte(64)] ~ sig[] ~ toPushOpcode(seq_bytes)
        ~ [ubyte(OP.FALSE)]);
}

//
public Scalar getUpdateScalar (in Scalar origin, in Hash utxo)
{
    const update_offset = Scalar(hashFull("update"));
    const seq_scalar = update_offset + Scalar(utxo);
    const derived = origin + seq_scalar;
    return derived;
}

//
public Point getUpdatePk (in Point origin, in Hash utxo, uint num_peers)
{
    const update_offset = Scalar(hashFull("update"));
    const seq_scalar = update_offset + Scalar(utxo);

    import std.stdio;
    Scalar sum_scalar = seq_scalar;
    while (--num_peers)  // add N-1 additional times
        sum_scalar = sum_scalar + seq_scalar;

    const derived = origin + sum_scalar.toPoint();
    return derived;
}

//
public Scalar getSettleScalar (in Scalar origin, in Hash utxo, in ulong seq_id)
{
    const settle_offset = Scalar(hashFull("settle"));
    const seq_scalar = Scalar(hashFull(seq_id)) + Scalar(utxo) + settle_offset;
    const derived = origin + seq_scalar;
    return derived;
}

//
public Point getSettlePk (in Point origin, in Hash utxo, in ulong seq_id,
    uint num_peers)
{
    const settle_offset = Scalar(hashFull("settle"));
    const seq_scalar = Scalar(hashFull(seq_id)) + Scalar(utxo) + settle_offset;

    Scalar sum_scalar = seq_scalar;
    while (--num_peers)  // add N-1 additional times
        sum_scalar = sum_scalar + seq_scalar;

    const derived = origin + sum_scalar.toPoint();
    return derived;
}

/// Simplified `schedule` routine
private class SchedulingTaskManager : LocalRestTaskManager
{
    /// Ditto
    public ITimer schedule (void delegate() dg) nothrow
    {
        return super.setTimer(0.seconds, dg);
    }
}

/// utility
private T clone (T)(in T input)
{
    return input.serializeFull.deserializeFull!T;
}

/// Ditto
unittest
{
    TestConf conf = TestConf.init;
    auto network = makeTestNetwork(conf);
    network.start();
    scope (exit) network.shutdown();
    //scope (exit) network.printLogs();
    //scope (failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node_1 = nodes[0];

    // split the genesis funds into WK.Keys[0] .. WK.Keys[7]
    auto txs = genesisSpendable().take(8).enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();
    txs.each!(tx => node_1.putTransaction(tx));
    network.expectBlock(Height(1), network.blocks[0].header);

    // a little awkward, but we need the addresses
    //auto

    auto factory = new FlashNodeFactory(network.getRegistry());
    scope (exit) factory.shutdown();

    // use Schnorr
    const alice_pair = Pair.fromScalar(secretKeyToCurveScalar(WK.Keys[0].secret));
    const bob_pair = Pair.fromScalar(secretKeyToCurveScalar(WK.Keys[1].secret));

    // workaround to get a handle to the node from another registry thread
    const string address = format("Validator #%s (%s)", 0,
        WK.Keys.NODE2.address);
    auto alice = factory.create(alice_pair, address);
    auto bob = factory.create(bob_pair, address);

    // 10 blocks settle time after / when trigger tx is published
    const Settle_10_Blocks = 10;

    // the utxo the funding tx will spend (only really important for the funder)
    const utxo = UTXO.getHash(hashFull(txs[0]), 0);
    alice.ctrlOpenChannel(utxo, Amount(10_000), Settle_10_Blocks, bob_pair.V);

    while (!alice.readyToExternalize())
    {
        // there should be an infinite loop here which keeps creating txs
        Thread.sleep(100.msecs);
    }

    // one of these txs will be a double-spend
    txs = txs.map!(tx => TxBuilder(tx, 0))
        .enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();
    txs.each!(tx => node_1.putTransaction(tx));
    network.expectBlock(Height(2), network.blocks[0].header);

    //while (!alice.isChannelOpen())
    //{
    //    // there should be an infinite loop here which keeps creating txs
    //    Thread.sleep(100.msecs);
    //}

    //alice.sendFlash(Amount(10_000));

    Thread.sleep(1.seconds);
}
