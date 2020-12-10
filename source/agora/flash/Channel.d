/*******************************************************************************

    Contains the flash Channel definition

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.Channel;

import agora.flash.API;
import agora.flash.Config;
import agora.flash.ErrorCode;
import agora.flash.Scripts;
import agora.flash.Signer;
import agora.flash.Types;

import agora.common.Amount;
import agora.common.crypto.Key;
import agora.common.crypto.ECC;
import agora.common.crypto.Schnorr;
import agora.common.Hash;
import agora.common.Task;
import agora.common.Types;
import agora.consensus.data.Block;
import agora.consensus.data.UTXO;
import agora.consensus.data.Transaction;
import agora.script.Lock;

import std.format;
import std.stdio;  // todo: remove

import core.time;

alias LockType = agora.script.Lock.LockType;

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

    /// Task manager to spawn fibers with
    public TaskManager taskman;

    /// The peer of the other end of the channel
    public FlashAPI peer;

    /// Current state of the channel
    private ChannelState state;

    /// Stored when the funding transaction is signed.
    /// For peers they receive this from the blockchain.
    public Transaction funding_tx_signed;

    /// The signer for an update / settle pair
    private Signer signer;

    /// The list of any off-chain updates which happened on this channel
    private UpdatePair[] channel_updates;

    /// The current sequence ID
    private uint cur_seq_id;

    /// The current balance of the channel. Initially empty until the
    /// funding tx is externalized.
    private Balance cur_balance;

    /// The closing transaction can spend from the funding transaction when
    /// the channel parties want to collaboratively close the channel.
    /// It requires both of the parties signatures. For safety reasons,
    /// the closing transaction should only be signed once the node marks
    /// the channel as 'PendingClose'.
    private static struct PendingClose
    {
        private Transaction tx;
        private Signature our_sig;
        private Signature peer_sig;
        private bool validated;
    }

    /// Ditto
    private PendingClose pending_close;

    /// Ctor
    public this (in ChannelConfig conf, in Pair kp, in PrivateNonce priv_nonce,
        in PublicNonce peer_nonce, FlashAPI peer, TaskManager taskman,
        void delegate (in Transaction) txPublisher)
    {
        this.conf = conf;
        this.kp = kp;
        this.is_owner = conf.funder_pk == kp.V;
        this.peer = peer;
        this.taskman = taskman;
        this.txPublisher = txPublisher;
        this.signer = new Signer(this.conf, this.kp, this.peer, this.taskman);
        this.taskman.setTimer(0.seconds,
            { this.start(priv_nonce, peer_nonce); });
    }

    /***************************************************************************

        Returns:
            true if the channel is awaiting the externalization of the
            funding transaction

    ***************************************************************************/

    public bool isWaitingForFunding ()
    {
        return this.state == ChannelState.WaitingForFunding;
    }

    /***************************************************************************

        Returns:
            true if the channel is funded and is open

    ***************************************************************************/

    public bool isOpen ()
    {
        return this.state == ChannelState.Open;
    }

    /***************************************************************************

        Returns:
            the current state of the channel

    ***************************************************************************/

    public ChannelState getState ()
    {
        return this.state;
    }

    /***************************************************************************

        Start the setup stage of the channel. Should only be called once.

        A signing task will be spawned which attempts to collect the settlement
        and trigger transaction signatures from the counterparty. Additionally,
        the counter-party will request our own settlement & update signatures
        in the process.

        Once the signatures are collected and are validated on our side,
        the channel will be in `WaitingForFunding` state and will await for the
        funding transaction to be externalized before marking the channel
        as `Open`.

        Params:
            priv_nonce = the private nonce pair of this node for signing the
                initial settlement & trigger transactions
            peer_nonce = the public nonce pair which the counter-party will use
                to sign the initial settlement & trigger transactions

    ***************************************************************************/

    private void start (in PrivateNonce priv_nonce, in PublicNonce peer_nonce)
    {
        assert(this.state == ChannelState.None);
        this.state = ChannelState.SettingUp;
        assert(this.cur_seq_id == 0);

        // initial output allocates all the funds back to the channel creator
        const seq_id = 0;
        auto balance = Balance([Output(this.conf.funding_amount,
            PublicKey(this.conf.funder_pk[]))]);

        auto pair = this.signer.collectSignatures(seq_id, balance, priv_nonce,
            peer_nonce, this.conf.funding_tx);
        this.onSetupComplete(pair);
    }

    /***************************************************************************

        Called when the setup stage of the channel has been completed.

        If this node is the initial funder of the channel, the funding
        transaction will be signed and published to the blockchain.

        When the funding transaction is detected as being externalized,
        the channel state will be changed to `ChannelState.Open`.

        Params:
            update_pair = the signed initial settlement & trigger transactions.
                These will only be published to the blockchain in case of an
                un-cooperative or one-sided close of a channel.
                In the ideal case, the peers in the channel would agree to
                create a spend from the funding transaction and await until
                it's externalized to ensure the `update_pair` can no longer
                be accepted into the blockchain.

    ***************************************************************************/

    private void onSetupComplete (UpdatePair update_pair)
    {
        assert(this.state == ChannelState.SettingUp);

        // this is not technically an error, but it would be very strange
        // that a funding tx was published before signing was complete,
        // as the funding party carries the risk of having their funds locked.
        // in this case we skip straight to the open state.
        if (this.funding_tx_signed != Transaction.init)
            this.state = ChannelState.Open;
        else
            this.state = ChannelState.WaitingForFunding;

        // if we're the funder then it's time to publish the funding tx
        if (this.is_owner)
        {
            this.funding_tx_signed = this.conf.funding_tx.clone();
            this.funding_tx_signed.inputs[0].unlock
                = genKeyUnlock(sign(this.kp, this.conf.funding_tx));

            writeln("Publishing funding tx..");
            this.txPublisher(this.funding_tx_signed);
        }

        this.channel_updates ~= update_pair;
    }

    /***************************************************************************

        Called when the funding transaction of this channel has been
        externalized in the blockchain.

        The state of this channel will change to `Open`, which will make make
        the channel open to receiving new balance update requests - which it
        may accept or deny based on whether all the channel parties agree
        to the new balance update request.

        Params:
            tx = the funding transaction. Must be equal to the hash of the
                funding transaction as set up in the initial `openChannel`
                call - otherwise it's ignored.

    ***************************************************************************/

    private void onFundingTxExternalized (in Transaction tx)
    {
        this.funding_tx_signed = tx.clone();
        if (this.state == ChannelState.WaitingForFunding)
            this.state = ChannelState.Open;

        // todo: assert that this is really the actual balance
        // it shouldn't be technically possible that it mismatches
        this.cur_balance = Balance([Output(this.conf.funding_amount,
            PublicKey(this.conf.funder_pk[]))]);
    }

    /***************************************************************************

        Called when the trigger / update transaction of this channel has been
        either detected in one of the nodes' transaction pools, or
        if it was externalized in the blockchain.

        This signals that the channel attemted to be unilaterally closed
        by some counter-party.

        The state of this channel will change to `PendingClose`, which will
        make make it reject any new balance update requests.

        If the `tx` is not the latest update transaction the Channel will try
        to publish the latest update transaction. The Channel will then publish
        the latest matching settlement transaction.

        Params:
            tx = the trigger / update transaction.

    ***************************************************************************/

    public void onUpdateTxExternalized (in Transaction tx)
    {
        this.state = ChannelState.PendingClose;

        // last update was published, publish just the settlement
        if (tx == this.channel_updates[$ - 1].update_tx)
        {
            const settle_tx = this.channel_updates[$ - 1].settle_tx;
            writefln("Publishing last settle tx %s: %s",
                this.channel_updates.length, settle_tx.hashFull());
            this.txPublisher(settle_tx);
        }
        else
        {
            // either the trigger or an outdated update tx was published.
            // publish the latest update first.
            const update_tx = this.channel_updates[$ - 1].update_tx;
            writefln("Publishing latest update tx %s: %s",
                this.channel_updates.length, update_tx.hashFull());
            this.txPublisher(update_tx);
        }
    }

    /***************************************************************************

        Called when a closing transaction has been detected as externalized.
        This was a collaborative channel close.

        At this point the channel becomes closed and it is safe to destroy
        all of its associated data.

        Params:
            tx = the closing transaction.

    ***************************************************************************/

    private void onClosingTxExternalized (in Transaction tx)
    {
        // todo: assert this is the actual closing transaction
        this.state = ChannelState.Closed;
    }

    /***************************************************************************

        Called when a settlement transaction has been detected as externalized.
        This was a unilateral channel close.

        At this point the channel becomes closed and it is safe to destroy
        all of its associated data. If the counter-party was the initiator
        of the channel closure but did not attempt to collaborate on the close,
        or if the counter-party deliberately published an outdated settlement
        transaction, then the peer could be added to the local node's ban list.

        Note that it cannot be proven that a peer acted maliciously when
        publishing a stale update / settlement. Consider the following scenario:

        - Nodes A and B have settle & update transactions for seq 1.
        - They try to negotiate settle & update transactions for seq 2.
        - Node A receives settle & update for seq 2, but refuses to send back
          the update signature for seq 2 to Node B.
        - Node A stops collaborating for a long time, either deliberately or
          due to network issues.
        - Node B is forced to try to close the channel by publishing the trigger
          transaction and its latest update transaction with seq 1.
        - Node A comes back online, sees the trigger / update transactions
          published to the blockchain. It quickly publishes update with seq 2,
          and the associated settlement transaction.

        There was no loss of funds in the above case, but node B could appear
        to look like the bad actor to the external observers because it
        published a stale update transaction.

        In fact, neither node could necessarily be at fault. It's possible
        there was a network outage at Node A's side.

        At this time we're unaware of any algorithm that allows for an
        atomic swap of each others' secrets (signatures) to prevent having
        one party accept a signature but never returning its own signature back.

        Params:
            tx = the closing transaction.

    ***************************************************************************/

    private void onSettleTxExternalized (in Transaction tx)
    {
        // todo: assert this is the actual closing transaction
        this.state = ChannelState.Closed;
    }

    /***************************************************************************

        Called when the counter-party requests a settlement signature.
        If the sequence ID is unrecognized, it will return an error code.

        Params:
            seq_id = the sequence ID.

        Returns:
            the settlement signature,
            or an error code with an optional error message.

    ***************************************************************************/

    public Result!Signature onRequestSettleSig (in uint seq_id)
    {
        if (seq_id != this.cur_seq_id)
            return Result!Signature(ErrorCode.InvalidSequenceID);

        return this.signer.getSettleSig();
    }

    /***************************************************************************

        Called when the counter-party requests an update signature.
        If the sequence ID is unrecognized, it will return an error code.

        Params:
            seq_id = the sequence ID.

        Returns:
            the update signature,
            or an error code with an optional error message.

    ***************************************************************************/

    public Result!Signature onRequestUpdateSig (in uint seq_id)
    {
        if (seq_id != this.cur_seq_id)
            return Result!Signature(ErrorCode.InvalidSequenceID);

        return this.signer.getUpdateSig();
    }

    /***************************************************************************

        Update the balance of the channel. This should be called only when
        all the counter-parties have agreed to a new channel balance update.

        Calling this starts a new signing task which will collect settlement
        & update transactions from the counterparties. Once the collection is
        complete, the settlement & update transaction pair will be added to
        the `channel_updates`, and the `cur_balance` will be updated to
        reflect the new balance.

        Params:
            seq_id = the sequence ID.

        Returns:
            the update signature,
            or an error code with an optional error message.

    ***************************************************************************/

    public void updateBalance (in uint seq_id, PrivateNonce priv_nonce,
        PublicNonce peer_nonce, in Balance new_balance)
    {
        writefln("%s: updateBalance(%s)", this.kp.V.prettify,
            seq_id);

        assert(this.state == ChannelState.Open);

        // todo: dupe calls should be handled somewhere, so maybe we
        // need a call like `canUpdateBalance(seq_id, ...)`?
        assert(seq_id == this.cur_seq_id + 1);

        this.cur_seq_id++;
        auto update_pair = this.signer.collectSignatures(this.cur_seq_id,
            new_balance, priv_nonce, peer_nonce,
            this.channel_updates[0].update_tx);  // spend from trigger tx

        writefln("%s: Got new pair!", this.kp.V.prettify);
        this.channel_updates ~= update_pair;
        this.cur_balance.outputs = new_balance.outputs.dup;
    }

    /***************************************************************************

        Called when a new block has been externalized.

        Checks if the block contains funding / trigger / update / settlement
        transactions which belong to this channel, and calls one of the
        handler routines based on the detected transaction type.

        Params:
            block = the newly externalized block

    ***************************************************************************/

    public void onBlockExternalized (in Block block)
    {
        foreach (tx; block.txs)
        {
            if (tx.hashFull() == this.conf.funding_tx_hash)
            {
                writefln("%s: Funding tx externalized(%s)",
                    this.kp.V.prettify, tx.hashFull());
                this.onFundingTxExternalized(tx);
            }
            else
            if (this.isUpdateTx(tx))
            {
                writefln("%s: Update tx externalized(%s)",
                    this.kp.V.prettify, tx.hashFull());
                this.onUpdateTxExternalized(tx);
            }
            else
            if (this.isSettleTx(tx))
            {
                writefln("%s: Settle tx externalized(%s)",
                    this.kp.V.prettify, tx.hashFull());
                this.onSettleTxExternalized(tx);
            }
        }
    }

    private bool isUpdateTx (in Transaction tx)
    {
        if (tx.inputs.length != 1)
            return false;

        if (tx.inputs[0].utxo == this.conf.funding_tx_hash)
            return true;

        // todo: could there be a timing issue here if our `channel_updates`
        // are not updated fast enough? chances are very slim, need to verify.
        return this.channel_updates.length > 0 &&
            tx.inputs[0].utxo == this.channel_updates[0].update_tx.inputs[0].utxo;
    }

    private bool isSettleTx (in Transaction tx)
    {
        // todo: how do we reliably detect our settlement tx?
        return false;
    }

    /***************************************************************************

        Begin a unilateral closure of the channel.

        The channel will attempt to co-operatively close by offering the
        counter-party to sign a closing transaction which spends directly
        from the funding transaction where the closing transaction is not
        encumbered by any sequence locks.

        This closing transaction will need to be externalized before the
        channel may be considered closed.

        If the counter-party is not collaborative or is non-responsive,
        the node will wait until `cooperative_close_timeout` time has passed
        since the last failed co-operative close request. If this timeout is
        reached the node will forcefully publish the trigger transaction.

        Once the trigger transaction is externalized the node will publish
        the latest update transaction if any, and subsequently will publish the
        settlement transaction. The settlement transaction may only be published
        after `settle_time` blocks were externalized after the trigger/update
        transaction's UTXO was included in the blockchain - this leaves enough
        time for the counter-party to react and publish a newer update &
        settlement transactions in case the closing party tries to cheat by
        publishing a stale update & settlement pair of transactions.

        Params:
            seq_id = the sequence ID.

        Returns:
            the update signature,
            or an error code with an optional error message.

    ***************************************************************************/

    public void beginUnilateralClose ()
    {
        // todo: should only be called once
        assert(this.state == ChannelState.Open);
        this.state = ChannelState.PendingClose;

        // publish the trigger transaction
        const trigger_tx = this.channel_updates[0].update_tx;
        writefln("Publishing trigger tx: %s", trigger_tx.hashFull());
        this.txPublisher(trigger_tx);

        // settlement cannot be published yet (relative time lock rejected)
        const settle_tx = this.channel_updates[0].settle_tx;
        writefln("Publishing settle tx: %s", settle_tx.hashFull());
        this.txPublisher(settle_tx);
    }

    version (unittest)
    public void ctrlPublishUpdate (uint index)
    {
        assert(this.channel_updates.length > index + 1);
        const update_tx = this.channel_updates[index].update_tx;
        writefln("Publishing update tx %s: %s", index, update_tx.hashFull());
        this.txPublisher(update_tx);
    }

    /***************************************************************************

        Begin a collaborative closure of the channel.

        The node will send the counter-party a `closeChannel` request,
        with the sequence ID of the last known state.

        The counter-party should return its signature for the closing
        transaction.

        Params:
            seq_id = the sequence ID.

        Returns:
            the update signature,
            or an error code with an optional error message.

    ***************************************************************************/

    public void beginCollaborativeClose ()
    {
        // todo: should only be called once
        assert(this.state == ChannelState.Open);
        this.state = ChannelState.PendingClose;

        // todo: index is hardcoded
        //const utxo = UTXO.getHash(hashFull(this.funding_tx), 0);
        //this.pending_close.tx = createClosingTx(utxo, this.cur_balance);

        //this.pending_close.our_sig = sign(this.kp.v, this.conf.pair_pk,
        //    nonce_pair_pk, priv_nonce.update.v, update_tx);

        //auto result = this.peer.closeChannel(this.conf.chan_id, this.cur_seq_id);
    }

    /***************************************************************************

        Attempt to collaboratively close the channel.

        The channel will attempt to co-operatively close by offering the
        counter-party to sign a closing transaction which spends directly
        from the funding transaction where the closing transaction is not
        encumbered by any sequence locks.

        This closing transaction will need to be externalized before the
        channel may be considered closed.

        If the counter-party is not collaborative or is non-responsive,
        the node will wait until `cooperative_close_timeout` time has passed
        since the last failed co-operative close request. If this timeout is
        reached the node will forcefully publish the trigger transaction.

        Once the trigger transaction is externalized the node will publish
        the latest update transaction if any, and subsequently will publish the
        settlement transaction. The settlement transaction may only be published
        after `settle_time` blocks were externalized after the trigger/update
        transaction's UTXO was included in the blockchain - this leaves enough
        time for the counter-party to react and publish a newer update &
        settlement transactions in case the closing party tries to cheat by
        publishing a stale update & settlement pair of transactions.

        Params:
            seq_id = the sequence ID.

        Returns:
            the update signature,
            or an error code with an optional error message.

    ***************************************************************************/

    public Result!PublicNonce onCloseChannelRequest (in uint seq_id,
        in PublicNonce peer_nonce, in Amount fee)
    {
        if (this.state != ChannelState.Open)
            return Result!PublicNonce(ErrorCode.ChannelNotOpen,
                format("Channel state is not open: %s", this.state));

        if (seq_id != this.cur_seq_id)
            return Result!PublicNonce(ErrorCode.InvalidSequenceID,
                format("Sequence ID %s does not match our latest ID %s.",
                    seq_id, this.cur_seq_id));

        // todo: need to calculate *our* balance here and see if we can
        // cover this fee.

        this.state = ChannelState.PendingClose;

        // todo
        return Result!PublicNonce(ErrorCode.InvalidSequenceID,
            format("Sequence ID %s does not match our latest ID %s.",
                seq_id, this.cur_seq_id));
    }
}
