/*******************************************************************************

    Contains the flash Channel definition

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.Node;

import agora.common.Amount;
import agora.common.crypto.ECC;
import agora.common.crypto.Schnorr;
import agora.common.Hash;
import agora.common.Task;
import agora.common.Types;
import agora.consensus.data.Transaction;
import agora.flash.API;
import agora.flash.Channel;
import agora.flash.Config;
import agora.flash.ErrorCode;
import agora.flash.Scripts;
import agora.flash.Types;

// todo: remove
import agora.test.Base;
import geod24.Registry;
import agora.consensus.data.genesis.Test;

/// Could be a payer, or a merchant. funds can go either way in the channel.
/// There may be any number of channels between two parties
/// (e.g. think multiple different micropayment services)
/// In this test we assume there may only be one payment channel between two parties.
public abstract class FlashNode : FlashAPI
{
    /// Schnorr key-pair belonging to this node
    protected const Pair kp;

    // random agora node
    protected RemoteAPI!TestAPI agora_node;
    protected Registry* flash_registry;
    protected TaskManager taskman;  // for scheduling

    // for sending tx's to the network
    protected TestAPIManager api_manager;

    /// Channels which are pending and not accepted yet.
    /// Once the channel handshake is complete and only after the funding
    /// transaction is externalized, the Channel channel gets promoted
    /// to a Channel with a unique ID derived from the hash of the funding tx.
    protected Channel[Hash] channels;

    protected bool ready_to_close;

    /// Ctor
    public this (const Pair kp, Registry* agora_registry,
        string agora_address, Registry* flash_registry)
    {
        this.kp = kp;
        this.flash_registry = flash_registry;
        // todo: use a passed-in task manager
        this.taskman = new LocalRestTaskManager();
        this.api_manager = api_manager;

        auto tid = agora_registry.locate(agora_address);
        assert(tid != typeof(tid).init, "Agora node not initialized");
        Duration timeout;
        this.agora_node = new RemoteAPI!TestAPI(tid, timeout);
    }

    ///
    public void start ()
    {
        this.taskman.setTimer(200.msecs, &this.monitorBlockchain, Periodic.Yes);
    }

    /// publishes a transaction to the blockchain
    protected void txPublisher (in Transaction tx)
    {
        this.agora_node.putTransaction(cast()tx);
    }

    ///
    public override Result!PublicNonce openChannel (in ChannelConfig chan_conf,
        in PublicNonce peer_nonce)
    {
        writefln("%s: openChannel()", this.kp.V.prettify);

        if (chan_conf.chan_id in this.channels)
            return Result!PublicNonce(ErrorCode.DuplicateChannelID,
                "There is already an open channel with this ID");

        auto peer = this.getFlashClient(chan_conf.funder_pk);

        const our_gen_hash = hashFull(GenesisBlock);
        if (chan_conf.gen_hash != our_gen_hash)
            return Result!PublicNonce(ErrorCode.InvalidGenesisHash,
                "Unrecognized blockchain genesis hash");

        const min_funding = Amount(1000);
        if (chan_conf.funding_amount < min_funding)
            return Result!PublicNonce(ErrorCode.FundingTooLow,
                format("Funding amount is too low. Want at least %s", min_funding));

        // todo: re-enable
        version (none)
        {
            const min_settle_time = 5;
            const max_settle_time = 10;
            if (chan_conf.settle_time < min_settle_time ||
                chan_conf.settle_time > max_settle_time)
                return OpenResult("Settle time is not within acceptable limits");
        }

        PrivateNonce priv_nonce = genPrivateNonce();
        auto channel = new Channel(chan_conf, this.kp, priv_nonce, peer_nonce,
            peer, this.taskman,
            &this.txPublisher);
        this.channels[chan_conf.chan_id] = channel;

        PublicNonce pub_nonce = priv_nonce.getPublicNonce();
        return Result!PublicNonce(pub_nonce);
    }

    ///
    public override Result!PublicNonce closeChannel (in Hash chan_id,
        in uint seq_id, in PublicNonce peer_nonce, in Amount fee )
    {
        if (auto channel = chan_id in this.channels)
            return channel.onCloseChannelRequest(seq_id, peer_nonce, fee);

        return Result!PublicNonce(ErrorCode.WrongChannelID,
            "Channel ID not found");
    }

    ///
    public override Result!ChannelState getChannelState (in Hash chan_id)
    {
        if (auto channel = chan_id in this.channels)
            return Result!ChannelState(channel.getState());

        return Result!ChannelState(ErrorCode.WrongChannelID,
            "Channel ID not found");
    }

    ///
    public override Result!Signature requestSettleSig (in Hash chan_id, in uint seq_id)
    {
        if (auto channel = chan_id in this.channels)
            return channel.onRequestSettleSig(seq_id);

        return Result!Signature(ErrorCode.WrongChannelID,
            "Channel ID not found");
    }

    ///
    public override Result!Signature requestUpdateSig (in Hash chan_id, in uint seq_id)
    {
        if (auto channel = chan_id in this.channels)
            return channel.onRequestUpdateSig(seq_id);

        return Result!Signature(ErrorCode.WrongChannelID,
            "Channel ID not found");
    }

    ///
    public override Result!PublicNonce requestBalanceUpdate (in Hash chan_id,
        in uint seq_id, in BalanceRequest balance_req)
    {
        // todo: verify sequence ID
        writefln("%s: requestBalanceUpdate(%s, %s)", this.kp.V.prettify,
            chan_id.prettify, seq_id);

        auto channel = chan_id in this.channels;
        if (channel is null)
            return Result!PublicNonce(ErrorCode.WrongChannelID,
                "Channel ID not found");

        if (!channel.isOpen())
            return Result!PublicNonce(ErrorCode.ChannelNotOpen,
                "This channel is not funded yet");

        if (channel.isCollecting())
            return Result!PublicNonce(ErrorCode.SigningInProcess,
                "This channel is still collecting signatures for a "
                ~ "previous sequence ID");

        // todo: need to add sequence ID verification here
        // todo: add logic if we agree with the new balance
        // todo: check sums for the balance so it doesn't exceed
        // the channel balance, and that it matches exactly.

        PrivateNonce priv_nonce = genPrivateNonce();
        PublicNonce pub_nonce = priv_nonce.getPublicNonce();

        // todo: there may be a double call here if the first request timed-out
        // and the client sends this request again. We should avoid calling
        // `updateBalance()` again.
        this.taskman.setTimer(0.seconds,
        {
            channel.updateBalance(seq_id, priv_nonce, balance_req.peer_nonce,
                balance_req.balance);
        });

        return Result!PublicNonce(pub_nonce);
    }

    ///
    protected FlashAPI getFlashClient (in Point peer_pk)
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
    private void monitorBlockchain ()
    {
        // todo: we actually need a getUTXO API
        // we would probably have to contact Stoa,
        // for now we simulate it through getBlocksFrom(),
        // we could provide this in the TestAPI
        static ulong last_read_height = 0;

        while (1)
        {
            auto latest_height = this.agora_node.getBlockHeight();
            if (last_read_height < latest_height)
            {
                auto next_block = this.agora_node.getBlocksFrom(
                    last_read_height + 1, 1)[0];

                foreach (channel; this.channels)
                    channel.onBlockExternalized(next_block);

                last_read_height++;
            }

            this.taskman.wait(0.msecs);
        }
    }
}
