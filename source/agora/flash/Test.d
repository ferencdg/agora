/*******************************************************************************

    Contains the flash Channel definition

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.flash.Test;

import agora.common.Amount;
import agora.common.Types;
import agora.common.crypto.ECC;
import agora.common.crypto.Key;
import agora.common.crypto.Schnorr;
import agora.common.Hash;
import agora.common.Task;
import agora.consensus.data.genesis.Test;
import agora.consensus.data.Transaction;
import agora.consensus.data.UTXO;
import agora.flash.API;
import agora.flash.Channel;
import agora.flash.Config;
import agora.flash.ErrorCode;
import agora.flash.Node;
import agora.flash.Scripts;
import agora.flash.Types;
import agora.test.Base;

import geod24.Registry;

import std.conv;
import std.exception;

import core.thread;

/// In addition to the Flash API, we provide controller methods to initiate
/// the channel creation procedures, and control each flash node's behavior.
public interface ControlAPI : FlashAPI
{
    /// start timers which monitor the blockchain for new relevant tx's
    public void ctrlStart();

    public void ctrlUnilateralClose (in Hash chan_id);

    public void ctrlCooperativeClose (in Hash chan_id);

    /// Open a channel with another flash node.
    public Hash ctrlOpenChannel (in Hash funding_hash, in Amount funding_amount,
        in uint settle_time, in Point peer_pk);

    public void ctrlWaitFunding (in Hash chan_id);

    public void ctrlUpdateBalance (in Hash chan_id, in Amount funder,
        in Amount peer);

    /// ditto
    public bool anyChannelOpen ();
}

public class ControlFlashNode : FlashNode, ControlAPI
{
    public this (const Pair kp, Registry* agora_registry,
        string agora_address, Registry* flash_registry)
    {
        super(kp, agora_registry, agora_address, flash_registry);
    }

    public override void ctrlStart ()
    {
        super.start();
    }

    /// Control API
    public override void ctrlWaitFunding (in Hash chan_id)
    {
        auto channel = chan_id in this.channels;
        assert(channel !is null);

        while (!channel.isOpen())
            this.taskman.wait(500.msecs);
    }

    public override Hash ctrlOpenChannel (in Hash funding_utxo,
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

        PrivateNonce priv_nonce = genPrivateNonce();
        PublicNonce pub_nonce = priv_nonce.getPublicNonce();

        auto result = peer.openChannel(chan_conf, pub_nonce);
        assert(result.error == ErrorCode.None, result.to!string);

        auto channel = new Channel(chan_conf, this.kp, priv_nonce, result.value,
            peer, this.taskman, &this.txPublisher);
        this.channels[chan_id] = channel;

        return chan_id;
    }

    public override void ctrlUnilateralClose (in Hash chan_id)
    {
        auto channel = chan_id in this.channels;
        assert(channel !is null);
        channel.beginUnilateralClose();
    }

    /// Control API
    public override void ctrlCooperativeClose (in Hash chan_id)
    {

    }

    /// Control API
    public override void ctrlUpdateBalance (in Hash chan_id,
        in Amount funder_amount, in Amount peer_amount)
    {
        writefln("%s: ctrlUpdateBalance(%s, %s, %s)", this.kp.V.prettify,
            chan_id.prettify, funder_amount, peer_amount);

        auto channel = chan_id in this.channels;
        assert(channel !is null);

        // todo: we need to track this somewhere else
        static uint new_seq_id = 0;
        ++new_seq_id;

        PrivateNonce priv_nonce = genPrivateNonce();
        PublicNonce pub_nonce = priv_nonce.getPublicNonce();

        const Balance balance = Balance(
            [Output(funder_amount, PublicKey(channel.conf.funder_pk[])),
             Output(peer_amount, PublicKey(channel.conf.peer_pk[]))]);

        const BalanceRequest balance_req =
        {
            balance    : balance,
            peer_nonce : pub_nonce,
        };

        auto result = channel.peer.requestBalanceUpdate(chan_id, new_seq_id,
            balance_req);
        assert(result.error == ErrorCode.None, result.to!string);
        channel.updateBalance(new_seq_id, priv_nonce, result.value, balance);
    }

    /// ditto
    public override bool anyChannelOpen ()
    {
        return this.channels.byValue.any!(chan => chan.isOpen());
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
        api.ctrlStart();

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


/// Ditto
unittest
{
    TestConf conf = { txs_to_nominate : 1 };
    auto network = makeTestNetwork(conf);
    network.start();
    scope (exit) network.shutdown();
    scope (failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node_1 = nodes[0];

    // split the genesis funds into WK.Keys[0] .. WK.Keys[7]
    auto txs = genesisSpendable().take(8).enumerate()
        .map!(en => en.value.refund(WK.Keys[en.index].address).sign())
        .array();

    foreach (idx, tx; txs)
    {
        node_1.putTransaction(tx);
        network.expectBlock(Height(idx + 1), network.blocks[0].header);
    }

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

    // 1 blocks settle time after / when trigger tx is published
    const Settle_1_Blocks = 0;
    //const Settle_10_Blocks = 10;

    // the utxo the funding tx will spend (only relevant to the funder)
    const utxo = UTXO.getHash(hashFull(txs[0]), 0);
    const chan_id = alice.ctrlOpenChannel(
        utxo, Amount(10_000), Settle_1_Blocks, bob_pair.V);

    // await funding transaction
    network.expectBlock(Height(9), network.blocks[0].header);
    const block_9 = node_1.getBlocksFrom(9, 1)[$ - 1];
    assert(block_9.txs.any!(tx => tx.hashFull() == chan_id));

    alice.ctrlWaitFunding(chan_id);
    bob.ctrlWaitFunding(chan_id);

    alice.ctrlUpdateBalance(chan_id, Amount(10_000), Amount(5_000));
    alice.ctrlUpdateBalance(chan_id, Amount(9_000),  Amount(6_000));
    alice.ctrlUpdateBalance(chan_id, Amount(8_000),  Amount(7_000));

    writefln("Alice unilaterally closing the channel..");
    alice.ctrlUnilateralClose(chan_id);

    network.expectBlock(Height(11), network.blocks[0].header);

    //// now we publish trigger tx
    //const block_2 = node_1.getBlocksFrom(0, 1024)[$ - 1];

    //const funding_tx_hash = Hash.fromString("0x54615ad5a07681a1a4e677ede7bd325c570d2d5003b0f86e6c03f3031a4d905514354cf72048f9c50c7ccdca251a01fa8971fe042f8e67e9b21652d54162241b");

    //txs = filtSpendable!(tx => tx.hashFull() != funding_tx_hash)(block_2)
    //    .enumerate()
    //    .map!(en => en.value.refund(WK.Keys[3].address).sign())
    //    .take(7)
    //    .array();
    //writefln("Posting update tx: %s", update_pair.update_tx.hashFull());
    //txs ~= update_pair.update_tx;

    //txs.each!(tx => node_1.putTransaction(tx));
    //network.expectBlock(Height(3), network.blocks[0].header);

    //const block_3 = node_1.getBlocksFrom(0, 1024)[$ - 1];
    //txs = filtSpendable!(tx => tx.hashFull() != update_pair.update_tx.hashFull())(block_3)
    //    .enumerate()
    //    .map!(en => en.value.refund(WK.Keys[3].address).sign())
    //    .take(7)
    //    .array();
    //writefln("Posting settle tx: %s", update_pair.settle_tx.hashFull());
    //txs ~= update_pair.settle_tx;

    //txs.each!(tx => node_1.putTransaction(tx));
    //network.expectBlock(Height(4), network.blocks[0].header);

    //Thread.sleep(1.seconds);
}

import agora.consensus.data.Block;
import std.range;
public auto filtSpendable (alias filt)(const ref Block block)
{
    return block.txs
        .filter!(tx => tx.type == TxType.Payment)
        .filter!(tx => filt(tx))
        .map!(tx => iota(tx.outputs.length).map!(idx => TxBuilder(tx, cast(uint)idx)))
        .joiner();
}
