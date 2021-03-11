/*******************************************************************************

    Contains tests for block reward distribution

    Copyright:
        Copyright (c) 2021 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.test.BlockReward;

import agora.test.Base;
import agora.consensus.data.Transaction;
import agora.common.Amount;
import agora.common.crypto.Key;
import agora.utils.WellKnownKeys;

unittest
{
    TestConf conf = {
        quorum_threshold : 100,
        block_reward_gap: 5,
        block_reward_delay: 2,
    };
    auto network = makeTestNetwork(conf);
    network.start();
    scope(exit) network.shutdown();
    scope(failure) network.printLogs();
    network.waitForDiscovery();

    auto nodes = network.clients;
    auto node1 = nodes[0];

    // get the genesis block, make sure it's the only block externalized
    auto blocks = node1.getBlocksFrom(0, 2);
    assert(blocks.length == 1);

    Transaction[] txs;

    void createAndExpectNewBlock (Height new_block_height)
    {
        // create enough tx's for a single block
        txs = blocks[new_block_height - 1].spendable().map!(txb => txb
            .sign()).array();

        // send it to one node
        txs.each!(tx => node1.putTransaction(tx));

        network.expectBlock(new_block_height, blocks[0].header);

        // add next block
        blocks ~= node1.getBlocksFrom(new_block_height, 1);

        auto cb_txs = blocks[$-1].txs.filter!(tx => tx.type == TxType.Coinbase)
            .array;

        // regular block
        immutable block_height = blocks[$-1].header.height;
        if ((block_height < conf.block_reward_delay + conf.block_reward_gap) ||
            ((block_height - conf.block_reward_delay) % conf.block_reward_gap))
            assert(cb_txs.length == 0);
        else
        {
            // payout block
            assert(cb_txs.length == 1);
            assert(cb_txs[0].outputs.length == 1 + blocks[0].header.enrollments.length);
            foreach (ref output; cb_txs[0].outputs)
            {
                // foundation block reward
                if (PublicKey(output.lock.bytes) == CommonsBudget.address)
                    assert(output.value == Amount(50 * 10_000_000), output.value.toString());
                else // validator block reward
                    assert(output.value == Amount(45 * 1_000_000), output.value.toString());
            }
        }
    }

    // create GenesisValidatorCycle - 1 blocks
    foreach (block_idx; 1 .. GenesisValidatorCycle)
    {
        createAndExpectNewBlock(Height(block_idx));
    }
}
