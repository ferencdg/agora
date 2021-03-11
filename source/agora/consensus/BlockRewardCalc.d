/*******************************************************************************

    Contains functions to calculate the block reward.

    1. We will only distribute block rewards in every X blocks
       as opposed to distributing it in every block. This was originally meant
       to reduce blockchain size.
    2. We will delay the distribution of the block rewards, so for
       blocks A .. B we will distribute the rewards at block B + Y.
       This is because we want to give enough time validators to share
       block signatures which is the basis of the block reward.
    3. Each validator will be rewarded based on how many blocks they signed
       and the reward will NOT be propotional to how much coin they staked.
    4  The block reward is divided between the validators and the Foundation.
    5. The total block reward for a particular height is fixed,
       however this doesn't mean that the total validator reward is fixed.
       The total validator reward is based on the total number of signatures
       on the blocks in question. The total validator reward is a
       nonlinear function of the the total signatures,
       so 2 times more signatures might increase the total validator reward by 4.
       This is to encourage validators to share signatures.
       The coins remaing is  'fixed block reward at height X' -
       'total validator reward' will go to the Foundation.
    6. The part of the total validator reward that cannot be didived equally
       between the validators will also go to the Foundation

    Copyright:
        Copyright (c) 2021 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.BlockRewardCalc;

import agora.common.Amount;
import agora.common.Types;
import agora.consensus.data.Params;
import agora.crypto.ECC : Point;
import agora.utils.Log;

import std.algorithm : min;
import std.math;
import std.typecons : Tuple, tuple;

import core.time;

mixin AddLogger!();

public class BlockRewardCalc
{

    ///
    public this (immutable(ConsensusParams) consensus_params) @safe @nogc pure nothrow
    {
        this.consensus_params = consensus_params;
    }

    ///
    private alias CurrentPeriodTup = Tuple!(ulong, "period", bool, "is_period_end");

    /***************************************************************************

    Returns which 'period' the height falls into and whether that height
    is the last height for that particular 'period'.

    'Periods' represent time periods and are stored in the block_rewards array.

    Params:
        height = the height for which we want to get the period information
        block_rewards = time periods

    Returns: which 'period' the particular height falls into and whether that height
    is the last height for that particular period

    ***************************************************************************/

    private CurrentPeriodTup getCurrentPeriod (in Height height, immutable(BlockRewardsTup)[] block_rewards) @safe const pure nothrow
    {
        ulong blocks_accumulated = 0;
        foreach (period; 0 .. block_rewards.length)
        {
            blocks_accumulated += block_rewards[period].dist_period_secs / consensus_params.BlockInterval.total!"seconds";
            if (blocks_accumulated >= height)
                return CurrentPeriodTup(period, blocks_accumulated == height);
        }
        return CurrentPeriodTup(block_rewards.length, false);
    }

    unittest
    {
        immutable block_rewards = [BlockRewardsTup(Amount(100), 7), BlockRewardsTup(Amount(100), 2)];
        auto block_reward_calc = getBlockRewardCalc(2, 5, block_rewards);
        assert(block_reward_calc.getCurrentPeriod(Height(0), block_rewards) == CurrentPeriodTup(0, false));
        assert(block_reward_calc.getCurrentPeriod(Height(7), block_rewards) == CurrentPeriodTup(0, true));
        assert(block_reward_calc.getCurrentPeriod(Height(8), block_rewards) == CurrentPeriodTup(1, false));
        assert(block_reward_calc.getCurrentPeriod(Height(9), block_rewards) == CurrentPeriodTup(1, true));
        assert(block_reward_calc.getCurrentPeriod(Height(10), block_rewards) == CurrentPeriodTup(2, false));
    }

    /***************************************************************************

    Returns the validator reward for each validator based on how many blocks
    each validator signed, and also calculates the remainder that cannot be evenly
    distributed to the validators.

    Params:
        height = the height of the block that will contain the CoinBase transaction
        validator_stakes = number of blocks signed by the validator identified by
                           its public key
        remainder = the remainder that cannot be evenly distributed to
                    the validators
        comply_perc = (#actual signatures / #expected signatures) * 100 on all
              the blocks for which we want to calculate the block reward

    Returns: the validator reward for each validator based on how many blocks
    each validator signed

    ***************************************************************************/

    public Amount[Point] getEachValidatorReward (in Height height, ushort[Point] validator_stakes,
        out Amount remainder, double comply_perc) @safe const nothrow
    {
        Amount[Point] each_validator_rewards;
        Amount total_validator_reward = getReducedValidatorReward(height, comply_perc);
        Amount gcd_validator_reward = total_validator_reward;

        ulong total_stakes;
        foreach (ref stake; validator_stakes.byValue())
            total_stakes += stake;
        assert(total_stakes != 0);

        Amount min_validator_reward = total_validator_reward;
        min_validator_reward.div(total_stakes);

        Amount actual_total_validator_reward;
        foreach (pkey_stake; validator_stakes.byKeyValue())
        {
            Amount validator_reward = min_validator_reward;
            validator_reward.mul(pkey_stake.value);
            each_validator_rewards[pkey_stake.key] = validator_reward;
            actual_total_validator_reward.mustAdd(validator_reward);
        }
        remainder = total_validator_reward;
        remainder.mustSub(actual_total_validator_reward);

        return each_validator_rewards;
    }

    unittest
    {
        ushort[Point] validator_stakes;
        Amount remainder;
        auto block_reward = getBlockRewardCalc(2, 3, cast(immutable(BlockRewardsTup)[])[BlockRewardsTup(Amount(100), 10)], 1.seconds);

        auto validator1 = Point.fromString("0xab4f6f6e85b8d0d38f5d5798a4bdc4dd444c8909c8a5389d3bb209a186105110");
        auto validator2 = Point.fromString("0xab4f6f6e85b8d0d38f5d5798a4bdc4dd444c8909c8a5389d3bb209a186105111");

        // equal stake, 0 remainder
        validator_stakes[validator1] = 3;
        validator_stakes[validator2] = 3;
        auto actual_rewards = block_reward.getEachValidatorReward(Height(5), validator_stakes, remainder, 100);
        Amount[Point] expected_rewards;
        expected_rewards[validator1] = Amount(15);
        expected_rewards[validator2] = Amount(15);
        assert(actual_rewards == expected_rewards);
        assert(remainder == Amount(0));

        // equal stake, non 0 remainder
        validator_stakes[validator1] = 4;
        validator_stakes[validator2] = 4;
        actual_rewards = block_reward.getEachValidatorReward(Height(5), validator_stakes, remainder, 100);
        expected_rewards.clear();
        expected_rewards[validator1] = Amount(12);
        expected_rewards[validator2] = Amount(12);
        assert(actual_rewards == expected_rewards);
        // there is no reason to use gcd in this case to get rid of the remainder,
        // because in real production system it is almost guaranteed that one of the validator stakes
        // will be 1, and that would make the gcd based solution equivalent to the current one
        assert(remainder == Amount(6));

        // non equal stake, 0 remainder
        validator_stakes[validator1] = 4;
        validator_stakes[validator2] = 2;
        actual_rewards = block_reward.getEachValidatorReward(Height(5), validator_stakes, remainder, 100);
        expected_rewards.clear();
        expected_rewards[validator1] = Amount(20);
        expected_rewards[validator2] = Amount(10);
        assert(actual_rewards == expected_rewards);
        assert(remainder == Amount(0));

        // non equal stake, 0 remainder
        validator_stakes[validator1] = 6;
        validator_stakes[validator2] = 2;
        actual_rewards = block_reward.getEachValidatorReward(Height(5), validator_stakes, remainder, 100);
        expected_rewards.clear();
        expected_rewards[validator1] = Amount(18);
        expected_rewards[validator2] = Amount(6);
        assert(actual_rewards == expected_rewards);
        assert(remainder == Amount(6));
    }

    /***************************************************************************

    Returns the total whitepaper validator reward.

    Params:
        height = the height of the block that will contain the CoinBase transaction

    Returns:
        validator whitepaper reward

    ***************************************************************************/

    public Amount getTotalValidatorReward (in Height height) @safe const nothrow
    {
        return getRewardImp(height, consensus_params.ValidatorBlockRewards);
    }

    public bool is_payout_time (Height height) @safe const pure nothrow
    {
        // making sure the height is big enough
        if (height < consensus_params.BlockRewardGap + consensus_params.BlockRewardDelay)
            return false;

        immutable period_end = height - consensus_params.BlockRewardDelay;
        immutable period_start = period_end - consensus_params.BlockRewardGap + 1;

        // checking wheter we should pay block rewards at this particular height
        if (period_end % consensus_params.BlockRewardGap != 0)
            return false;

        // making sure the height is small enough
        if ((getCurrentPeriod(Height(period_start), consensus_params.ValidatorBlockRewards).period >=
                              consensus_params.ValidatorBlockRewards.length) &&
            (getCurrentPeriod(Height(period_start), consensus_params.FoundationBlockRewards).period >=
                              consensus_params.FoundationBlockRewards.length)
           )
            return false;

        return true;
    }

    /***************************************************************************

    Returns the block rewards/number of generated coins at a particular height

    Params:
        height = the height for which we want to return the number of coins

    Returns:
        validator whitepaper reward

    ***************************************************************************/

    protected Amount getRewardImp (in Height height, immutable(BlockRewardsTup)[] block_rewards) @safe const nothrow
    {
        if (!is_payout_time(height))
            return Amount(0);

        immutable period_end = height - consensus_params.BlockRewardDelay;
        immutable period_start = period_end - consensus_params.BlockRewardGap + 1;

        Amount total_validator_reward;
        log.trace("-------------");
        log.trace("first reward block inclusive: {}", period_start);
        log.trace("last reward block inclusive: {}", period_end);

        foreach (block_num; period_start .. period_end + 1)
        {
            immutable current_period_tup = getCurrentPeriod(Height(block_num), block_rewards);
            immutable current_period = current_period_tup.period;
            if (current_period >= block_rewards.length)
                break;

            log.trace("current period: {}", current_period);
            immutable number_of_blocks_per_period = block_rewards[current_period].dist_period_secs
                                                    / consensus_params.BlockInterval.total!"seconds";

            Amount block_reward = block_rewards[current_period].amount;
            log.trace("total period reward: {}", block_reward);
            immutable remainder = block_reward.div(number_of_blocks_per_period);
            if (current_period_tup.is_period_end)
                block_reward.mustAdd(remainder);
            log.trace("partial reward calculated: {}", block_reward);
            total_validator_reward.mustAdd(block_reward);
        }
        log.trace("reward calculated: {}", total_validator_reward);
        return total_validator_reward;
    }

    unittest
    {
        // no extra reward for the the last block of the period
        // no block reward payout spans adjecent period
        auto actual_rewards = getTestRewards!"TotalValidatorReward"(Height(0), Height(19), 2, 3,
                [BlockRewardsTup(Amount(12), 6), BlockRewardsTup(Amount(18), 6)]);
        assert(getAmountArr([0, 0, 0, 0, 0, 6, 0, 0, 6, 0, 0, 9, 0, 0, 9, 0, 0, 0, 0]) == actual_rewards);

        // extra reward for the the last block of the period
        // no block reward payout spans adjecent periods
        actual_rewards = getTestRewards!"TotalValidatorReward"(Height(0), Height(19), 2, 3,
            [BlockRewardsTup(Amount(14), 6), BlockRewardsTup(Amount(21), 6)]);
        assert(getAmountArr([0, 0, 0, 0, 0, 6, 0, 0, 8, 0, 0, 9, 0, 0, 12, 0, 0, 0, 0]) == actual_rewards);

        // no extra reward for the the last block of the period
        // block reward payout spans adjecent periods
        actual_rewards = getTestRewards!"TotalValidatorReward"(Height(0), Height(19), 2, 3,
            [BlockRewardsTup(Amount(15), 5), BlockRewardsTup(Amount(25), 5)]);
        assert(getAmountArr([0, 0, 0, 0, 0, 9, 0, 0, 11, 0, 0, 15, 0, 0, 5, 0, 0, 0, 0]) == actual_rewards);

        // extra reward for the the last block of the period
        // block reward payout spans adjecent periods
        actual_rewards = getTestRewards!"TotalValidatorReward"(Height(0), Height(19), 2, 3,
            [BlockRewardsTup(Amount(16), 5), BlockRewardsTup(Amount(26), 5)]);
        assert(getAmountArr([0, 0, 0, 0, 0, 9, 0, 0, 12, 0, 0, 15, 0, 0, 6, 0, 0, 0, 0]) == actual_rewards);

        // extra reward for the the last block of the period
        // block reward payout spans adjecent periods
        // periods have different length
        actual_rewards = getTestRewards!"TotalValidatorReward"(Height(0), Height(22), 2, 3,
            [BlockRewardsTup(Amount(17), 4), BlockRewardsTup(Amount(7), 3), BlockRewardsTup(Amount(15), 6)]);
        assert(getAmountArr([0, 0, 0, 0, 0, 12, 0, 0, 9, 0, 0, 7, 0, 0, 6, 0, 0, 5, 0, 0, 0, 0]) == actual_rewards);

        // Checking whether we conform to the whitepaper's
        // coin generation rate of 27 BOA coins per 5 second for the first year.
        actual_rewards = getTestRewards!"TotalValidatorReward"(Height(0), Height(22), 2, 3,
        ConsensusConfig().validator_block_rewards, 100, 5.seconds);
        assert(getAmountArr([0, 0, 0, 0, 0, 810000000, 0, 0, 810000000, 0, 0, 810000000, 0, 0,
                             810000000, 0, 0, 810000000, 0, 0, 810000000, 0]) == actual_rewards);
    }

    /***************************************************************************

    Returns the total validator reward after applying the penalty for
    missing signatures.

    Params:
        height = the height of the block that will contain the CoinBase transaction
        comply_perc = (#actual signatures / #expected signatures) * 100 on all
                      the blocks for which we want to calculate the block reward

    Returns:
        validator whitepaper reward - penalty on validators due to missing signature

    ***************************************************************************/

    public Amount getReducedValidatorReward (in Height height, double comply_perc) @safe const nothrow
    {
        Amount total_validator_reward = getTotalValidatorReward(height);
        ubyte reduce_perc = cast(ubyte) round(
            consensus_params.BlockRewardFactorB *
            exp(comply_perc * consensus_params.BlockRewardFactorA) +
            consensus_params.BlockRewardFactorC);
        log.trace("comply percentage: {}", comply_perc);
        log.trace("reduce percentage: {}", reduce_perc);
        reduce_perc = cast(ubyte) min(reduce_perc, 100);

        if (reduce_perc == 100)
            return total_validator_reward;
        total_validator_reward.div(100);
        log.trace("after division: {}", total_validator_reward);
        total_validator_reward.mul(reduce_perc);
        log.trace("after mul: {}", total_validator_reward);
        assert(total_validator_reward.isValid());

        return total_validator_reward;
    }

    unittest
    {
        // 100 percent of the validators comply with the consensus rules
        auto reduced_validator_reward = getTestRewards!"ReducedValidatorReward"(Height(5), Height(6), 2, 3,
            [BlockRewardsTup(Amount(1200), 6), BlockRewardsTup(Amount(18), 6)], 100);
        assert(Amount(600) == reduced_validator_reward[0], reduced_validator_reward[0].toString());

        // 50 percent of the validators comply with the consensus rules
        reduced_validator_reward = getTestRewards!"ReducedValidatorReward"(Height(5), Height(6), 2, 3,
            [BlockRewardsTup(Amount(1200), 6), BlockRewardsTup(Amount(18), 6)], 50);
        assert(Amount(66) == reduced_validator_reward[0], reduced_validator_reward[0].toString());

        // 0 percent of the validators comply with the consensus rules
        reduced_validator_reward = getTestRewards!"ReducedValidatorReward"(Height(5), Height(6), 2, 3,
            [BlockRewardsTup(Amount(1200), 6), BlockRewardsTup(Amount(18), 6)], 0);
        assert(Amount(12) == reduced_validator_reward[0], reduced_validator_reward[0].toString());
    }

    /***************************************************************************

    Returns the total foundation reward minus the remainder that cannot be evenly
    distributed to the validators.

    Params:
        height = the height of the block that will contain the CoinBase transaction
        comply_perc = (#actual signatures / #expected signatures) * 100 on all
                      the blocks for which we want to calculate the block reward

    Returns:
        foundation whitepaper reward + penalty on validators
        due to missing signature =
        total foundation reward - the remainder that cannot be evenly
        distributed to the validators

    ***************************************************************************/

    public Amount getTotalCommonsBudgetReward (in Height height, double comply_perc) @safe const nothrow
    {
        Amount total_commons_budget_reward = getCommonsBudgetReward(height);
        total_commons_budget_reward.mustAdd(getExtraCommonsBudgetReward(height, comply_perc));
        return total_commons_budget_reward;
    }

    public Amount getCommonsBudgetReward (in Height height) nothrow const @safe
    {
        return getRewardImp(height, consensus_params.FoundationBlockRewards);
    }

    unittest
    {
        // Checking whether we conform to the whitepaper's
        // coin generation rate of 50 BOA coins per 5 second for the first year.
        auto actual_rewards = getTestRewards!"TotalValidatorReward"(Height(1), Height(22), 2, 3,
        ConsensusConfig().foundation_block_rewards);
        assert(getAmountArr([0, 0, 0, 0, 30_0000000, 0, 0, 30_0000000, 0, 0, 30_0000000, 0,
                             0, 30_0000000, 0, 0, 30_0000000, 0, 0, 30_0000000, 0]) == actual_rewards);

        // Checking whether we conform to the whitepaper's
        // coin generation rate of 50 BOA coins per 5 second for the last year.
        ulong height = 31_536_000 * 5 + 42;
        actual_rewards = getTestRewards!"TotalValidatorReward"(Height(height), Height(height + 22), 2, 3,
        ConsensusConfig().foundation_block_rewards);
        assert(getAmountArr([0, 0, 300000000, 0, 0, 300000000, 0, 0, 300000000, 0, 0, 300000000, 0, 0,
                             300000000, 0, 0, 300000000, 0, 0, 300000000, 0]) == actual_rewards);
    }

    /***************************************************************************

    Returns the foundation reward that was given due to the penatly applied
    to the validators because of missing signatures.

    Params:
        height = the height of the block that will contain the CoinBase transaction
        comply_perc = (#actual signatures / #expected signatures) * 100 on all
                      the blocks for which we want to calculate the block reward

    Returns:
        penalty on validators due to missing signatures

    ***************************************************************************/

    public Amount getExtraCommonsBudgetReward (in Height height, double comply_perc) @safe const nothrow
    {
        Amount extra_commons_budget_reward = getTotalValidatorReward(height);
        extra_commons_budget_reward.mustSub(getReducedValidatorReward(height, comply_perc));
        return extra_commons_budget_reward;
    }

    ///
    private immutable(ConsensusParams) consensus_params;

    /***************************************************************************

    Prints the block rewards to the log, used only for debugging

    Params:
        block_rewards = the block rewards to print

    ***************************************************************************/

    version(unittest)
    private static void printRewards (Amount[] block_rewards) @safe nothrow
    {
        foreach (ind, amount; block_rewards)
            log.trace("{} -> {}", ind, amount);
        log.trace("{}", block_rewards);
    }

    /***************************************************************************

    Converts block rewards stored in uint[] to Amount[]

    Params:
        block_rewards = the block rewards that needs to be converted to Amount

    Returns:
        block rewards stored in Amount[] and converted from int[]

    ***************************************************************************/

    version(unittest)
    private static Amount[] getAmountArr (int[] block_rewards) @safe pure nothrow
    {
        import std.algorithm : map;
        import std.array : array;

        return block_rewards.map!(block_reward => Amount(block_reward)).array();
    }


    /***************************************************************************

    Returns a newly created `BlockRewardCalc`

    Params:
        block_reward_delay = the delay (measured in blocks) after which the
                             block reward is payed
        block_reward_gap = the number of blocks between 2 block reward payout
        block_rewards = the amount of block rewards per period
        block_interval = how often blocks are expected to be created

    Returns:
        a newly created `BlockRewardCalc`

    ***************************************************************************/

    version(unittest)
    private static BlockRewardCalc getBlockRewardCalc (ushort block_reward_delay, ushort block_reward_gap,
        immutable(BlockRewardsTup)[] block_rewards, Duration block_interval = 1.seconds) @safe pure nothrow
    {
        import agora.consensus.data.genesis.Test : GenesisBlock;
        import agora.utils.WellKnownKeys;

        ConsensusConfig consensus_config =
        {
            block_reward_delay : block_reward_delay,
            block_reward_gap : block_reward_gap,
            validator_block_rewards : block_rewards,
            foundation_block_rewards : block_rewards,
        };
        immutable consensus_params = new immutable(ConsensusParams)(GenesisBlock, CommonsBudget.address,
                                                                    consensus_config, block_interval);
        return new BlockRewardCalc(consensus_params);
    }

    /***************************************************************************

    Returns an array of BlockRewards for the specified height interval
        and for the spefificed consensus parameters

    Params:
        begin_height = the smallest height in the interval(inclusive)
        end_height = the biggest height in the interval(inclusive)
        block_reward_delay = the delay (measured in blocks) after which the
                             block reward is payed
        block_reward_gap = the number of blocks between 2 block reward payout
        block_rewards = the amount of block rewards per period
        comply_perc = (#actual signatures / #expected signatures) * 100 on all
                      the blocks for which we want to calculate the block reward
        block_interval = how often blocks are expected to be created

    Returns:
        a newly created `BlockRewardCalc`

    ***************************************************************************/

    version(unittest)
    private static Amount[] getTestRewards (string block_reward_type)(Height begin_height, Height end_height,
                            ushort block_reward_delay, ushort block_reward_gap,
                            immutable(BlockRewardsTup)[] block_rewards, double comply_perc = 100,
                            Duration block_interval = 1.seconds) @safe nothrow
    {
        auto block_reward = getBlockRewardCalc(block_reward_delay, block_reward_gap,
                                           block_rewards, block_interval);

        Amount[] block_rewards_calculated;
        foreach (height; begin_height .. end_height)
            static if (block_reward_type == "ReducedValidatorReward")
                block_rewards_calculated ~= mixin("block_reward.get" ~ block_reward_type ~ "(height, comply_perc)");
            else
                block_rewards_calculated ~= mixin("block_reward.get" ~ block_reward_type ~ "(height)");
        printRewards(block_rewards_calculated);
        return block_rewards_calculated;
    }
}

/***************************************************************************

    Utility function to create a BlockRewardsTup

    Params:
        amount = the amount of coins we would like to distribute
        dist_period_secs = the amount of seconds during which we distribute the coins

    Returns: the newly created BlockRewardsTup

***************************************************************************/

BlockRewardsTup mbr (ulong amount, uint dist_period_secs = 60*60*24*365) @safe pure nothrow
{
    auto block_rewards_tup = BlockRewardsTup(Amount(amount), dist_period_secs);
    return block_rewards_tup;
}

///
alias BlockRewardsTup = Tuple!(Amount, "amount", uint, "dist_period_secs");
