/*******************************************************************************

    Common classes and utilities shared between the network tests.
    Classes and utilities in this module are considered higher level than
    in Base.d.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.test.Common;

import agora.common.Config;
import agora.consensus.EnrollmentManager;
import agora.consensus.data.PreImageInfo;
import agora.consensus.state.UTXODB;
import agora.test.Base;

import core.atomic;

// EnrollmentManager that might or migh not reveal preimage based on the value
// current value of an atomic shared variable
version (unittest)
package class MissingPreImageEM : EnrollmentManager
{
    private shared bool* reveal_preimage;

    ///
    public this (Parameters!(EnrollmentManager.__ctor) args,
        shared(bool)* reveal_preimage)
    {
        assert(reveal_preimage !is null);
        this.reveal_preimage = reveal_preimage;
        super(args);
    }

    ///
    public override bool getNextPreimage (out PreImageInfo preimage,
        Height height) @safe
    {
        if (!atomicLoad(*this.reveal_preimage))
            return false;

        return super.getNextPreimage(preimage, height);
    }
}

// Validator node that might or might not reveal preimage based on the value
// current value of an atomic shared variable
version (unittest)
package class NoPreImageVN : TestValidatorNode
{
    public static shared UTXOSet utxo_set;
    private shared bool* reveal_preimage;

    ///
    public this (Parameters!(TestValidatorNode.__ctor) args,
        shared(bool)* reveal_preimage)
    {
        this.reveal_preimage = reveal_preimage;
        super(args);
    }

    ///
    protected override EnrollmentManager getEnrollmentManager ()
    {
        return new MissingPreImageEM(
            ":memory:", this.config.validator.key_pair, params,
            this.reveal_preimage);
    }

    ///
    protected override UTXOSet getUtxoSet()
    {
        this.utxo_set = cast(shared UTXOSet)super.getUtxoSet();
        return cast(UTXOSet)this.utxo_set;
    }
}

version (unittest)
package class MissingPreimageAPIManager(int[] missing_preimage_validator_idxs) : TestAPIManager
{
    public static shared bool reveal_preimage = false;

    ///
    mixin ForwardCtor!();

    ///
    public override void createNewNode (Config conf, string file, int line)
    {
        if (missing_preimage_validator_idxs.canFind(this.nodes.length))
            this.addNewNode!NoPreImageVN(conf, &reveal_preimage, file, line);
        else
            super.createNewNode(conf, file, line);
    }
}
