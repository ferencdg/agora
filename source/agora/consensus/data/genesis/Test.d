/*******************************************************************************

    Defines a genesis block suitable for testing purpose

    This genesis block is used in multiple places:
    - Most unittests;
    - Most network unittests (TODO);
    - The system unit tests;
    - The system integration tests;

    The keys in this module are well-known, and hence not suitable for anything
    that isn't a test.

    Copyright:
        Copyright (c) 2019-2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.data.genesis.Test;

import agora.common.Amount;
import agora.common.BitField;
import agora.common.Hash;
import agora.common.Types;
import agora.common.crypto.Key;
import agora.consensus.data.Block;
import agora.consensus.data.Enrollment;
import agora.consensus.data.Transaction;
import agora.utils.Test;

/*******************************************************************************

    The genesis block as used by most tests

    Note that this is more of a 'test' block than a 'unittest' block,
    and it's currently used in a few integration test, hence why it is not
    `version (unittest)`.
    It can also be used for system integration testing.

    It contains a total of 500M initial coins, of which 12M have been frozen
    among 6 nodes, and the rest is evenly split between 8 outputs (61M each).

*******************************************************************************/

public immutable Block GenesisBlock = {
    header: {
        prev_block:  Hash.init,
        height:      Height(0),
        merkle_root: GenesisMerkleTree[$ - 1],
        timestamp:   1596153600, // 2020.07.31 12:00:00AM
        validators:  BitField!ubyte(6),
        signature:   Signature.init,

        enrollments: [
            // Node 4
            Enrollment(
                Hash("0x278c37cf9f4afd5f1b845b09835acd8e6aa4d5c4035b3f2425b8231da0fa648" ~
                     "04c1199720a565ed70b3a70a31539e115f8aa1ab90072c58dd6250d794b116058"),
                Hash("0x69d5c9613d40f32400221c0628cbcd068fe41346a98b321ab88c27dc0dd98ca" ~
                     "5b87b5ccc794a4759694bf5c7dd7f437448bd16dfeaef806b5c66bfcc04174b6c"),
                20,
                Signature("0x074b0f191738e4d61f1a60b8ae0b3d46767ac63c84c43d83d0fd9e450ee68c8" ~
                          "3896eaac5ccfc4d23084255ba247dc9bc7042222d7269b8cc5ba7977d0139b8eb")
            ),

            // Node 7
            Enrollment(
                Hash("0x2e9a2fcb0a8d310ac82fea1f077166ba19a805b599c05b4857bacc0c3f7244d" ~
                     "ff6abc25e0730da89e98483b96a4752563c530990b2b49a242ac50eabbc1bb500"),
                Hash("0xf552010ddc44e29344fbebf24792667f64544ae88bc187cfa329dd9f5bf2059" ~
                     "425b19308986cb592ffa239b7fd2775ccf3fa878657cfd9af116aa6c5be5a8554"),
                20,
                Signature("0x015e101b711a57ac96d7f951015ffbde0a38d5ffe83d5d0a50c664d06a9d48e" ~
                          "a4751a330a071eec15e0d38598e8be72ca318fdc59e3dd853edab7fdd8f93772d")
            ),

            // Node 6
            Enrollment(
                Hash("0x30be553dc34ece937dbb3317c450303114376bc0862a0fcf30c505ac554a5d5" ~
                     "e3ec1c3b0d820649b7404ef3c8f6c431e40e9fe2a0d6809f4eb9dcc9965909488"),
                Hash("0xad4a28584e901f18a884c0246e2b4a587379271ab76494290c00e9ac2876bc4" ~
                     "9131c9df1d3dd3ee92233b6bf6efd87bc9133be31f744b0d6c73b194caa6e9dcc"),
                     20,
                Signature("0x0e1a3adbd27d1b23379c79a2061f6321e98f8d9fd4d583cc58b84da1c805f9c" ~
                          "23e8551532a265986de8428146dd91eeaf8548dcb92c490eb152b3150a41e54db")
            ),

            // Node 5
            Enrollment(
                Hash("0x30cd5e782fd045f0be0905102c5ec0b156fb716fd6b735cb0fe9e41203422f2" ~
                     "ca188f2b1c5c58c8565695d5fd49ecaa739b8e8db0954691c2199143e35cec65b"),
                Hash("0xc45f17c18d787c20b3263ba2cfa7e3a3b73c610541e386118c3fcc4bbbefb12" ~
                     "11efad324270acc0aeccba0516e14a8384c579e22c5631527ddc4b358a97a5d44"),
                20,
                Signature("0x09951f733df03e959c11da8e5dfb4c52c294ad4c2224a5aba7753402367a693" ~
                          "6cf02590e81848509bbdbd3b223165203cb17acf26aaa872cd8eb73edd10c9d8e")
            ),

            // Node 2
            Enrollment(
                Hash("0x38c4a35f0d09b33b9a91da7d01aa31cb4d3d5d233ea08eaf418f3b7d7bd97c3" ~
                     "ded082ccb545a8e2fbecace2044ebe04d96a44e2c16ea2b6f0cfc4b417adecf15"),
                Hash("0x645caa4a68fc4044698633be0ec7a84282c0600fce2c1e102c9fa66a1edc1e4" ~
                     "55d305acaa68e5d9f8f41fa90a3b28e5132bb306d135a5f63c029a45d24652908"),
                20,
                Signature("0x0437db24d14277eb5baf7b611f54141ef08f075144125d2d75901bec807062e" ~
                          "4102a345b9de5783b83ab5051c7d2d3831834ca6224bd2c8daab3c7b97a6468eb")
            ),

            // Node 3
            Enrollment(
                Hash("0x91c17a3fe680c4f4fd471f40a061482ea76123945c6cd7727a33f303c0d5965" ~
                     "05f8451e0ef9a197ced730f6f49730089484e85420d272507064e4edfb82f9265"),
                Hash("0xf909c7fc9a39ff228662aeeaf6006ec31b7287da530ce7bee51b9177d0711da" ~
                     "2adda703d648e53f249eae2b363ffcd0785b4ae6a08afab74253b0a75776a9f58"),
                20,
                Signature("0x082919c0beeb0e877c0ca5b094f8b546cb299fb07f88d46b6a21c7a9599074c" ~
                          "bef7df5d9d80690a0f01a98056e9c910e0962d82937c49f6f0712dd44da55b35e")
            )
        ],
    },
    merkle_tree: GenesisMerkleTree,
    txs: [
        {
            TxType.Payment,
            outputs: [
                Output(Amount(61_000_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(61_000_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(61_000_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(61_000_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(61_000_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(61_000_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(61_000_000L * 10_000_000L), GenesisOutputAddress),
                Output(Amount(61_000_000L * 10_000_000L), GenesisOutputAddress),
            ],
        },
        {
            TxType.Freeze,
            outputs: [
                Output(Amount(2_000_000L * 10_000_000L), WK.Keys.NODE2.address),
                Output(Amount(2_000_000L * 10_000_000L), WK.Keys.NODE3.address),
                Output(Amount(2_000_000L * 10_000_000L), WK.Keys.NODE4.address),
                Output(Amount(2_000_000L * 10_000_000L), WK.Keys.NODE5.address),
                Output(Amount(2_000_000L * 10_000_000L), WK.Keys.NODE6.address),
                Output(Amount(2_000_000L * 10_000_000L), WK.Keys.NODE7.address),
            ],
        }
    ],
};

///
unittest
{
    import std.algorithm;
    import agora.consensus.PreImage;
    import agora.common.crypto.ECC;
    import agora.common.crypto.Schnorr;
    import agora.consensus.data.UTXO;

    version (none)
    {
        import std.stdio;
        import std.range;
        import agora.consensus.EnrollmentManager;

        const txs = GenesisBlock.txs;

        if (!txs.isStrictlyMonotonic())
        {
            writeln("WARN: Genesis block transactions are unsorted!");
            txs.enumerate.each!((idx, tx) => writefln("[%d]: %s", idx, tx));
        }

        Hash[] merkle_tree;
        writeln("Merkle root: ", Block.buildMerkleTree(txs, merkle_tree));
        writeln("\tMerkle tree: ", merkle_tree);

        const ValidatorCycle = 20;
        const txhash = txs[0].hashFull();
        Enrollment[] enrolls = txs[0].outputs.enumerate()
            .map!(tup => EnrollmentManager.makeEnrollment(
                      WK.Keys[tup.value.address],
                      UTXO.getHash(txhash, tup.index),
                      ValidatorCycle))
            .array();

        enrolls.sort!((a, b) => a.utxo_key < b.utxo_key);
        writeln("Enrollments: ", enrolls);
    }

    Amount amount;
    assert(GenesisBlock.txs.all!(tx => tx.getSumOutput(amount)));
    assert(amount == Amount.MaxUnitSupply, amount.toString());
    assert(GenesisBlock.merkle_tree.length == GenesisMerkleTree.length);
    assert(GenesisBlock.header.merkle_root == GenesisBlock.merkle_tree[$-1]);
}

private immutable Hash[] GenesisMerkleTree = [
    Hash(`0x754cb2ed6f0848c8f2c3aa7fee0a63754415506776bafc154874ab28779fc3135` ~
         `572db478837d8a13574eebd6dda12cd875fcd05dc9c9c1525dac8ead17fdebd`),
    Hash(`0xadf2ccdb7427e0a8a17ec1266bcba831a7096eff1a6cad8350f76e15c6935604c` ~
         `0e7c07bb6fe07d0918f9ec4f5b32f0450e8db9709b35addd566f2b92f8c162d`),
    Hash(`0x67da862ed1429f771115347725dd3de706525796bd9cf2b7e2096c759b2e0` ~
         `604a275b8b534efdb16c147905005db656f4ab245364caf36c1180d648a97ad6949`),
];

/// GCOQEOHAUFYUAC6G22FJ3GZRNLGVCCLESEJ2AXBIJ5BJNUVTAERPLRIJ
private immutable PublicKey GenesisOutputAddress = GenesisAddressUbyte;

///
private immutable ubyte[] GenesisAddressUbyte =
    [
        0x9D, 0x02, 0x38, 0xE0, 0xA1, 0x71, 0x40, 0x0B,
        0xC6, 0xD6, 0x8A, 0x9D, 0x9B, 0x31, 0x6A, 0xCD,
        0x51, 0x09, 0x64, 0x91, 0x13, 0xA0, 0x5C, 0x28,
        0x4F, 0x42, 0x96, 0xD2, 0xB3, 0x01, 0x22, 0xF5,
    ];

unittest
{
    assert(GenesisOutputAddress.toString()
           == `GCOQEOHAUFYUAC6G22FJ3GZRNLGVCCLESEJ2AXBIJ5BJNUVTAERPLRIJ`);
}

/// GCOMMONBGUXXP4RFCYGEF74JDJVPUW2GUENGTKKJECDNO6AGO32CUWGU
public immutable PublicKey CommonsBudgetAddress = CommonsBudgetUbyte;

///
private immutable ubyte[] CommonsBudgetUbyte =
    [
        0x9c, 0xc6, 0x39, 0xa1, 0x35, 0x2f, 0x77, 0xf2,
        0x25, 0x16, 0x0c, 0x42, 0xff, 0x89, 0x1a, 0x6a,
        0xfa, 0x5b, 0x46, 0xa1, 0x1a, 0x69, 0xa9, 0x49,
        0x20, 0x86, 0xd7, 0x78, 0x06, 0x76, 0xf4, 0x2a,
    ];

unittest
{
    assert(CommonsBudgetAddress.toString()
           == `GCOMMONBGUXXP4RFCYGEF74JDJVPUW2GUENGTKKJECDNO6AGO32CUWGU`);
}

unittest
{
    import agora.common.Serializer;
    testSymmetry(GenesisBlock.txs[0]);
    testSymmetry(GenesisBlock);
}
