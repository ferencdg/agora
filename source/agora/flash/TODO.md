todo: move watchtower stuff.. into a Watchtower class?

todo: handle pendingclosed and closed
todo: make sure that we are not catching up when we try to determine
if the funding tx of our channel has "just now" been exernalized
todo: do not accept funding transactions which have been spent. They must be
in the UTXO set.

todo: add ability to renegotiate update TXs.
but the trigger tx should be non-negotiable

todo: there needs to be an invoice-based API like in c-lightning
something like: `cli invoice <amount> <label>` which produces <UUID>
and then `cli pay <UUID>`
todo: a channel should be a struct. maybe it should have an ID like a Hash.

todo: call each node a "peer" for better terminology.

todo: for intermediary HTLC nodes we would call them "hops", or a "hop".

todo: we might not need HTLC's if we use channel factories
todo: we also might not need HTLC's if we can use multi-cosigners for the
funding transaction

todo: encryption

todo: extensibility (and therefore backwards compatibility) of the protocol
lightning uses "TLV stream"

channel IDs are temporary (ephemeral) until the funding transaction is
externalized. Then, we can easily derive a unique channel ID using the hash
of the funding transaction.

todo: base many things on https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md

benefit to list in the demo: we don't have to wait for many confirmations
before using a channel, but only 10 minutes until the first block is
externalized.
however: with channel factories we'll be able to reduce this to zero wait
time. we should at least make a note of that.

todo: use the hash of the genesis block as the chain_hash like in LN.

todo: need to guard against replay attacks.

todo: we need a state transition here:
we need to track the funding UTXO, and then when the following is true
we know the channel is read:
- we have a valid trigger tx
- we have a valid settlement tx
- the funding utxo was published to the blockchain

todo 'connect()' should be a separate API point. We need to connect to
a node before establishing channels.

todo: invoice() and pay(). should be usable both-ways
see readme in https://github.com/ElementsProject/lightning

todo: both parties could attempt to send each other invoices at the same
time. how does C-LN handle this? Maybe the sequence ID should be part of
the invoice, and only one can cooperatively be accepted.

todo: make the channel ID a const struct?

todo: limit accepting only one funding UTXO, should not accept the same one
for multiple channels.
todo: once we've signed the very first channel accept message for a UTXO,
never accept it again for opening of a new channel.

todo: create an example where we use a new update attaching to a settlement
which immediately refunds everyone. This is a cooperative closing of a channel.

todo: allocation of Outputs in subsequent updates must equal exactly the
channel sum amount, otherwise we end up creating fees for no reason.

todo: invoicing will be needed for the API to work. This is what we can present
to the clients and libraries. They just need to interact with the Flash node.
todo: must support QR codes. Such as in https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md
Amount can be optional in the invoice, in case of donations. But perhaps
a minimum donation limit could be set.
todo: add a SemVer version field, so compatibility can be easily derived between protocols.

LN uses <type,length,bytes[length] value> tuplets for all field types, this way
enabling skipping some fields for future/backwards compatibility.
We should probably add the protocol descriptor (unique ID) in each message.

todo: consider just having a single API end-point with the tuplet values.
todo: should have an init() to initialize any *new* connection to a node.
it's possible that a user updates its flash node and suddenly becomes incompatible,
therefore renegotiating the setup is important.

design decisions taken from LN (https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md):

    > By default SHA2 and Bitcoin public keys are both encoded as big endian, thus it would be unusual to use a different endian for other fields.
    => We can just use LE

    > Length is limited to 65535 bytes by the cryptographic wrapping, and messages in the protocol are never more than that length anyway.
    => This is a good hint. We should check if we can encrypt 64k via Schnorr or if we're reaching
    some kind of limit here.

todo: channel ID should be derived from the UTXO, not from just the hash of the funding tx.
so we should provide the funding tx and also the output index (?). Hence why we used the
implicit index 0 in some places, we should explicitly specify it, because the funding tx
may have more outputs than just 1.

todo: nodes should signal each other when they have discovered the funding tx in the blockchain.

todo: maybe the creation of the funding tx should be delayed until the counterparty
accepts the proposal.

todo: channel discovery in LN: Only the least-significant bit of channel_flags is currently defined: announce_channel. This indicates whether the initiator of the funding flow wishes to advertise this channel publicly to the network, as detailed within BOLT #7.
