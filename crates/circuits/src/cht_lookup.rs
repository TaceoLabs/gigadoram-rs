//! CHT lookup circuit:
//! Compares the key tag against two candidate tags, output the matching
//! 32-bit index or the dummy index, and output found = match0 XOR match1.

use fancy_garbling::{BinaryBundle, FancyBinary, WireLabel, WireMod2};
use mpc_core::protocols::{
    rep3::{
        Rep3State,
        id::PartyID,
        network::Rep3NetworkExt,
        yao::{evaluator::Rep3Evaluator, garbler::Rep3Garbler},
    },
    rep3_ring::{casts::downcast, conversion::y2b, ring::ring_impl::RingElement},
};
use mpc_net::Network;
use primitives::{BlockShare, XShare, types::BitShare};
use scuttlebutt::Block;

const KEY_TAG_BITS: usize = 96;
const INDEX_BITS: usize = 32;
const INDEX_MASK: u128 = u32::MAX as u128;
const LOOKUP_INPUT_BITS: usize = 3 * (KEY_TAG_BITS + INDEX_BITS);

// Circuit inputs are 3 BlockShares and a XShare, structured as follows:
// key = key tag (96) | key unused bits
// cht_b0 = b0 tag (96) | b0 index (32)
// cht_b1 = b1 tag (96) | b1 index (32)
// dummy_index (32)
pub fn compute(
    key: BlockShare,
    cht_b0: BlockShare,
    cht_b1: BlockShare,
    dummy_index: XShare,
    net: &impl Network,
    state: &mut Rep3State,
) -> eyre::Result<(XShare, BitShare)> {
    let inputs = pack_lookup_inputs(key, cht_b0, cht_b1, dummy_index);
    let output = match state.id {
        PartyID::ID0 => eval(net, state)?,
        PartyID::ID1 | PartyID::ID2 => garble(inputs, net, state)?,
    };
    Ok((downcast(output), output.get_bit(INDEX_BITS)))
}

fn eval<N: Network>(net: &N, state: &mut Rep3State) -> eyre::Result<BlockShare> {
    let [x01, x2] = receive_input_bundles(net)?;
    let mut evaluator = Rep3Evaluator::new(net);
    evaluator.receive_circuit()?;
    let output = evaluate_lookup_circuit(&mut evaluator, &x01, &x2)
        .map_err(|err| eyre::eyre!("CHT lookup garbled evaluation failed: {err:?}"))?;
    y2b(output, net, state)
}

fn garble<N: Network>(
    inputs: [BlockShare; 3],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BlockShare> {
    let delta = state
        .rngs
        .generate_random_garbler_delta(state.id)
        .expect("delta should be present");
    let mut garbler = Rep3Garbler::new_with_delta(net, state, delta);
    let [x01, x2] = garble_lookup_inputs(&inputs, net, state.id, &mut garbler)?;
    let output = evaluate_lookup_circuit(&mut garbler, &x01, &x2)
        .map_err(|err| eyre::eyre!("CHT lookup garbling failed: {err:?}"))?;
    garbler.send_circuit()?;
    y2b(output, net, state)
}

fn garble_lookup_inputs<N: Network>(
    inputs: &[BlockShare; 3],
    net: &N,
    id: PartyID,
    garbler: &mut Rep3Garbler<N>,
) -> eyre::Result<[BinaryBundle<WireMod2>; 2]> {
    let mut x01 = Vec::with_capacity(LOOKUP_INPUT_BITS);
    let mut x2 = Vec::with_capacity(LOOKUP_INPUT_BITS);
    let mut evaluator_inputs = Vec::with_capacity(LOOKUP_INPUT_BITS);

    for party in [PartyID::ID1, PartyID::ID2] {
        let garbler_wires = if party == PartyID::ID1 {
            &mut x01
        } else {
            &mut x2
        };
        for input in inputs {
            let owns_input = id == party;
            let value = match party {
                PartyID::ID1 if owns_input => input.a.0 ^ input.b.0,
                PartyID::ID2 if owns_input => input.a.0,
                _ => 0,
            };
            encode_input(
                value,
                owns_input,
                garbler,
                garbler_wires,
                &mut evaluator_inputs,
            );
        }
    }

    net.send_many(PartyID::ID0, &evaluator_inputs)?;
    Ok([BinaryBundle::new(x01), BinaryBundle::new(x2)])
}

fn encode_input<N: Network>(
    value: u128,
    send_to_evaluator: bool,
    garbler: &mut Rep3Garbler<N>,
    garbler_wires: &mut Vec<WireMod2>,
    evaluator_inputs: &mut Vec<[u8; 16]>,
) {
    for bit in 0..128 {
        let (zero, evaluator) = garbler.encode_wire(((value >> bit) & 1) as u16);
        garbler_wires.push(zero);
        if send_to_evaluator {
            evaluator_inputs.push(wire_to_bytes(&evaluator));
        }
    }
}

fn evaluate_lookup_circuit<G: FancyBinary>(
    g: &mut G,
    x01: &BinaryBundle<G::Item>,
    x2: &BinaryBundle<G::Item>,
) -> Result<BinaryBundle<G::Item>, G::Error> {
    let inputs = x01
        .wires()
        .iter()
        .zip(x2.wires())
        .map(|(lhs, rhs)| g.xor(lhs, rhs))
        .collect::<Result<Vec<_>, _>>()?;

    let (key_tag, b0_index) = inputs[..128].split_at(KEY_TAG_BITS);
    let (b0_tag, b1_index) = inputs[128..256].split_at(KEY_TAG_BITS);
    let (b1_tag, dummy_index) = inputs[256..].split_at(KEY_TAG_BITS);

    // Equality checks decide whether key matches b0 or b1.
    let key_equals_b0 = tags_equal(g, key_tag, b0_tag)?;
    let key_equals_b1 = tags_equal(g, key_tag, b1_tag)?;

    // Select b0_index, b1_index, or dummy_index.
    let b1_or_dummy = mux_many(g, &key_equals_b1, b1_index, dummy_index)?;
    let selected_index = mux_many(g, &key_equals_b0, b0_index, &b1_or_dummy)?;

    // Append found = key_equals_b0 XOR key_equals_b1.
    let mut output = selected_index;
    output.reserve(1);
    output.push(g.xor(&key_equals_b0, &key_equals_b1)?);
    Ok(BinaryBundle::new(output))
}

fn tags_equal<G: FancyBinary>(
    g: &mut G,
    lhs: &[G::Item],
    rhs: &[G::Item],
) -> Result<G::Item, G::Error> {
    let equal_bits = lhs
        .iter()
        .zip(rhs)
        .map(|(lhs, rhs)| {
            let xor = g.xor(lhs, rhs)?;
            g.negate(&xor)
        })
        .collect::<Result<Vec<_>, _>>()?;
    g.and_many(&equal_bits)
}

fn mux_many<G: FancyBinary>(
    g: &mut G,
    condition: &G::Item,
    truthy: &[G::Item],
    falsey: &[G::Item],
) -> Result<Vec<G::Item>, G::Error> {
    truthy
        .iter()
        .zip(falsey)
        .map(|(truthy, falsey)| g.mux(condition, falsey, truthy))
        .collect()
}

fn pack_lookup_inputs(
    key: BlockShare,
    cht_b0: BlockShare,
    cht_b1: BlockShare,
    dummy_index: XShare,
) -> [BlockShare; 3] {
    [
        // key_tag | b0_index
        pack_tag_and_index(key, cht_b0.a, cht_b0.b),
        // b0_tag | b1_index
        pack_tag_and_index(cht_b0, cht_b1.a, cht_b1.b),
        // b1_tag | dummy_index
        pack_tag_and_index(
            cht_b1,
            RingElement(u128::from(dummy_index.a.0)),
            RingElement(u128::from(dummy_index.b.0)),
        ),
    ]
}

fn pack_tag_and_index(
    tag: BlockShare,
    index_a: RingElement<u128>,
    index_b: RingElement<u128>,
) -> BlockShare {
    BlockShare::new_ring(
        RingElement((tag.a.0 >> INDEX_BITS) | ((index_a.0 & INDEX_MASK) << KEY_TAG_BITS)),
        RingElement((tag.b.0 >> INDEX_BITS) | ((index_b.0 & INDEX_MASK) << KEY_TAG_BITS)),
    )
}

fn receive_input_bundles<N: Network>(net: &N) -> eyre::Result<[BinaryBundle<WireMod2>; 2]> {
    Ok([
        receive_input_bundle(net, PartyID::ID1)?,
        receive_input_bundle(net, PartyID::ID2)?,
    ])
}

fn receive_input_bundle<N: Network>(
    net: &N,
    from: PartyID,
) -> eyre::Result<BinaryBundle<WireMod2>> {
    let labels: Vec<[u8; 16]> = net.recv_many(from)?;
    if labels.len() != LOOKUP_INPUT_BITS {
        eyre::bail!("invalid CHT lookup input label count");
    }
    Ok(BinaryBundle::new(
        labels.into_iter().map(bytes_to_wire).collect(),
    ))
}

fn wire_to_bytes(wire: &WireMod2) -> [u8; 16] {
    wire.as_block().as_ref().try_into().unwrap()
}

fn bytes_to_wire(bytes: [u8; 16]) -> WireMod2 {
    WireMod2::from_block(Block::from(bytes), 2)
}
