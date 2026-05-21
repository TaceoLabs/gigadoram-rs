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
const FOUND_BITS: usize = 1;
const OUTPUT_BITS: usize = INDEX_BITS + FOUND_BITS;
const INDEX_MASK: u128 = u32::MAX as u128;
const LOOKUP_INPUT_BITS: usize = 3 * (KEY_TAG_BITS + INDEX_BITS);

pub fn lookup_circuit(
    key: BlockShare,
    cht_b0: BlockShare,
    cht_b1: BlockShare,
    dummy_index: XShare,
    net: &impl Network,
    state: &mut Rep3State,
) -> eyre::Result<(XShare, BitShare)> {
    let output = lookup_garbled_circuit(key, cht_b0, cht_b1, dummy_index, net, state)?;
    Ok((downcast(output), output.get_bit(INDEX_BITS)))
}

fn lookup_garbled_circuit<N: Network>(
    key: BlockShare,
    cht_b0: BlockShare,
    cht_b1: BlockShare,
    dummy_index: XShare,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BlockShare> {
    let delta = state.rngs.generate_random_garbler_delta(state.id);
    let packed_inputs = pack_lookup_inputs(key, cht_b0, cht_b1, dummy_index);

    match state.id {
        PartyID::ID0 => {
            let x01 = receive_input_bundle(net, PartyID::ID1)?;
            let x2 = receive_input_bundle(net, PartyID::ID2)?;
            let mut evaluator = Rep3Evaluator::new(net);
            evaluator.receive_circuit()?;
            let output = evaluate_lookup_circuit(&mut evaluator, &x01, &x2)
                .map_err(|err| eyre::eyre!("CHT lookup garbled evaluation failed: {err:?}"))?;
            y2b(output, net, state)
        }
        PartyID::ID1 | PartyID::ID2 => {
            let mut garbler =
                Rep3Garbler::new_with_delta(net, state, delta.expect("delta should be present"));
            let [x01, x2] = garble_lookup_inputs(&packed_inputs, net, state.id, &mut garbler)?;
            let output = evaluate_lookup_circuit(&mut garbler, &x01, &x2)
                .map_err(|err| eyre::eyre!("CHT lookup garbling failed: {err:?}"))?;
            garbler.send_circuit()?;
            y2b(output, net, state)
        }
    }
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

    for input in inputs {
        let owns_input = id == PartyID::ID1;
        encode_input(
            if owns_input { input.a.0 ^ input.b.0 } else { 0 },
            owns_input,
            garbler,
            &mut x01,
            &mut evaluator_inputs,
        );
    }
    for input in inputs {
        let owns_input = id == PartyID::ID2;
        encode_input(
            if owns_input { input.a.0 } else { 0 },
            owns_input,
            garbler,
            &mut x2,
            &mut evaluator_inputs,
        );
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
    let mut bytes = [0; 16];
    bytes.copy_from_slice(wire.as_block().as_ref());
    bytes
}

fn bytes_to_wire(bytes: [u8; 16]) -> WireMod2 {
    let mut block = Block::default();
    block.as_mut().copy_from_slice(&bytes);
    WireMod2::from_block(block, 2)
}

fn pack_lookup_inputs(
    key: BlockShare,
    cht_b0: BlockShare,
    cht_b1: BlockShare,
    dummy_index: XShare,
) -> [BlockShare; 3] {
    [
        pack_tag_and_index(key, cht_b0.a, cht_b0.b),
        pack_tag_and_index(cht_b0, cht_b1.a, cht_b1.b),
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

    let key_equals_b0 = tags_equal(g, key_tag, b0_tag)?;
    let key_equals_b1 = tags_equal(g, key_tag, b1_tag)?;
    let b1_or_dummy = mux_many(g, &key_equals_b1, dummy_index, b1_index)?;
    let selected_index = mux_many(g, &key_equals_b0, &b1_or_dummy, b0_index)?;
    let found = g.xor(&key_equals_b0, &key_equals_b1)?;

    let mut output = Vec::with_capacity(OUTPUT_BITS);
    output.extend(selected_index);
    output.push(found);
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
    and_all_balanced(g, &equal_bits)
}

fn and_all_balanced<G: FancyBinary>(g: &mut G, values: &[G::Item]) -> Result<G::Item, G::Error> {
    if values.len() == 1 {
        return Ok(values[0].clone());
    }

    let mid = values.len() / 2;
    let lhs = and_all_balanced(g, &values[..mid])?;
    let rhs = and_all_balanced(g, &values[mid..])?;
    g.and(&lhs, &rhs)
}

fn mux_many<G: FancyBinary>(
    g: &mut G,
    select: &G::Item,
    when_false: &[G::Item],
    when_true: &[G::Item],
) -> Result<Vec<G::Item>, G::Error> {
    when_false
        .iter()
        .zip(when_true)
        .map(|(when_false, when_true)| g.mux(select, when_false, when_true))
        .collect()
}
