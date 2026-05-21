use fancy_garbling::{BinaryBundle, FancyBinary};
use mpc_core::protocols::{
    rep3::{
        Rep3State,
        id::PartyID,
        yao::{evaluator::Rep3Evaluator, garbler::Rep3Garbler},
    },
    rep3_ring::{
        casts::downcast, conversion::y2b, ring::ring_impl::RingElement,
        yao::joint_input_binary_xored_many,
    },
};
use mpc_net::Network;
use primitives::{BlockShare, XShare, types::BitShare};

const KEY_TAG_BITS: usize = 96;
const INDEX_BITS: usize = 32;
const FOUND_BITS: usize = 1;
const OUTPUT_BITS: usize = INDEX_BITS + FOUND_BITS;
const INDEX_MASK: u128 = u32::MAX as u128;

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
    let [x01, x2] = joint_input_binary_xored_many(
        &pack_lookup_inputs(key, cht_b0, cht_b1, dummy_index),
        delta,
        net,
        state,
    )?;

    match state.id {
        PartyID::ID0 => {
            let mut evaluator = Rep3Evaluator::new(net);
            evaluator.receive_circuit()?;
            let output = evaluate_lookup_circuit(&mut evaluator, &x01, &x2)
                .map_err(|err| eyre::eyre!("CHT lookup garbled evaluation failed: {err:?}"))?;
            y2b(output, net, state)
        }
        PartyID::ID1 | PartyID::ID2 => {
            let mut garbler =
                Rep3Garbler::new_with_delta(net, state, delta.expect("delta should be present"));
            let output = evaluate_lookup_circuit(&mut garbler, &x01, &x2)
                .map_err(|err| eyre::eyre!("CHT lookup garbling failed: {err:?}"))?;
            garbler.send_circuit()?;
            y2b(output, net, state)
        }
    }
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
