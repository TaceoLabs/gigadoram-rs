use fancy_garbling::{BinaryBundle, FancyBinary, WireLabel, WireMod2};
use mpc_core::protocols::{
    rep3::{
        Rep3State,
        id::PartyID,
        network::Rep3NetworkExt,
        yao::{circuits::FancyBinaryConstant, evaluator::Rep3Evaluator, garbler::Rep3Garbler},
    },
    rep3_ring::{
        binary::{and_vec, and_with_public, shift_r_public},
        casts::downcast,
        conversion,
        ring::{int_ring::IntRing2k, ring_impl::RingElement},
    },
};
use mpc_net::Network;
use primitives::{
    Block, BlockShare, XShare, bit_to_binary_mask, is_zero_many, types::BitShare, upcast_x_to_block,
};

const INDEX_BITS: usize = 32;
const TAG_BITS: usize = 96;
const COMPACT_INPUT_BITS: usize =
    TAG_BITS + INDEX_BITS + TAG_BITS + INDEX_BITS + TAG_BITS + INDEX_BITS;

pub fn lookup_circuit(
    key: BlockShare,
    cht_b0: BlockShare,
    cht_b1: BlockShare,
    dummy_index: XShare,
    net: &impl Network,
    state: &mut Rep3State,
) -> eyre::Result<(XShare, BitShare)> {
    lookup_circuit_yao(key, cht_b0, cht_b1, dummy_index, net, state)
}

pub fn lookup_circuit_rep3(
    key: BlockShare,
    cht_b0: BlockShare,
    cht_b1: BlockShare,
    dummy_index: XShare,
    net: &impl Network,
    state: &mut Rep3State,
) -> eyre::Result<(XShare, BitShare)> {
    let shift = RingElement::from(32);
    let mask = RingElement::from(0xFFFFFFFF);

    let key_tag = shift_r_public(&key, shift);
    let cht_b0_index = and_with_public(&cht_b0, &mask);
    let cht_b0_tag = shift_r_public(&cht_b0, shift);
    let cht_b1_index = and_with_public(&cht_b1, &mask);
    let cht_b1_tag = shift_r_public(&cht_b1, shift);

    let equalities = is_zero_many(&[key_tag ^ cht_b0_tag, key_tag ^ cht_b1_tag], net, state)?;
    let [key_equals_b0, key_equals_b1] = equalities.try_into().unwrap();
    let out_found = key_equals_b0 ^ key_equals_b1;

    let selection_masks = [
        bit_to_binary_mask(&key_equals_b0),
        bit_to_binary_mask(&key_equals_b1),
    ];
    let dummy_index = upcast_x_to_block(dummy_index);
    let index_deltas = [cht_b0_index ^ dummy_index, cht_b1_index ^ dummy_index];

    let selected_deltas = and_vec(&selection_masks, &index_deltas, net, state)?;
    let out_index = dummy_index ^ selected_deltas[0] ^ selected_deltas[1];
    let out_index = downcast(out_index);

    Ok((out_index, out_found))
}

pub fn lookup_circuit_from_2shares<N: Network>(
    lookup_values: [RingElement<Block>; 3],
    dummy_index: XShare,
    builder: PartyID,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(XShare, BitShare)> {
    eyre::ensure!(
        builder == PartyID::ID0,
        "CHT Yao lookup currently expects the builder/evaluator to be ID0"
    );

    let delta = state.rngs.generate_random_garbler_delta(state.id);
    let [x01, x2] = input_cht_lookup_2shares(lookup_values, dummy_index, delta, net, state)?;

    let yao_output = match state.id {
        PartyID::ID0 => {
            let mut evaluator = Rep3Evaluator::new(net);
            evaluator.receive_circuit()?;
            lookup_yao_bundle_compact(&mut evaluator, &x01, &x2)
                .map_err(|err| eyre::eyre!("CHT Yao lookup failed: {err}"))?
        }
        PartyID::ID1 | PartyID::ID2 => {
            let delta = delta.ok_or_else(|| eyre::eyre!("missing garbler delta"))?;
            let mut garbler = Rep3Garbler::new_with_delta(net, state, delta);
            let output = lookup_yao_bundle_compact(&mut garbler, &x01, &x2)
                .map_err(|err| eyre::eyre!("CHT Yao lookup failed: {err}"))?;
            garbler.send_circuit()?;
            output
        }
    };

    let [packed] = conversion::y2b_many::<u64, _>(yao_output, net, state)?
        .try_into()
        .map_err(|_| eyre::eyre!("CHT Yao lookup returned invalid output length"))?;
    let out_found = packed.get_bit(32);
    let out_index = downcast(packed);

    Ok((out_index, out_found))
}

fn lookup_circuit_yao<N: Network>(
    key: BlockShare,
    cht_b0: BlockShare,
    cht_b1: BlockShare,
    dummy_index: XShare,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(XShare, BitShare)> {
    let dummy_index = upcast_x_to_block(dummy_index);
    let inputs = [key, cht_b0, cht_b1, dummy_index];
    let delta = state.rngs.generate_random_garbler_delta(state.id);
    let yao_inputs = conversion::b2y_many(&inputs, delta, net, state)?;

    let yao_output = match state.id {
        PartyID::ID0 => {
            let mut evaluator = Rep3Evaluator::new(net);
            evaluator.receive_circuit()?;
            lookup_yao_bundle_from_full_inputs(&mut evaluator, &yao_inputs)
                .map_err(|err| eyre::eyre!("CHT Yao lookup failed: {err}"))?
        }
        PartyID::ID1 | PartyID::ID2 => {
            let delta = delta.ok_or_else(|| eyre::eyre!("missing garbler delta"))?;
            let mut garbler = Rep3Garbler::new_with_delta(net, state, delta);
            let output = lookup_yao_bundle_from_full_inputs(&mut garbler, &yao_inputs)
                .map_err(|err| eyre::eyre!("CHT Yao lookup failed: {err}"))?;
            garbler.send_circuit()?;
            output
        }
    };

    let [packed] = conversion::y2b_many::<u64, _>(yao_output, net, state)?
        .try_into()
        .map_err(|_| eyre::eyre!("CHT Yao lookup returned invalid output length"))?;
    let out_found = packed.get_bit(32);
    let out_index = downcast(packed);

    Ok((out_index, out_found))
}

fn lookup_yao_bundle_compact<G>(
    g: &mut G,
    x01: &BinaryBundle<G::Item>,
    x2: &BinaryBundle<G::Item>,
) -> Result<BinaryBundle<G::Item>, G::Error>
where
    G: FancyBinary + FancyBinaryConstant,
{
    let inputs = x01
        .wires()
        .iter()
        .zip(x2.wires())
        .map(|(lhs, rhs)| g.xor(lhs, rhs))
        .collect::<Result<Vec<_>, _>>()?;
    lookup_yao_bundle_from_compact_inputs(g, &BinaryBundle::new(inputs))
}

fn lookup_yao_bundle_from_full_inputs<G>(
    g: &mut G,
    inputs: &BinaryBundle<G::Item>,
) -> Result<BinaryBundle<G::Item>, G::Error>
where
    G: FancyBinary + FancyBinaryConstant,
{
    let wires = inputs.wires();
    debug_assert_eq!(wires.len(), 4 * 128);

    let key = &wires[0..128];
    let cht_b0 = &wires[128..256];
    let cht_b1 = &wires[256..384];
    let dummy_index = &wires[384..512];

    let key_equals_b0 = tags_equal(g, &key[INDEX_BITS..], &cht_b0[INDEX_BITS..])?;
    let key_equals_b1 = tags_equal(g, &key[INDEX_BITS..], &cht_b1[INDEX_BITS..])?;
    let out_found = g.xor(&key_equals_b0, &key_equals_b1)?;

    let mut output = Vec::with_capacity(64);
    for i in 0..INDEX_BITS {
        let b0_delta = g.xor(&cht_b0[i], &dummy_index[i])?;
        let b1_delta = g.xor(&cht_b1[i], &dummy_index[i])?;
        let selected_b0_delta = g.and(&key_equals_b0, &b0_delta)?;
        let selected_b1_delta = g.and(&key_equals_b1, &b1_delta)?;
        let selected = g.xor(&dummy_index[i], &selected_b0_delta)?;
        output.push(g.xor(&selected, &selected_b1_delta)?);
    }

    output.push(out_found);
    output.resize(64, g.const_zero()?);
    Ok(BinaryBundle::new(output))
}

fn lookup_yao_bundle_from_compact_inputs<G>(
    g: &mut G,
    inputs: &BinaryBundle<G::Item>,
) -> Result<BinaryBundle<G::Item>, G::Error>
where
    G: FancyBinary + FancyBinaryConstant,
{
    let wires = inputs.wires();
    debug_assert_eq!(wires.len(), COMPACT_INPUT_BITS);

    let key_tag = &wires[0..TAG_BITS];
    let b0_index = &wires[TAG_BITS..TAG_BITS + INDEX_BITS];
    let b0_tag = &wires[TAG_BITS + INDEX_BITS..2 * TAG_BITS + INDEX_BITS];
    let b1_index = &wires[2 * TAG_BITS + INDEX_BITS..2 * TAG_BITS + 2 * INDEX_BITS];
    let b1_tag = &wires[2 * TAG_BITS + 2 * INDEX_BITS..3 * TAG_BITS + 2 * INDEX_BITS];
    let dummy_index = &wires[3 * TAG_BITS + 2 * INDEX_BITS..COMPACT_INPUT_BITS];

    let key_equals_b0 = tags_equal(g, key_tag, b0_tag)?;
    let key_equals_b1 = tags_equal(g, key_tag, b1_tag)?;
    let out_found = g.xor(&key_equals_b0, &key_equals_b1)?;

    let mut output = Vec::with_capacity(64);
    for i in 0..INDEX_BITS {
        let b0_delta = g.xor(&b0_index[i], &dummy_index[i])?;
        let b1_delta = g.xor(&b1_index[i], &dummy_index[i])?;
        let selected_b0_delta = g.and(&key_equals_b0, &b0_delta)?;
        let selected_b1_delta = g.and(&key_equals_b1, &b1_delta)?;
        let selected = g.xor(&dummy_index[i], &selected_b0_delta)?;
        output.push(g.xor(&selected, &selected_b1_delta)?);
    }

    output.push(out_found);
    output.resize(64, g.const_zero()?);
    Ok(BinaryBundle::new(output))
}

fn tags_equal<G>(g: &mut G, lhs: &[G::Item], rhs: &[G::Item]) -> Result<G::Item, G::Error>
where
    G: FancyBinary + FancyBinaryConstant,
{
    debug_assert_eq!(lhs.len(), TAG_BITS);
    debug_assert_eq!(rhs.len(), TAG_BITS);

    let mut equal_bits = Vec::with_capacity(96);
    for (lhs, rhs) in lhs.iter().zip(rhs) {
        let diff = g.xor(lhs, rhs)?;
        equal_bits.push(g.negate(&diff)?);
    }
    g.and_many(&equal_bits)
}

fn input_cht_lookup_2shares<N: Network>(
    lookup_values: [RingElement<Block>; 3],
    dummy_index: XShare,
    delta: Option<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<[BinaryBundle<WireMod2>; 2]> {
    match state.id {
        PartyID::ID0 => {
            let (x01, x2) = mpc_net::join(
                || receive_bundle_from(COMPACT_INPUT_BITS, net, PartyID::ID1),
                || receive_bundle_from(COMPACT_INPUT_BITS, net, PartyID::ID2),
            );
            Ok([x01?, x2?])
        }
        PartyID::ID1 => {
            let delta = delta.ok_or_else(|| eyre::eyre!("missing garbler delta"))?;
            let (x01, evaluator_x01) = encode_owned_cht_lookup_inputs(
                lookup_values[0],
                lookup_values[1],
                lookup_values[2],
                dummy_index.a ^ dummy_index.b,
                delta,
                state,
            );
            let x2 = sample_garbler_input_labels(COMPACT_INPUT_BITS, state);
            send_bundle_to(&evaluator_x01, net, PartyID::ID0)?;
            Ok([x01, x2])
        }
        PartyID::ID2 => {
            let delta = delta.ok_or_else(|| eyre::eyre!("missing garbler delta"))?;
            let x01 = sample_garbler_input_labels(COMPACT_INPUT_BITS, state);
            let (x2, evaluator_x2) = encode_owned_cht_lookup_inputs(
                lookup_values[0],
                lookup_values[1],
                lookup_values[2],
                dummy_index.a,
                delta,
                state,
            );
            send_bundle_to(&evaluator_x2, net, PartyID::ID0)?;
            Ok([x01, x2])
        }
    }
}

fn encode_owned_cht_lookup_inputs(
    key: RingElement<Block>,
    b0: RingElement<Block>,
    b1: RingElement<Block>,
    dummy_index: RingElement<u32>,
    delta: WireMod2,
    state: &mut Rep3State,
) -> (BinaryBundle<WireMod2>, BinaryBundle<WireMod2>) {
    let mut garbler_wires = Vec::with_capacity(COMPACT_INPUT_BITS);
    let mut evaluator_wires = Vec::with_capacity(COMPACT_INPUT_BITS);

    push_owned_encoded_bits(
        &mut garbler_wires,
        &mut evaluator_wires,
        key,
        INDEX_BITS,
        TAG_BITS,
        delta,
        state,
    );
    push_owned_encoded_bits(
        &mut garbler_wires,
        &mut evaluator_wires,
        b0,
        0,
        INDEX_BITS,
        delta,
        state,
    );
    push_owned_encoded_bits(
        &mut garbler_wires,
        &mut evaluator_wires,
        b0,
        INDEX_BITS,
        TAG_BITS,
        delta,
        state,
    );
    push_owned_encoded_bits(
        &mut garbler_wires,
        &mut evaluator_wires,
        b1,
        0,
        INDEX_BITS,
        delta,
        state,
    );
    push_owned_encoded_bits(
        &mut garbler_wires,
        &mut evaluator_wires,
        b1,
        INDEX_BITS,
        TAG_BITS,
        delta,
        state,
    );
    push_owned_encoded_bits(
        &mut garbler_wires,
        &mut evaluator_wires,
        dummy_index,
        0,
        INDEX_BITS,
        delta,
        state,
    );

    (
        BinaryBundle::new(garbler_wires),
        BinaryBundle::new(evaluator_wires),
    )
}

fn push_owned_encoded_bits<T: IntRing2k>(
    garbler_wires: &mut Vec<WireMod2>,
    evaluator_wires: &mut Vec<WireMod2>,
    value: RingElement<T>,
    offset: usize,
    len: usize,
    delta: WireMod2,
    state: &mut Rep3State,
) {
    let mut shifted = value >> offset;
    for _ in 0..len {
        let bit = u16::from((shifted & RingElement(T::from(true))) == RingElement(T::from(true)));
        let zero = next_garbler_input_label(state);
        let encoded = zero.plus(&delta.cmul(bit));
        garbler_wires.push(zero);
        evaluator_wires.push(encoded);
        shifted >>= 1;
    }
}

fn sample_garbler_input_labels(n_bits: usize, state: &mut Rep3State) -> BinaryBundle<WireMod2> {
    BinaryBundle::new(
        (0..n_bits)
            .map(|_| next_garbler_input_label(state))
            .collect(),
    )
}

fn next_garbler_input_label(state: &mut Rep3State) -> WireMod2 {
    WireMod2::from_block(state.rngs.generate_garbler_randomness(state.id), 2)
}

fn send_bundle_to<N: Network>(
    bundle: &BinaryBundle<WireMod2>,
    net: &N,
    to: PartyID,
) -> eyre::Result<()> {
    let blocks = bundle.wires().iter().map(wire_to_bytes).collect::<Vec<_>>();
    net.send_many(to, &blocks)
}

fn wire_to_bytes(wire: &WireMod2) -> [u8; 16] {
    let block = wire.as_block();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(block.as_ref());
    bytes
}

fn bytes_to_wire(bytes: [u8; 16]) -> WireMod2 {
    let mut block = WireMod2::zero(2).as_block();
    block.as_mut().copy_from_slice(&bytes);
    WireMod2::from_block(block, 2)
}

fn receive_bundle_from<N: Network>(
    n_bits: usize,
    net: &N,
    from: PartyID,
) -> eyre::Result<BinaryBundle<WireMod2>> {
    let blocks: Vec<[u8; 16]> = net.recv_many(from)?;
    eyre::ensure!(blocks.len() == n_bits, "invalid Yao input bundle length");

    let wires = blocks.into_iter().map(bytes_to_wire).collect();
    Ok(BinaryBundle::new(wires))
}
