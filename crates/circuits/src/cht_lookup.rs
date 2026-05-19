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

    let dummy_index = upcast_x_to_block(dummy_index);
    let delta = state.rngs.generate_random_garbler_delta(state.id);
    let [x01, x2] = input_cht_lookup_2shares(lookup_values, dummy_index, delta, net, state)?;

    let yao_output = match state.id {
        PartyID::ID0 => {
            let mut evaluator = Rep3Evaluator::new(net);
            evaluator.receive_circuit()?;
            lookup_yao_bundle(&mut evaluator, &x01, &x2)
                .map_err(|err| eyre::eyre!("CHT Yao lookup failed: {err}"))?
        }
        PartyID::ID1 | PartyID::ID2 => {
            let delta = delta.ok_or_else(|| eyre::eyre!("missing garbler delta"))?;
            let mut garbler = Rep3Garbler::new_with_delta(net, state, delta);
            let output = lookup_yao_bundle(&mut garbler, &x01, &x2)
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
            lookup_yao_bundle_from_inputs(&mut evaluator, &yao_inputs)
                .map_err(|err| eyre::eyre!("CHT Yao lookup failed: {err}"))?
        }
        PartyID::ID1 | PartyID::ID2 => {
            let delta = delta.ok_or_else(|| eyre::eyre!("missing garbler delta"))?;
            let mut garbler = Rep3Garbler::new_with_delta(net, state, delta);
            let output = lookup_yao_bundle_from_inputs(&mut garbler, &yao_inputs)
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

fn lookup_yao_bundle<G>(
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
    lookup_yao_bundle_from_inputs(g, &BinaryBundle::new(inputs))
}

fn lookup_yao_bundle_from_inputs<G>(
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

    let key_equals_b0 = tags_equal(g, key, cht_b0)?;
    let key_equals_b1 = tags_equal(g, key, cht_b1)?;
    let out_found = g.xor(&key_equals_b0, &key_equals_b1)?;

    let mut output = Vec::with_capacity(64);
    for i in 0..32 {
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

fn tags_equal<G>(g: &mut G, lhs: &[G::Item], rhs: &[G::Item]) -> Result<G::Item, G::Error>
where
    G: FancyBinary + FancyBinaryConstant,
{
    let mut equal_bits = Vec::with_capacity(96);
    for i in 32..128 {
        let diff = g.xor(&lhs[i], &rhs[i])?;
        equal_bits.push(g.negate(&diff)?);
    }
    g.and_many(&equal_bits)
}

fn input_cht_lookup_2shares<N: Network>(
    lookup_values: [RingElement<Block>; 3],
    dummy_index: BlockShare,
    delta: Option<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<[BinaryBundle<WireMod2>; 2]> {
    const NUM_INPUTS: usize = 4;
    const NUM_BITS: usize = NUM_INPUTS * 128;

    match state.id {
        PartyID::ID0 => {
            let (x01, x2) = mpc_net::join(
                || receive_bundle_from(NUM_BITS, net, PartyID::ID1),
                || receive_bundle_from(NUM_BITS, net, PartyID::ID2),
            );
            Ok([x01?, x2?])
        }
        PartyID::ID1 => {
            let delta = delta.ok_or_else(|| eyre::eyre!("missing garbler delta"))?;
            let mut x01_values = [RingElement(0); NUM_INPUTS];
            x01_values[..3].copy_from_slice(&lookup_values);
            x01_values[3] = dummy_index.a ^ dummy_index.b;

            let x01 = encode_ring_inputs(&x01_values, delta, state);
            send_inputs(&x01, net, PartyID::ID2)?;
            let x2 = receive_bundle_from(NUM_BITS, net, PartyID::ID2)?;
            Ok([x01.garbler_wires, x2])
        }
        PartyID::ID2 => {
            let delta = delta.ok_or_else(|| eyre::eyre!("missing garbler delta"))?;
            let mut x2_values = [RingElement(0); NUM_INPUTS];
            x2_values[..3].copy_from_slice(&lookup_values);
            x2_values[3] = dummy_index.a;

            let x2 = encode_ring_inputs(&x2_values, delta, state);
            send_inputs(&x2, net, PartyID::ID1)?;
            let x01 = receive_bundle_from(NUM_BITS, net, PartyID::ID1)?;
            Ok([x01, x2.garbler_wires])
        }
    }
}

struct GarbledInputs {
    garbler_wires: BinaryBundle<WireMod2>,
    evaluator_wires: BinaryBundle<WireMod2>,
}

fn encode_ring_inputs<T: IntRing2k>(
    values: &[RingElement<T>],
    delta: WireMod2,
    state: &mut Rep3State,
) -> GarbledInputs {
    let mut garbler_wires = Vec::with_capacity(values.len() * T::K);
    let mut evaluator_wires = Vec::with_capacity(values.len() * T::K);

    for value in values {
        let mut value = *value;
        for _ in 0..T::K {
            let bit = u16::from((value & RingElement(T::from(true))) == RingElement(T::from(true)));
            let zero = WireMod2::rand(&mut state.rng, 2);
            let encoded = zero.plus(&delta.cmul(bit));
            garbler_wires.push(zero);
            evaluator_wires.push(encoded);
            value >>= 1;
        }
    }

    GarbledInputs {
        garbler_wires: BinaryBundle::new(garbler_wires),
        evaluator_wires: BinaryBundle::new(evaluator_wires),
    }
}

fn send_inputs<N: Network>(
    inputs: &GarbledInputs,
    net: &N,
    other_garbler: PartyID,
) -> eyre::Result<()> {
    let (send_garbler, send_evaluator) = mpc_net::join(
        || send_bundle_to(&inputs.garbler_wires, net, other_garbler),
        || send_bundle_to(&inputs.evaluator_wires, net, PartyID::ID0),
    );
    send_garbler?;
    send_evaluator?;
    Ok(())
}

fn send_bundle_to<N: Network>(
    bundle: &BinaryBundle<WireMod2>,
    net: &N,
    to: PartyID,
) -> eyre::Result<()> {
    let blocks = bundle
        .wires()
        .iter()
        .map(|wire| {
            let block = wire.as_block();
            let mut bytes = [0; 16];
            bytes.copy_from_slice(block.as_ref());
            bytes
        })
        .collect::<Vec<_>>();
    net.send_many(to, &blocks)
}

fn receive_bundle_from<N: Network>(
    n_bits: usize,
    net: &N,
    from: PartyID,
) -> eyre::Result<BinaryBundle<WireMod2>> {
    let blocks: Vec<[u8; 16]> = net.recv_many(from)?;
    eyre::ensure!(blocks.len() == n_bits, "invalid Yao input bundle length");

    let wires = blocks
        .into_iter()
        .map(|bytes| {
            let mut block = WireMod2::zero(2).as_block();
            block.as_mut().copy_from_slice(&bytes);
            WireMod2::from_block(block, 2)
        })
        .collect();
    Ok(BinaryBundle::new(wires))
}
