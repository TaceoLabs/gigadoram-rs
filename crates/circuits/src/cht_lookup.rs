//! CHT lookup circuit:
//! Compares the key tag against two candidate tags, output the matching
//! 32-bit index or the dummy index, and output found = match0 XOR match1.

use fancy_garbling::{
    BinaryBundle, Fancy, FancyBinary, WireLabel, WireMod2, errors::EvaluatorError, hash_wires,
    util::tweak2,
};
use mpc_core::protocols::{
    rep3::{Rep3State, id::PartyID, network::Rep3NetworkExt, yao::garbler::Rep3Garbler},
    rep3_ring::{
        Rep3RingShare,
        casts::downcast,
        conversion::y2b,
        ring::{bit::Bit, ring_impl::RingElement},
    },
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

pub fn compute_found_with_public_index(
    key: BlockShare,
    cht_b0: BlockShare,
    cht_b1: BlockShare,
    dummy_index: XShare,
    net: &impl Network,
    state: &mut Rep3State,
) -> eyre::Result<(u32, BitShare)> {
    let inputs = pack_lookup_inputs(key, cht_b0, cht_b1, dummy_index);
    let output = match state.id {
        PartyID::ID0 => eval_raw(net)?,
        PartyID::ID1 | PartyID::ID2 => garble_raw(inputs, net, state)?,
    };
    decode_public_index_and_found(output, net, state)
}

pub fn compute_2share_found_with_public_index(
    key: u128,
    cht_b0: u128,
    cht_b1: u128,
    dummy_index: XShare,
    net: &impl Network,
    state: &mut Rep3State,
) -> eyre::Result<(u32, BitShare)> {
    let inputs = pack_lookup_input_values(key, cht_b0, cht_b1, dummy_index, state.id);
    let output = match state.id {
        PartyID::ID0 => eval_raw(net)?,
        PartyID::ID1 | PartyID::ID2 => garble_raw_values(inputs, net, state)?,
    };
    decode_public_index_and_found(output, net, state)
}

fn decode_public_index_and_found<N: Network>(
    output: BinaryBundle<WireMod2>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(u32, BitShare)> {
    let (index, found) = output.wires().split_at(INDEX_BITS);
    let found = found[0];
    match state.id {
        PartyID::ID0 => {
            let found = collapse_bit(&found);
            let r = state.rngs.rand.random_element_rng1::<RingElement<Bit>>();
            let masked_found = found ^ r;
            let mut payload = Vec::with_capacity(5);
            payload.push(u8::from(masked_found.0.convert()));
            payload.extend_from_slice(&collapse_u32(index).0.to_le_bytes());
            net.send(PartyID::ID2.into(), &payload)?;
            let garbler_index =
                net.send_and_recv(PartyID::ID1, collapse_u32(index), PartyID::ID1)?;
            Ok((
                (collapse_u32(index) ^ garbler_index).0,
                Rep3RingShare::new_ring(r, masked_found),
            ))
        }
        PartyID::ID1 => {
            let found = collapse_bit(&found);
            let r = state.rngs.rand.random_element_rng2::<RingElement<Bit>>();
            let evaluator_index =
                net.send_and_recv(PartyID::ID0, collapse_u32(index), PartyID::ID0)?;
            Ok((
                (evaluator_index ^ collapse_u32(index)).0,
                Rep3RingShare::new_ring(found, r),
            ))
        }
        PartyID::ID2 => {
            let payload = net.recv(PartyID::ID0.into())?;
            if payload.len() != 5 {
                eyre::bail!("invalid CHT public index payload length");
            }
            let masked_found = RingElement(Bit::new(payload[0] != 0));
            let index_from_id0 = RingElement(u32::from_le_bytes(payload[1..].try_into().unwrap()));
            let index = (index_from_id0 ^ collapse_u32(index)).0;
            Ok((
                index,
                Rep3RingShare::new_ring(masked_found, collapse_bit(&found)),
            ))
        }
    }
}

fn eval<N: Network>(net: &N, state: &mut Rep3State) -> eyre::Result<BlockShare> {
    y2b(eval_raw(net)?, net, state)
}

fn eval_raw<N: Network>(net: &N) -> eyre::Result<BinaryBundle<WireMod2>> {
    let [x01, x2] = receive_input_bundles(net)?;
    let mut evaluator = FastEvaluator::receive_no_hash(net)?;
    evaluate_lookup_circuit(&mut evaluator, &x01, &x2)
        .map_err(|err| eyre::eyre!("CHT fast eval: {err:?}"))
}

fn garble<N: Network>(
    inputs: [BlockShare; 3],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BlockShare> {
    y2b(garble_raw(inputs, net, state)?, net, state)
}

fn garble_raw<N: Network>(
    inputs: [BlockShare; 3],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryBundle<WireMod2>> {
    garble_raw_with(inputs, garble_lookup_inputs, net, state)
}

fn garble_raw_values<N: Network>(
    inputs: [u128; 3],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryBundle<WireMod2>> {
    garble_raw_with(inputs, garble_lookup_input_values, net, state)
}

fn garble_raw_with<N: Network, T>(
    inputs: T,
    pack_inputs: fn(
        &T,
        &N,
        PartyID,
        &mut Rep3Garbler<N>,
    ) -> eyre::Result<[BinaryBundle<WireMod2>; 2]>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<BinaryBundle<WireMod2>> {
    let delta = state
        .rngs
        .generate_random_garbler_delta(state.id)
        .expect("delta should be present");
    let mut garbler = Rep3Garbler::new_with_delta(net, state, delta);
    let [x01, x2] = pack_inputs(&inputs, net, state.id, &mut garbler)?;
    let output = evaluate_lookup_circuit(&mut garbler, &x01, &x2)
        .map_err(|err| eyre::eyre!("CHT fast garble: {err:?}"))?;
    if state.id == PartyID::ID1 {
        // ID1 sends the actual garbled gates.
        garbler.send_circuit()?;
    }
    // ID2 intentionally skips send_circuit() — no hash is sent to ID0.
    Ok(output)
}

fn evaluate_and_gate_local(
    gate_num: usize,
    a: &WireMod2,
    b: &WireMod2,
    gate0: &Block,
    gate1: &Block,
) -> WireMod2 {
    let g = tweak2(gate_num as u64, 0);
    let [hash_a, hash_b] = hash_wires([a, b], g);
    let l_block = if a.color() & 1 == 1 {
        hash_a ^ *gate0
    } else {
        hash_a
    };
    let r_block = if b.color() & 1 == 1 {
        hash_b ^ *gate1
    } else {
        hash_b
    };
    let l = WireMod2::from_block(l_block, 2);
    let r = WireMod2::from_block(r_block, 2);
    l.plus_mov(&r.plus_mov(&a.cmul(b.color())))
}

struct FastEvaluator {
    circuit: Vec<[u8; 16]>,
    current_gate: usize,
    current_circuit_element: usize,
}

impl FastEvaluator {
    /// Receive the garbled circuit from ID1 without waiting for a hash from ID2.
    fn receive_no_hash<N: Network>(net: &N) -> eyre::Result<Self> {
        let circuit: Vec<[u8; 16]> = net.recv_many(PartyID::ID1)?;
        Ok(Self {
            circuit,
            current_gate: 0,
            current_circuit_element: 0,
        })
    }

    fn get_block(&mut self) -> eyre::Result<Block> {
        if self.current_circuit_element >= self.circuit.len() {
            eyre::bail!("Too few gates in CHT lookup circuit");
        }
        let mut block = Block::default();
        block
            .as_mut()
            .copy_from_slice(&self.circuit[self.current_circuit_element]);
        self.current_circuit_element += 1;
        Ok(block)
    }
}

impl Fancy for FastEvaluator {
    type Item = WireMod2;
    type Error = EvaluatorError;

    fn constant(&mut self, _: u16, _q: u16) -> Result<WireMod2, Self::Error> {
        let block = self
            .get_block()
            .map_err(|e| EvaluatorError::CommunicationError(e.to_string()))?;
        Ok(WireMod2::from_block(block, 2))
    }

    fn output(&mut self, _x: &WireMod2) -> Result<Option<u16>, Self::Error> {
        Ok(None)
    }
}

impl FancyBinary for FastEvaluator {
    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        Ok(*x)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        Ok(x.plus(y))
    }

    fn and(&mut self, a: &Self::Item, b: &Self::Item) -> Result<Self::Item, Self::Error> {
        let gate0 = self
            .get_block()
            .map_err(|e| EvaluatorError::CommunicationError(e.to_string()))?;
        let gate1 = self
            .get_block()
            .map_err(|e| EvaluatorError::CommunicationError(e.to_string()))?;
        let gate_num = self.current_gate;
        self.current_gate += 1;
        Ok(evaluate_and_gate_local(gate_num, a, b, &gate0, &gate1))
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

fn garble_lookup_input_values<N: Network>(
    inputs: &[u128; 3],
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
            encode_input(
                if id == party { *input } else { 0 },
                id == party,
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

fn pack_lookup_input_values(
    key: u128,
    cht_b0: u128,
    cht_b1: u128,
    dummy_index: XShare,
    id: PartyID,
) -> [u128; 3] {
    let dummy_index = match id {
        PartyID::ID1 => u128::from((dummy_index.a ^ dummy_index.b).0),
        PartyID::ID2 => u128::from(dummy_index.a.0),
        PartyID::ID0 => 0,
    };
    [
        pack_tag_and_index_value(key, cht_b0),
        pack_tag_and_index_value(cht_b0, cht_b1),
        pack_tag_and_index_value(cht_b1, dummy_index),
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

fn pack_tag_and_index_value(tag: u128, index: u128) -> u128 {
    (tag >> INDEX_BITS) | ((index & INDEX_MASK) << KEY_TAG_BITS)
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

fn collapse_u32(wires: &[WireMod2]) -> RingElement<u32> {
    let mut value = 0u32;
    for wire in wires.iter().rev() {
        value <<= 1;
        value |= u32::from(wire.color() & 1);
    }
    RingElement(value)
}

fn collapse_bit(wire: &WireMod2) -> RingElement<Bit> {
    RingElement(Bit::new(wire.color() & 1 == 1))
}
