use mpc_core::protocols::{
    rep3::Rep3State,
    rep3_ring::{
        Rep3RingShare, binary,
        ring::{bit::Bit, ring_impl::RingElement},
    },
};
use mpc_net::Network;

pub const X_TYPE_BITS: usize = 32;
pub const Y_TYPE_BITS: usize = 64;
pub const X_QUERY_OFFSET: usize = 0;
pub const STORED_X_OFFSET: usize = X_TYPE_BITS;
pub const INPUT_Y_OFFSET: usize = 2 * X_TYPE_BITS;
pub const OUTPUT_X_MASK_OFFSET: usize = 0;
pub const OUTPUT_Y_OFFSET: usize = X_TYPE_BITS;
pub const OUTPUT_FOUND_OFFSET: usize = X_TYPE_BITS + Y_TYPE_BITS;
pub const X_MASK_U128: u128 = (1u128 << X_TYPE_BITS) - 1;
pub const Y_MASK_U128: u128 = (1u128 << Y_TYPE_BITS) - 1;

pub fn xy_if_xs_equal_circuit(
    circuit_input: &BlockShare,
    net: &impl Network,
    state: &mut Rep3State,
) -> eyre::Result<BlockShare> {
    let x_query = unpack_x(circuit_input, X_QUERY_OFFSET);
    let x = unpack_x(circuit_input, STORED_X_OFFSET);
    let y = unpack_y(circuit_input, INPUT_Y_OFFSET);

    let x_delta = binary::xor(&x_query, &x);
    let is_match = binary::is_zero(&x_delta, net, state)?;
    let x_match_mask = bit_to_x_mask(&is_match);
    let y_match_mask = bit_to_y_mask(&is_match);

    let remove_duplicate_addr_mask = binary::cmux(&x_match_mask, &x, &X::zero_share(), net, state)?;
    let y_if_equal = binary::cmux(&y_match_mask, &y, &Y::zero_share(), net, state)?;
    let found = bit_to_x(&is_match);

    Ok(pack_x(&remove_duplicate_addr_mask, OUTPUT_X_MASK_OFFSET)
        ^ pack_y(&y_if_equal, OUTPUT_Y_OFFSET)
        ^ pack_x(&found, OUTPUT_FOUND_OFFSET))
}

pub fn xor_of_all_elements(elements: &[BlockShare]) -> BlockShare {
    elements
        .iter()
        .fold(BlockShare::zero_share(), |acc, element| {
            binary::xor(&acc, element)
        })
}

pub fn pack_x(x: &X, offset: usize) -> BlockShare {
    BlockShare::new(u128::from(x.a.0), u128::from(x.b.0)) << offset
}

pub fn pack_y(y: &Y, offset: usize) -> BlockShare {
    BlockShare::new(u128::from(y.a.0), u128::from(y.b.0)) << offset
}

pub fn unpack_x(block: &BlockShare, offset: usize) -> X {
    let shifted = block >> offset;
    let masked = &shifted & &RingElement(X_MASK_U128);
    X::new(masked.a.0 as u32, masked.b.0 as u32)
}

pub fn unpack_y(block: &BlockShare, offset: usize) -> Y {
    let shifted = block >> offset;
    let masked = &shifted & &RingElement(Y_MASK_U128);
    Y::new(masked.a.0 as u64, masked.b.0 as u64)
}

fn bit_to_x(bit: &Rep3RingShare<Bit>) -> X {
    X::new(u32::from(bit.a.0.convert()), u32::from(bit.b.0.convert()))
}

fn bit_to_x_mask(bit: &Rep3RingShare<Bit>) -> X {
    X::new(
        if bit.a.0.convert() { u32::MAX } else { 0 },
        if bit.b.0.convert() { u32::MAX } else { 0 },
    )
}

fn bit_to_y_mask(bit: &Rep3RingShare<Bit>) -> Y {
    Y::new(
        if bit.a.0.convert() { u64::MAX } else { 0 },
        if bit.b.0.convert() { u64::MAX } else { 0 },
    )
}
