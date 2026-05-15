use mpc_core::protocols::{
    rep3::Rep3State,
    rep3_ring::{
        binary::{and_vec, and_with_public, shift_r_public},
        casts::downcast,
        ring::ring_impl::RingElement,
    },
};
use mpc_net::Network;
use primitives::{
    BlockShare, XShare, bit_to_binary_mask, is_zero_many, types::BitShare, upcast_x_to_block,
};

pub fn lookup_circuit(
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
