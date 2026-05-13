use mpc_core::protocols::{
    rep3::Rep3State,
    rep3_ring::{
        binary::{self, and_with_public, shift_r_public},
        casts::downcast,
        ring::ring_impl::RingElement,
        yao::upcast_many,
    },
};
use mpc_net::Network;
use primitives::{BlockShare, XShare, types::BitShare};

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

    // TODO: Single round
    let key_equals_b0 = binary::is_zero(&(key_tag ^ cht_b0_tag), net, state)?;
    let key_equals_b1 = binary::is_zero(&(key_tag ^ cht_b1_tag), net, state)?;
    let out_found = key_equals_b0 ^ key_equals_b1;

    // TODO: Single round
    let [key_equals_b0, key_equals_b1] = upcast_many(&[key_equals_b0, key_equals_b1], net, state)?
        .try_into()
        .unwrap();
    let dummy_index = upcast_many(&[dummy_index], net, state)?[0];

    // TODO: Can we combine these?
    let out_index = binary::cmux(&key_equals_b1, &cht_b1_index, &dummy_index, net, state)?;
    let out_index = binary::cmux(&key_equals_b0, &cht_b0_index, &out_index, net, state)?;
    let out_index = downcast(out_index);

    Ok((out_index, out_found))
}
