use mpc_core::protocols::{
    rep3::Rep3State,
    rep3_ring::{
        Rep3RingShare,
        binary::{self, and_with_public, shift_r_public},
        casts::downcast,
        ring::ring_impl::RingElement,
    },
};
use mpc_net::Network;
use primitives::{BlockShare, XShare, bit_to_binary_mask, types::BitShare};

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

    let key_equals_b0 = bit_to_binary_mask(&key_equals_b0);
    let key_equals_b1 = bit_to_binary_mask(&key_equals_b1);
    let dummy_index = upcast_binary_x_to_block(dummy_index);

    // TODO: Can we combine these?
    let out_index = binary::cmux(&key_equals_b1, &cht_b1_index, &dummy_index, net, state)?;
    let out_index = binary::cmux(&key_equals_b0, &cht_b0_index, &out_index, net, state)?;
    let out_index = downcast(out_index);

    Ok((out_index, out_found))
}

fn upcast_binary_x_to_block(share: XShare) -> BlockShare {
    Rep3RingShare::new_ring(
        RingElement(u128::from(share.a.0)),
        RingElement(u128::from(share.b.0)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_core::protocols::{
        rep3::{conversion::A2BType, id::PartyID},
        rep3_ring::binary,
    };
    use mpc_net::local::LocalNetwork;

    #[derive(Clone, Copy, Debug)]
    struct LookupCase {
        key: u128,
        b0: u128,
        b1: u128,
        dummy_index: u32,
    }

    #[test]
    fn test_lookup_circuit() {
        let tag0 = 0xabcdu128;
        let tag1 = 0xdef0u128;
        let tag_miss = 0x1234u128;
        let cases = vec![
            LookupCase {
                key: tag(tag0),
                b0: entry(tag0, 11),
                b1: entry(tag1, 22),
                dummy_index: 99,
            },
            LookupCase {
                key: tag(tag1),
                b0: entry(tag0, 11),
                b1: entry(tag1, 22),
                dummy_index: 99,
            },
            LookupCase {
                key: tag(tag_miss),
                b0: entry(tag0, 11),
                b1: entry(tag1, 22),
                dummy_index: 99,
            },
        ];
        let expected = vec![(11u32, true), (22u32, true), (99u32, false)];
        let networks = LocalNetwork::new_3_parties();

        std::thread::scope(|scope| {
            let handles = networks
                .into_iter()
                .map(|network| {
                    let cases = cases.clone();
                    scope.spawn(move || {
                        let mut state = Rep3State::new(&network, A2BType::Direct).unwrap();
                        cases
                            .iter()
                            .map(|case| {
                                let (index, found) = lookup_circuit(
                                    public_block_share(state.id, case.key),
                                    public_block_share(state.id, case.b0),
                                    public_block_share(state.id, case.b1),
                                    public_x_share(state.id, case.dummy_index),
                                    &network,
                                    &mut state,
                                )
                                .unwrap();
                                (
                                    binary::open(&index, &network).unwrap().0,
                                    binary::open(&found, &network).unwrap().0.convert(),
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect::<Vec<_>>();

            let [party0, party1, party2] = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .expect("three party outputs");

            for opened in [party0, party1, party2] {
                assert_eq!(opened, expected);
            }
        });
    }

    fn tag(tag: u128) -> u128 {
        tag << 32
    }

    fn entry(tag: u128, index: u32) -> u128 {
        (tag << 32) | u128::from(index)
    }

    fn public_block_share(id: PartyID, value: u128) -> BlockShare {
        binary::promote_to_trivial_share(id, &RingElement(value))
    }

    fn public_x_share(id: PartyID, value: u32) -> XShare {
        binary::promote_to_trivial_share(id, &RingElement(value))
    }
}
