#[path = "mod.rs"]
mod common;

use circuits::cht_lookup::lookup_circuit;
use common::{public_block_share, public_x_share, run_parties};
use mpc_core::protocols::{
    rep3::{Rep3State, conversion::A2BType},
    rep3_ring::binary,
};

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

    let outputs = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        cases
            .iter()
            .map(|case| {
                let (index, found) = lookup_circuit(
                    public_block_share(state.id, case.key),
                    public_block_share(state.id, case.b0),
                    public_block_share(state.id, case.b1),
                    public_x_share(state.id, case.dummy_index),
                    &net,
                    &mut state,
                )
                .unwrap();
                (
                    binary::open(&index, &net).unwrap().0,
                    binary::open(&found, &net).unwrap().0.convert(),
                )
            })
            .collect::<Vec<_>>()
    });

    for opened in outputs {
        assert_eq!(opened, expected);
    }
}

fn tag(tag: u128) -> u128 {
    tag << 32
}

fn entry(tag: u128, index: u32) -> u128 {
    (tag << 32) | u128::from(index)
}
