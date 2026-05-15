mod common;

use common::run_parties;
use data_structures::SpeedCache;
use mpc_core::protocols::{
    rep3::{Rep3State, conversion::A2BType},
    rep3_ring::{
        arithmetic, binary,
        ring::{bit::Bit, ring_impl::RingElement},
    },
};

fn init_speed_cache(state: &Rep3State) -> SpeedCache {
    let mut cache = SpeedCache::new(2);
    cache.write(
        vec![
            binary::promote_to_trivial_share(state.id, &RingElement(7u32)),
            binary::promote_to_trivial_share(state.id, &RingElement(8u32)),
        ],
        vec![
            binary::promote_to_trivial_share(state.id, &RingElement(70u64)),
            binary::promote_to_trivial_share(state.id, &RingElement(80u64)),
        ],
    );
    cache
}

#[test]
fn test_speed_cache_query() {
    let results = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let mut cache = init_speed_cache(&state);

        let query_addr = vec![binary::promote_to_trivial_share(
            state.id,
            &RingElement(7u32),
        )];

        let (value, found) = cache.query(query_addr, &net, &mut state).unwrap();
        let value = arithmetic::open_bit(value, &net).unwrap();
        let found = arithmetic::open_bit(found, &net).unwrap();

        (value, found)
    });

    for (value, found) in results {
        assert_eq!(value, RingElement(70u64));
        assert_eq!(found, RingElement(Bit::new(true)));
    }
}
