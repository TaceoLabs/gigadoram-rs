use data_structures::SpeedCache;
use mpc_core::protocols::{
    rep3::{Rep3State, conversion::A2BType},
    rep3_ring::{
        arithmetic,
        ring::{bit::Bit, ring_impl::RingElement},
    },
};
use primitives::{promote_public, run_parties};

fn init_speed_cache(state: &Rep3State) -> SpeedCache {
    let mut cache = SpeedCache::new(2, 4, state.id);
    cache.write(
        vec![
            promote_public(state.id, 7u32),
            promote_public(state.id, 8u32),
        ],
        vec![
            promote_public(state.id, 70u64),
            promote_public(state.id, 80u64),
        ],
    );
    cache
}

#[test]
fn test_speed_cache_query() {
    let results = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let mut cache = init_speed_cache(&state);

        [7u32, 8]
            .into_iter()
            .map(|addr| {
                let query_addr = promote_public(state.id, addr);

                let (value, found) = cache.query(query_addr, None, &net, &mut state).unwrap();
                let value = arithmetic::open_bit(value, &net).unwrap();
                let found = arithmetic::open_bit(found, &net).unwrap();

                (value, found)
            })
            .collect::<Vec<_>>()
    })
    .unwrap();

    for opened in results {
        assert_eq!(
            opened,
            vec![
                (RingElement(70u64), RingElement(Bit::new(true))),
                (RingElement(80u64), RingElement(Bit::new(true))),
            ]
        );
    }
}
