type SpeedCache = data_structures::SpeedCache<primitives::FieldValue<primitives::YField>>;
use mpc_core::protocols::{
    rep3::{Rep3State, conversion::A2BType},
    rep3_ring::arithmetic,
};
use primitives::{
    Y, YField, YRecord, open_y, promote_public, promote_public_y, random_bigints, run_parties,
};
use rand::thread_rng;

fn init_speed_cache(state: &Rep3State, ys: &[Y]) -> SpeedCache {
    let mut cache = SpeedCache::new(2, 4, state.id);
    cache.write(
        vec![
            promote_public(state.id, 7u32),
            promote_public(state.id, 8u32),
        ],
        vec![
            YRecord::from_value(promote_public_y(state.id, ys[0])),
            YRecord::from_value(promote_public_y(state.id, ys[1])),
        ],
    );
    cache
}

#[test]
fn test_speed_cache_query() {
    let mut rng = thread_rng();
    let ys = random_bigints::<YField, _>(&mut rng, 2);
    let results = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let mut cache = init_speed_cache(&state, &ys);

        [7u32, 8]
            .into_iter()
            .map(|addr| {
                let query_addr = promote_public(state.id, addr);

                let (value, found) = cache.query(query_addr, None, &net, &mut state).unwrap();
                let value = open_y(&value.value, &net);
                let found = arithmetic::open_bit(found, &net).unwrap();

                (value, found.0.convert())
            })
            .collect::<Vec<_>>()
    })
    .unwrap();

    for opened in results {
        assert_eq!(opened, vec![(ys[0], true), (ys[1], true)]);
    }
}
