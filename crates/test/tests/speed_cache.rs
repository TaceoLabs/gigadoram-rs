use mpc_core::protocols::{
    rep3::{Rep3State, conversion::A2BType, id::PartyID},
    rep3_ring::{Rep3RingShare, arithmetic, binary, ring::ring_impl::RingElement},
};
use mpc_net::local::LocalNetwork;
use serde::Deserialize;
use structures::SpeedCache;

#[derive(Clone, Debug, Deserialize)]
struct SpeedCacheStateFixture {
    capacity: usize,
    num_stored: usize,
    slots: Vec<SpeedCacheSlotFixture>,
}

#[derive(Clone, Debug, Deserialize)]
struct SpeedCacheSlotFixture {
    addr: u32,
    data: u64,
    state: String,
}

#[derive(Clone, Debug, Deserialize)]
struct SpeedCacheQueryFixture {
    component: String,
    query_addr: u32,
    result_y: u64,
    found: bool,
}

const AFTER_WRITE: &str = include_str!("fixtures/speed_cache/speed_cache_after_write.json");
const QUERY_X3: &str = include_str!("fixtures/speed_cache/speed_cache_query_x3.json");
const AFTER_QUERY_X3: &str = include_str!("fixtures/speed_cache/speed_cache_after_query_x3.json");

#[test]
fn speed_cache_write_matches_fixture_snapshot() {
    let fixture = state_fixture(AFTER_WRITE);
    let mut cache = SpeedCache::new(fixture.capacity);

    write_live_slots_locally(&mut cache, &fixture);
    assert_eq!(cache.len(), fixture.num_stored);

    let (addresses, values) = extract_full_local_snapshot(cache, &fixture);
    assert_eq!(addresses, fixture_addresses(&fixture));
    assert_eq!(values, fixture_values(&fixture));
}

#[test]
fn speed_cache_query_matches_fixture_snapshots() {
    let before = state_fixture(AFTER_WRITE);
    let query = query_fixture(QUERY_X3);
    let after = state_fixture(AFTER_QUERY_X3);
    assert_eq!(query.component, "SpeedCache/StupidLevel query");
    assert_eq!(before.capacity, after.capacity);
    assert_eq!(before.num_stored, after.num_stored);

    let expected_value = RingElement(query.result_y);
    let expected_found = RingElement(u32::from(query.found));
    let expected_addresses = fixture_addresses(&after)
        .into_iter()
        .map(RingElement)
        .collect::<Vec<_>>();
    let expected_values = fixture_values(&after)
        .into_iter()
        .map(RingElement)
        .collect::<Vec<_>>();

    let networks = LocalNetwork::new_3_parties();
    std::thread::scope(|scope| {
        let handles = networks.map(|network| {
            let before = before.clone();
            let expected_addresses = expected_addresses.clone();
            let expected_values = expected_values.clone();

            scope.spawn(move || {
                let mut state = Rep3State::new(&network, A2BType::Direct).unwrap();
                let mut cache = SpeedCache::new(before.capacity);
                write_live_slots_mpc(&mut cache, &before, state.id);

                let result = cache
                    .query_address(
                        vec![binary::promote_to_trivial_share(
                            state.id,
                            &RingElement(query.query_addr),
                        )],
                        &network,
                        &mut state,
                    )
                    .unwrap();

                let value = arithmetic::open_bit(result.value[0], &network).unwrap();
                let found = arithmetic::open_bit(result.found[0], &network).unwrap();
                let (addresses, values) = extract_full_mpc_snapshot(cache, &before, &network);

                (
                    value,
                    found,
                    addresses,
                    values,
                    expected_addresses,
                    expected_values,
                )
            })
        });

        for handle in handles {
            let (value, found, addresses, values, expected_addresses, expected_values) =
                handle.join().unwrap();
            assert_eq!(value, expected_value);
            assert_eq!(found, expected_found);
            assert_eq!(addresses, expected_addresses);
            assert_eq!(values, expected_values);
        }
    });
}

fn state_fixture(json: &str) -> SpeedCacheStateFixture {
    serde_json::from_str(json).expect("speed cache state fixture parses")
}

fn query_fixture(json: &str) -> SpeedCacheQueryFixture {
    serde_json::from_str(json).expect("speed cache query fixture parses")
}

fn write_live_slots_locally(cache: &mut SpeedCache, fixture: &SpeedCacheStateFixture) {
    let live_slots = fixture_live_slots(fixture);
    cache.write(
        live_slots.iter().map(|slot| x_share(slot.addr)).collect(),
        live_slots.iter().map(|slot| y_share(slot.data)).collect(),
    );
}

fn write_live_slots_mpc(cache: &mut SpeedCache, fixture: &SpeedCacheStateFixture, id: PartyID) {
    let live_slots = fixture_live_slots(fixture);
    cache.write(
        live_slots
            .iter()
            .map(|slot| binary::promote_to_trivial_share(id, &RingElement(slot.addr)))
            .collect(),
        live_slots
            .iter()
            .map(|slot| binary::promote_to_trivial_share(id, &RingElement(slot.data)))
            .collect(),
    );
}

fn fixture_live_slots(fixture: &SpeedCacheStateFixture) -> Vec<&SpeedCacheSlotFixture> {
    fixture
        .slots
        .iter()
        .filter(|slot| slot.state == "live")
        .collect()
}

fn extract_full_local_snapshot(
    mut cache: SpeedCache,
    fixture: &SpeedCacheStateFixture,
) -> (Vec<u32>, Vec<u64>) {
    cache.skip(fixture.capacity - fixture.num_stored);
    let mut xs = Vec::new();
    let mut ys = Vec::new();
    cache.extract(&mut xs, &mut ys);
    (
        xs.into_iter().map(|share| share.a.0).collect(),
        ys.into_iter().map(|share| share.a.0).collect(),
    )
}

fn extract_full_mpc_snapshot(
    mut cache: SpeedCache,
    fixture: &SpeedCacheStateFixture,
    network: &LocalNetwork,
) -> (Vec<RingElement<u32>>, Vec<RingElement<u64>>) {
    cache.skip(fixture.capacity - fixture.num_stored);
    let mut xs = Vec::new();
    let mut ys = Vec::new();
    cache.extract(&mut xs, &mut ys);
    (
        xs.into_iter()
            .map(|address| arithmetic::open_bit(address, network).unwrap())
            .collect(),
        ys.into_iter()
            .map(|value| arithmetic::open_bit(value, network).unwrap())
            .collect(),
    )
}

fn fixture_addresses(fixture: &SpeedCacheStateFixture) -> Vec<u32> {
    fixture.slots.iter().map(|slot| slot.addr).collect()
}

fn fixture_values(fixture: &SpeedCacheStateFixture) -> Vec<u64> {
    fixture.slots.iter().map(|slot| slot.data).collect()
}

fn x_share(value: u32) -> Rep3RingShare<u32> {
    Rep3RingShare::new(value, 0)
}

fn y_share(value: u64) -> Rep3RingShare<u64> {
    Rep3RingShare::new(value, 0)
}
