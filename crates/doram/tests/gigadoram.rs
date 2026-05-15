use std::collections::{BTreeMap, BTreeSet, HashMap};

use doram::{GigaDoram, GigaDoramConfig};
use mpc_core::protocols::{
    rep3::{Rep3State, conversion::A2BType, id::PartyID, network::Rep3NetworkExt},
    rep3_ring::binary,
};
use mpc_net::local::LocalNetwork;
use primitives::{Block, X, Y, open_many, promote_public, run_parties};
use structures::{OhTable, cht};

const NUM_LEVELS: usize = 4;
const LOG_STUPID_LEVEL_SIZE: usize = 4;
const SPEED_CACHE_SIZE: usize = 1 << LOG_STUPID_LEVEL_SIZE;
const STASH_SIZE: usize = 8;
const LOG_AMP_FACTOR: usize = 2;
const AMP_FACTOR: usize = 1 << LOG_AMP_FACTOR;
const FILL_TIME: usize = SPEED_CACHE_SIZE - STASH_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Read(X),
    Write(X, Y),
}

impl Op {
    const fn read(x: X) -> Self {
        Self::Read(x)
    }

    const fn write(x: X, y: Y) -> Self {
        Self::Write(x, y)
    }

    const fn x(self) -> X {
        match self {
            Self::Read(x) | Self::Write(x, _) => x,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct TestData {
    config: GigaDoramConfig,
}

#[derive(Clone, Debug)]
struct BeforeOp {
    speed_cache_len: usize,
    speed_cache_addrs: Vec<X>,
    level_query_counts: Vec<usize>,
}

#[derive(Debug)]
struct ClearDoram {
    speed_cache_addrs: Vec<X>,
    speed_cache_data: Vec<Y>,
    levels: Vec<Option<ClearOhTable>>,
}

#[derive(Debug)]
struct ClearOhTable {
    qs_builder_order: Vec<Block>,
    receiver_xs: Vec<X>,
    receiver_ys: Vec<Y>,
    stash_xs: Vec<X>,
    stash_ys: Vec<Y>,
    dummy_indices: Vec<X>,
    cht: Vec<Block>,
}

impl TestData {
    fn setup() -> Self {
        assert!(NUM_LEVELS.is_power_of_two());
        assert!(SPEED_CACHE_SIZE.is_power_of_two());
        assert!(STASH_SIZE.is_power_of_two());
        assert!(AMP_FACTOR.is_power_of_two());
        assert_eq!(SPEED_CACHE_SIZE, 1usize << LOG_STUPID_LEVEL_SIZE);
        assert_eq!(AMP_FACTOR, 1usize << LOG_AMP_FACTOR);

        Self {
            config: GigaDoramConfig {
                num_levels: NUM_LEVELS,
                log_stupid_level_size: LOG_STUPID_LEVEL_SIZE,
                log_amp_factor: LOG_AMP_FACTOR,
                stash_size: STASH_SIZE,
            },
        }
    }

    fn assert_trace(&self, trace: &[Op], expected: &[Y]) {
        let outputs = self.run_trace(trace);

        for party_output in outputs {
            assert_eq!(party_output, expected);
        }
    }

    fn first_rebuild_trace(&self) -> Vec<Op> {
        (1..=FILL_TIME)
            .map(|x| Op::write(x as X, x as Y * 10))
            .collect()
    }

    fn first_rebuild_trace_with_tail(&self, tail: &[Op]) -> Vec<Op> {
        let mut trace = self.first_rebuild_trace();
        trace.extend_from_slice(tail);
        trace
    }

    fn run_trace(&self, trace: &[Op]) -> [Vec<Y>; 3] {
        run_parties(|net| {
            let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
            let mut doram = GigaDoram::new(self.config);
            let mut outputs = Vec::with_capacity(trace.len());

            for op in trace {
                let value = match *op {
                    Op::Read(x) => doram.read(promote_public(state.id, x), &net, &mut state),
                    Op::Write(x, y) => doram.write(
                        promote_public(state.id, x),
                        promote_public(state.id, y),
                        &net,
                        &mut state,
                    ),
                }
                .unwrap();

                outputs.push(binary::open(&value, &net).unwrap().0);
            }

            outputs
        })
    }

    fn run_trace_with_cache_len(&self, trace: &[Op]) -> [(Vec<Y>, usize); 3] {
        run_parties(|net| {
            let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
            let mut doram = GigaDoram::new(self.config);
            let mut outputs = Vec::with_capacity(trace.len());

            for op in trace {
                let value = match *op {
                    Op::Read(x) => doram.read(promote_public(state.id, x), &net, &mut state),
                    Op::Write(x, y) => doram.write(
                        promote_public(state.id, x),
                        promote_public(state.id, y),
                        &net,
                        &mut state,
                    ),
                }
                .unwrap();

                outputs.push(binary::open(&value, &net).unwrap().0);
            }

            (outputs, doram.speed_cache_len())
        })
    }

    fn run_trace_with_invariants(&self, trace: &[Op]) -> [Vec<Y>; 3] {
        run_parties(|net| {
            let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
            let mut doram = GigaDoram::new(self.config);
            let mut oracle = BTreeMap::new();
            let mut outputs = Vec::with_capacity(trace.len());

            for op in trace {
                let before = before_op(&doram, &net);
                let old_value = *oracle.get(&op.x()).unwrap_or(&0);
                let value = match *op {
                    Op::Read(x) => doram.read(promote_public(state.id, x), &net, &mut state),
                    Op::Write(x, y) => doram.write(
                        promote_public(state.id, x),
                        promote_public(state.id, y),
                        &net,
                        &mut state,
                    ),
                }
                .unwrap();

                let opened = binary::open(&value, &net).unwrap().0;
                outputs.push(opened);

                match *op {
                    Op::Read(x) => {
                        assert_eq!(opened, old_value);
                        oracle.insert(x, old_value);
                    }
                    Op::Write(x, y) => {
                        assert_eq!(opened, old_value);
                        oracle.insert(x, y);
                    }
                }

                assert_doram_invariants(&doram, &oracle, *op, old_value, &before, &net, &state);
            }

            outputs
        })
    }
}

// Empty reads should return the default value.
#[test]
fn test_empty_reads_return_zero() {
    let trace = [Op::read(1), Op::read(2), Op::read(1)];

    TestData::setup().assert_trace(&trace, &[0, 0, 0]);
}

// A write should be visible to a later read of the same key.
#[test]
fn test_single_write_then_read() {
    let trace = [Op::write(1, 10), Op::read(1)];

    TestData::setup().assert_trace(&trace, &[0, 10]);
}

// Overwriting a key should return the old value.
#[test]
fn test_overwrite_returns_old_value() {
    let trace = [Op::write(1, 10), Op::write(1, 11), Op::read(1)];

    TestData::setup().assert_trace(&trace, &[0, 10, 11]);
}

// Writes to distinct keys should not change each other.
#[test]
fn test_distinct_keys_do_not_interfere() {
    let trace = [Op::write(1, 10), Op::write(2, 20), Op::read(1), Op::read(2)];

    TestData::setup().assert_trace(&trace, &[0, 0, 10, 20]);
}

// Reading a value should reinsert it so it can be read again.
#[test]
fn test_read_reinserts_value() {
    let trace = [Op::write(1, 10), Op::read(1), Op::read(1)];

    TestData::setup().assert_trace(&trace, &[0, 10, 10]);
}

// The first rebuild should preserve values written before it.
#[test]
fn test_first_rebuild_preserves_values() {
    let data = TestData::setup();
    let trace = data.first_rebuild_trace_with_tail(&[Op::read(1), Op::read(2), Op::read(3)]);
    let mut expected = vec![0; FILL_TIME];
    expected.extend_from_slice(&[10, 20, 30]);

    data.assert_trace(&trace, &expected);
}

// A read after the first rebuild should find values in the hierarchy.
#[test]
fn test_read_from_hierarchy_after_rebuild() {
    let data = TestData::setup();
    let trace = data.first_rebuild_trace_with_tail(&[Op::read(2)]);
    let mut expected = vec![0; FILL_TIME];
    expected.push(20);

    data.assert_trace(&trace, &expected);
}

// Overwrites after a rebuild should use the newest value.
#[test]
fn test_overwrite_after_rebuild_uses_newest_value() {
    let data = TestData::setup();
    let trace = data.first_rebuild_trace_with_tail(&[Op::read(1), Op::write(1, 11), Op::read(1)]);
    let mut expected = vec![0; FILL_TIME];
    expected.extend_from_slice(&[10, 10, 11]);

    data.assert_trace(&trace, &expected);
}

// Rebuilding should insert the rebuilt table's stash into the speed cache.
#[test]
fn test_stashed_items_are_inserted_into_cache() {
    let data = TestData::setup();
    let trace = data.first_rebuild_trace_with_tail(&[Op::read((FILL_TIME + 1) as X)]);
    let mut expected = vec![0; FILL_TIME];
    expected.push(0);

    for (outputs, speed_cache_len) in data.run_trace_with_cache_len(&trace) {
        assert_eq!(outputs, expected);
        assert_eq!(speed_cache_len, STASH_SIZE + 1);
    }
}

// A longer flow should match a plain HashMap oracle.
#[test]
fn test_flow_hashmap_oracle() {
    let data = TestData::setup();
    let trace = [
        Op::write(1, 10),
        Op::write(2, 20),
        Op::write(3, 30),
        Op::write(4, 40),
        Op::write(5, 50),
        Op::write(6, 60),
        Op::write(7, 70),
        Op::write(8, 80),
        Op::read(1),
        Op::write(1, 11),
        Op::read(1),
        Op::read(2),
        Op::read(9),
    ];
    let expected_outputs = oracle(&trace);

    for outputs in data.run_trace_with_invariants(&trace) {
        assert_eq!(outputs, expected_outputs);
    }
}

fn oracle(trace: &[Op]) -> Vec<Y> {
    let mut map = HashMap::new();
    let mut outputs = Vec::with_capacity(trace.len());

    for op in trace {
        match *op {
            Op::Read(x) => outputs.push(*map.get(&x).unwrap_or(&0)),
            Op::Write(x, y) => {
                let old = map.insert(x, y).unwrap_or(0);
                outputs.push(old);
            }
        }
    }

    outputs
}

fn before_op(doram: &GigaDoram, net: &LocalNetwork) -> BeforeOp {
    BeforeOp {
        speed_cache_len: doram.speed_cache.num_stored,
        speed_cache_addrs: open_many(
            &doram.speed_cache.addrs[..doram.speed_cache.num_stored],
            net,
        ),
        level_query_counts: doram
            .levels
            .iter()
            .map(|level| level.as_ref().map_or(0, |table| table.query_count))
            .collect(),
    }
}

fn assert_doram_invariants(
    doram: &GigaDoram,
    oracle: &BTreeMap<X, Y>,
    op: Op,
    old_value: Y,
    before: &BeforeOp,
    net: &LocalNetwork,
    state: &Rep3State,
) {
    let clear = clear_doram(doram, net, state);

    // The freshest copies equal the HashMap oracle.
    let logical = collect_latest_values_by_freshness(doram, &clear);
    assert_eq!(&logical, oracle);

    // No OHTable slot has been touched twice (TODO: This one is a bit tautological I guess)
    for (level, table) in doram.levels.iter().enumerate() {
        if let Some(table) = table {
            assert!(
                table.touched.iter().filter(|&&touched| touched).count()
                    == table.params.stash_size + table.query_count,
                "level {level} has too many touched slots"
            );
        }
    }

    // Every query appends one fresh logical copy to the speed cache.
    assert_eq!(
        clear.speed_cache_addrs[doram.speed_cache.num_stored - 1],
        op.x()
    );

    // TODO: rebuilds preserve all live logical values.

    assert_speed_cache_invariants(doram, &clear, op, old_value, before);
    assert_ohtable_invariants(doram, &clear, before, state);

    for (level, table) in doram.levels.iter().enumerate() {
        if level < doram.config.num_levels - 1 {
            // Non-bottom levels are empty exactly when base_b state is zero.
            assert_eq!(table.is_none(), doram.base_b_state_vec[level] == 0);
        }
    }
}

fn assert_speed_cache_invariants(
    doram: &GigaDoram,
    clear: &ClearDoram,
    op: Op,
    old_value: Y,
    before: &BeforeOp,
) {
    let cache = &doram.speed_cache;

    assert!(cache.num_stored > 0);
    assert!(cache.num_stored <= SPEED_CACHE_SIZE);
    assert_eq!(clear.speed_cache_addrs.len(), SPEED_CACHE_SIZE);
    assert_eq!(clear.speed_cache_data.len(), SPEED_CACHE_SIZE);

    let live_addrs = &clear.speed_cache_addrs[..cache.num_stored];
    let live_data = &clear.speed_cache_data[..cache.num_stored];

    // There are no duplicate live real addresses.
    let mut seen = BTreeSet::new();
    for &x in live_addrs.iter().filter(|&&x| is_real_addr(x)) {
        assert!(seen.insert(x), "duplicate live cache address {x}");
    }

    // Every operation appends a fresh copy for op.x().
    let last = cache.num_stored - 1;
    assert_eq!(live_addrs[last], op.x());

    let expected_appended_y = match op {
        Op::Write(_, y_new) => y_new,
        Op::Read(_) => old_value,
    };
    assert_eq!(live_data[last], expected_appended_y);

    // No rebuild happened. Querying SpeedCache removes old matching live entry.
    if before.speed_cache_len < SPEED_CACHE_SIZE {
        for (i, &before_x) in before.speed_cache_addrs[..before.speed_cache_len]
            .iter()
            .enumerate()
        {
            if before_x == op.x() && is_real_addr(before_x) {
                assert_eq!(
                    live_addrs[i],
                    0,
                    "old SpeedCache slot {i} for x={} was not removed",
                    op.x()
                );
            }
        }
    }
}
fn assert_ohtable_invariants(
    doram: &GigaDoram,
    clear: &ClearDoram,
    before: &BeforeOp,
    state: &Rep3State,
) {
    for (level, table) in doram.levels.iter().enumerate() {
        let Some(table) = table else {
            continue;
        };
        let clear_table = clear.levels[level]
            .as_ref()
            .expect("clear view should exist for every live level");

        assert_ohtable_build_invariants(table);
        assert_cht_invariants(table, clear_table);
        assert_receiver_order_invariants(table, clear_table, state);
        assert_query_invariants(table, clear_table, before.level_query_counts[level], state);
    }
}

fn assert_ohtable_build_invariants(table: &OhTable) {
    assert_eq!(
        table.params.total_size(),
        table.params.num_elements + table.params.num_dummies
    );
    assert_eq!(table.dummy_indices.len(), table.params.num_dummies);
    assert_eq!(table.stash_xs.len(), table.params.stash_size);
    assert_eq!(table.stash_ys.len(), table.params.stash_size);
    assert_eq!(table.touched.len(), table.params.total_size());
    assert_eq!(table.builder_stash_indices.len(), table.params.stash_size);
    assert!(table.query_count <= table.params.num_dummies);
}

fn assert_cht_invariants(table: &OhTable, clear: &ClearOhTable) {
    let log = table.params.log_single_col_len;
    let total_size = table.params.total_size();
    let stash_size = table.params.stash_size;

    let real_builder_indices = clear
        .qs_builder_order
        .iter()
        .enumerate()
        .filter_map(|(i, &q)| (q != 0).then_some(i))
        .collect::<BTreeSet<_>>();

    // There should be exactly one real builder index per real input item.
    assert_eq!(real_builder_indices.len(), table.params.num_elements);

    let mut placed = BTreeSet::new();

    for (position, &entry) in clear.cht.iter().enumerate() {
        if entry == 0 {
            continue;
        }

        // Every CHT entry must be stored at one of its two hash locations.
        assert!(
            position == cht::h0(entry, log) || position == cht::h1(entry, log),
            "CHT entry at slot {position} is not at either hash location"
        );

        let builder_index = entry as u32 as usize;

        // The encoded builder index must point inside the builder array.
        assert!(builder_index < total_size);

        // The encoded builder index must point to a real item, not a dummy.
        assert!(real_builder_indices.contains(&builder_index));

        // No builder index may appear twice in the CHT.
        assert!(
            placed.insert(builder_index),
            "duplicate placed builder index {builder_index}"
        );
    }

    let stash = table
        .builder_stash_indices
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();

    // The stash must not contain duplicates.
    assert_eq!(stash.len(), stash_size, "duplicate stash index");

    for &i in &stash {
        // Every stashed index must point inside the builder array.
        assert!(i < total_size);

        // Every stashed index must point to a real item, not a dummy.
        assert!(real_builder_indices.contains(&i));
    }

    // An item cannot be both placed in the CHT and stored in the stash.
    assert!(placed.is_disjoint(&stash));

    let covered = placed.union(&stash).copied().collect::<BTreeSet<_>>();

    // Every real item is either in the CHT or in the stash.
    assert_eq!(covered, real_builder_indices);
}

fn assert_receiver_order_invariants(table: &OhTable, clear: &ClearOhTable, state: &Rep3State) {
    if state.id == PartyID::ID0 {
        return;
    }

    let mut receiver_shuffle = table.receiver_shuffle.clone().unwrap();

    let expected_touched = table
        .builder_stash_indices
        .iter()
        .map(|&builder_index| receiver_shuffle.evaluate_at(builder_index))
        .collect::<BTreeSet<_>>();

    for (stash_pos, &builder_index) in table.builder_stash_indices.iter().enumerate() {
        let receiver_index = receiver_shuffle.evaluate_at(builder_index);

        // Stashed entries are marked touched in receiver order.
        assert!(table.touched[receiver_index]);

        // Each stash slot copies exactly the matching receiver-order x.
        assert_eq!(clear.stash_xs[stash_pos], clear.receiver_xs[receiver_index]);

        // Each stash slot copies exactly the matching receiver-order y.
        assert_eq!(clear.stash_ys[stash_pos], clear.receiver_ys[receiver_index]);
    }

    if table.query_count == 0 {
        let actual_touched = table
            .touched
            .iter()
            .enumerate()
            .filter_map(|(i, &touched)| touched.then_some(i))
            .collect::<BTreeSet<_>>();

        // Right after build, only stashed entries are touched.
        assert_eq!(actual_touched, expected_touched);
    }
}

fn assert_query_invariants(
    table: &OhTable,
    clear: &ClearOhTable,
    old_query_count: usize,
    state: &Rep3State,
) {
    if table.query_count == old_query_count {
        return;
    }

    let trace = table
        .last_query_trace
        .expect("a queried OHTable should remember its last query");

    // The trace should describe the query we just observed.
    assert_eq!(trace.old_query_count, old_query_count);

    // The query must consume one available dummy slot.
    assert!(trace.old_query_count < table.params.num_dummies);

    // The query counter increases by exactly one.
    assert_eq!(table.query_count, old_query_count + 1);

    // The selected receiver slot must be in bounds.
    assert!(trace.selected_receiver_index < table.params.total_size());

    // The selected receiver slot was fresh before the query.
    assert!(!trace.was_touched_before);

    // The selected receiver slot is consumed after the query.
    assert!(table.touched[trace.selected_receiver_index]);

    if state.id == PartyID::ID0 {
        return;
    }

    let selected_x = clear.receiver_xs[trace.selected_receiver_index];

    if selected_x == 0 {
        let dummy_index = clear.dummy_indices[trace.old_query_count] as usize;
        let mut receiver_shuffle = table.receiver_shuffle.clone().unwrap();

        // A dummy/missing lookup consumes the next scheduled dummy slot.
        assert_eq!(
            trace.selected_receiver_index,
            receiver_shuffle.evaluate_at(dummy_index)
        );
    }
}

fn clear_doram(doram: &GigaDoram, net: &LocalNetwork, state: &Rep3State) -> ClearDoram {
    ClearDoram {
        speed_cache_addrs: open_many(&doram.speed_cache.addrs, net),
        speed_cache_data: open_many(&doram.speed_cache.data, net)
            .into_iter()
            .map(clear_alibi_bits)
            .collect(),
        levels: doram
            .levels
            .iter()
            .map(|level| {
                level.as_ref().map(|table| ClearOhTable {
                    qs_builder_order: open_many(&table.qs_builder_order, net),
                    receiver_xs: open_many(&table.xs_receiver_order, net),
                    receiver_ys: open_many(&table.ys_receiver_order, net)
                        .into_iter()
                        .map(clear_alibi_bits)
                        .collect(),
                    stash_xs: open_many(&table.stash_xs, net),
                    stash_ys: open_many(&table.stash_ys, net)
                        .into_iter()
                        .map(clear_alibi_bits)
                        .collect(),
                    dummy_indices: open_many(&table.dummy_indices, net),
                    cht: open_cht(
                        table
                            .cht_2shares
                            .as_ref()
                            .expect("live OHTable should have CHT shares"),
                        net,
                        state,
                    ),
                })
            })
            .collect(),
    }
}

fn collect_latest_values_by_freshness(doram: &GigaDoram, clear: &ClearDoram) -> BTreeMap<X, Y> {
    let mut values = BTreeMap::new();

    for i in (0..doram.speed_cache.num_stored).rev() {
        let x = clear.speed_cache_addrs[i];
        if is_real_addr(x) {
            values.entry(x).or_insert(clear.speed_cache_data[i]);
        }
    }

    for (level, table) in doram.levels.iter().enumerate() {
        let Some(table) = table else {
            continue;
        };
        let clear_table = clear.levels[level].as_ref().unwrap();
        for (i, (&x, &y)) in clear_table
            .receiver_xs
            .iter()
            .zip(clear_table.receiver_ys.iter())
            .enumerate()
        {
            if is_real_addr(x) && !table.touched[i] {
                values.entry(x).or_insert(y);
            }
        }
    }

    values
}

fn open_cht(table: &[Block], net: &LocalNetwork, state: &Rep3State) -> Vec<Block> {
    match state.id {
        PartyID::ID0 => {
            let from_1 = blocks_from_wire(&net.recv_from::<Vec<u64>>(PartyID::ID1).unwrap());
            let from_2 = blocks_from_wire(&net.recv_from::<Vec<u64>>(PartyID::ID2).unwrap());
            let clear = from_1
                .iter()
                .zip(from_2.iter())
                .map(|(a, b)| *a ^ *b)
                .collect::<Vec<_>>();
            net.send_to(PartyID::ID1, blocks_to_wire(&clear)).unwrap();
            net.send_to(PartyID::ID2, blocks_to_wire(&clear)).unwrap();
            clear
        }
        PartyID::ID1 | PartyID::ID2 => {
            net.send_to(PartyID::ID0, blocks_to_wire(table)).unwrap();
            blocks_from_wire(&net.recv_from::<Vec<u64>>(PartyID::ID0).unwrap())
        }
    }
}

// TODO: what even is this, I don't understand this
fn blocks_to_wire(blocks: &[Block]) -> Vec<u64> {
    blocks
        .iter()
        .flat_map(|block| [*block as u64, (*block >> 64) as u64])
        .collect()
}

fn blocks_from_wire(words: &[u64]) -> Vec<Block> {
    assert_eq!(words.len() % 2, 0);
    words
        .chunks_exact(2)
        .map(|chunk| Block::from(chunk[0]) | (Block::from(chunk[1]) << 64))
        .collect()
}

fn clear_alibi_bits(y: Y) -> Y {
    let keep_bits = Y::BITS as usize - NUM_LEVELS;
    y & ((1u64 << keep_bits) - 1)
}

// TODO: what about the address space maybe dummies have x > 1 << log_address_space
fn is_real_addr(x: X) -> bool {
    x != 0
}
