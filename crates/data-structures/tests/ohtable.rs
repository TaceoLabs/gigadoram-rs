use circuits::lowmc::ROUND_KEYS;
use data_structures::{OHTableParams, OhTable, cht};
use mpc_core::protocols::{
    rep3::{Rep3State, conversion::A2BType, id::PartyID},
    rep3_ring::{
        binary,
        ring::{bit::Bit, ring_impl::RingElement},
    },
};
use mpc_net::Network;
use primitives::{
    Block, X, Y, YShare, low_u32, promote_public_values, run_parties, run_parties_may_panic,
};
use rand::Rng;

const NUM_ELEMENTS: usize = 10;
const STASH_SIZE: usize = 2;

struct TestData {
    table_0: OhTable,
    table_1: OhTable,
    table_2: OhTable,
}

impl TestData {
    fn clear_cht(&self) -> Vec<Block> {
        let id1 = self.table_1.cht_2shares.as_ref().unwrap();
        let id2 = self.table_2.cht_2shares.as_ref().unwrap();
        let mut cht = Vec::with_capacity(id1.len());

        for (a, b) in id1.iter().zip(id2.iter()) {
            cht.push(a ^ b);
        }

        cht
    }

    fn qs_clear(&self) -> Vec<Block> {
        let mut qs = Vec::with_capacity(self.table_0.qs_builder_order.len());

        for (q0, q2) in self
            .table_0
            .qs_builder_order
            .iter()
            .zip(self.table_2.qs_builder_order.iter())
        {
            qs.push((q0.a ^ q0.b ^ q2.b).0);
        }

        qs
    }

    fn tables(&self) -> [&OhTable; 3] {
        [&self.table_0, &self.table_1, &self.table_2]
    }

    fn table(&self, id: PartyID) -> OhTable {
        match id {
            PartyID::ID0 => self.table_0.clone(),
            PartyID::ID1 => self.table_1.clone(),
            PartyID::ID2 => self.table_2.clone(),
        }
    }

    fn real_builder_indices(&self) -> Vec<usize> {
        real_builder_indices(&self.qs_clear())
    }

    fn is_in_cht(&self, builder_index: usize) -> bool {
        for entry in self.clear_cht() {
            if entry == 0 {
                continue;
            }

            if low_u32(entry) as usize == builder_index {
                return true;
            }
        }

        false
    }

    fn is_in_stash(&self, builder_index: usize) -> bool {
        let mut receiver_shuffle = self.table_1.receiver_shuffle.clone().unwrap();
        let receiver_index = receiver_shuffle.evaluate_at(builder_index);
        self.table_1.touched[receiver_index]
    }

    fn stashed_builder_indices(&self) -> Vec<usize> {
        let mut indices = Vec::new();

        for builder_index in self.real_builder_indices() {
            if self.is_in_stash(builder_index) {
                indices.push(builder_index);
            }
        }

        indices
    }

    fn non_stashed_builder_indices(&self) -> Vec<usize> {
        let mut indices = Vec::new();

        for builder_index in self.real_builder_indices() {
            if !self.is_in_stash(builder_index) {
                indices.push(builder_index);
            }
        }

        indices
    }

    fn receiver_index(&self, builder_index: usize) -> usize {
        let mut receiver_shuffle = self.table_1.receiver_shuffle.clone().unwrap();
        receiver_shuffle.evaluate_at(builder_index)
    }

    fn dummy_receiver_index(&self, query_index: usize) -> usize {
        let d0 = &self.table_0.dummy_indices[query_index];
        let d2 = &self.table_2.dummy_indices[query_index];
        let dummy_index = (d0.a ^ d0.b ^ d2.b).0 as usize;

        self.receiver_index(dummy_index)
    }

    fn query<N: Network>(
        &self,
        table: &mut OhTable,
        builder_index: usize,
        use_dummy: bool,
        net: &N,
        state: &mut Rep3State,
    ) -> (YShare, bool) {
        let q = table.qs_builder_order[builder_index];
        let use_dummy =
            binary::promote_to_trivial_share(state.id, &RingElement(Bit::new(use_dummy)));
        let (value, found) = table.query(q, use_dummy, net, state, None).unwrap();
        let found = binary::open(&found, net).unwrap().0.convert();

        (value, found)
    }
}

// Build creates all expected buffers and leaves the table ready for queries.
#[test]
fn test_build_shape() {
    let data = setup(2);

    for (id, table) in [
        (PartyID::ID0, &data.table_0),
        (PartyID::ID1, &data.table_1),
        (PartyID::ID2, &data.table_2),
    ] {
        assert_eq!(table.params.num_elements, NUM_ELEMENTS);
        assert_eq!(table.params.stash_size, STASH_SIZE);
        assert_eq!(table.stash_xs.len(), STASH_SIZE);
        assert_eq!(table.stash_ys.len(), STASH_SIZE);
        assert_eq!(table.xs_receiver_order.len(), table.params.total_size());
        assert_eq!(table.ys_receiver_order.len(), table.params.total_size());
        assert_eq!(
            table.cht_2shares.as_ref().unwrap().len(),
            table.params.cht_full_table_length()
        );
        if id == table.params.builder {
            assert_eq!(table.receiver_shuffle, None);
        } else {
            assert_eq!(
                table.receiver_shuffle.as_ref().unwrap().n,
                table.params.total_size()
            );
        }
        assert_eq!(table.query_count, 0);
        assert_eq!(table.touched.len(), table.params.total_size());
    }
}

// Every non empty CHT slot must contain an item at one of its two hash locations.
#[test]
fn test_cht_placement() {
    let data = setup(2);
    let cht = data.clear_cht();
    let params = data.table_0.params;

    for (i, entry) in cht.iter().copied().enumerate() {
        if entry == 0 {
            continue;
        }

        assert!(
            cht::h0(entry, params.log_single_col_len) == i
                || cht::h1(entry, params.log_single_col_len) == i,
            "CHT entry at {i} is not at either hash location"
        );
    }
}

// Stash has the expected size.
#[test]
fn test_fixed_stash() {
    let data = setup(2);

    for table in data.tables() {
        assert_eq!(table.stash_xs.len(), STASH_SIZE);
        assert_eq!(table.stash_ys.len(), STASH_SIZE);
    }
}

// Every real item is either placed in the CHT or put in the stash.
#[test]
fn test_partition() {
    let data = setup(2);
    let real = data.real_builder_indices();
    let mut in_cht_count = 0;
    let mut in_stash_count = 0;

    for builder_index in real.iter().copied() {
        in_cht_count += usize::from(data.is_in_cht(builder_index));
        in_stash_count += usize::from(data.is_in_stash(builder_index));
    }

    assert_eq!(in_cht_count + in_stash_count, real.len());

    for builder_index in real {
        assert!(
            data.is_in_cht(builder_index) ^ data.is_in_stash(builder_index),
            "builder index {builder_index} was not in exactly one partition"
        );
    }
}

// Stashed builder indices must map to touched receiver slots with matching stash data.
#[test]
fn test_receiver_mapping() {
    let data = setup(2);
    let table = &data.table_1;
    for builder_index in data.real_builder_indices() {
        if !data.is_in_stash(builder_index) {
            continue;
        }

        let receiver_index = data.receiver_index(builder_index);
        let in_stash = table
            .stash_xs
            .iter()
            .zip(table.stash_ys.iter())
            .any(|(x, y)| {
                *x == table.xs_receiver_order[receiver_index]
                    && *y == table.ys_receiver_order[receiver_index]
            });

        assert!(table.touched[receiver_index]);
        assert!(in_stash);
    }
}

// Querying non-stashed real items returns their value and marks their receiver slot touched.
#[test]
fn test_query_existing_item() {
    let data = setup(NUM_ELEMENTS);
    let builder_indices = data.non_stashed_builder_indices();
    run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let mut table = data.table(state.id);
        let builder_indices = builder_indices.clone();

        for (query_index, builder_index) in builder_indices.iter().copied().enumerate() {
            let receiver_index = data.receiver_index(builder_index);
            let expected_y = table.ys_receiver_order[receiver_index];
            assert_eq!(table.query_count, query_index);
            assert!(!table.touched[receiver_index]);

            let (value, found) = data.query(&mut table, builder_index, false, &net, &mut state);

            assert_eq!(value, expected_y);
            assert!(found);
            assert_eq!(table.query_count, query_index + 1);
            assert!(table.touched[receiver_index]);
        }
    })
    .unwrap();
}

// Querying a stashed item misses in the CHT and consumes the current dummy slot instead.
#[test]
fn test_query_stashed_item() {
    let data = setup(1);
    let builder_index = data.stashed_builder_indices()[0];
    let expected_receiver = data.dummy_receiver_index(0);
    run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let mut table = data.table(state.id);

        let expected_y = table.ys_receiver_order[expected_receiver];
        let (value, found) = data.query(&mut table, builder_index, false, &net, &mut state);

        assert_eq!(value, expected_y);
        assert!(!found);
        assert_eq!(table.query_count, 1);
        assert!(table.touched[expected_receiver]);
    })
    .unwrap();
}

// A dummy query ignores the key and returns the current dummy slot as not found.
#[test]
fn test_dummy_query() {
    let data = setup(1);
    let expected_receiver = data.dummy_receiver_index(0);
    run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let mut table = data.table(state.id);
        let expected_y = table.ys_receiver_order[expected_receiver];

        let (value, found) = data.query(&mut table, 0, true, &net, &mut state);

        assert_eq!(value, expected_y);
        assert!(!found);
        assert_eq!(table.query_count, 1);
        assert!(table.touched[expected_receiver]);
    })
    .unwrap();
}

// Querying the same receiver slot twice must fail instead of double-touching it.
#[test]
fn test_no_double_touch() {
    let data = setup(2);
    let builder_index = data.non_stashed_builder_indices()[0];
    let results = run_parties_may_panic(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let mut table = data.table(state.id);

        for _ in 0..2 {
            let _ = data.query(&mut table, builder_index, false, &net, &mut state);
        }
    });

    assert!(results.into_iter().any(|result| result.is_err()));
}

// Extract returns exactly the receiver-order entries that were never touched.
#[test]
fn test_extract() {
    let data = setup(STASH_SIZE);
    let builder_indices = data.stashed_builder_indices();
    run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let mut table = data.table(state.id);
        let builder_indices = builder_indices.clone();

        for (query_index, builder_index) in builder_indices.into_iter().enumerate() {
            let (value, found) = data.query(&mut table, builder_index, false, &net, &mut state);
            let expected_receiver = data.dummy_receiver_index(query_index);
            let expected_y = table.ys_receiver_order[expected_receiver];

            assert_eq!(value, expected_y);
            assert!(!found);
        }

        let expected = table
            .xs_receiver_order
            .iter()
            .zip(table.ys_receiver_order.iter())
            .enumerate()
            .filter(|(receiver_index, _)| !table.touched[*receiver_index])
            .map(|(_, (x, y))| (*x, *y))
            .collect::<Vec<_>>();
        let mut extract_xs = Vec::new();
        let mut extract_ys = Vec::new();
        table.extract(&mut extract_xs, &mut extract_ys);

        let extracted = extract_xs
            .iter()
            .zip(extract_ys.iter())
            .map(|(x, y)| (*x, *y))
            .collect::<Vec<_>>();

        assert_eq!(extracted, expected);
    })
    .unwrap();
}

fn setup(num_dummies: usize) -> TestData {
    let mut table_0 = None;
    let mut table_1 = None;
    let mut table_2 = None;
    let mut rng = rand::thread_rng();
    let key = (0..ROUND_KEYS).map(|_| rng.r#gen()).collect::<Vec<_>>();

    let tables = run_parties(|net| {
        let mut state = Rep3State::new(&net, A2BType::Direct).unwrap();
        let table = build_table(num_dummies, &key, &net, &mut state);

        (state.id, table)
    })
    .unwrap();

    for (id, table) in tables {
        match id {
            PartyID::ID0 => table_0 = Some(table),
            PartyID::ID1 => table_1 = Some(table),
            PartyID::ID2 => table_2 = Some(table),
        }
    }

    TestData {
        table_0: table_0.unwrap(),
        table_1: table_1.unwrap(),
        table_2: table_2.unwrap(),
    }
}

fn build_table<N: Network>(
    num_dummies: usize,
    clear_key: &[Block],
    net: &N,
    state: &mut Rep3State,
) -> OhTable {
    let params = OHTableParams::new(NUM_ELEMENTS, num_dummies, STASH_SIZE, 4, 5);
    let xs_clear = (0..NUM_ELEMENTS).map(|i| 10 + i as X).collect::<Vec<_>>();
    let ys_clear = (0..NUM_ELEMENTS).map(|i| 1000 + i as Y).collect::<Vec<_>>();
    let xs = promote_public_values(state.id, &xs_clear);
    let ys = promote_public_values(state.id, &ys_clear);
    let key = promote_public_values(state.id, clear_key);

    OhTable::new(params, xs, ys, key, net, state, None)
}

fn real_builder_indices(qs_clear: &[Block]) -> Vec<usize> {
    let mut indices = Vec::new();
    for (builder_index, q) in qs_clear.iter().copied().enumerate() {
        if q != Block::default() {
            indices.push(builder_index);
        }
    }
    indices
}
